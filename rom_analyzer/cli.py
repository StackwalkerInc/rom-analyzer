"""CLI entry point for rom-analyzer."""

import os
import sys
from io import StringIO
from pathlib import Path

import click

from rom_analyzer.crc import Instruction, extract_crc_region
from rom_analyzer.data_refs import propagate_data_labels
from rom_analyzer.diff import run_ghidriff
from rom_analyzer.emit_ld import (
    emit_crc_region_toml,
    emit_description_ld,
    emit_flash_free_toml,
    emit_omni_stub,
    emit_ram_free_toml,
)
from rom_analyzer.flash_space import find_free_blocks
from rom_analyzer.ghidra import import_and_dump
from rom_analyzer.propagate import propagate_function_labels
from rom_analyzer.ram_space import find_free_ram_blocks
from rom_analyzer.types import PropagatedSymbol
from rom_analyzer.xml_io import load_reference_symbols


VARIANT_TO_LANGUAGE = {
    "fp8000": "m32r:2:fp8000",
    "fpc000": "m32r:2:default",
}

_REFERENCE_DIR = Path(__file__).parent.parent / "reference"


@click.command()
@click.argument("rom_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--variant", type=click.Choice(["fp8000", "fpc000"]), required=True)
@click.option("--reference", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              default=_REFERENCE_DIR / "33520003.xml",
              help="Reference Ghidra XML (metadata-only; merged with colt_flash/map at load time)")
@click.option("--flash-txt", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              default=_REFERENCE_DIR / "colt_flash.txt",
              help="colt_flash.txt symbol table for enrichment (vendored in reference/)")
@click.option("--map-txt", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              default=_REFERENCE_DIR / "colt_map.txt",
              help="colt_map.txt RAM symbol table for enrichment (vendored in reference/)")
@click.option("--reference-rom", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              default=Path(__file__).parent.parent / "roms" / "Z27AG_JDM_5MT_1860B104.bin",
              help="The ROM bin that the reference XML was generated from (user-supplied at roms/)")
@click.option("--ghidra-home", type=click.Path(exists=True, file_okay=False, path_type=Path),
              default=os.environ.get("GHIDRA_HOME", "/opt/homebrew/opt/ghidra/libexec"))
@click.option("--project-dir", type=click.Path(path_type=Path),
              default=Path.home() / "rom-analyzer-projects",
              help="Persistent Ghidra project dir (no path element may start with '.')")
@click.option("--project-name", default="rom-analyzer",
              help="Ghidra project name (also used by ghidriff to find pre-imported programs)")
@click.option("--out", "out_dir", type=click.Path(path_type=Path), required=True,
              help="Output directory for emitted files")
@click.option("--min-flash-block", type=int, default=64)
@click.option("--min-ram-block", type=int, default=4)
@click.option("--reference-name", default="33520003")
@click.option("--diff-engine", type=click.Choice(["VersionTrackingDiff", "SimpleDiff"]),
              default="VersionTrackingDiff")
def main(rom_path, variant, reference, flash_txt, map_txt, reference_rom, ghidra_home,
         project_dir, project_name, out_dir, min_flash_block, min_ram_block,
         reference_name, diff_engine):
    """Analyze a ROM and emit description.ld, omni.ld stub, and reports.

    \b
    Example:
        rom-analyzer ./Z27AG_other.bin --variant fp8000 --out ./out
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    project_dir = Path(project_dir)
    is_self_diff = rom_path.resolve() == reference_rom.resolve()

    language_id = VARIANT_TO_LANGUAGE[variant]

    # [1/7] Load enriched reference symbols
    click.echo(f"[1/7] Loading reference symbols from {reference} + colt_flash/map")
    flash_txt_path = Path(flash_txt) if flash_txt else None
    map_txt_path = Path(map_txt) if map_txt else None
    ref_symbols = load_reference_symbols(reference, flash_txt=flash_txt_path, map_txt=map_txt_path)
    ref_symbols_by_addr = {s.address: s for s in ref_symbols}

    crc_step_addr = next(
        (s.address for s in ref_symbols if s.name == "rom_crc_check_step"),
        None,
    )
    if crc_step_addr is None:
        click.echo("   warning: rom_crc_check_step not in reference symbols; CRC detection skipped")

    # [2/7] Import reference ROM into Ghidra + apply symbol overlay
    click.echo(f"[2/7] Importing reference ROM into Ghidra: {reference_rom}")
    if not reference_rom.exists():
        click.echo(f"   warning: reference ROM not found at {reference_rom}; skipping reference import")
        ref_run = None
    else:
        ref_run = import_and_dump(
            ghidra_home, project_dir, project_name,
            reference_rom, language_id,
            crc_step_address=crc_step_addr,
            ref_symbols_for_overlay=ref_symbols,
            collect_data_refs_flag=(not is_self_diff),
        )

    # [3/7] Import new ROM into Ghidra
    click.echo(f"[3/7] Importing new ROM into Ghidra: {rom_path}")
    new_run = import_and_dump(
        ghidra_home, project_dir, project_name,
        rom_path, language_id,
        crc_step_address=crc_step_addr,
        collect_data_refs_flag=(not is_self_diff),
    )

    # [4/7] Diff (identity or ghidriff)
    if is_self_diff:
        click.echo(f"[4/7] Self-diff detected; using identity matches")
        from rom_analyzer.types import MatchedFunction
        matches = [
            MatchedFunction(ref_name=s.name, ref_address=s.address,
                            new_address=s.address, similarity=1.0)
            for s in ref_symbols if s.category == "function"
        ]
    else:
        click.echo(f"[4/7] Diffing via ghidriff ({diff_engine})")
        matches = run_ghidriff(
            ghidra_home, project_dir, project_name,
            reference_rom, rom_path,
            engine=diff_engine,
        )

    matched_count = len(matches)
    total_ref = sum(1 for s in ref_symbols if s.category == "function")
    match_summary = f"{matched_count}/{total_ref} ({100.0 * matched_count / max(1, total_ref):.1f}%)"

    # [5/7] Propagate symbols
    click.echo("[5/7] Propagating symbols")
    propagated_fns = propagate_function_labels(ref_symbols, matches)

    new_ram_refs = set(new_run.ram_refs)
    ram_globals = [
        PropagatedSymbol(s.name, s.address, s.address, "ram_global", "high")
        for s in ref_symbols
        if s.category == "ram_global" and s.address in new_ram_refs
    ]

    if not is_self_diff and ref_run is not None and ref_run.data_refs and new_run.data_refs:
        data_labels = propagate_data_labels(
            ref_run.data_refs, new_run.data_refs, matches, ref_symbols_by_addr
        )
        click.echo(f"   data labels propagated: {len(data_labels)}")
    elif is_self_diff:
        data_labels = [
            PropagatedSymbol(s.name, s.address, s.address, "data", "high")
            for s in ref_symbols if s.category == "data"
        ]
    else:
        data_labels = []

    propagated_all = propagated_fns + ram_globals + data_labels

    # [6/7] Detect CRC, scan free space
    click.echo("[6/7] Detecting CRC, scanning free space")
    if new_run.rom_crc_check_step:
        instrs = [Instruction(i["mnemonic"], tuple(i["operands"]))
                  for i in new_run.rom_crc_check_step["instructions"]]
        try:
            crc = extract_crc_region(instrs)
        except Exception as e:
            click.echo(f"   warning: CRC extraction failed: {e}")
            crc = None
    else:
        click.echo("   warning: rom_crc_check_step not located in new ROM")
        crc = None

    rom_bytes = rom_path.read_bytes()
    flash_blocks = find_free_blocks(rom_bytes, crc, min_length=min_flash_block) if crc else []
    ram_blocks = find_free_ram_blocks(new_ram_refs, min_length=min_ram_block)

    # [7/7] Emit outputs
    click.echo("[7/7] Emitting outputs")
    (out_dir / "description.ld").write_text(emit_description_ld(
        propagated_all,
        source_rom=rom_path.name,
        reference_name=reference_name,
        variant=language_id,
        match_summary=match_summary,
    ))
    (out_dir / "omni.ld.stub").write_text(emit_omni_stub(flash_blocks, ram_globals))
    (out_dir / "crc-region.toml").write_text(
        emit_crc_region_toml(crc) if crc else "# CRC region not detected\n"
    )
    (out_dir / "flash-free.toml").write_text(emit_flash_free_toml(flash_blocks))
    (out_dir / "ram-free.toml").write_text(emit_ram_free_toml(ram_blocks))

    report = StringIO()
    report.write("# rom-analyzer match report\n\n")
    report.write(f"Source ROM: {rom_path.name}\n")
    report.write(f"Reference:  {reference_name}\n")
    report.write(f"Variant:    {language_id}\n\n")
    report.write(f"## Summary\n- Matched functions: {match_summary}\n")
    report.write(f"- Propagated data labels: {len(data_labels)}\n\n")
    if crc is not None:
        report.write(f"## CRC region\n")
        report.write(f"- Full mode:    [{crc.full_start:#x}, {crc.full_end:#x})\n")
        report.write(f"- Partial mode: [{crc.partial_start:#x}, {crc.partial_end:#x})\n")
    (out_dir / "match-report.md").write_text(report.getvalue())

    click.echo(f"\nDone. Outputs in {out_dir}/")


if __name__ == "__main__":
    main()
