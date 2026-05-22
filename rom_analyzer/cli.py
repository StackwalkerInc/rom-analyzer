"""CLI entry point for rom-analyzer."""

import os
import sys
from io import StringIO
from pathlib import Path

import click

from rom_analyzer.crc import Instruction, extract_crc_region
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


@click.command()
@click.argument("rom_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--variant", type=click.Choice(["fp8000", "fpc000"]), required=True)
@click.option("--reference", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              default=Path(__file__).parent.parent / "reference" / "33520003.xml",
              help="Reference Ghidra XML (metadata-only; used as a name lookup, not loaded into Ghidra)")
@click.option("--reference-rom", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              default=Path(__file__).parent.parent / "roms" / "Z27AG_JDM_5MT_1860B104.bin",
              help="The ROM bin that the reference XML was generated from (user-supplied at roms/)")
@click.option("--ghidra-home", type=click.Path(exists=True, file_okay=False, path_type=Path),
              default=os.environ.get("GHIDRA_HOME", "/opt/homebrew/opt/ghidra/libexec"))
@click.option("--project-dir", type=click.Path(path_type=Path),
              default=Path.home() / "rom-analyzer-projects",
              help="Persistent Ghidra project dir (no path element may start with '.')")
@click.option("--out", "out_dir", type=click.Path(path_type=Path), required=True,
              help="Output directory for emitted files")
@click.option("--min-flash-block", type=int, default=64)
@click.option("--min-ram-block", type=int, default=4)
@click.option("--reference-name", default="33520003")
def main(rom_path, variant, reference, reference_rom, ghidra_home, project_dir, out_dir,
         min_flash_block, min_ram_block, reference_name):
    """Analyze a ROM and emit description.ld, omni.ld stub, and reports.

    \b
    Example:
        rom-analyzer ./Z27AG_other.bin --variant fp8000 --out ./out
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    project_dir = Path(project_dir)

    language_id = VARIANT_TO_LANGUAGE[variant]

    click.echo(f"[1/5] Loading reference XML symbols from {reference}")
    ref_symbols = load_reference_symbols(reference)

    crc_step_addr = next(
        (s.address for s in ref_symbols if s.name == "rom_crc_check_step"),
        None,
    )

    click.echo(f"[2/5] Importing new ROM into Ghidra: {rom_path}")
    new_run = import_and_dump(ghidra_home, project_dir, "rom-analyzer",
                              rom_path, language_id,
                              crc_step_address=crc_step_addr)

    if rom_path.resolve() == reference_rom.resolve():
        click.echo(f"[3/5] Self-diff detected (reference_rom == rom_path); using identity match")
        from rom_analyzer.types import MatchedFunction
        matches = [
            MatchedFunction(ref_name=s.name, ref_address=s.address,
                            new_address=s.address, similarity=1.0)
            for s in ref_symbols if s.category == "function"
        ]
    else:
        click.echo(f"[3/5] Diffing via ghidriff (reference: {reference_rom}, new: {rom_path})")
        matches = run_ghidriff(ghidra_home, reference_rom, rom_path, project_dir, language_id)
    matched_count = len(matches)
    total_ref = sum(1 for s in ref_symbols if s.category == "function")
    match_summary = f"{matched_count}/{total_ref} ({100.0 * matched_count / max(1, total_ref):.1f}%)"

    click.echo("[4/5] Propagating symbols")
    propagated_fns = propagate_function_labels(ref_symbols, matches)
    # RAM globals propagate when the same RAM address is referenced in the new ROM
    new_ram_refs = set(new_run.ram_refs)
    ram_globals = [
        PropagatedSymbol(s.name, s.address, s.address, "ram_global", "high")
        for s in ref_symbols
        if s.category == "ram_global" and s.address in new_ram_refs
    ]
    propagated_all = propagated_fns + ram_globals

    click.echo("[5/5] Detecting CRC, scanning free space, emitting outputs")
    if new_run.rom_crc_check_step:
        instrs = [Instruction(i["mnemonic"], tuple(i["operands"]))
                  for i in new_run.rom_crc_check_step["instructions"]]
        try:
            crc = extract_crc_region(instrs)
        except Exception as e:
            click.echo(f"   warning: CRC extraction failed: {e}; emitting empty crc-region.toml")
            crc = None
    else:
        click.echo("   warning: rom_crc_check_step not located; emitting empty crc-region.toml")
        crc = None

    rom_bytes = rom_path.read_bytes()
    if crc is not None:
        flash_blocks = find_free_blocks(rom_bytes, crc, min_length=min_flash_block)
    else:
        flash_blocks = []
    ram_blocks = find_free_ram_blocks(new_ram_refs, min_length=min_ram_block)

    (out_dir / "description.ld").write_text(emit_description_ld(
        propagated_all,
        source_rom=rom_path.name,
        reference_name=reference_name,
        variant=language_id,
        match_summary=match_summary,
    ))
    (out_dir / "omni.ld.stub").write_text(emit_omni_stub(flash_blocks, ram_globals))
    if crc is not None:
        (out_dir / "crc-region.toml").write_text(emit_crc_region_toml(crc))
    else:
        (out_dir / "crc-region.toml").write_text("# CRC region not detected\n")
    (out_dir / "flash-free.toml").write_text(emit_flash_free_toml(flash_blocks))
    (out_dir / "ram-free.toml").write_text(emit_ram_free_toml(ram_blocks))

    # match-report.md
    report = StringIO()
    report.write("# rom-analyzer match report\n\n")
    report.write(f"Source ROM: {rom_path.name}\n")
    report.write(f"Reference:  {reference_name}\n")
    report.write(f"Variant:    {language_id}\n\n")
    report.write(f"## Summary\n- Matched functions: {match_summary}\n\n")
    if crc is not None:
        report.write(f"## CRC region\n- Full mode:    [{crc.full_start:#x}, {crc.full_end:#x})\n")
        report.write(f"- Partial mode: [{crc.partial_start:#x}, {crc.partial_end:#x})\n")
    (out_dir / "match-report.md").write_text(report.getvalue())

    click.echo(f"\nDone. Outputs in {out_dir}/")


if __name__ == "__main__":
    main()
