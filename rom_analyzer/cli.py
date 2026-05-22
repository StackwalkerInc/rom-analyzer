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
    "fp8000": "m32r:BE:32:fp8000:default",
    "fpc000": "m32r:BE:32:default",
}


@click.command()
@click.argument("rom_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--variant", type=click.Choice(["fp8000", "fpc000"]), required=True)
@click.option("--reference", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              default=Path(__file__).parent.parent / "reference" / "33520003.xml",
              help="Reference Ghidra XML")
@click.option("--ghidra-home", type=click.Path(exists=True, file_okay=False, path_type=Path),
              default=os.environ.get("GHIDRA_HOME", "/opt/homebrew/opt/ghidra/libexec"))
@click.option("--project-dir", type=click.Path(path_type=Path),
              default=Path.home() / ".cache" / "rom-analyzer" / "proj",
              help="Persistent Ghidra project dir")
@click.option("--out", "out_dir", type=click.Path(path_type=Path), required=True,
              help="Output directory for emitted files")
@click.option("--min-flash-block", type=int, default=64)
@click.option("--min-ram-block", type=int, default=4)
@click.option("--reference-name", default="33520003")
def main(rom_path, variant, reference, ghidra_home, project_dir, out_dir,
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

    click.echo(f"[1/6] Importing reference XML: {reference}")
    ref_run = import_and_dump(ghidra_home, project_dir, "rom-analyzer",
                              reference, language_id)
    ref_symbols = load_reference_symbols(reference)

    click.echo(f"[2/6] Importing new ROM: {rom_path}")
    new_run = import_and_dump(ghidra_home, project_dir, "rom-analyzer",
                              rom_path, language_id)

    click.echo("[3/6] Diffing via ghidriff")
    matches = run_ghidriff(ghidra_home, reference, rom_path, project_dir, language_id)
    matched_count = len(matches)
    total_ref = sum(1 for s in ref_symbols if s.category == "function")
    match_summary = f"{matched_count}/{total_ref} ({100.0 * matched_count / max(1, total_ref):.1f}%)"

    click.echo("[4/6] Propagating symbols")
    propagated_fns = propagate_function_labels(ref_symbols, matches)
    # RAM globals propagate when the same RAM address is referenced in the new ROM
    new_ram_refs = set(new_run.ram_refs)
    ram_globals = [
        PropagatedSymbol(s.name, s.address, s.address, "ram_global", "high")
        for s in ref_symbols
        if s.category == "ram_global" and s.address in new_ram_refs
    ]
    propagated_all = propagated_fns + ram_globals

    click.echo("[5/6] Detecting CRC region")
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

    click.echo("[6/6] Scanning free space and emitting outputs")
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
