"""CLI entry point for rom-analyzer."""

import os
import sys
from io import StringIO
from pathlib import Path

import click

from rom_analyzer.callgraph import (
    bootstrap_anchors, bfs_preseed, gap_fill, bytecode_identity_match,
)
from rom_analyzer.crc import Instruction, extract_crc_region
from rom_analyzer.data_refs import propagate_data_labels, propagate_ram_labels
from rom_analyzer.diff import run_vt_diff
from rom_analyzer.emit_ld import (
    emit_crc_region_toml,
    emit_description_ld,
    emit_flash_free_toml,
    emit_omni_stub,
    emit_ram_free_toml,
)
from rom_analyzer.flash_space import find_free_blocks
from rom_analyzer.ghidra import (
    apply_labels, apply_mut_table_in_ghidra, fetch_instructions_at,
    ghidriff_program_name, import_and_dump, setup_environment,
)
from rom_analyzer.mut_table import find_mut_table_in_run, mut_table_to_propagated_symbol
from rom_analyzer.propagate import propagate_function_labels
from rom_analyzer.ram_space import find_free_ram_blocks
from rom_analyzer.types import CrcRegion, MatchedFunction, PropagatedSymbol
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
@click.option("--reference-rom", type=click.Path(dir_okay=False, path_type=Path),
              default=Path(__file__).parent.parent / "roms" / "Z27AG_JDM_5MT_1860B104.bin",
              help="The ROM bin that the reference XML was generated from (user-supplied at roms/)")
@click.option("--ghidra-home", type=click.Path(exists=True, file_okay=False, path_type=Path),
              default=os.environ.get("GHIDRA_HOME", "/opt/homebrew/opt/ghidra/libexec"))
@click.option("--project-dir", type=click.Path(path_type=Path),
              default=Path.home() / "rom-analyzer-projects",
              help="Persistent Ghidra project dir (no path element may start with '.')")
@click.option("--project-name", default="rom-analyzer",
              help="Ghidra project name for the persistent PyGhidra project")
@click.option("--out", "out_dir", type=click.Path(path_type=Path), required=True,
              help="Output directory for emitted files")
@click.option("--min-flash-block", type=int, default=64)
@click.option("--min-ram-block", type=int, default=4)
@click.option("--reference-name", default="33520003")
@click.option("--clean-project", is_flag=True, default=False,
              help="Delete and recreate the Ghidra project dir before starting (forces fresh analysis)")
@click.option("--enrich-project", is_flag=True, default=False,
              help="Apply propagated symbols back into the Ghidra project for the new ROM")
@click.option("--inline-source-annotations", is_flag=True, default=False,
              help="Write heuristic source as a pre-comment at each labeled address")
def main(rom_path, variant, reference, flash_txt, map_txt, reference_rom, ghidra_home,
         project_dir, project_name, out_dir, min_flash_block, min_ram_block,
         reference_name, clean_project, enrich_project, inline_source_annotations):
    """Analyze a ROM and emit description.ld, omni.ld stub, and reports.

    \b
    Example:
        rom-analyzer ./Z27AG_other.bin --variant fp8000 --out ./out
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    project_dir = Path(project_dir)
    if clean_project and project_dir.exists():
        import shutil
        nested = project_dir / project_name
        if nested.exists():
            click.echo(f"--clean-project: removing {nested}")
            shutil.rmtree(nested)
    is_self_diff = rom_path.resolve() == reference_rom.resolve()  # True implies reference_rom exists (rom_path has exists=True)

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

    # Start Ghidra JVM and open the project once for the full run.
    setup_environment(ghidra_home)
    import pyghidra
    pyghidra.start()

    project_path = project_dir / project_name
    project_path.mkdir(parents=True, exist_ok=True)
    project = pyghidra.open_project(project_path, project_name, create=True)
    try:
        new_prog_name = ghidriff_program_name(rom_path)

        # [2/7] Import reference ROM into Ghidra + apply symbol overlay
        click.echo(f"[2/7] Importing reference ROM into Ghidra: {reference_rom}")
        if not reference_rom.exists():
            click.echo(f"   warning: reference ROM not found at {reference_rom}; skipping reference import")
            ref_run = None
        else:
            ref_run = import_and_dump(
                project,
                reference_rom, language_id,
                crc_step_address=crc_step_addr,
                ref_symbols_for_overlay=ref_symbols,
                collect_data_refs_flag=(not is_self_diff),
            )

        # [3/7] Import new ROM into Ghidra
        click.echo(f"[3/7] Importing new ROM into Ghidra: {rom_path}")
        new_run = import_and_dump(
            project,
            rom_path, language_id,
            crc_step_address=crc_step_addr,
            collect_data_refs_flag=(not is_self_diff),
        )

        # Read ROM bytes now — used by call-graph bootstrap and CRC scan
        rom_bytes = rom_path.read_bytes()

        # Call-graph bootstrap + BFS pre-seed (cross-ROM only)
        anchors: list[MatchedFunction] = []
        bfs_matches: list[MatchedFunction] = []
        if not is_self_diff and ref_run is not None:
            ref_bytes = reference_rom.read_bytes()
            ref_symbols_by_name = {s.name: s for s in ref_symbols}
            anchors = bootstrap_anchors(ref_bytes, rom_bytes, ref_run, new_run,
                                        ref_symbols_by_name, ref_symbols_by_addr)
            bfs_overlays, bfs_matches = bfs_preseed(anchors, ref_run, new_run,
                                                     ref_symbols_by_addr,
                                                     ref_bytes=ref_bytes,
                                                     new_bytes=rom_bytes)
            by_src: dict[str, int] = {}
            for a in anchors:
                by_src[a.source] = by_src.get(a.source, 0) + 1
            src_str = ", ".join(f"{s}: {n}" for s, n in sorted(by_src.items()))
            click.echo(f"   call-graph anchors: {len(anchors)} ({src_str})")
            click.echo(f"   call-graph BFS overlays: {len(bfs_overlays)}")
            if bfs_overlays:
                # Deduplicate by new-ROM address: multiple BFS paths can converge on the
                # same target; writing all of them as Ghidra labels creates spurious
                # multi-label clutter that persists across runs.
                seen_bfs: set[int] = set()
                unique_bfs = []
                for s in bfs_overlays:
                    if s.address not in seen_bfs:
                        seen_bfs.add(s.address)
                        unique_bfs.append(s)
                bfs_propagated = [
                    PropagatedSymbol(s.name, 0, s.address, s.category, "medium",
                                     source="callgraph_bfs", score=1.0)
                    for s in unique_bfs
                ]
                apply_labels(project, new_prog_name, bfs_propagated,
                             add_comments=inline_source_annotations)

        # [4/7] Diff (identity or VTSession)
        if is_self_diff:
            click.echo(f"[4/7] Self-diff detected; using identity matches")
            matches = [
                MatchedFunction(ref_name=s.name, ref_address=s.address,
                                new_address=s.address, similarity=1.0,
                                source="identity")
                for s in ref_symbols if s.category == "function"
            ]
        elif ref_run is None:
            click.echo("[4/7] Skipping diff — reference ROM unavailable")
            matches = []
        else:
            click.echo(f"[4/7] Diffing via Ghidra VTSession")
            ref_prog_name = ghidriff_program_name(reference_rom)
            matches = run_vt_diff(project, ref_prog_name, new_prog_name)
            gap_matches = gap_fill(ref_run, new_run, matches + anchors + bfs_matches,
                                   ref_bytes=ref_bytes, new_bytes=rom_bytes)
            click.echo(f"   call-graph gap-fill: {len(gap_matches)} additional matches")
            all_matches = matches + anchors + bfs_matches + gap_matches

            identity_matches = bytecode_identity_match(
                ref_bytes, rom_bytes, ref_run, new_run,
                all_matches, ref_symbols_by_addr,
            )
            click.echo(f"   bytecode identity: {len(identity_matches)} additional matches")
            matches = all_matches + identity_matches

        # Source priority — used in both dedup passes.
        # Structural ROM-invariant sources (vector_table, icu_vector_table, mut_table)
        # override bytecode-comparison matches.  Within a tier, higher similarity wins.
        SOURCE_PRIORITY = {"vector_table": 3, "icu_vector_table": 3,
                           "bytecode_identity": 2, "mut_table": 2,
                           "callgraph_bfs": 1, "callgraph_gap": 1, "vt_diff": 0}
        def _match_rank(m: MatchedFunction) -> tuple:
            return (SOURCE_PRIORITY.get(m.source, 0), m.similarity)

        # Deduplicate by ref_address — when multiple phases claimed the same
        # reference function, keep the highest-ranked match.
        best_by_ref: dict[int, MatchedFunction] = {}
        for m in matches:
            if m.ref_address not in best_by_ref or _match_rank(m) > _match_rank(best_by_ref[m.ref_address]):
                best_by_ref[m.ref_address] = m
        matches = list(best_by_ref.values())

        # Deduplicate by new_address — when two different ref functions map to
        # the same new address, keep only the highest-ranked match.
        best_by_new: dict[int, MatchedFunction] = {}
        for m in matches:
            if m.new_address not in best_by_new or _match_rank(m) > _match_rank(best_by_new[m.new_address]):
                best_by_new[m.new_address] = m
        matches = list(best_by_new.values())

        named_ref_addrs = {s.address for s in ref_symbols if s.category == "function"}
        matched_count = sum(1 for m in matches if m.ref_address in named_ref_addrs)
        total_ref = len(named_ref_addrs)
        match_summary = f"{matched_count}/{total_ref} ({100.0 * matched_count / max(1, total_ref):.1f}%)"

        # [5/7] Propagate symbols
        click.echo("[5/7] Propagating symbols")
        propagated_fns = propagate_function_labels(ref_symbols, matches)

        new_ram_refs = set(new_run.ram_refs)
        # Ram-global propagation by absolute address is only valid for same-ECU ROMs
        # (identical RAM layout).  Cross-family analysis (e.g. Z27AG vs Outlander)
        # must not copy reference RAM labels: a given fp-offset may hold a completely
        # different variable in the target ECU.  For cross-ROM analysis, per-function
        # RAM ref tracking would be required — that is not yet implemented.
        if is_self_diff:
            ram_globals = [
                PropagatedSymbol(s.name, s.address, s.address, "ram_global", "high",
                                 source="ram_global", score=1.0)
                for s in ref_symbols
                if s.category == "ram_global" and s.address in new_ram_refs
            ]
        else:
            ram_globals = []

        if not is_self_diff and ref_run is not None and ref_run.data_refs and new_run.data_refs:
            data_labels = propagate_data_labels(
                ref_run.data_refs, new_run.data_refs, matches, ref_symbols_by_addr
            )
            click.echo(f"   data labels propagated: {len(data_labels)}")
        elif is_self_diff:
            data_labels = [
                PropagatedSymbol(s.name, s.address, s.address, "data", "high",
                                 source="identity", score=1.0)
                for s in ref_symbols if s.category == "data"
            ]
        else:
            data_labels = []

        if not is_self_diff and ref_run is not None and ref_run.ram_data_refs and new_run.ram_data_refs:
            ram_labels = propagate_ram_labels(
                ref_run.ram_data_refs, new_run.ram_data_refs, matches, ref_symbols_by_addr
            )
            click.echo(f"   ram labels propagated: {len(ram_labels)}")
        else:
            ram_labels = []  # self-diff: ram_globals covers RAM vars by identity address

        propagated_all = propagated_fns + ram_globals + data_labels + ram_labels

        # [5.5/7] MUT table identification (cross-ROM only)
        _mut_table_ghidra_applied = False
        if not is_self_diff and new_run.data_refs:
            mut_result = find_mut_table_in_run(matches, new_run, rom_bytes)
            if mut_result is not None:
                click.echo(
                    f"   MUT table: {mut_result.table_address:#x}, size={mut_result.table_size}"
                )
                if mut_result.triplet_mismatch:
                    click.echo(
                        f"   warning: MUT table triplet scan disagrees; "
                        f"using data-ref result at {mut_result.table_address:#x}"
                    )
                ref_table_sym = next(
                    (s for s in ref_symbols if s.name == "flash_mut_variables_table"), None
                )
                ref_table_addr = ref_table_sym.address if ref_table_sym is not None else 0
                # data_labels (step [5/7]) may have already emitted flash_mut_variables_table
                # if the data-ref offset in get_mut_pointer aligned between ref and new ROM.
                # The MUT pass is authoritative; remove any prior entry for this name.
                propagated_all = [p for p in propagated_all if p.name != "flash_mut_variables_table"]
                propagated_all.append(
                    mut_table_to_propagated_symbol(mut_result, ref_table_addr)
                )
                if enrich_project:
                    apply_mut_table_in_ghidra(project, new_prog_name, mut_result)
                    _mut_table_ghidra_applied = True
            else:
                click.echo(
                    "   warning: MUT table not identified via get_mut_pointer data refs"
                )

        # [6/7] Detect CRC, scan free space
        click.echo("[6/7] Detecting CRC, scanning free space")

        # For self-diff the reference address equals the new-ROM address, so the
        # pre-fetched new_run.rom_crc_check_step is correct.  For cross-ROM analysis
        # crc_step_addr is the *reference* ROM's address (wrong for the target ROM);
        # look up the matched address from VTSession/BFS and re-fetch instructions.
        _crc_instrs_raw: list[dict] | None = None
        if is_self_diff:
            if new_run.rom_crc_check_step:
                _crc_instrs_raw = new_run.rom_crc_check_step["instructions"]
            else:
                click.echo("   warning: rom_crc_check_step not located in new ROM")
        else:
            crc_match = next((m for m in matches if m.ref_name == "rom_crc_check_step"), None)
            if crc_match is not None:
                click.echo(f"   fetching rom_crc_check_step at matched address {crc_match.new_address:#x}")
                _crc_instrs_raw = fetch_instructions_at(
                    project, new_prog_name, crc_match.new_address,
                )
                if _crc_instrs_raw is None:
                    click.echo("   warning: no instructions found at matched rom_crc_check_step address")
            else:
                click.echo("   warning: rom_crc_check_step not in VTSession/BFS matches; CRC detection skipped")

        crc: CrcRegion | None = None
        if _crc_instrs_raw is not None:
            instrs = [Instruction(i["mnemonic"], tuple(i["operands"])) for i in _crc_instrs_raw]
            try:
                crc = extract_crc_region(instrs)
            except Exception as e:
                click.echo(f"   warning: CRC extraction failed: {e}")

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
        scalar_count = sum(1 for d in data_labels if d.source == "data_refs_scalar")
        label_summary = (
            f"{len(data_labels)} ({scalar_count} via scalar refs)"
            if scalar_count
            else str(len(data_labels))
        )
        report.write(f"- Propagated data labels: {label_summary}\n")
        report.write(f"- Propagated RAM labels: {len(ram_labels)}\n\n")
        src_counts: dict[str, int] = {}
        for m in matches:
            src_counts[m.source] = src_counts.get(m.source, 0) + 1
        if src_counts:
            report.write("## Match sources\n")
            for src, cnt in sorted(src_counts.items()):
                report.write(f"- {src}: {cnt}\n")
            report.write("\n")
        if crc is not None:
            report.write(f"## CRC region\n")
            report.write(f"- Full mode:    [{crc.full_start:#x}, {crc.full_end:#x})\n")
            report.write(f"- Partial mode: [{crc.partial_start:#x}, {crc.partial_end:#x})\n")
        (out_dir / "match-report.md").write_text(report.getvalue())

        click.echo(f"\nDone. Outputs in {out_dir}/")

        if enrich_project:
            # apply_mut_table_in_ghidra already set the void*[N] datatype + label for
            # flash_mut_variables_table.  Exclude it here to avoid a redundant label
            # write and a duplicate bookmark at the same address.
            labels_for_apply = (
                [p for p in propagated_all if p.name != "flash_mut_variables_table"]
                if _mut_table_ghidra_applied else propagated_all
            )
            click.echo(f"[+] Enriching Ghidra project with {len(labels_for_apply)} propagated symbols")
            n = apply_labels(project, new_prog_name, labels_for_apply,
                             add_comments=inline_source_annotations)
            click.echo(f"    Applied {n} label(s) to {rom_path.name} Ghidra project")
    finally:
        project.close()


if __name__ == "__main__":
    main()
