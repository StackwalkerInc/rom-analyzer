"""CLI entry point for rom-analyzer."""

import os
import sys
from dataclasses import dataclass, replace
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
    emit_dtc_map_toml,
    emit_flash_free_toml,
    emit_mode23_binding_line,
    emit_omni_stub,
    emit_can_slots_toml,
    emit_obd_pid_symbols,
    emit_ram_free_toml,
    emit_reference_conflicts_md,
)
from rom_analyzer.flash_space import find_free_blocks
from rom_analyzer.ghidra import (
    apply_data_types, apply_labels, apply_mut_table_in_ghidra,
    fetch_function_entry, fetch_callers_of, fetch_data_read_sites,
    fetch_dtc_helpers_structural,
    fetch_instructions_at, fetch_r0_imm_before,
    ghidriff_program_name, import_and_dump, setup_environment,
)
from rom_analyzer.merge import (
    match_rank, merge_matches, arbitrate_symbols,
)
from rom_analyzer.mode23_bindings import (
    resolve_nearest_site,
    resolve_can_call_sites,
    decode_ldi_r0_before,
)
from rom_analyzer.mut_table import find_mut_table_in_run, mut_table_to_propagated_symbol
from rom_analyzer.propagate import propagate_function_labels, apply_reference_provenance
from rom_analyzer.ram_signature import build_ram_signatures, match_by_ram_signature
from rom_analyzer.ram_space import find_free_ram_blocks
from rom_analyzer.registry import (
    ReferenceEntry, load_registry, select_references, partition_available,
)
from rom_analyzer.types import CrcRegion, MatchedFunction, PropagatedSymbol
from rom_analyzer.annotations_io import (
    AnnotationFunction, load_annotations, load_reference_symbols, save_annotations,
)
from rom_analyzer.types import DataTypeDefinition
from rom_analyzer.enrich import (
    LabelCandidate, gather_candidates, classify, build_reconcile_items, write_reconcile,
)
from rom_analyzer.scripts.build_reference_from_txt import (
    drop_imprecise_s_duplicates, drop_erased_flash_entries, dedup_symbol_names,
)


VARIANT_TO_LANGUAGE = {
    "fp8000": "m32r:2:fp8000",
    "fpc000": "m32r:2:default",
}

_REFERENCE_DIR = Path(__file__).parent.parent / "reference"


@dataclass
class ReferenceResult:
    entry: ReferenceEntry
    matches: list          # list[MatchedFunction], tagged with reference=entry.id
    propagated: list       # list[PropagatedSymbol], tagged + family-gated
    ref_run: object        # ImportRun handle (for single-source passes), may be None
    ref_symbols: list      # list[ReferenceSymbol] for this reference
    # Detail fields for the match-report (primary reference only)
    data_labels: list      # list[PropagatedSymbol]
    ram_labels: list       # list[PropagatedSymbol]
    sig_matches: list      # list[MatchedFunction]
    ram_labels_p2: list    # list[PropagatedSymbol]
    data_labels_p2: list   # list[PropagatedSymbol]


def analyze_against_reference(project, entry, language_id, rom_path, rom_bytes,
                              new_run, new_prog_name, target_family,
                              inline_source_annotations):
    """Run the full matching + propagation pipeline for ONE reference against
    the already-imported target. Returns reference-tagged, family-gated results."""

    reference_rom = entry.rom_path
    reference = entry.json_path

    is_self_diff = rom_path.resolve() == reference_rom.resolve()

    # [1/7] Load enriched reference symbols
    click.echo(f"[1/7] Loading reference symbols from {reference}")
    ref_symbols = load_reference_symbols(reference)
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
            project,
            reference_rom, language_id,
            crc_step_address=crc_step_addr,
            ref_symbols_for_overlay=ref_symbols,
            collect_data_refs_flag=(not is_self_diff),
        )

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

    # Deduplicate by ref_address — when multiple phases claimed the same
    # reference function, keep the highest-ranked match.
    # Within one reference, the reference-priority component is constant so {} is fine.
    best_by_ref: dict[int, MatchedFunction] = {}
    for m in matches:
        if m.ref_address not in best_by_ref or match_rank(m, {}) > match_rank(best_by_ref[m.ref_address], {}):
            best_by_ref[m.ref_address] = m
    matches = list(best_by_ref.values())

    # Deduplicate by new_address — when two different ref functions map to
    # the same new address, keep only the highest-ranked match.
    best_by_new: dict[int, MatchedFunction] = {}
    for m in matches:
        if m.new_address not in best_by_new or match_rank(m, {}) > match_rank(best_by_new[m.new_address], {}):
            best_by_new[m.new_address] = m
    matches = list(best_by_new.values())

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

    # [5.25/7] RAM-signature match + second propagation pass
    sig_matches: list[MatchedFunction] = []
    ram_labels_p2: list[PropagatedSymbol] = []
    data_labels_p2: list[PropagatedSymbol] = []
    if not is_self_diff and ref_run is not None and ref_run.ram_data_refs and new_run.ram_data_refs and ram_labels:
        click.echo("[5.25/7] RAM-signature matching")
        ref_label_map = {s.address: s.name for s in ref_symbols if s.category == "ram_global"}
        new_label_map = {ps.new_address: ps.name for ps in ram_labels}
        ref_sigs = build_ram_signatures(ref_run.ram_data_refs, ref_label_map)
        new_sigs = build_ram_signatures(new_run.ram_data_refs, new_label_map)
        sig_matches = match_by_ram_signature(ref_sigs, new_sigs, matches, ref_symbols_by_addr)
        click.echo(f"   ram-signature matches: {len(sig_matches)}")
        if sig_matches:
            extended_matches = matches + sig_matches
            fn_labels_p2 = propagate_function_labels(ref_symbols, sig_matches)
            ram_labels_p2 = propagate_ram_labels(
                ref_run.ram_data_refs, new_run.ram_data_refs,
                extended_matches, ref_symbols_by_addr,
            )
            if ref_run.data_refs and new_run.data_refs:
                data_labels_p2 = propagate_data_labels(
                    ref_run.data_refs, new_run.data_refs,
                    extended_matches, ref_symbols_by_addr,
                )
            click.echo(f"   ram labels (p2): {len(ram_labels_p2)}")
            click.echo(f"   data labels (p2): {len(data_labels_p2)}")
            propagated_all += fn_labels_p2 + ram_labels_p2 + data_labels_p2
            matches = extended_matches

    # Tag matches and propagated symbols with origin reference id, apply family gating
    matches = [replace(m, reference=entry.id) for m in matches]
    family_match = (entry.family == target_family)
    propagated_all = apply_reference_provenance(
        propagated_all, reference=entry.id, family_match=family_match)

    return ReferenceResult(
        entry=entry,
        matches=matches,
        propagated=propagated_all,
        ref_run=ref_run,
        ref_symbols=ref_symbols,
        data_labels=data_labels,
        ram_labels=ram_labels,
        sig_matches=sig_matches,
        ram_labels_p2=ram_labels_p2,
        data_labels_p2=data_labels_p2,
    )


@click.command("analyze")
@click.argument("rom_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--variant", type=click.Choice(["fp8000", "fpc000"]), required=True)
@click.option("--reference", type=click.Path(exists=True, dir_okay=False, path_type=Path),
              default=_REFERENCE_DIR / "33520003.json",
              help="Reference annotations JSON (vendored in reference/)")
@click.option("--reference-rom", type=click.Path(dir_okay=False, path_type=Path),
              default=Path(__file__).parent.parent / "roms" / "Z27AG_JDM_5MT_1860B104.bin",
              help="The reference ROM bin (user-supplied at roms/)")
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
@click.option("--emit-mode23", is_flag=True, default=False,
              help="Resolve and append the mode-0x23 code splice-site bindings to description.ld")
@click.option("--emit-obd", is_flag=True, default=False,
              help="Extract OBD PID + DTC ground-truth labels and emit dtc-map.toml")
@click.option("--emit-can-slots", is_flag=True, default=False,
              help="Decode per-slot CAN SIDs and emit can-slots.toml (semantic "
                   "names by SID, reliable across slot-index shifts)")
@click.option("--registry", "registry_path", type=click.Path(path_type=Path),
              default=_REFERENCE_DIR / "registry.toml",
              help="Reference registry TOML (multi-reference). Falls back to "
                   "--reference/--reference-rom if absent.")
@click.option("--reference-id", "reference_ids", multiple=True,
              help="Restrict to these registry reference ids (repeatable).")
@click.option("--exclude-id", "exclude_ids", multiple=True,
              help="Drop these registry reference ids (repeatable).")
@click.option("--fast", is_flag=True, default=False,
              help="Greedy incremental: match against the top-priority "
                   "reference first, later references only fill gaps. "
                   "(Accepted but not yet implemented — reserved for a future iteration.)")
def analyze(rom_path, variant, reference, reference_rom, ghidra_home,
         project_dir, project_name, out_dir, min_flash_block, min_ram_block,
         reference_name, clean_project, enrich_project, inline_source_annotations,
         emit_mode23, emit_obd, emit_can_slots,
         registry_path, reference_ids, exclude_ids, fast):
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

    language_id = VARIANT_TO_LANGUAGE[variant]

    if fast:
        click.echo("   warning: --fast not yet implemented; running full pipeline")

    # Build the selected reference set from the registry (or fall back to
    # legacy --reference / --reference-rom flags when the registry is absent).
    if registry_path.exists():
        entries = load_registry(registry_path)
        selected = select_references(entries, variant=variant,
                                     include_ids=list(reference_ids),
                                     exclude_ids=list(exclude_ids))
        selected, missing = partition_available(selected)
        for e in missing:
            click.echo(f"   skipping reference {e.id}: ROM bin not found at {e.rom_path}")
        if not selected:
            raise click.ClickException("No usable references (registry empty or all bins missing).")
    else:
        selected = [ReferenceEntry(
            id=reference_name, json_path=reference, rom_path=reference_rom,
            family="", variant=variant, priority=0, features=[], notes="")]

    priority = {e.id: e.priority for e in selected}
    target_family = selected[0].family   # primary (highest-priority) defines target family
    primary = selected[0]
    click.echo(f"[refs] {len(selected)} reference(s): "
               + ", ".join(f"{e.id}(p{e.priority})" for e in selected))

    # Load data type definitions from the primary reference for --enrich-project
    _primary_ref_store = load_annotations(primary.json_path)
    data_type_defs = [
        DataTypeDefinition(s.address, s.data_type, 0)
        for s in _primary_ref_store.symbols if s.data_type
    ]

    # Start Ghidra JVM and open the project once for the full run.
    setup_environment(ghidra_home)
    import pyghidra
    pyghidra.start()

    project_path = project_dir / project_name
    project_path.mkdir(parents=True, exist_ok=True)
    project = pyghidra.open_project(project_path, project_name, create=True)
    try:
        new_prog_name = ghidriff_program_name(rom_path)

        # [3/7] Import new ROM into Ghidra (once, shared across all references)
        click.echo(f"[3/7] Importing new ROM into Ghidra: {rom_path}")
        # Use the primary reference's crc_step_addr for the target import.
        # The primary drives single-source passes anyway, so this is consistent.
        _primary_ref_symbols_preview = load_reference_symbols(primary.json_path)
        _primary_crc_step_addr = next(
            (s.address for s in _primary_ref_symbols_preview if s.name == "rom_crc_check_step"),
            None,
        )
        _primary_is_self_diff = rom_path.resolve() == primary.rom_path.resolve()
        new_run = import_and_dump(
            project,
            rom_path, language_id,
            crc_step_address=_primary_crc_step_addr,
            collect_data_refs_flag=(not _primary_is_self_diff),
        )

        # Read ROM bytes now — used by call-graph bootstrap and CRC scan
        rom_bytes = rom_path.read_bytes()

        # Run the full matching + propagation pipeline for each reference
        results: list[ReferenceResult] = []
        for entry in selected:
            click.echo(f"[ref {entry.id}] matching")
            results.append(analyze_against_reference(
                project, entry, language_id, rom_path, rom_bytes,
                new_run, new_prog_name, target_family, inline_source_annotations))

        # Merge matches and arbitrate symbols across all references
        matches = merge_matches([r.matches for r in results], priority)
        all_propagated = [s for r in results for s in r.propagated]
        propagated_all, disagreements = arbitrate_symbols(all_propagated, priority)
        cross_family = [s for s in propagated_all if not s.family_match]
        click.echo(f"[merge] {len(propagated_all)} symbols, "
                   f"{len(disagreements)} disagreement(s), "
                   f"{len(cross_family)} cross-family VERIFY")
        show_provenance = len(selected) > 1

        # Single-source passes use the primary reference
        primary_result = results[0]
        ref_symbols = primary_result.ref_symbols
        ref_run = primary_result.ref_run
        ref_symbols_by_addr = {s.address: s for s in ref_symbols}

        named_ref_addrs = {s.address for s in ref_symbols if s.category == "function"}
        matched_count = sum(1 for m in matches if m.ref_address in named_ref_addrs)
        total_ref = len(named_ref_addrs)
        match_summary = f"{matched_count}/{total_ref} ({100.0 * matched_count / max(1, total_ref):.1f}%)"

        # RAM globals for omni.ld.stub: use the primary reference's propagated symbols
        ram_globals = [s for s in primary_result.propagated if s.category == "ram_global"]

        # [5.5/7] MUT table identification (cross-ROM only)
        _mut_table_ghidra_applied = False
        if not _primary_is_self_diff and new_run.data_refs:
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

        # [5.75/7] OBD PID + DTC analysis
        obd_result = None
        obd_pid_text: str = ""
        if emit_obd:
            from rom_analyzer.obd_analysis import run_obd_analysis
            click.echo("[5.75/7] OBD PID + DTC analysis")

            # Locate flash_trouble_code_table in the new ROM
            dtc_table_sym = next(
                (p for p in propagated_all if p.name == "flash_trouble_code_table"),
                None,
            )
            if dtc_table_sym is not None:
                dtc_table_addr_new = dtc_table_sym.new_address
            else:
                # 0x12948 is the 33520003 reference-ROM address; safe only if ROM map is identical
                click.echo("   warning: flash_trouble_code_table not propagated; using reference-ROM fallback 0x12948")
                dtc_table_addr_new = 0x12948

            # Build (mode, entry_addr) pairs from matched functions
            _handler_refs = [
                (1,    "sio0_obd_request_data_by_pid"),
                (2,    "obd_get_freeze_frame0"),
                (0x18, "obd_mode18_handler"),
                (0x59, "obd_mode59_handler"),
            ]
            match_by_name = {m.ref_name: m for m in matches if m.ref_name}
            handler_entries: list[tuple[int, int]] = []
            for mode, ref_name in _handler_refs:
                m = match_by_name.get(ref_name)
                if m is not None:
                    handler_entries.append((mode, m.new_address))
                else:
                    click.echo(
                        f"   warning: {ref_name} not matched; "
                        f"mode {mode:#x} PID trace skipped"
                    )

            # Resolve DTC helper addresses: Layer 1 = VTSession match
            set_match = match_by_name.get("probably_set_dtc")
            reset_match = match_by_name.get("probably_reset_dtc")
            set_addr = set_match.new_address if set_match else None
            reset_addr = reset_match.new_address if reset_match else None

            # Layer 2 fallback: structural opcode signature scan
            if set_addr is None or reset_addr is None:
                click.echo(
                    "   DTC helpers not fully resolved via VTSession; trying structural scan for missing one(s)"
                )
                scan_set, scan_reset = fetch_dtc_helpers_structural(
                    project, new_prog_name
                )
                # Layer 3 cross-check: warn if structural candidate has < 5 callers
                if scan_set is not None:
                    n_callers = len(fetch_callers_of(project, new_prog_name, scan_set))
                    if n_callers < 5:
                        click.echo(
                            f"   warning: structural set_dtc candidate "
                            f"{scan_set:#x} has only {n_callers} callers (expected ≥5)"
                        )
                if scan_reset is not None:
                    n_reset_callers = len(fetch_callers_of(project, new_prog_name, scan_reset))
                    if n_reset_callers < 2:
                        click.echo(
                            f"   warning: structural reset_dtc candidate "
                            f"{scan_reset:#x} has only {n_reset_callers} callers (expected ≥2)"
                        )
                set_addr = set_addr or scan_set
                reset_addr = reset_addr or scan_reset

            if set_addr is None and reset_addr is None:
                click.echo(
                    "   warning: could not identify DTC helper functions; "
                    "setter attribution will be empty"
                )

            obd_result = run_obd_analysis(
                project, new_prog_name,
                rom_bytes,
                dtc_table_addr_new,
                handler_entries,
                set_addr,
                reset_addr,
            )
            click.echo(
                f"   DTC entries: {len(obd_result.dtc_entries)}, "
                f"PID entries: {len(obd_result.pid_entries)}"
            )
            obd_pid_text = emit_obd_pid_symbols(obd_result.pid_entries)

        # [5.8/7] CAN slot SID decode + semantic enrichment
        can_slots_result = None
        if emit_can_slots:
            import re as _re
            from rom_analyzer.can_slots import analyze_can_slots
            click.echo("[5.8/7] CAN slot SID decode")
            prop_by_name = {p.name: p.new_address for p in propagated_all}
            check_addr = prop_by_name.get("can0_slot_check_sid")
            if check_addr is None:
                check_addr = next(
                    (m.new_address for m in matches if m.ref_name == "can0_slot_check_sid"),
                    None,
                )
            if check_addr is None:
                click.echo("   warning: can0_slot_check_sid not located; CAN slot decode skipped")
            else:
                # Map slot index -> (rx_handler, tx_handler) from labeled handlers,
                # accepting both plain (can0_slot11_rx_update) and already-semantic
                # (can0_slot0_apps_tps_extra_tx_update) names.
                _h = _re.compile(r"^can0_slot(\d+)_(?:.+_)?(rx|tx)_update$")
                slot_handlers: dict[int, list[int | None]] = {}
                for p in propagated_all:
                    mm = _h.match(p.name)
                    if mm is None:
                        continue
                    slot, direction = int(mm.group(1)), mm.group(2)
                    rx, tx = slot_handlers.setdefault(slot, [None, None])
                    # Prefer the lowest (canonical) address when a name is
                    # duplicated across mirrored code regions.
                    if direction == "rx":
                        if rx is None or p.new_address < rx:
                            slot_handlers[slot] = [p.new_address, tx]
                    else:
                        if tx is None or p.new_address < tx:
                            slot_handlers[slot] = [rx, p.new_address]
                handlers = {k: (v[0], v[1]) for k, v in slot_handlers.items()}
                can_slots_result = analyze_can_slots(rom_bytes, check_addr, handlers)
                known = sum(1 for s in can_slots_result if s.semantic)
                click.echo(
                    f"   decoded {len(can_slots_result)} slots, "
                    f"{known} with known semantics"
                )

        # [6/7] Detect CRC, scan free space
        click.echo("[6/7] Detecting CRC, scanning free space")

        # For self-diff the reference address equals the new-ROM address, so the
        # pre-fetched new_run.rom_crc_check_step is correct.  For cross-ROM analysis
        # crc_step_addr is the *reference* ROM's address (wrong for the target ROM);
        # look up the matched address from VTSession/BFS and re-fetch instructions.
        _crc_instrs_raw: list[dict] | None = None
        if _primary_is_self_diff:
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

        new_ram_refs = set(new_run.ram_refs)
        flash_blocks = find_free_blocks(rom_bytes, crc, min_length=min_flash_block) if crc else []
        ram_blocks = find_free_ram_blocks(new_ram_refs, min_length=min_ram_block)

        # [7/7] Emit outputs
        click.echo("[7/7] Emitting outputs")
        mode23_lines: list[str] = []
        if emit_mode23:
            click.echo("[7/7] Resolving mode-0x23 splice-site bindings")
            match_by_ref = {m.ref_address: m for m in matches}
            match_by_name = {m.ref_name: m for m in matches if m.ref_name}

            # K-Line: the injection replaces the dispatcher's `lduh sio0_tx_count`
            # return-load. Anchor on the read of sio0_tx_count inside the matched
            # dispatcher nearest the reference's relative offset.
            kline_ref_addr = next(
                (s.address for s in ref_symbols
                 if s.name == "obd_rest_handler_injection_location"), None)
            txcount_ref = next(
                (s.address for s in ref_symbols if s.name == "sio0_tx_count"), None)
            if kline_ref_addr is not None and txcount_ref is not None and ref_run is not None:
                # Only the K-Line block needs the reference program; resolve its
                # name here so --emit-mode23 doesn't touch the reference ROM when
                # the reference is unavailable.
                ref_prog_name = ghidriff_program_name(primary.rom_path)
                ref_container = fetch_function_entry(project, ref_prog_name, kline_ref_addr)
                if _primary_is_self_diff:
                    new_container = ref_container
                else:
                    cm = match_by_ref.get(ref_container) if ref_container is not None else None
                    new_container = cm.new_address if cm is not None else None
                # sio0_tx_count moves between ROMs (the Colt RAM map is NOT identity),
                # so anchor on its PROPAGATED new-ROM address. Fall back to the
                # reference address (identity) only if propagation didn't carry it;
                # if that address is wrong no reads are found and the binding degrades
                # to VERIFY (safe).
                prop_by_name = {p.name: p.new_address for p in propagated_all}
                txcount_new = prop_by_name.get("sio0_tx_count", txcount_ref)
                if ref_container is not None and new_container is not None:
                    expected = new_container + (kline_ref_addr - ref_container)
                    reads = fetch_data_read_sites(
                        project, new_prog_name, txcount_new, new_container)
                    res = resolve_nearest_site(reads, expected)
                else:
                    res = resolve_nearest_site([], 0)
                mode23_lines.append(
                    emit_mode23_binding_line("obd_rest_handler_injection_location", res))

            # CAN: the trampoline replaces the call to canrx12_15_process at BOTH
            # call sites (slot 12 / canrx12_data and slot 15 / canrx15_data). Anchor
            # on the callers of the matched dispatcher; label each by the slot
            # immediate (`ldi r0,#N`) preceding it.
            can_target = match_by_name.get("canrx12_15_process")
            if can_target is not None:
                callers = fetch_callers_of(project, new_prog_name, can_target.new_address)
                slot_of: dict[int, int | None] = {}
                for c in callers:
                    imm = fetch_r0_imm_before(project, new_prog_name, c)
                    if imm is None:
                        imm = decode_ldi_r0_before(rom_bytes, c)
                    slot_of[c] = imm
                can_bindings, can_verify = resolve_can_call_sites(callers, slot_of)
                for b in can_bindings:
                    mode23_lines.append(
                        emit_mode23_binding_line(b.name, b.resolution))
                mode23_lines.append(can_verify)
            for ln in mode23_lines:
                click.echo("   " + ln.rstrip())

        _desc = emit_description_ld(
            propagated_all,
            source_rom=rom_path.name,
            reference_name=("multi" if len(selected) > 1 else primary.id),
            variant=language_id,
            match_summary=match_summary,
            show_provenance=show_provenance,
        )
        if mode23_lines:
            _desc += "\n/* mode 0x23 splice-site bindings (--emit-mode23) */\n"
            _desc += "".join(mode23_lines)
        if obd_pid_text:
            _desc += obd_pid_text
        (out_dir / "description.ld").write_text(_desc)
        (out_dir / "omni.ld.stub").write_text(emit_omni_stub(flash_blocks, ram_globals))
        (out_dir / "crc-region.toml").write_text(
            emit_crc_region_toml(crc) if crc else "# CRC region not detected\n"
        )
        (out_dir / "flash-free.toml").write_text(emit_flash_free_toml(flash_blocks))
        (out_dir / "ram-free.toml").write_text(emit_ram_free_toml(ram_blocks))
        if obd_result is not None:
            dtc_map_path = out_dir / "dtc-map.toml"
            dtc_map_path.write_text(emit_dtc_map_toml(obd_result.dtc_entries))
            click.echo(f"   wrote {dtc_map_path}")
        if can_slots_result is not None:
            can_slots_path = out_dir / "can-slots.toml"
            can_slots_path.write_text(emit_can_slots_toml(can_slots_result))
            click.echo(f"   wrote {can_slots_path}")

        (out_dir / "reference-conflicts.md").write_text(
            emit_reference_conflicts_md(disagreements, cross_family))

        # Detail fields from the primary reference for the match-report
        data_labels = primary_result.data_labels
        ram_labels = primary_result.ram_labels
        sig_matches = primary_result.sig_matches
        ram_labels_p2 = primary_result.ram_labels_p2
        data_labels_p2 = primary_result.data_labels_p2

        report = StringIO()
        report.write("# rom-analyzer match report\n\n")
        report.write(f"Source ROM: {rom_path.name}\n")
        report.write(f"Reference:  {primary.id}\n")
        report.write(f"Variant:    {language_id}\n\n")
        report.write(f"## Summary\n- Matched functions: {match_summary}\n")
        scalar_count = sum(1 for d in data_labels if d.source == "data_refs_scalar")
        label_summary = (
            f"{len(data_labels)} ({scalar_count} via scalar refs)"
            if scalar_count
            else str(len(data_labels))
        )
        report.write(f"- Propagated data labels: {label_summary}\n")
        report.write(f"- Propagated RAM labels: {len(ram_labels)}\n")
        if sig_matches:
            report.write(f"- RAM-signature matches: {len(sig_matches)}\n")
            report.write(f"- Propagated RAM labels (p2): {len(ram_labels_p2)}\n")
            report.write(f"- Propagated data labels (p2): {len(data_labels_p2)}\n")
        report.write("\n")
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

        report.write("\n## References\n")
        for r in results:
            won = sum(1 for s in propagated_all if s.reference == r.entry.id)
            report.write(f"- {r.entry.id} (priority {r.entry.priority}): "
                         f"{len(r.matches)} matches, {won} symbols won\n")
        report.write("\n")

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
            if data_type_defs:
                m = apply_data_types(project, new_prog_name, data_type_defs)
                click.echo(f"    Applied {m} data type definition(s)")
    finally:
        project.close()


# ---------------------------------------------------------------------------
# Click group and enrich subcommand
# ---------------------------------------------------------------------------

@click.group()
def cli():
    """rom-analyzer: M32R ROM analysis and reference enrichment."""


cli.add_command(analyze)


# ---------------------------------------------------------------------------
# Helpers for enrich
# ---------------------------------------------------------------------------

def _rom_bytes_cached(entry: ReferenceEntry, _cache: dict = {}) -> bytes:
    """Read and cache a reference entry's ROM bytes."""
    if entry.id not in _cache:
        _cache[entry.id] = entry.rom_path.read_bytes()
    return _cache[entry.id]


def _erased_addrs(entry: ReferenceEntry, window: int = 8) -> set[int]:
    """Return the set of function-entry addresses that land in erased flash."""
    rom = _rom_bytes_cached(entry)
    store = load_annotations(entry.json_path)
    erased: set[int] = set()
    for f in store.functions:
        addr = f.entry_point
        if addr + window <= len(rom) and all(b == 0xFF for b in rom[addr:addr + window]):
            erased.add(addr)
    return erased


def _append_functions(store, cands: list[LabelCandidate]) -> int:
    """Append new AnnotationFunctions for auto candidates not already present.

    Returns the number appended.
    """
    existing = {f.entry_point for f in store.functions}
    n = 0
    for c in cands:
        if c.address not in existing:
            store.functions.append(AnnotationFunction(
                name=c.proposed,
                entry_point=c.address,
                confidence="medium",
                source=f"xref:{c.source}",
            ))
            existing.add(c.address)
            n += 1
    return n


@cli.command("enrich")
@click.argument("new_id")
@click.option("--ghidra-home", type=click.Path(exists=True, file_okay=False, path_type=Path),
              default=os.environ.get("GHIDRA_HOME", "/opt/homebrew/opt/ghidra/libexec"))
@click.option("--project-dir", type=click.Path(path_type=Path),
              default=Path.home() / "rom-analyzer-projects")
@click.option("--project-name", default="rom-analyzer")
@click.option("--out", "out_dir", type=click.Path(path_type=Path),
              default=_REFERENCE_DIR / "enrichment", show_default=True)
@click.option("--inline-source-annotations", is_flag=True, default=False)
def enrich(new_id, ghidra_home, project_dir, project_name, out_dir, inline_source_annotations):
    """Cross-match <new_id> against all references; auto-apply new functions and
    emit a reconcile.toml of conflicts + RAM/data for review."""
    registry_path = _REFERENCE_DIR / "registry.toml"
    if not registry_path.exists():
        raise click.ClickException(f"Registry not found at {registry_path}")

    entries = load_registry(registry_path)
    by_id = {e.id: e for e in entries}
    if new_id not in by_id:
        raise click.ClickException(f"Reference id {new_id!r} not found in registry")

    new_entry = by_id[new_id]
    if not new_entry.rom_path.exists():
        raise click.ClickException(
            f"ROM for {new_id} not found at {new_entry.rom_path}"
        )

    others = [e for e in entries if e.id != new_id and e.rom_path.exists()]
    if not others:
        raise click.ClickException("No other references with available ROMs to cross-match against")

    priority = {e.id: e.priority for e in entries}
    language_id = VARIANT_TO_LANGUAGE.get(new_entry.variant)
    if language_id is None:
        raise click.ClickException(f"Unknown variant {new_entry.variant!r} for {new_id}")

    setup_environment(ghidra_home)
    import pyghidra
    pyghidra.start()

    project_path = Path(project_dir) / project_name
    project_path.mkdir(parents=True, exist_ok=True)
    project = pyghidra.open_project(project_path, project_name, create=True)

    try:
        new_prog_name = ghidriff_program_name(new_entry.rom_path)
        rom_bytes = new_entry.rom_path.read_bytes()

        # Load the new entry's store once; build fn-name lookup
        new_store = load_annotations(new_entry.json_path)
        new_fn_names: dict[int, str] = {f.entry_point: f.name for f in new_store.functions}

        # Import new ROM into Ghidra once (shared across all cross-matches)
        _new_ref_symbols_preview = load_reference_symbols(new_entry.json_path)
        _new_crc_step_addr = next(
            (s.address for s in _new_ref_symbols_preview if s.name == "rom_crc_check_step"),
            None,
        )
        click.echo(f"[import] Importing new ROM {new_id}: {new_entry.rom_path}")
        new_run = import_and_dump(
            project,
            new_entry.rom_path, language_id,
            crc_step_address=_new_crc_step_addr,
            collect_data_refs_flag=True,
        )

        all_candidates: list[LabelCandidate] = []

        for ref in others:
            if ref.variant != new_entry.variant:
                click.echo(
                    f"   [skip] {ref.id}: variant {ref.variant!r} != {new_entry.variant!r} "
                    f"(cross-variant matching not yet supported)"
                )
                continue

            click.echo(f"[cross-match] {new_id} vs {ref.id}")
            result = analyze_against_reference(
                project, ref, language_id,
                new_entry.rom_path, rom_bytes,
                new_run, new_prog_name,
                target_family=new_entry.family,
                inline_source_annotations=inline_source_annotations,
            )

            ref_store = load_annotations(ref.json_path)
            ref_fn_names: dict[int, str] = {f.entry_point: f.name for f in ref_store.functions}

            cands = gather_candidates(
                new_id, ref.id,
                result.matches,
                new_fn_names, ref_fn_names,
                ram_data_candidates=None,
            )
            all_candidates.extend(cands)
            click.echo(f"   {len(cands)} candidates from {ref.id}")

        # Compute erased-address sets per target ROM (keyed by target id)
        target_ids = {c.target for c in all_candidates}
        erased_by_target: dict[str, set[int]] = {}
        for tid in target_ids:
            if tid == new_id:
                erased_by_target[tid] = _erased_addrs(new_entry)
            elif tid in by_id:
                erased_by_target[tid] = _erased_addrs(by_id[tid])
            else:
                erased_by_target[tid] = set()

        # Classify
        auto_all: list[LabelCandidate] = []
        review_all: list[LabelCandidate] = []
        by_target: dict[str, list[LabelCandidate]] = {}
        for c in all_candidates:
            by_target.setdefault(c.target, []).append(c)

        for tid, group in by_target.items():
            classified = classify(group, erased=erased_by_target.get(tid, set()))
            auto_all.extend(classified.auto)
            review_all.extend(classified.review)

        # Auto-apply: new function gaps only
        # Group auto candidates by target
        auto_by_target: dict[str, list[LabelCandidate]] = {}
        for c in auto_all:
            auto_by_target.setdefault(c.target, []).append(c)

        total_auto_applied = 0
        store_cache: dict[str, object] = {}

        for tid, cands in auto_by_target.items():
            if tid not in by_id:
                click.echo(f"   [skip auto] target {tid!r} not in registry")
                continue
            target_entry = by_id[tid]
            st = load_annotations(target_entry.json_path)
            n_appended = _append_functions(st, cands)
            if n_appended:
                target_rom_bytes = (
                    rom_bytes if tid == new_id
                    else _rom_bytes_cached(target_entry)
                )
                drop_imprecise_s_duplicates(st)
                drop_erased_flash_entries(st, target_rom_bytes)
                dedup_symbol_names(st)
                save_annotations(target_entry.json_path, st)
                click.echo(f"   [auto] {tid}: applied {n_appended} new function(s)")
            total_auto_applied += n_appended

        # Build reconcile items from review candidates
        items = build_reconcile_items(review_all, priority)

        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        reconcile_path = out_dir / f"{new_id}.reconcile.toml"
        write_reconcile(reconcile_path, items)

        click.echo(
            f"\nDone. Auto-applied: {total_auto_applied} function(s). "
            f"Review items: {len(items)}. "
            f"Reconcile: {reconcile_path}"
        )

    finally:
        project.close()


if __name__ == "__main__":
    cli()
