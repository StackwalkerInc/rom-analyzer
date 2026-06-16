"""Per-reference matching pipeline: import target ROM, run callgraph + VT diff +
propagation, return ReferenceMatchResult.

import_stage()   — import the target ROM into Ghidra once for all references
match_reference() — run the full matching + propagation pass for one reference
"""

from __future__ import annotations

from dataclasses import replace

import click

from rom_analyzer.annotations_io import load_reference_symbols
from rom_analyzer.callgraph import (
    bootstrap_anchors, bfs_preseed, bytecode_identity_match, gap_fill,
)
from rom_analyzer.data_refs import propagate_data_labels, propagate_ram_labels
from rom_analyzer.diff import run_vt_diff
from rom_analyzer.ghidra import (
    apply_labels, ghidriff_program_name, import_and_dump,
)
from rom_analyzer.ghidra.session import GhidraSession
from rom_analyzer.merge import match_rank
from rom_analyzer.pipeline.types import ImportResult, ReferenceMatchResult, RomContext
from rom_analyzer.propagate import apply_reference_provenance, propagate_function_labels
from rom_analyzer.ram_signature import build_ram_signatures, match_by_ram_signature
from rom_analyzer.registry import ReferenceEntry
from rom_analyzer.types import MatchedFunction, PropagatedSymbol


def import_stage(
    session: GhidraSession,
    ctx: RomContext,
    primary_entry: ReferenceEntry,
) -> ImportResult:
    """Import the target ROM into Ghidra (once, shared across all references).

    Loads primary reference symbols to extract crc_step_address before import.
    """
    ref_symbols_preview = load_reference_symbols(primary_entry.json_path)
    crc_step_addr = next(
        (s.address for s in ref_symbols_preview if s.name == "rom_crc_check_step"),
        None,
    )
    click.echo(f"[3/7] Importing new ROM into Ghidra: {ctx.rom_path}")
    new_run = session.import_rom(
        ctx.rom_path,
        ctx.language_id,
        crc_step_address=crc_step_addr,
        collect_data_refs=(not ctx.is_self_diff),
    )
    return ImportResult(
        new_run=new_run,
        new_prog_name=session.prog_name_for(ctx.rom_path),
    )


def match_reference(
    session: GhidraSession,
    ctx: RomContext,
    imported: ImportResult,
    entry: ReferenceEntry,
) -> ReferenceMatchResult:
    """Run the full matching + propagation pass for one reference ROM."""
    project = session.project
    new_run = imported.new_run
    new_prog_name = imported.new_prog_name
    inline_source_annotations = session.inline_source_annotations
    rom_bytes = ctx.rom_bytes
    reference_rom = entry.rom_path
    reference = entry.json_path
    is_self_diff = ctx.is_self_diff

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
            reference_rom, ctx.language_id,
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
    family_match = (entry.family == ctx.target_family)
    propagated_all = apply_reference_provenance(
        propagated_all, reference=entry.id, family_match=family_match)

    return ReferenceMatchResult(
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
