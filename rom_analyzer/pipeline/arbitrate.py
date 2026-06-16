"""Cross-reference arbitration: merge matches, pick winning symbols, apply auto verdicts."""

from __future__ import annotations

from pathlib import Path

import click

from rom_analyzer.annotations_io import AnnotationFunction, load_annotations, save_annotations
from rom_analyzer.cleanup import dedup_symbol_names, drop_erased_flash_entries, drop_imprecise_s_duplicates
from rom_analyzer.enrich import (
    LabelCandidate, ReconcileItem, build_reconcile_items, classify,
    gather_candidates, merge_candidates, write_reconcile, apply_verdicts,
)
from rom_analyzer.merge import arbitrate_symbols, merge_matches
from rom_analyzer.pipeline.types import MergeResult, ReferenceMatchResult
from rom_analyzer.registry import ReferenceEntry
from rom_analyzer.types import PropagatedSymbol


# ---------------------------------------------------------------------------
# Helpers
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


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------

def arbitrate_references(
    results: list[ReferenceMatchResult],
    priority: dict[str, int],
) -> MergeResult:
    """Merge matches and arbitrate symbols across all references.

    Returns a MergeResult with merged matches, winning propagated symbols,
    disagreements, cross-family symbols, and a human-readable match summary.
    """
    matches = merge_matches([r.matches for r in results], priority)
    all_propagated = [s for r in results for s in r.propagated]
    propagated_all, disagreements = arbitrate_symbols(all_propagated, priority)
    cross_family = [s for s in propagated_all if not s.family_match]
    click.echo(f"[merge] {len(propagated_all)} symbols, "
               f"{len(disagreements)} disagreement(s), "
               f"{len(cross_family)} cross-family VERIFY")

    ref_symbols = results[0].ref_symbols
    named_ref_addrs = {s.address for s in ref_symbols if s.category == "function"}
    matched_count = sum(1 for m in matches if m.ref_address in named_ref_addrs)
    total_ref = len(named_ref_addrs)
    match_summary = f"{matched_count}/{total_ref} ({100.0 * matched_count / max(1, total_ref):.1f}%)"

    return MergeResult(
        matches=matches,
        propagated=propagated_all,
        disagreements=disagreements,
        cross_family=cross_family,
        priority=priority,
        match_summary=match_summary,
    )


def classify_and_apply(
    results,
    new_entry: ReferenceEntry,
    new_fn_names: dict[int, str],
    by_id: dict[str, ReferenceEntry],
    priority: dict[str, int],
    out_dir: Path,
    rom_bytes: bytes,
) -> None:
    """Build candidates, classify, auto-apply gap fills and renames, write reconcile.toml."""
    new_id = new_entry.id
    all_candidates: list[LabelCandidate] = []

    for result in results:
        ref = result.entry
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

    all_candidates = merge_candidates(all_candidates, priority)
    click.echo(f"Merged: {len(all_candidates)} unique (target, address, category) candidates")

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
        classified = classify(group, erased=erased_by_target.get(tid, set()),
                              priority=priority)
        auto_all.extend(classified.auto)
        review_all.extend(classified.review)

    # Auto-apply: new function gaps and authority-backed renames
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

        gap_cands = [c for c in cands if c.current is None]
        rename_cands = [c for c in cands if c.current is not None]

        n_appended = _append_functions(st, gap_cands)

        if rename_cands:
            rename_items = [ReconcileItem(
                target=tid, direction=c.direction, address=c.address,
                category=c.category, current=c.current, proposed=c.proposed,
                source=c.source, evidence=c.evidence, verdict="proposed",
            ) for c in rename_cands]
            n_renamed = apply_verdicts(st, rename_items, target=tid)
        else:
            n_renamed = 0

        if n_appended + n_renamed:
            target_rom_bytes = (
                rom_bytes if tid == new_id
                else _rom_bytes_cached(target_entry)
            )
            drop_imprecise_s_duplicates(st)
            drop_erased_flash_entries(st, target_rom_bytes)
            dedup_symbol_names(st)
            save_annotations(target_entry.json_path, st)
            click.echo(
                f"   [auto] {tid}: applied {n_appended} new function(s), "
                f"{n_renamed} rename(s)"
            )
        total_auto_applied += n_appended + n_renamed

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
