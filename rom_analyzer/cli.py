"""CLI entry point for rom-analyzer."""

import os
from io import StringIO
from pathlib import Path

import click

from rom_analyzer.emit_ld import (
    emit_crc_region_toml,
    emit_description_ld,
    emit_dtc_map_toml,
    emit_flash_free_toml,
    emit_omni_stub,
    emit_can_slots_toml,
    emit_ram_free_toml,
    emit_reference_conflicts_md,
)
from rom_analyzer.ghidra import (
    GhidraSession,
    apply_data_types, apply_labels,
)
from rom_analyzer.registry import (
    ReferenceEntry, load_registry, select_references, partition_available,
)
from rom_analyzer.annotations_io import load_annotations, save_annotations
from rom_analyzer.types import DataTypeDefinition
from rom_analyzer.enrich import read_reconcile, apply_verdicts
from rom_analyzer.cleanup import (
    drop_imprecise_s_duplicates, drop_erased_flash_entries, dedup_symbol_names,
)
from rom_analyzer.pipeline.arbitrate import arbitrate_references, classify_and_apply
from rom_analyzer.pipeline.post_match import post_match_analysis
from rom_analyzer.pipeline.reference import import_stage, match_reference
from rom_analyzer.pipeline.types import AnalysisResult, RomContext, ReferenceMatchResult


VARIANT_TO_LANGUAGE = {
    "fp8000": "m32r:2:fp8000",
    "fpc000": "m32r:2:default",
}

_REFERENCE_DIR = Path(__file__).parent.parent / "reference"


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
    with GhidraSession.open(
        project_dir / project_name, project_name, ghidra_home,
        clean=clean_project,
        inline_source_annotations=inline_source_annotations,
    ) as session:
        project = session.project   # keep existing calls working for now

        _primary_is_self_diff = rom_path.resolve() == primary.rom_path.resolve()
        # Read ROM bytes now — used by call-graph bootstrap and CRC scan
        rom_bytes = rom_path.read_bytes()

        ctx = RomContext(
            rom_path=rom_path, rom_bytes=rom_bytes, language_id=language_id,
            out_dir=out_dir, target_family=primary.family,
            is_self_diff=_primary_is_self_diff,
            emit_mode23=emit_mode23, emit_obd=emit_obd, emit_can_slots=emit_can_slots,
            enrich_project=enrich_project,
            min_flash_block=min_flash_block, min_ram_block=min_ram_block,
        )
        imported = import_stage(session, ctx, primary)
        new_run = imported.new_run
        new_prog_name = imported.new_prog_name

        # Run the full matching + propagation pipeline for each reference
        results: list[ReferenceMatchResult] = []
        for entry in selected:
            click.echo(f"[ref {entry.id}] matching")
            results.append(match_reference(session, ctx, imported, entry))

        # Merge matches and arbitrate symbols across all references
        merged = arbitrate_references(results, priority)
        show_provenance = len(selected) > 1

        # Single-source passes use the primary reference
        primary_result = results[0]
        ref_symbols = primary_result.ref_symbols
        ref_run = primary_result.ref_run
        ref_symbols_by_addr = {s.address: s for s in ref_symbols}

        matches = merged.matches
        propagated_all = merged.propagated
        disagreements = merged.disagreements
        cross_family = merged.cross_family
        match_summary = merged.match_summary

        # RAM globals for omni.ld.stub: use the primary reference's propagated symbols
        ram_globals = [s for s in primary_result.propagated if s.category == "ram_global"]

        analysis = post_match_analysis(
            session, ctx, imported, merged,
            primary_entry=primary,
            ref_symbols=ref_symbols,
            ref_run=ref_run,
            enrich_project=enrich_project,
        )
        # propagated_all may have been updated by MUT table pass
        propagated_all = merged.propagated

        # [7/7] Emit outputs
        click.echo("[7/7] Emitting outputs")

        _desc = emit_description_ld(
            propagated_all,
            source_rom=rom_path.name,
            reference_name=("multi" if len(selected) > 1 else primary.id),
            variant=language_id,
            match_summary=match_summary,
            show_provenance=show_provenance,
        )
        if analysis.mode23_lines:
            _desc += "\n/* mode 0x23 splice-site bindings (--emit-mode23) */\n"
            _desc += "".join(analysis.mode23_lines)
        if analysis.obd_pid_text:
            _desc += analysis.obd_pid_text
        (out_dir / "description.ld").write_text(_desc)
        (out_dir / "omni.ld.stub").write_text(emit_omni_stub(analysis.flash_blocks, ram_globals))
        (out_dir / "crc-region.toml").write_text(
            emit_crc_region_toml(analysis.crc) if analysis.crc else "# CRC region not detected\n"
        )
        (out_dir / "flash-free.toml").write_text(emit_flash_free_toml(analysis.flash_blocks))
        (out_dir / "ram-free.toml").write_text(emit_ram_free_toml(analysis.ram_blocks))
        if analysis.obd_result is not None:
            dtc_map_path = out_dir / "dtc-map.toml"
            dtc_map_path.write_text(emit_dtc_map_toml(analysis.obd_result.dtc_entries))
            click.echo(f"   wrote {dtc_map_path}")
        if analysis.can_slots_result is not None:
            can_slots_path = out_dir / "can-slots.toml"
            can_slots_path.write_text(emit_can_slots_toml(analysis.can_slots_result))
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
        if analysis.crc is not None:
            report.write(f"## CRC region\n")
            report.write(f"- Full mode:    [{analysis.crc.full_start:#x}, {analysis.crc.full_end:#x})\n")
            report.write(f"- Partial mode: [{analysis.crc.partial_start:#x}, {analysis.crc.partial_end:#x})\n")

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
            _mut_table_ghidra_applied = analysis.mut_result is not None and enrich_project
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


# ---------------------------------------------------------------------------
# Click group and enrich subcommand
# ---------------------------------------------------------------------------

@click.group()
def cli():
    """rom-analyzer: M32R ROM analysis and reference enrichment."""


cli.add_command(analyze)



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

    with GhidraSession.open(
        Path(project_dir) / project_name, project_name, ghidra_home,
    ) as session:
        project = session.project   # keep existing calls working for now
        rom_bytes = new_entry.rom_path.read_bytes()

        ctx = RomContext(
            rom_path=new_entry.rom_path, rom_bytes=rom_bytes,
            language_id=language_id, out_dir=Path(out_dir),
            target_family=new_entry.family,
            is_self_diff=False,
            emit_mode23=False, emit_obd=False, emit_can_slots=False,
            enrich_project=False,
            min_flash_block=64, min_ram_block=4,
        )
        click.echo(f"[import] Importing new ROM {new_id}: {new_entry.rom_path}")
        imported = import_stage(session, ctx, new_entry)
        new_prog_name = imported.new_prog_name

        results: list[ReferenceMatchResult] = []

        for ref in others:
            if ref.variant != new_entry.variant:
                click.echo(
                    f"   [skip] {ref.id}: variant {ref.variant!r} != {new_entry.variant!r} "
                    f"(cross-variant matching not yet supported)"
                )
                continue

            click.echo(f"[cross-match] {new_id} vs {ref.id}")
            result = match_reference(session, ctx, imported, ref)
            results.append(result)

        new_store = load_annotations(new_entry.json_path)
        new_fn_names: dict[int, str] = {f.entry_point: f.name for f in new_store.functions}
        classify_and_apply(
            results, new_entry, new_fn_names, by_id, priority, Path(out_dir), rom_bytes
        )


@cli.command("apply-enrichment")
@click.argument("reconcile_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def apply_enrichment(reconcile_file):
    """Apply human verdicts from a reconcile.toml to the reference JSONs,
    re-deduplicate each touched reference, and report what changed.

    Refreshing the e2e golden for any touched reference that has one (e.g.
    33520003) is a separate operator step via the analyze command.
    """
    registry_path = _REFERENCE_DIR / "registry.toml"
    if not registry_path.exists():
        raise click.ClickException(f"Registry not found at {registry_path}")
    by_id = {e.id: e for e in load_registry(registry_path)}

    items = read_reconcile(Path(reconcile_file))
    if not items:
        click.echo("No items in reconcile file; nothing to do.")
        return

    targets = sorted({it.target for it in items})
    touched_golden = []
    for tid in targets:
        if tid not in by_id:
            click.echo(f"   [skip] target {tid!r} not in registry")
            continue
        entry = by_id[tid]
        st = load_annotations(entry.json_path)
        n = apply_verdicts(st, items, target=tid)
        drop_imprecise_s_duplicates(st)
        if entry.rom_path.exists():
            drop_erased_flash_entries(st, entry.rom_path.read_bytes())
        dedup_symbol_names(st)
        save_annotations(entry.json_path, st)
        click.echo(f"   {tid}: applied {n} verdict(s)")
        if tid == "33520003":
            touched_golden.append(tid)

    if touched_golden:
        click.echo(
            "\nNOTE: refresh the e2e golden for "
            + ", ".join(touched_golden)
            + " by re-running the analyze command and updating tests/golden/, "
            "then run scripts/run-e2e.sh."
        )
    click.echo("Done.")


if __name__ == "__main__":
    cli()
