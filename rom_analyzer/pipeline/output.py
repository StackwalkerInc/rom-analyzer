"""Write all output files produced by the analyze command.

Extracted from cli.py so the CLI orchestration layer stays thin.
Zero logic changes — this is a verbatim extraction.
"""

from __future__ import annotations

from io import StringIO

import click

from rom_analyzer.emit_ld import (
    emit_can_slots_toml, emit_crc_region_toml, emit_description_ld,
    emit_dtc_map_toml, emit_flash_free_toml, emit_omni_stub,
    emit_ram_free_toml, emit_reference_conflicts_md,
)
from rom_analyzer.ghidra.session import GhidraSession
from rom_analyzer.pipeline.types import AnalysisResult, MergeResult, ReferenceMatchResult, RomContext
from rom_analyzer.registry import ReferenceEntry


def write_outputs(
    session: GhidraSession,
    ctx: RomContext,
    merged: MergeResult,
    analysis: AnalysisResult,
    results: list[ReferenceMatchResult],
    selected: list[ReferenceEntry],
    data_type_defs: list,
    show_provenance: bool,
) -> None:
    """Write all output files for an analyze run.

    Emits description.ld, omni.ld.stub, CRC/flash/RAM TOML reports,
    optional dtc-map.toml and can-slots.toml, reference-conflicts.md,
    match-report.md, and optionally enriches the Ghidra project.
    """
    out_dir = ctx.out_dir
    propagated_all = merged.propagated
    matches = merged.matches

    # Pull detail fields from the primary reference result for the match-report
    primary_result = results[0]
    primary = selected[0]
    match_summary = merged.match_summary
    disagreements = merged.disagreements
    cross_family = merged.cross_family
    language_id = ctx.language_id

    # RAM globals for omni.ld.stub: use the primary reference's propagated symbols
    ram_globals = [s for s in primary_result.propagated if s.category == "ram_global"]

    # [7/7] Emit outputs
    click.echo("[7/7] Emitting outputs")

    _desc = emit_description_ld(
        propagated_all,
        source_rom=ctx.rom_path.name,
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
    report.write(f"Source ROM: {ctx.rom_path.name}\n")
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

    if ctx.enrich_project:
        # apply_mut_table_in_ghidra already set the void*[N] datatype + label for
        # flash_mut_variables_table.  Exclude it here to avoid a redundant label
        # write and a duplicate bookmark at the same address.
        _mut_applied = analysis.mut_result is not None
        labels_for_apply = (
            [p for p in propagated_all if p.name != "flash_mut_variables_table"]
            if _mut_applied else propagated_all
        )
        click.echo(f"[+] Enriching Ghidra project with {len(labels_for_apply)} propagated symbols")
        n = session.apply_labels(ctx.rom_path, labels_for_apply)
        click.echo(f"    Applied {n} label(s) to {ctx.rom_path.name} Ghidra project")
        if data_type_defs:
            m = session.apply_data_types(ctx.rom_path, data_type_defs)
            click.echo(f"    Applied {m} data type definition(s)")
