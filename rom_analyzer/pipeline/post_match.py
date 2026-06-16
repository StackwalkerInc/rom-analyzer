"""Post-match analysis pipeline stage.

Runs after arbitrate_references(): MUT table, OBD PID/DTC, CAN slots,
CRC detection, free-space scan, and mode-0x23 splice-site bindings.
"""

from __future__ import annotations

import re as _re
from pathlib import Path

import click

from rom_analyzer.crc import Instruction, extract_crc_region
from rom_analyzer.flash_space import find_free_blocks
from rom_analyzer.ghidra import (
    fetch_callers_of, fetch_dtc_helpers_structural, fetch_instructions_at,
    fetch_r0_imm_before, fetch_function_entry, fetch_data_read_sites,
    ghidriff_program_name,
)
from rom_analyzer.ghidra.session import GhidraSession
from rom_analyzer.mode23_bindings import decode_ldi_r0_before, resolve_can_call_sites, resolve_nearest_site
from rom_analyzer.mut_table import find_mut_table_in_run, mut_table_to_propagated_symbol
from rom_analyzer.pipeline.types import AnalysisResult, ImportResult, MergeResult, RomContext
from rom_analyzer.ram_space import find_free_ram_blocks
from rom_analyzer.registry import ReferenceEntry
from rom_analyzer.emit_ld import emit_mode23_binding_line
from rom_analyzer.types import CrcRegion, PropagatedSymbol


def post_match_analysis(
    session: GhidraSession,
    ctx: RomContext,
    imported: ImportResult,
    merged: MergeResult,
    primary_entry: ReferenceEntry,
    ref_symbols: list,
    ref_run: object | None,
    enrich_project: bool,
) -> AnalysisResult:
    """Run post-match analysis passes and return results."""
    project = session.project
    new_prog_name = imported.new_prog_name
    new_run = imported.new_run
    matches = merged.matches
    propagated_all = merged.propagated
    rom_bytes = ctx.rom_bytes
    _primary_is_self_diff = ctx.is_self_diff

    # [5.5/7] MUT table identification (cross-ROM only)
    mut_result = None
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
                from rom_analyzer.ghidra import apply_mut_table_in_ghidra
                apply_mut_table_in_ghidra(project, new_prog_name, mut_result)
                _mut_table_ghidra_applied = True
        else:
            click.echo(
                "   warning: MUT table not identified via get_mut_pointer data refs"
            )

    # Update merged.propagated to reflect MUT table mutations
    merged.propagated = propagated_all

    # [5.75/7] OBD PID + DTC analysis
    obd_result = None
    obd_pid_text: str = ""
    if ctx.emit_obd:
        from rom_analyzer.obd_analysis import run_obd_analysis
        from rom_analyzer.emit_ld import emit_obd_pid_symbols
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
    if ctx.emit_can_slots:
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
    flash_blocks = find_free_blocks(rom_bytes, crc, min_length=ctx.min_flash_block) if crc else []
    ram_blocks = find_free_ram_blocks(new_ram_refs, min_length=ctx.min_ram_block)

    # [7/7] Resolve mode-0x23 splice-site bindings
    mode23_lines: list[str] = []
    if ctx.emit_mode23:
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
            ref_prog_name = ghidriff_program_name(primary_entry.rom_path)
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

    return AnalysisResult(
        crc=crc,
        flash_blocks=flash_blocks,
        ram_blocks=ram_blocks,
        mut_result=mut_result,
        obd_result=obd_result,
        can_slots_result=can_slots_result,
        obd_pid_text=obd_pid_text,
        mode23_lines=mode23_lines,
    )
