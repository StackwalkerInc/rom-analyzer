#!/usr/bin/env python3
"""Batch decompile / context-build script for agent-enrich.

Reads agent_enrich_state/batch.json, opens the shared Ghidra project, and for
each entry:
  - item_type=="function": decompile the function body, gather named callers/callees
  - item_type=="variable": gather named readers/writers, adjacent named symbols from
    the reference JSON, and optionally decompile the single named writer function

Writes ctx_{rom}_{addr}.json files to the output directory.

Usage:
    .venv/bin/python scripts/agent_enrich_decompile.py
        [--batch agent_enrich_state/batch.json]
        [--out-dir agent_enrich_state]
        [--reference-dir reference]
        [--project-dir ~/rom-analyzer-projects]
        [--project-name rom-analyzer]
        [--ghidra-home /opt/homebrew/opt/ghidra/libexec]
        [--sibling-window 64]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

GHIDRA_HOME = Path(os.environ.get("GHIDRA_HOME", "/opt/homebrew/opt/ghidra/libexec"))
PROJ_DIR = Path.home() / "rom-analyzer-projects"
PROJ_NAME = "rom-analyzer"
STATE_DIR = REPO / "agent_enrich_state"
REFERENCE_DIR = REPO / "reference"


def _build_function_ctx(
    rom, address_str, current_name, prog_name,
    program, func_mgr, ref_mgr, is_auto_name, is_placeholder,
):
    """Build context dict for a function candidate (existing logic)."""
    from ghidra.app.decompiler import DecompInterface
    import pyghidra

    address = int(address_str, 16)
    af = program.getAddressFactory().getDefaultAddressSpace()
    addr = af.getAddress(address)
    func = func_mgr.getFunctionAt(addr)
    if func is None:
        return None

    decomp = DecompInterface()
    decomp.openProgram(program)
    result = decomp.decompileFunction(func, 30, pyghidra.task_monitor())
    decomp.dispose()
    if result is None or not result.decompileCompleted():
        return None
    decompiled = result.getDecompiledFunction().getC()

    callers: list[str] = []
    for ref in ref_mgr.getReferencesTo(addr):
        if ref.getReferenceType().isCall():
            caller_func = func_mgr.getFunctionContaining(ref.getFromAddress())
            if caller_func is not None:
                name = str(caller_func.getName())
                if not (name.startswith("FUN_") or is_auto_name(name) or is_placeholder(name)):
                    callers.append(name)

    callees: list[str] = []
    body = func.getBody()
    for body_addr in body.getAddresses(True):
        for ref in ref_mgr.getReferencesFrom(body_addr):
            if ref.getReferenceType().isCall():
                callee_func = func_mgr.getFunctionAt(ref.getToAddress())
                if callee_func is not None:
                    name = str(callee_func.getName())
                    if not (name.startswith("FUN_") or is_auto_name(name) or is_placeholder(name)):
                        callees.append(name)

    return {
        "rom": rom,
        "address": address_str,
        "current_name": current_name,
        "prog_name": prog_name,
        "decompiled": decompiled,
        "callers": sorted(set(callers)),
        "callees": sorted(set(callees)),
    }


def _build_variable_ctx(
    rom, address_str, current_name, prog_name, category,
    program, func_mgr, ref_mgr, is_auto_name, is_placeholder,
    store,   # AnnotationStore for this ROM
    sibling_window: int,
):
    """Build context dict for a variable candidate."""
    from ghidra.app.decompiler import DecompInterface
    import pyghidra

    address = int(address_str, 16)
    af = program.getAddressFactory().getDefaultAddressSpace()
    addr_obj = af.getAddress(address)

    # Ghidra data type at this address
    data_type = None
    data_at = program.getListing().getDataAt(addr_obj)
    if data_at is not None:
        data_type = str(data_at.getDataType().getName())

    named_readers: list[str] = []
    named_writers: list[str] = []
    named_writer_funcs: dict[str, object] = {}

    for ref in ref_mgr.getReferencesTo(addr_obj):
        ref_type = ref.getReferenceType()
        if not ref_type.isData():
            continue
        caller = func_mgr.getFunctionContaining(ref.getFromAddress())
        if caller is None:
            continue
        caller_name = str(caller.getName())
        if is_auto_name(caller_name) or is_placeholder(caller_name) or caller_name.startswith("FUN_"):
            continue
        if ref_type.isWrite():
            if caller_name not in named_writers:
                named_writers.append(caller_name)
                named_writer_funcs[caller_name] = caller
        elif ref_type.isRead():
            if caller_name not in named_readers:
                named_readers.append(caller_name)

    # Adjacent named symbols from the annotation store within ±sibling_window bytes
    adjacent: list[dict] = []
    for sym in store.symbols:
        if is_auto_name(sym.name) or is_placeholder(sym.name):
            continue
        offset = sym.address - address
        if 0 < abs(offset) <= sibling_window:
            adjacent.append({
                "name": sym.name,
                "offset": offset,
                "data_type": sym.data_type,
            })
    adjacent.sort(key=lambda x: x["offset"])

    if not named_readers and not named_writers and not adjacent:
        return None

    # Decompile single named writer if exactly one exists
    writer_decompile = None
    if len(named_writer_funcs) == 1:
        writer_func = next(iter(named_writer_funcs.values()))
        decomp = DecompInterface()
        decomp.openProgram(program)
        result = decomp.decompileFunction(writer_func, 30, pyghidra.task_monitor())
        decomp.dispose()
        if result is not None and result.decompileCompleted():
            writer_decompile = result.getDecompiledFunction().getC()

    return {
        "rom": rom,
        "address": address_str,
        "current_name": current_name,
        "item_type": "variable",
        "category": category,
        "data_type": data_type,
        "named_readers": sorted(named_readers),
        "named_writers": sorted(named_writers),
        "adjacent_symbols": adjacent,
        "writer_decompile": writer_decompile,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", type=Path, default=STATE_DIR / "batch.json")
    parser.add_argument("--out-dir", type=Path, default=STATE_DIR)
    parser.add_argument("--reference-dir", type=Path, default=REFERENCE_DIR)
    parser.add_argument("--project-dir", type=Path, default=PROJ_DIR)
    parser.add_argument("--project-name", default=PROJ_NAME)
    parser.add_argument("--ghidra-home", type=Path, default=GHIDRA_HOME)
    parser.add_argument("--sibling-window", type=int, default=64)
    args = parser.parse_args()

    batch = json.loads(args.batch.read_text())
    if not batch:
        print("Empty batch, nothing to do.")
        return

    from rom_analyzer.ghidra import setup_environment
    from rom_analyzer.enrich import is_auto_name, is_placeholder
    from rom_analyzer.registry import load_registry
    from rom_analyzer.annotations_io import load_annotations

    setup_environment(args.ghidra_home)
    import pyghidra
    pyghidra.start()

    registry = load_registry(args.reference_dir / "registry.toml")
    json_paths = {e.id: e.json_path for e in registry}

    project = pyghidra.open_project(args.project_dir, args.project_name, create=False)

    written = 0
    with project:
        for item in batch:
            rom = item["rom"]
            address_str = item["address"]
            prog_name = item["prog_name"]
            current_name = item["current_name"]
            item_type = item.get("item_type", "function")
            category = item.get("category", "")

            out_path = args.out_dir / f"ctx_{rom}_{address_str[2:]}.json"

            with pyghidra.program_context(project, f"/{prog_name}") as program:
                func_mgr = program.getFunctionManager()
                ref_mgr = program.getReferenceManager()

                if item_type == "variable":
                    json_path = json_paths.get(rom)
                    if json_path is None or not json_path.exists():
                        print(f"  [{rom}] {address_str}: no reference JSON, skipping variable")
                        continue
                    store = load_annotations(json_path)
                    ctx = _build_variable_ctx(
                        rom, address_str, current_name, prog_name, category,
                        program, func_mgr, ref_mgr, is_auto_name, is_placeholder,
                        store, args.sibling_window,
                    )
                    if ctx is None:
                        print(f"  [{rom}] {address_str}: variable context build failed, skipping")
                        continue
                    out_path.write_text(json.dumps(ctx, indent=2))
                    adj_count = len(ctx["adjacent_symbols"])
                    rw = f"{len(ctx['named_readers'])}r/{len(ctx['named_writers'])}w"
                    print(f"  [{rom}] {address_str} [var]: wrote {out_path.name} "
                          f"({rw}, {adj_count} adjacent)")
                else:
                    ctx = _build_function_ctx(
                        rom, address_str, current_name, prog_name,
                        program, func_mgr, ref_mgr, is_auto_name, is_placeholder,
                    )
                    if ctx is None:
                        print(f"  [{rom}] {address_str}: decompilation failed, skipping")
                        continue
                    out_path.write_text(json.dumps(ctx, indent=2))
                    print(f"  [{rom}] {address_str}: wrote {out_path.name} "
                          f"({len(ctx['callers'])} callers, {len(ctx['callees'])} callees)")

            written += 1

    print(f"Processed {written}/{len(batch)} batch entries.")


if __name__ == "__main__":
    main()
