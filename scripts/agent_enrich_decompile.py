#!/usr/bin/env python3
"""Batch decompile script for agent-enrich.

Reads agent_enrich_state/batch.json, opens the shared Ghidra project, decompiles
each function, fetches named callers/callees, and writes ctx_{rom}_{addr}.json.

Usage:
    .venv/bin/python scripts/agent_enrich_decompile.py
        [--batch agent_enrich_state/batch.json]
        [--out-dir agent_enrich_state]
        [--project-dir ~/rom-analyzer-projects]
        [--project-name rom-analyzer]
        [--ghidra-home /opt/homebrew/opt/ghidra/libexec]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

GHIDRA_HOME = Path("/opt/homebrew/opt/ghidra/libexec")
PROJ_DIR = Path.home() / "rom-analyzer-projects"
PROJ_NAME = "rom-analyzer"
STATE_DIR = REPO / "agent_enrich_state"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", type=Path, default=STATE_DIR / "batch.json")
    parser.add_argument("--out-dir", type=Path, default=STATE_DIR)
    parser.add_argument("--project-dir", type=Path, default=PROJ_DIR)
    parser.add_argument("--project-name", default=PROJ_NAME)
    parser.add_argument("--ghidra-home", type=Path, default=GHIDRA_HOME)
    args = parser.parse_args()

    batch = json.loads(args.batch.read_text())
    if not batch:
        print("Empty batch, nothing to do.")
        return

    from rom_analyzer.ghidra import setup_environment
    from rom_analyzer.enrich import is_auto_name, is_placeholder

    setup_environment(args.ghidra_home)
    import pyghidra
    pyghidra.start()

    project = pyghidra.open_project(args.project_dir, args.project_name, create=False)

    written = 0
    with project:
        for item in batch:
            rom = item["rom"]
            address_str = item["address"]
            prog_name = item["prog_name"]
            current_name = item["current_name"]
            address = int(address_str, 16)

            out_path = args.out_dir / f"ctx_{rom}_{address_str[2:]}.json"

            from ghidra.app.decompiler import DecompInterface
            with pyghidra.program_context(project, f"/{prog_name}") as program:
                func_mgr = program.getFunctionManager()
                af = program.getAddressFactory().getDefaultAddressSpace()
                ref_mgr = program.getReferenceManager()

                addr = af.getAddress(address)
                func = func_mgr.getFunctionAt(addr)
                if func is None:
                    print(f"  [{rom}] {address_str}: no function at address, skipping")
                    continue

                decomp = DecompInterface()
                decomp.openProgram(program)
                result = decomp.decompileFunction(func, 30, pyghidra.task_monitor())
                decomp.dispose()
                if result is None or not result.decompileCompleted():
                    print(f"  [{rom}] {address_str}: decompilation failed, skipping")
                    continue
                decompiled = result.getDecompiledFunction().getC()

                callers: list[str] = []
                for ref in ref_mgr.getReferencesTo(addr):
                    if ref.getReferenceType().isCall():
                        caller_func = func_mgr.getFunctionContaining(ref.getFromAddress())
                        if caller_func is not None:
                            name = str(caller_func.getName())
                            if not (name.startswith("FUN_")
                                    or is_auto_name(name) or is_placeholder(name)):
                                callers.append(name)

                callees: list[str] = []
                body = func.getBody()
                for ref in ref_mgr.getReferencesFromBody(body):
                    if ref.getReferenceType().isCall():
                        callee_func = func_mgr.getFunctionAt(ref.getToAddress())
                        if callee_func is not None:
                            name = str(callee_func.getName())
                            if not (name.startswith("FUN_")
                                    or is_auto_name(name) or is_placeholder(name)):
                                callees.append(name)

            ctx = {
                "rom": rom,
                "address": address_str,
                "current_name": current_name,
                "prog_name": prog_name,
                "decompiled": decompiled,
                "callers": sorted(set(callers)),
                "callees": sorted(set(callees)),
            }
            out_path.write_text(json.dumps(ctx, indent=2))
            print(f"  [{rom}] {address_str}: wrote {out_path.name} "
                  f"({len(set(callers))} callers, {len(set(callees))} callees)")
            written += 1

    print(f"Decompiled {written}/{len(batch)} functions.")


if __name__ == "__main__":
    main()
