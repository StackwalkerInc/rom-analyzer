#!/usr/bin/env python3
"""One-time initialization for the agent-enrich loop.

Loads all available reference ROMs into the shared Ghidra project, applies
annotations, enumerates naming candidates (FUN_XXXX and placeholder-named
functions), scores each by named-neighbor count, and writes
agent_enrich_state/queue.json.

Usage:
    .venv/bin/python scripts/agent_enrich_init.py [--force]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

GHIDRA_HOME = Path("/opt/homebrew/opt/ghidra/libexec")
PROJ_DIR = Path.home() / "rom-analyzer-projects"
PROJ_NAME = "rom-analyzer"
REGISTRY = REPO / "reference" / "registry.toml"
STATE_DIR = REPO / "agent_enrich_state"

LANG_DEFAULTS = {
    "fp8000": "m32r:2:fp8000",
    "default": "m32r:2:default",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true",
                        help="Overwrite existing queue.json if present")
    parser.add_argument("--ghidra-home", type=Path, default=GHIDRA_HOME)
    parser.add_argument("--project-dir", type=Path, default=PROJ_DIR)
    parser.add_argument("--project-name", default=PROJ_NAME)
    args = parser.parse_args()

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    queue_path = STATE_DIR / "queue.json"
    yield_path = STATE_DIR / "yield_history.json"

    if queue_path.exists() and not args.force:
        print(f"queue.json already exists at {queue_path}. Use --force to overwrite.")
        sys.exit(0)

    from rom_analyzer.registry import load_registry, partition_available
    from rom_analyzer.annotations_io import load_annotations
    from rom_analyzer.enrich import is_auto_name, is_placeholder
    from rom_analyzer.agent_enrich import QueueEntry, save_queue
    from rom_analyzer.ghidra import (
        setup_environment, _import_program, _overlay_from_annotations,
        ghidriff_program_name,
    )

    setup_environment(args.ghidra_home)
    import pyghidra
    pyghidra.start()

    entries = load_registry(REGISTRY)
    available, missing = partition_available(entries)
    if missing:
        print(f"Skipping {len(missing)} entries with missing ROMs: "
              f"{[e.id for e in missing]}")

    project = pyghidra.open_project(args.project_dir, args.project_name, create=True)

    rom_annotations: dict[str, set[int]] = {}
    rom_placeholders: dict[str, set[int]] = {}
    rom_prog_names: dict[str, str] = {}

    with project:
        from ghidra.program.util import GhidraProgramUtilities

        for entry in available:
            store = load_annotations(entry.json_path)
            all_eps = {f.entry_point for f in store.functions}
            placeholder_eps = {
                f.entry_point for f in store.functions
                if is_auto_name(f.name) or is_placeholder(f.name)
            }
            rom_annotations[entry.id] = all_eps
            rom_placeholders[entry.id] = placeholder_eps

            prog_name = ghidriff_program_name(entry.rom_path)
            rom_prog_names[entry.id] = prog_name
            lang_id = LANG_DEFAULTS.get(entry.variant, "m32r:2:fp8000")

            print(f"[{entry.id}] Importing {entry.rom_path.name} as {prog_name}")
            _import_program(project, entry.rom_path, prog_name, lang_id)

            with pyghidra.program_context(project, f"/{prog_name}") as program:
                if GhidraProgramUtilities.shouldAskToAnalyze(program):
                    print(f"[{entry.id}] Running Ghidra analysis...")
                    pyghidra.analyze(program)
                    program.save("Analyzed", pyghidra.task_monitor())
                print(f"[{entry.id}] Applying annotations...")
                with pyghidra.transaction(program, "Apply annotations"):
                    _overlay_from_annotations(program, store)
                program.save("Annotations", pyghidra.task_monitor())

        queue: list[QueueEntry] = []
        print("Enumerating candidates...")

        for entry in available:
            prog_name = rom_prog_names[entry.id]
            all_eps = rom_annotations[entry.id]
            placeholder_eps = rom_placeholders[entry.id]

            with pyghidra.program_context(project, f"/{prog_name}") as program:
                func_mgr = program.getFunctionManager()
                af = program.getAddressFactory().getDefaultAddressSpace()

                for func in func_mgr.getFunctions(True):
                    ep = int(func.getEntryPoint().getOffset()) & 0xFFFFFFFF
                    name = str(func.getName())
                    is_fun_xx = name.startswith("FUN_") and ep not in all_eps
                    is_placeholder_entry = ep in placeholder_eps

                    if not (is_fun_xx or is_placeholder_entry):
                        continue

                    neighbor_eps: set[int] = set()
                    named_eps: set[int] = set()

                    ref_mgr = program.getReferenceManager()
                    target_addr = af.getAddress(ep)
                    for ref in ref_mgr.getReferencesTo(target_addr):
                        if ref.getReferenceType().isCall():
                            caller_func = func_mgr.getFunctionContaining(
                                ref.getFromAddress()
                            )
                            if caller_func is not None:
                                caller_ep = (
                                    int(caller_func.getEntryPoint().getOffset()) & 0xFFFFFFFF
                                )
                                neighbor_eps.add(caller_ep)
                                caller_name = str(caller_func.getName())
                                if not (caller_name.startswith("FUN_")
                                        or is_auto_name(caller_name)
                                        or is_placeholder(caller_name)):
                                    named_eps.add(caller_ep)

                    body = func.getBody()
                    for ref in ref_mgr.getReferencesFromBody(body):
                        if ref.getReferenceType().isCall():
                            callee_func = func_mgr.getFunctionAt(ref.getToAddress())
                            if callee_func is not None:
                                callee_ep = (
                                    int(callee_func.getEntryPoint().getOffset()) & 0xFFFFFFFF
                                )
                                neighbor_eps.add(callee_ep)
                                callee_name = str(callee_func.getName())
                                if not (callee_name.startswith("FUN_")
                                        or is_auto_name(callee_name)
                                        or is_placeholder(callee_name)):
                                    named_eps.add(callee_ep)

                    queue.append(QueueEntry(
                        rom=entry.id,
                        address=f"0x{ep:x}",
                        current_name=name,
                        prog_name=prog_name,
                        named_neighbor_count=len(named_eps),
                        priority=len(named_eps),
                        neighbor_addresses=sorted(f"0x{a:x}" for a in neighbor_eps),
                    ))

    queue.sort(key=lambda e: e.priority, reverse=True)
    save_queue(STATE_DIR, queue)

    if not yield_path.exists():
        yield_path.write_text("[]")

    print(f"Done. {len(queue)} candidates written to {queue_path}")
    print("Top 5 by priority:")
    for e in queue[:5]:
        print(f"  [{e.rom}] {e.address} ({e.current_name}) — {e.priority} named neighbors")


if __name__ == "__main__":
    main()
