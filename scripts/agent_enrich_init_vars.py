#!/usr/bin/env python3
"""Initialize the variable candidate queue for agent-enrich.

Requires a Ghidra project already created by agent_enrich_init.py.
Enumerates unnamed DAT_* symbols in RAM (0x804000–0x80FFFF) and flash data
(0x0–0x7FFFF) regions, scores each by named-function xref count plus named
annotation-symbol sibling proximity, and writes agent_enrich_state/queue_vars.json.

Usage:
    .venv/bin/python scripts/agent_enrich_init_vars.py [--force] [--sibling-window 64]
"""
from __future__ import annotations

import argparse
import dataclasses
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

GHIDRA_HOME = Path("/opt/homebrew/opt/ghidra/libexec")
PROJ_DIR = Path.home() / "rom-analyzer-projects"
PROJ_NAME = "rom-analyzer"
REGISTRY = REPO / "reference" / "registry.toml"
STATE_DIR = REPO / "agent_enrich_state"

RAM_MIN = 0x804000
RAM_MAX = 0x80FFFF
FLASH_MAX = 0x7FFFF


def _category(addr: int) -> str | None:
    """Return 'ram_global', 'data', or None if outside target regions."""
    if RAM_MIN <= addr <= RAM_MAX:
        return "ram_global"
    if addr <= FLASH_MAX:
        return "data"
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true",
                        help="Overwrite existing queue_vars.json if present")
    parser.add_argument("--sibling-window", type=int, default=64,
                        help="Byte radius for sibling scoring (default: 64)")
    parser.add_argument("--ghidra-home", type=Path, default=GHIDRA_HOME)
    parser.add_argument("--project-dir", type=Path, default=PROJ_DIR)
    parser.add_argument("--project-name", default=PROJ_NAME)
    args = parser.parse_args()

    queue_path = STATE_DIR / "queue_vars.json"
    yield_path = STATE_DIR / "yield_history_vars.json"

    if queue_path.exists() and not args.force:
        print(f"queue_vars.json already exists at {queue_path}. Use --force to overwrite.")
        sys.exit(0)

    from rom_analyzer.registry import load_registry, partition_available
    from rom_analyzer.annotations_io import load_annotations
    from rom_analyzer.enrich import is_auto_name, is_placeholder
    from rom_analyzer.agent_enrich import QueueEntry, save_var_queue
    from rom_analyzer.ghidra import setup_environment, ghidriff_program_name

    setup_environment(args.ghidra_home)
    import pyghidra
    pyghidra.start()

    entries = load_registry(REGISTRY)
    available, missing = partition_available(entries)
    if missing:
        print(f"Skipping {len(missing)} entries with missing ROMs: {[e.id for e in missing]}")

    project = pyghidra.open_project(args.project_dir, args.project_name, create=False)

    raw_queue: list[QueueEntry] = []

    with project:
        for entry in available:
            store = load_annotations(entry.json_path)
            prog_name = ghidriff_program_name(entry.rom_path)

            # Named annotation symbols: address → name (excludes auto/placeholder names)
            named_sym_by_addr: dict[int, str] = {
                s.address: s.name
                for s in store.symbols
                if not (is_auto_name(s.name) or is_placeholder(s.name))
            }
            covered_addrs: set[int] = set(named_sym_by_addr.keys())

            print(f"[{entry.id}] Scanning ({len(covered_addrs)} named symbols already covered)...")

            with pyghidra.program_context(project, f"/{prog_name}") as program:
                sym_table = program.getSymbolTable()
                func_mgr = program.getFunctionManager()
                ref_mgr = program.getReferenceManager()
                af = program.getAddressFactory().getDefaultAddressSpace()

                for sym in sym_table.getAllSymbols(False):
                    name = str(sym.getName())
                    if not (name.startswith("DAT_") or is_auto_name(name) or is_placeholder(name)):
                        continue

                    addr_int = int(sym.getAddress().getOffset()) & 0xFFFFFFFF
                    cat = _category(addr_int)
                    if cat is None:
                        continue
                    if addr_int in covered_addrs:
                        continue

                    addr_obj = af.getAddress(addr_int)

                    # Skip if a function lives at this address (DAT_ sometimes overlaps fn area)
                    if func_mgr.getFunctionAt(addr_obj) is not None:
                        continue

                    named_readers: set[str] = set()
                    named_writers: set[str] = set()
                    reader_writer_eps: set[str] = set()

                    for ref in ref_mgr.getReferencesTo(addr_obj):
                        ref_type = ref.getReferenceType()
                        if not ref_type.isData():
                            continue
                        caller = func_mgr.getFunctionContaining(ref.getFromAddress())
                        if caller is None:
                            continue
                        caller_name = str(caller.getName())
                        if is_auto_name(caller_name) or is_placeholder(caller_name):
                            continue
                        caller_ep = f"0x{int(caller.getEntryPoint().getOffset()) & 0xFFFFFFFF:x}"
                        reader_writer_eps.add(caller_ep)
                        if ref_type.isWrite():
                            named_writers.add(caller_name)
                        else:
                            named_readers.add(caller_name)

                    # Named sibling count: annotation symbols within ±sibling_window bytes
                    named_sibling_count = sum(
                        1 for a in covered_addrs
                        if 0 < abs(a - addr_int) <= args.sibling_window
                        and _category(a) == cat
                    )

                    priority = len(named_readers) + len(named_writers) + named_sibling_count

                    raw_queue.append(QueueEntry(
                        rom=entry.id,
                        address=f"0x{addr_int:x}",
                        current_name=name,
                        prog_name=prog_name,
                        named_neighbor_count=len(named_readers) + len(named_writers),
                        priority=priority,
                        neighbor_addresses=sorted(reader_writer_eps),
                        item_type="variable",
                        category=cat,
                        sibling_addresses=[],   # filled in post-pass below
                    ))

            count = sum(1 for e in raw_queue if e.rom == entry.id)
            print(f"[{entry.id}] {count} candidates found")

    # Post-pass: fill sibling_addresses with OTHER candidate addresses within ±window
    by_rom: dict[str, list[QueueEntry]] = {}
    for e in raw_queue:
        by_rom.setdefault(e.rom, []).append(e)

    final_queue: list[QueueEntry] = []
    for e in raw_queue:
        rom_candidates = by_rom[e.rom]
        addr_int = int(e.address, 16)
        siblings = sorted(
            c.address for c in rom_candidates
            if c.address != e.address
            and c.category == e.category
            and 0 < abs(int(c.address, 16) - addr_int) <= args.sibling_window
        )
        final_queue.append(dataclasses.replace(e, sibling_addresses=siblings))

    final_queue.sort(key=lambda e: e.priority, reverse=True)
    save_var_queue(STATE_DIR, final_queue)

    if not yield_path.exists():
        yield_path.write_text("[]")

    total = len(final_queue)
    print(f"\nDone. {total} variable candidates written to {queue_path}")
    print("Top 5 by priority:")
    for e in final_queue[:5]:
        print(f"  [{e.rom}] {e.address} ({e.current_name}) — priority {e.priority} "
              f"({e.named_neighbor_count} xrefs, {len(e.sibling_addresses)} candidate siblings)")


if __name__ == "__main__":
    main()
