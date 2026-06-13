"""One-off: trace control flow into OEM K-Line DMA-logging activation on 33520003.

Drives headless Ghidra (PyGhidra) over the reference Z27AG ROM. Emits:
  - reverse call graph from the DMA-exec functions up toward the main loop
  - decompiled C for the activation/driver functions
  - caller sites (with containing function) for each DMA primitive

Run with the project venv:  .venv/bin/python scripts/dma_activation_analysis.py
"""
import sys
from pathlib import Path

from rom_analyzer.ghidra import (
    setup_environment,
    import_and_dump,
    ghidriff_program_name,
    decompile_function,
    fetch_callers_of,
    fetch_function_entry,
)
from rom_analyzer.annotations_io import load_reference_symbols

REPO = Path(__file__).resolve().parent.parent
ROM = REPO / "roms" / "Z27AG_JDM_5MT_1860B104.bin"
REF_JSON = REPO / "reference" / "33520003.json"
LANG = "m32r:2:fp8000"
GHIDRA_HOME = Path("/opt/homebrew/opt/ghidra/libexec")
PROJ_DIR = Path.home() / "rom-analyzer-projects" / "rom-analyzer"
PROJ_NAME = "rom-analyzer"

# Functions of interest (from z27ag.S annotations).
NAMES = {
    0x2f8f0: "update_sio0_protocol",
    0x30c40: "update_sio0_mut_protocol",
    0x2fb2c: "sio0_reply_mut2",
    0x2fa58: "sio0_fast_model_call",
    0x30414: "sio0_5baud_init_step",
    0x10858: "mut_log_reply_std",
    0x11598: "sio0_dma_fill_free_form_log",
    0x55f00: "mut_get_values",
    0x17f00: "sio0_rx_dma_init",
    0x17e98: "sio0_tx_dma_init",
    0x17fdc: "sio0_dma_disable",
    0x30980: "sio0_reply_proto20_default_data",
}
# Leaf DMA primitives we want the reverse call graph for.
DMA_PRIMITIVES = [0x17f00, 0x17e98, 0x10858, 0x11598, 0x55f00]
# Functions to decompile in full.
DECOMPILE = [0x30c40, 0x2f8f0, 0x10858, 0x11598, 0x2fb2c, 0x30414]

OUT = REPO / "out" / "dma_activation_report.txt"


def main() -> None:
    setup_environment(GHIDRA_HOME)
    import pyghidra
    pyghidra.start()

    project = pyghidra.open_project(PROJ_DIR, PROJ_NAME, create=True)
    prog_name = ghidriff_program_name(ROM)

    lines: list[str] = []
    log = lines.append

    # Ensure imported + analyzed (idempotent; fast if cached). Overlay names for readable decomp.
    ref_symbols = load_reference_symbols(REF_JSON)
    log(f"# DMA activation control-flow report — {prog_name}")
    log(f"# reference symbols loaded: {len(ref_symbols)}")
    import_and_dump(project, ROM, LANG, ref_symbols_for_overlay=ref_symbols)

    def name_of(entry: int | None) -> str:
        if entry is None:
            return "<none>"
        return NAMES.get(entry, f"sub_{entry:x}")

    # ---- Reverse call graph (BFS up from each DMA primitive) ----
    log("\n" + "=" * 70)
    log("REVERSE CALL GRAPH (callers, up to depth 5)")
    log("=" * 70)
    for prim in DMA_PRIMITIVES:
        log(f"\n## {name_of(prim)} @ {prim:#x}")
        frontier = {prim}
        seen = {prim}
        depth = 0
        while frontier and depth < 5:
            depth += 1
            next_frontier: set[int] = set()
            for tgt in sorted(frontier):
                sites = fetch_callers_of(project, prog_name, tgt)
                # map each call site -> containing function entry (once)
                caller_of_site: dict[int, int] = {}
                for site in sites:
                    ent = fetch_function_entry(project, prog_name, site)
                    caller_of_site[site] = ent if ent is not None else site
                for c in sorted(set(caller_of_site.values())):
                    site = next(s for s, e in caller_of_site.items() if e == c)
                    tag = " <-- in NAMES" if c in NAMES else ""
                    log(f"  {'  '*depth}d{depth}: {name_of(tgt)} <- {name_of(c)} @ {c:#x}"
                        f" (call site {site:#x}){tag}")
                    if c not in seen:
                        seen.add(c)
                        next_frontier.add(c)
            frontier = next_frontier

    # ---- Caller sites for each primitive (flat) ----
    log("\n" + "=" * 70)
    log("DIRECT CALLER SITES")
    log("=" * 70)
    for prim in DMA_PRIMITIVES:
        sites = fetch_callers_of(project, prog_name, prim)
        log(f"\n## {name_of(prim)} @ {prim:#x}: {len(sites)} call site(s)")
        for site in sites:
            ent = fetch_function_entry(project, prog_name, site)
            log(f"   {site:#x}  in {name_of(ent)} @ {ent:#x}" if ent else f"   {site:#x}  (no func)")

    # ---- Decompiled activation/driver functions ----
    log("\n" + "=" * 70)
    log("DECOMPILED FUNCTIONS")
    log("=" * 70)
    for addr in DECOMPILE:
        log(f"\n{'#'*70}\n# {name_of(addr)} @ {addr:#x}\n{'#'*70}")
        try:
            c = decompile_function(project, prog_name, addr)
        except Exception as e:  # noqa: BLE001
            c = f"<decompile failed: {e}>"
        log(c)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines))
    print(f"WROTE {OUT} ({len(lines)} lines)")


if __name__ == "__main__":
    sys.exit(main())
