"""Decompile the DMA request-decoder / session functions for wire-protocol extraction."""
import sys
from pathlib import Path

from rom_analyzer.ghidra import (
    setup_environment, import_and_dump, ghidriff_program_name, decompile_function,
)
from rom_analyzer.xml_io import load_reference_symbols

REPO = Path(__file__).resolve().parent.parent
ROM = REPO / "roms" / "Z27AG_JDM_5MT_1860B104.bin"
REF_XML = REPO / "reference" / "33520003.xml"
FLASH_TXT = REPO / "reference" / "colt_flash.txt"
MAP_TXT = REPO / "reference" / "colt_map.txt"
LANG = "m32r:2:fp8000"
GHIDRA_HOME = Path("/opt/homebrew/opt/ghidra/libexec")
PROJ_DIR = Path.home() / "rom-analyzer-projects" / "rom-analyzer"
PROJ_NAME = "rom-analyzer"

TARGETS = {
    0x10040: "sio_dma_mode_select",
    0x10d10: "sio_dma_code10_mode_select",
    0x107a0: "sio_dma_try_wait_session_init",
    0x113fc: "sio_dma_reply_free_form_log",
    0x11598: "sio0_dma_fill_free_form_log",
    0x10b84: "sio_dma_reply_2fu16_3vu16",
    0x30f38: "sio_dma_fast_model_session_init_or_reply",
}
OUT = REPO / "out" / "dma_decode_report.txt"


def main() -> None:
    setup_environment(GHIDRA_HOME)
    import pyghidra
    pyghidra.start()
    project = pyghidra.open_project(PROJ_DIR, PROJ_NAME, create=True)
    prog_name = ghidriff_program_name(ROM)
    ref_symbols = load_reference_symbols(REF_XML, flash_txt=FLASH_TXT, map_txt=MAP_TXT)
    import_and_dump(project, ROM, LANG, ref_symbols_for_overlay=ref_symbols)

    out = []
    for addr, name in TARGETS.items():
        out.append(f"\n{'#'*70}\n# {name} @ {addr:#x}\n{'#'*70}")
        try:
            out.append(decompile_function(project, prog_name, addr))
        except Exception as e:  # noqa: BLE001
            out.append(f"<decompile failed: {e}>")
    OUT.write_text("\n".join(out))
    print(f"WROTE {OUT}")


if __name__ == "__main__":
    sys.exit(main())
