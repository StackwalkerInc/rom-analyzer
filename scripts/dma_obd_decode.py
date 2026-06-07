"""Decompile OBD-II + remaining MUT functions for the protocol spec (static derivation)."""
import sys
from pathlib import Path
from rom_analyzer.ghidra import setup_environment, import_and_dump, ghidriff_program_name, decompile_function
from rom_analyzer.xml_io import load_reference_symbols

REPO = Path(__file__).resolve().parent.parent
ROM = REPO / "roms" / "Z27AG_JDM_5MT_1860B104.bin"
LANG = "m32r:2:fp8000"
PROJ_DIR = Path.home() / "rom-analyzer-projects" / "rom-analyzer"

TARGETS = {
    0x5ecd4: "sio0_reply_obd",
    0x5efa8: "sio0_obd_request_data_by_pid",
    0x5f670: "sio0_fill_trouble_codes",
    0x2fee4: "mut_request_data_or_actuators",
}
OUT = REPO / "out" / "obd_decode_report.txt"


def main() -> None:
    setup_environment(Path("/opt/homebrew/opt/ghidra/libexec"))
    import pyghidra
    pyghidra.start()
    project = pyghidra.open_project(PROJ_DIR, "rom-analyzer", create=True)
    prog_name = ghidriff_program_name(ROM)
    ref_symbols = load_reference_symbols(REPO / "reference" / "33520003.xml",
                                         flash_txt=REPO / "reference" / "colt_flash.txt",
                                         map_txt=REPO / "reference" / "colt_map.txt")
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
