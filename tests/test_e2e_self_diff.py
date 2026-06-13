"""End-to-end self-diff: running rom-analyzer on the reference ROM must
produce outputs matching checked-in goldens byte-for-byte.

This test is marked `e2e` and only runs when:
    pytest -m e2e

It requires:
- Ghidra 12.x at $GHIDRA_HOME (or /opt/homebrew/opt/ghidra/libexec)
- The RcusStackwalker/ghidra-m32r processor module installed in that Ghidra
- A user-supplied ROM at roms/Z27AG_JDM_5MT_1860B104.bin (gitignored)

ROMs are never distributed (CLAUDE.md). The test SKIPs if the ROM is absent.
"""

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
LOCAL_ROM = REPO_ROOT / "roms" / "Z27AG_JDM_5MT_1860B104.bin"
REFERENCE_XML = REPO_ROOT / "reference" / "33520003.xml"
GOLDEN_DIR = REPO_ROOT / "tests" / "golden"

# Resolve the rom-analyzer entry point: prefer the venv script next to the
# current Python interpreter so the test works regardless of PATH.
_VENV_BIN = Path(sys.executable).parent
_ROM_ANALYZER_CMD = _VENV_BIN / "rom-analyzer"
ROM_ANALYZER = str(_ROM_ANALYZER_CMD) if _ROM_ANALYZER_CMD.exists() else "rom-analyzer"


@pytest.mark.e2e
def test_self_diff_matches_goldens(tmp_path):
    if not LOCAL_ROM.exists():
        pytest.skip(
            f"E2E test requires a user-supplied ROM at {LOCAL_ROM} "
            f"(see README; ROMs are never distributed)"
        )
    out_dir = tmp_path / "out"
    subprocess.run(
        [
            ROM_ANALYZER, str(LOCAL_ROM),
            "--variant", "fp8000",
            "--reference", str(REFERENCE_XML),
            "--out", str(out_dir),
            "--emit-mode23",
        ],
        check=True,
    )

    for filename in (
        "description.ld",
        "omni.ld.stub",
        "crc-region.toml",
        "flash-free.toml",
        "ram-free.toml",
    ):
        expected = (GOLDEN_DIR / f"33520003.{filename}").read_text()
        actual = (out_dir / filename).read_text()
        assert expected == actual, f"{filename} drift; diff via local pytest output"

    # CRC detection: verify the CRC region was actually detected (not a stub comment)
    crc_content = (out_dir / "crc-region.toml").read_text()
    assert "CRC region not detected" not in crc_content, (
        "CRC region should be detected with enriched symbols"
    )

    # v0.2: verify enriched description.ld contains colt_flash data labels and functions
    content = (out_dir / "description.ld").read_text()
    assert "rom_crc_check_step" in content, (
        "rom_crc_check_step function should appear in description.ld (from colt_flash enrichment)"
    )
    assert content.count("flash_") > 50, (
        "Expected >50 flash_* data labels in description.ld (from colt_flash.txt)"
    )
    assert "adc_run" in content, (
        "adc_run should appear as a function entry in description.ld"
    )

    # mode 0x23: self-diff maps the K-Line splice to itself at 0x5ef34 (high conf).
    desc = (out_dir / "description.ld").read_text()
    assert "obd_rest_handler_injection_location = 0x5ef34;" in desc, (
        "K-Line mode-0x23 splice should resolve to 0x5ef34 in self-diff"
    )
    # CAN: both call-site bindings (slot 12 / slot 15) must be emitted as named
    # symbols (resolved or VERIFY — addresses come from the golden comparison above).
    assert "canrx12_15_call_location_slot12" in desc, (
        "slot-12 CAN mode-0x23 splice binding should be emitted"
    )
    assert "canrx12_15_call_location_slot15" in desc, (
        "slot-15 CAN mode-0x23 splice binding should be emitted"
    )


@pytest.mark.e2e
def test_emit_obd_produces_dtc_map(tmp_path):
    if not LOCAL_ROM.exists():
        pytest.skip(
            f"E2E test requires a user-supplied ROM at {LOCAL_ROM} "
            f"(see README; ROMs are never distributed)"
        )
    out_dir = tmp_path / "out"
    subprocess.run(
        [
            ROM_ANALYZER, str(LOCAL_ROM),
            "--variant", "fp8000",
            "--out", str(out_dir),
            "--emit-obd",
        ],
        check=True,
    )

    dtc_map = out_dir / "dtc-map.toml"
    assert dtc_map.exists(), "dtc-map.toml must be emitted with --emit-obd"

    import tomllib
    data = tomllib.loads(dtc_map.read_text())
    dtc_entries = data.get("dtc", [])
    assert len(dtc_entries) >= 50, (
        f"Expected ≥50 DTC entries; got {len(dtc_entries)}"
    )

    high_conf_pid_syms = out_dir / "description.ld"
    if high_conf_pid_syms.exists():
        ld_content = high_conf_pid_syms.read_text()
        # At least one standard OBD PID should appear as a PROVIDE symbol
        assert "PROVIDE(engine_rpm" in ld_content or "PROVIDE(vehicle_speed" in ld_content, (
            "Expected at least one standard OBD PID PROVIDE() symbol in description.ld"
        )
