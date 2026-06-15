"""End-to-end cross-ROM test: outlander-c7280011 against the Z27AG reference.

Validates cross-ROM analysis behaviour:
- Flash data labels are correctly propagated when the Outlander accesses the
  same flash address via a genuine memory read (LD24 + LDUH).
- RAM-global symbols are NOT propagated across ECU families (different RAM
  layouts mean absolute-address RAM labels are meaningless on the target).

This test is marked `e2e` and only runs when:
    pytest -m e2e

It requires:
- Ghidra 12.x at $GHIDRA_HOME (or /opt/homebrew/opt/ghidra/libexec)
- The StackwalkerInc/ghidra-m32r processor module installed in that Ghidra
- User-supplied ROMs at roms/ (gitignored):
    roms/outlander-c7280011.bin
    roms/Z27AG_JDM_5MT_1860B104.bin

ROMs are never distributed (CLAUDE.md). The test SKIPs if either ROM is absent.
"""

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
OUTLANDER_ROM = REPO_ROOT / "roms" / "outlander-c7280011.bin"
REFERENCE_ROM = REPO_ROOT / "roms" / "Z27AG_JDM_5MT_1860B104.bin"
REFERENCE_JSON = REPO_ROOT / "reference" / "33520003.json"

_VENV_BIN = Path(sys.executable).parent
_ROM_ANALYZER_CMD = _VENV_BIN / "rom-analyzer"
ROM_ANALYZER = str(_ROM_ANALYZER_CMD) if _ROM_ANALYZER_CMD.exists() else "rom-analyzer"


def _skip_if_roms_absent():
    missing = [p for p in (OUTLANDER_ROM, REFERENCE_ROM) if not p.exists()]
    if missing:
        pytest.skip(
            "E2E test requires user-supplied ROMs (see README): "
            + ", ".join(str(p) for p in missing)
        )


@pytest.mark.e2e
def test_cross_rom_data_label_propagation(tmp_path):
    """Flash data labels that exist at the same address in both ROMs propagate
    correctly.  flash_injector_latency_scaling lives at 0x0800 in both Z27AG
    and the Outlander; the Outlander reads it via LD24 r4, 0x800 + LDUH r1, @r4
    (a genuine flash read), so the label must appear in description.ld.
    """
    _skip_if_roms_absent()
    out_dir = tmp_path / "out"
    project_dir = tmp_path / "ghidra-project"
    subprocess.run(
        [
            ROM_ANALYZER, str(OUTLANDER_ROM),
            "--variant", "fp8000",
            "--reference", str(REFERENCE_JSON),
            "--reference-rom", str(REFERENCE_ROM),
            "--project-dir", str(project_dir),
            "--project-name", "outlander-cross-rom-test",
            "--out", str(out_dir),
            "--clean-project",
        ],
        check=True,
    )
    content = (out_dir / "description.ld").read_text()

    # Flash label correctly propagated: Outlander accesses this table via
    # LD24 + LDUH (a genuine read), so the label must appear.
    assert "flash_injector_latency_scaling = 0x800" in content, (
        "flash_injector_latency_scaling should be propagated to 0x800 — "
        "the Outlander reads it via LD24 r4,0x800 + LDUH r1,@r4"
    )


@pytest.mark.e2e
def test_cross_rom_no_ram_global_propagation(tmp_path):
    """RAM-global symbols must NOT be propagated in a cross-family analysis.

    Z27AG and the Outlander have different RAM layouts; copying absolute-address
    RAM labels would place them on the wrong variables in the Outlander project.
    Concretely, decays_x1.standing_boost_delay (fp-offset variable in Z27AG)
    must not appear in the Outlander description.ld.
    """
    _skip_if_roms_absent()
    out_dir = tmp_path / "out"
    project_dir = tmp_path / "ghidra-project"
    subprocess.run(
        [
            ROM_ANALYZER, str(OUTLANDER_ROM),
            "--variant", "fp8000",
            "--reference", str(REFERENCE_JSON),
            "--reference-rom", str(REFERENCE_ROM),
            "--project-dir", str(project_dir),
            "--project-name", "outlander-cross-rom-test",
            "--out", str(out_dir),
            "--clean-project",
        ],
        check=True,
    )
    content = (out_dir / "description.ld").read_text()

    # Ram-global propagation is disabled for cross-ROM analysis.
    assert "decays_x1.standing_boost_delay" not in content, (
        "RAM-global symbol decays_x1.standing_boost_delay must not be propagated "
        "to the Outlander — cross-family ECUs have different RAM layouts"
    )
    assert "ram_global" not in content, (
        "No ram_global category entries should appear in a cross-ROM description.ld"
    )
