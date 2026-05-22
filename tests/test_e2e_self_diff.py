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
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
LOCAL_ROM = REPO_ROOT / "roms" / "Z27AG_JDM_5MT_1860B104.bin"
REFERENCE_XML = REPO_ROOT / "reference" / "33520003.xml"
GOLDEN_DIR = REPO_ROOT / "tests" / "golden"


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
            "rom-analyzer", str(LOCAL_ROM),
            "--variant", "fp8000",
            "--reference", str(REFERENCE_XML),
            "--out", str(out_dir),
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
