"""E2E smoke test: SLEIGH correctness check via function decompilation.

Decompiles adc1_run_helper (Outlander ROM, 0xead8) and asserts that the
output is structurally sane — no infinite loops, no undefined temporaries.
This catches SLEIGH regressions that cause the decompiler to lose track of
condition-flag dataflow (e.g. BC/BNC reading PSW bitfields instead of CBR).

This test is marked `e2e` and only runs when:
    pytest -m e2e

It requires:
- Ghidra 12.x at $GHIDRA_HOME (or /opt/homebrew/opt/ghidra/libexec)
- The StackwalkerInc/ghidra-m32r processor module installed in that Ghidra
- A user-supplied ROM at roms/outlander-c7280011.bin (gitignored)

ROMs are never distributed (CLAUDE.md). The test SKIPs if the ROM is absent.
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
OUTLANDER_ROM = REPO_ROOT / "roms" / "outlander-c7280011.bin"
REFERENCE_XML = REPO_ROOT / "reference" / "33520003.xml"

# Address of adc1_run_helper in the Outlander ROM
ADC1_RUN_HELPER_ADDR = 0xead8


@pytest.mark.e2e
def test_adc1_run_helper_decompiles_cleanly(tmp_path):
    """adc1_run_helper must not contain infinite loops or undefined temporaries.

    Before the June 2026 SLEIGH fix, BC/BNC read PSW[0,1] (a 1-bit bitfield)
    instead of CBR.  The Ghidra decompiler loses track of bitfield-write
    dataflow, so any loop controlled by a TSTb31/ADDV branch appeared as
    'do {} while(true)' with undefined temporaries.
    """
    if not OUTLANDER_ROM.exists():
        pytest.skip(
            f"E2E test requires a user-supplied ROM at {OUTLANDER_ROM} "
            f"(see README; ROMs are never distributed)"
        )

    from rom_analyzer.ghidra import (
        decompile_function,
        ghidriff_program_name,
        import_and_dump,
        setup_environment,
    )

    ghidra_home = Path(
        __import__("os").environ.get(
            "GHIDRA_HOME", "/opt/homebrew/opt/ghidra/libexec"
        )
    )
    setup_environment(ghidra_home)

    import pyghidra

    pyghidra.start()
    project_dir = tmp_path / "ghidra-project"
    project_dir.mkdir()
    project = pyghidra.open_project(project_dir, "decompile-test", create=True)

    prog_name = ghidriff_program_name(OUTLANDER_ROM)
    import_and_dump(project, OUTLANDER_ROM, "m32r:BE:32:fp8000:default")

    src = decompile_function(project, prog_name, ADC1_RUN_HELPER_ADDR)

    assert "while( true )" not in src, (
        "adc1_run_helper contains 'while( true )' — "
        "BC/BNC may be reading PSW bitfield instead of CBR (SLEIGH regression)"
    )
    assert "undefined" not in src, (
        "adc1_run_helper contains 'undefined' temporaries — "
        "condition dataflow lost (SLEIGH regression)"
    )
    assert "popi" in src or "pop" in src.lower(), (
        "adc1_run_helper missing expected pop instruction — "
        "function may not have been located at the right address"
    )
