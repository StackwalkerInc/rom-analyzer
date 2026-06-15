"""End-to-end self-diff: running rom-analyzer on the reference ROM must
produce outputs matching checked-in goldens byte-for-byte.

This test is marked `e2e` and only runs when:
    pytest -m e2e

It requires:
- Ghidra 12.x at $GHIDRA_HOME (or /opt/homebrew/opt/ghidra/libexec)
- The StackwalkerInc/ghidra-m32r processor module installed in that Ghidra
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
            ROM_ANALYZER, "analyze", str(LOCAL_ROM),
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


REGISTRY = REPO_ROOT / "reference" / "registry.toml"


@pytest.mark.e2e
def test_single_entry_registry_matches_goldens(tmp_path):
    """A registry with only 33520003 must reproduce the single-reference
    goldens byte-for-byte (show_provenance is off for a lone reference)."""
    if not LOCAL_ROM.exists() or not REGISTRY.exists():
        pytest.skip("requires local ROM + registry.toml")
    out_dir = tmp_path / "out"
    subprocess.run(
        [ROM_ANALYZER, "analyze", str(LOCAL_ROM), "--variant", "fp8000",
         "--registry", str(REGISTRY), "--reference-id", "33520003",
         "--out", str(out_dir), "--emit-mode23"],
        check=True,
    )
    for filename in ("description.ld", "omni.ld.stub", "crc-region.toml",
                     "flash-free.toml", "ram-free.toml"):
        expected = (GOLDEN_DIR / f"33520003.{filename}").read_text()
        actual = (out_dir / filename).read_text()
        assert expected == actual, f"{filename} drift under single-entry registry"
    # Provenance must NOT appear for a lone reference (backward compatible).
    assert "/* from" not in (out_dir / "description.ld").read_text()


@pytest.mark.e2e
def test_multi_reference_emits_conflicts_and_provenance(tmp_path):
    """Two references (when a second bin+json is available) produce a conflicts
    report and provenance comments. Skips unless a second reference is usable."""
    if not LOCAL_ROM.exists() or not REGISTRY.exists():
        pytest.skip("requires local ROM + registry.toml")
    from rom_analyzer.registry import load_registry, partition_available
    usable, _ = partition_available(load_registry(REGISTRY))
    fp8000 = [e for e in usable if e.variant == "fp8000"]
    if len(fp8000) < 2:
        pytest.skip("multi-reference e2e needs ≥2 usable fp8000 references")
    out_dir = tmp_path / "out"
    subprocess.run(
        [ROM_ANALYZER, "analyze", str(LOCAL_ROM), "--variant", "fp8000",
         "--registry", str(REGISTRY), "--out", str(out_dir)],
        check=True,
    )
    conflicts = out_dir / "reference-conflicts.md"
    assert conflicts.exists()
    md = conflicts.read_text()
    assert "## Disagreements" in md and "## Cross-family VERIFY" in md
    assert "/* from" in (out_dir / "description.ld").read_text()


@pytest.mark.e2e
def test_enrich_emits_reconcile_nondestructive(tmp_path):
    """`enrich` cross-matches a reference against all others and writes a
    reconcile.toml. Non-destructive: enrich auto-applies new functions to the
    reference JSONs, so we snapshot every reference/*.json and restore it."""
    if not LOCAL_ROM.exists() or not REGISTRY.exists():
        pytest.skip("requires local ROM + registry.toml")
    from rom_analyzer.registry import load_registry, partition_available
    from rom_analyzer.enrich import read_reconcile
    usable, _ = partition_available(load_registry(REGISTRY))
    fp8000 = [e for e in usable if e.variant == "fp8000"]
    if len(fp8000) < 2:
        pytest.skip("enrich e2e needs ≥2 usable fp8000 references")

    ref_dir = REPO_ROOT / "reference"
    snapshot = {p: p.read_bytes() for p in ref_dir.glob("*.json")}
    out_dir = tmp_path / "enr"
    try:
        subprocess.run(
            [ROM_ANALYZER, "enrich", "e5090011", "--out", str(out_dir)],
            check=True,
        )
        reconcile = out_dir / "e5090011.reconcile.toml"
        assert reconcile.exists(), "enrich must emit <id>.reconcile.toml"
        items = read_reconcile(reconcile)
        assert isinstance(items, list)
        # every item must carry a verdict the apply step understands
        for it in items:
            assert it.verdict  # non-empty (proposed/keep/drop/custom)
    finally:
        for p, data in snapshot.items():
            p.write_bytes(data)


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
            ROM_ANALYZER, "analyze", str(LOCAL_ROM),
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
