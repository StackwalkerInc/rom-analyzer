from rom_analyzer.types import ReferenceSymbol
from rom_analyzer.xml_io import load_reference_symbols


def test_load_reference_symbols_categorizes_by_address(fixtures_dir):
    syms = load_reference_symbols(fixtures_dir / "tiny_ghidra.xml")

    by_name = {s.name: s for s in syms}

    assert by_name["adc_run"] == ReferenceSymbol("adc_run", 0x1533c, "function")
    assert by_name["flash_fuel_map_rpm_axis"] == ReferenceSymbol(
        "flash_fuel_map_rpm_axis", 0xb2fa, "data"
    )
    assert by_name["engine_rpm"] == ReferenceSymbol(
        "engine_rpm", 0x804e5c, "ram_global"
    )


def test_load_reference_symbols_skips_imported_vectors(fixtures_dir):
    syms = load_reference_symbols(fixtures_dir / "tiny_ghidra.xml")
    names = {s.name for s in syms}
    assert "RI" not in names, "imported vector labels should be filtered out"
