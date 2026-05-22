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


def test_load_reference_symbols_merges_flash_txt(fixtures_dir):
    syms = load_reference_symbols(
        fixtures_dir / "tiny_ghidra.xml",
        flash_txt=fixtures_dir / "tiny_colt_flash.txt",
    )
    by_name = {s.name: s for s in syms}
    # From tiny_ghidra.xml
    assert "adc_run" in by_name
    assert by_name["adc_run"].category == "function"
    # From tiny_colt_flash.txt — should be merged
    assert "flash_password" in by_name
    assert by_name["flash_password"].category == "data"
    assert by_name["flash_password"].address == 0x84
    assert "rom_crc_check_step" in by_name
    assert by_name["rom_crc_check_step"].category == "function"
    assert by_name["rom_crc_check_step"].address == 0x1524c
    assert "flash_fuel_map_rpm_axis" in by_name
    assert by_name["flash_fuel_map_rpm_axis"].category == "data"


def test_load_reference_symbols_merges_map_txt(fixtures_dir):
    syms = load_reference_symbols(
        fixtures_dir / "tiny_ghidra.xml",
        map_txt=fixtures_dir / "tiny_colt_map.txt",
    )
    by_name = {s.name: s for s in syms}
    assert "eeprom.block" in by_name
    assert by_name["eeprom.block"].category == "ram_global"
    assert by_name["eeprom.block"].address == 0x804010


def test_load_reference_symbols_xml_wins_on_conflict(fixtures_dir):
    # engine_rpm is in tiny_ghidra.xml at 0x804e5c; tiny_colt_map.txt also has it
    syms = load_reference_symbols(
        fixtures_dir / "tiny_ghidra.xml",
        map_txt=fixtures_dir / "tiny_colt_map.txt",
    )
    # No duplication — exactly one entry for engine_rpm
    assert sum(1 for s in syms if s.name == "engine_rpm") == 1
