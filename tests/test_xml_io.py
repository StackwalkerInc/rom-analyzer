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


from pathlib import Path
from rom_analyzer.types import DataTypeDefinition
from rom_analyzer.xml_io import load_data_type_definitions


def _write_xml(tmp_path, content):
    p = tmp_path / "test.xml"
    p.write_text(content)
    return p


def test_load_data_type_definitions_basic(tmp_path):
    xml = _write_xml(tmp_path, """<?xml version="1.0"?>
<PROGRAM>
  <DATA>
    <DEFINED_DATA ADDRESS="00800720" DATATYPE="byte[23]"
                  DATATYPE_NAMESPACE="/" SIZE="0x17" />
    <DEFINED_DATA ADDRESS="00000084" DATATYPE="uint8_t[12]"
                  DATATYPE_NAMESPACE="/" SIZE="0xc" />
  </DATA>
</PROGRAM>""")
    result = load_data_type_definitions(xml)
    assert len(result) == 2
    assert result[0].address == 0x800720
    assert result[0].datatype == "byte[23]"
    assert result[0].size == 0x17
    assert result[1].address == 0x84
    assert result[1].datatype == "uint8_t[12]"
    assert result[1].size == 0xc


def test_load_data_type_definitions_missing_size(tmp_path):
    xml = _write_xml(tmp_path, """<?xml version="1.0"?>
<PROGRAM>
  <DATA>
    <DEFINED_DATA ADDRESS="00800730" DATATYPE="pointer32" />
  </DATA>
</PROGRAM>""")
    result = load_data_type_definitions(xml)
    assert len(result) == 1
    assert result[0].size == 0


def test_load_data_type_definitions_empty(tmp_path):
    xml = _write_xml(tmp_path, """<?xml version="1.0"?>
<PROGRAM>
  <DATA />
</PROGRAM>""")
    result = load_data_type_definitions(xml)
    assert result == []
