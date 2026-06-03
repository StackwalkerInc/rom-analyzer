"""Tests for enrich.py: signature parser, type mapper, register allocator, XML enricher."""
from rom_analyzer.parsers import Param, ParsedSignature, parse_function_signature


# ---------------------------------------------------------------------------
# Signature parser
# ---------------------------------------------------------------------------

def test_parse_sig_no_params():
    result = parse_function_signature("void reset_rom_crc_checker()")
    assert result == ParsedSignature(return_type="void", name="reset_rom_crc_checker", params=[])


def test_parse_sig_semicolon_stripped():
    result = parse_function_signature("void sio_dma_reset();")
    assert result is not None
    assert result.name == "sio_dma_reset"
    assert result.params == []


def test_parse_sig_with_params():
    result = parse_function_signature("uint16_t ps16_divu32_16(uint32_t l, uint16_t r)")
    assert result is not None
    assert result.return_type == "uint16_t"
    assert result.name == "ps16_divu32_16"
    assert result.params == [
        Param(type_str="uint32_t", name="l"),
        Param(type_str="uint16_t", name="r"),
    ]


def test_parse_sig_pointer_return():
    result = parse_function_signature("uint8_t *get_mut_pointer(uint16_t req)")
    assert result is not None
    assert result.return_type == "uint8_t *"
    assert result.name == "get_mut_pointer"
    assert result.params == [Param(type_str="uint16_t", name="req")]


def test_parse_sig_pointer_param():
    result = parse_function_signature("void adc_run(int ch, uint16_t *result)")
    assert result is not None
    assert result.return_type == "void"
    assert result.name == "adc_run"
    assert result.params == [
        Param(type_str="int", name="ch"),
        Param(type_str="uint16_t *", name="result"),
    ]


def test_parse_sig_void_param_list():
    result = parse_function_signature("void func(void)")
    assert result == ParsedSignature(return_type="void", name="func", params=[])


def test_parse_sig_data_entry_returns_none():
    assert parse_function_signature("uint8_t flash_password[16]") is None


def test_parse_sig_data_entry_with_equals_returns_none():
    assert parse_function_signature("uint8_t flash_default_mut_enabled_flags = 0") is None


from rom_analyzer.enrich import GhidraType, assign_arg_registers, map_c_type


# ---------------------------------------------------------------------------
# Type mapper
# ---------------------------------------------------------------------------

def test_map_c_type_stdint():
    assert map_c_type("uint8_t")  == GhidraType("uint8_t",  "/stdint.h", 1)
    assert map_c_type("uint16_t") == GhidraType("uint16_t", "/stdint.h", 2)
    assert map_c_type("uint32_t") == GhidraType("uint32_t", "/stdint.h", 4)
    assert map_c_type("uint64_t") == GhidraType("uint64_t", "/stdint.h", 8)
    assert map_c_type("int16_t")  == GhidraType("int16_t",  "/stdint.h", 2)


def test_map_c_type_void():
    gt = map_c_type("void")
    assert gt.datatype == "void"
    assert gt.namespace == ""
    assert gt.size_bytes == 0


def test_map_c_type_int():
    gt = map_c_type("int")
    assert gt.datatype == "int"
    assert gt.namespace == ""
    assert gt.size_bytes == 4


def test_map_c_type_pointer():
    gt = map_c_type("uint8_t *")
    assert gt.datatype == "uint8_t *"
    assert gt.namespace == ""
    assert gt.size_bytes == 4  # M32R pointers are 32-bit


def test_map_c_type_unknown_struct():
    gt = map_c_type("struct run_state_flags_bits")
    assert gt.datatype == "struct run_state_flags_bits"
    assert gt.namespace == ""
    assert gt.size_bytes == 0


# ---------------------------------------------------------------------------
# Register allocator
# ---------------------------------------------------------------------------

def test_assign_registers_two_args():
    params = [Param("uint16_t", "p0"), Param("uint32_t", "p1")]
    result = assign_arg_registers(params)
    assert [(p.name, r) for p, r in result] == [("p0", "R0"), ("p1", "R1")]


def test_assign_registers_64bit_uses_two_slots():
    params = [Param("uint64_t", "big"), Param("uint16_t", "small")]
    result = assign_arg_registers(params)
    assert result[0][1] == "R0"   # uint64_t → R0
    assert result[1][1] == "R2"   # next arg skips R1, gets R2


def test_assign_registers_overflow_to_stack():
    params = [Param("uint16_t", f"p{i}") for i in range(5)]
    result = assign_arg_registers(params)
    regs = [r for _, r in result]
    assert regs == ["R0", "R1", "R2", "R3", None]


from pathlib import Path
from lxml import etree
from rom_analyzer.enrich import enrich_reference_xml


# ---------------------------------------------------------------------------
# XML enrichment integration tests (tmp_path; no Ghidra)
# ---------------------------------------------------------------------------

_MINIMAL_XML = """\
<?xml version="1.0" standalone="yes"?>
<PROGRAM NAME="test" IMAGE_BASE="00000000">
    <SYMBOL_TABLE>
        <SYMBOL ADDRESS="0004f440" NAME="FUN_0004f440" NAMESPACE="" TYPE="function" SOURCE_TYPE="ANALYSIS" PRIMARY="y" />
    </SYMBOL_TABLE>
    <FUNCTIONS>
        <FUNCTION ENTRY_POINT="0004f440" NAME="FUN_0004f440" LIBRARY_FUNCTION="n">
            <ADDRESS_RANGE START="0004f440" END="0004f473" />
            <STACK_FRAME LOCAL_VAR_SIZE="0x0" PARAM_OFFSET="0x0" RETURN_ADDR_SIZE="0x0" />
        </FUNCTION>
    </FUNCTIONS>
</PROGRAM>
"""

_FLASH_ONE_FUNC = (
    "Address\t\tSize\tDeclaration\n"
    "0x04f440\t0x34\tuint16_t ps16_divu32_16(uint32_t l, uint16_t r)\n"
)

_FLASH_MISSING_FUNC = (
    "Address\t\tSize\tDeclaration\n"
    "0x01533c\t0x38\tvoid adc_run(int ch, uint16_t *result)\n"
)

_XML_WITH_STALE_TYPEINFO = """\
<?xml version="1.0" standalone="yes"?>
<PROGRAM NAME="test" IMAGE_BASE="00000000">
    <SYMBOL_TABLE>
        <SYMBOL ADDRESS="0004f440" NAME="FUN_0004f440" NAMESPACE="" TYPE="function" SOURCE_TYPE="ANALYSIS" PRIMARY="y" />
    </SYMBOL_TABLE>
    <FUNCTIONS>
        <FUNCTION ENTRY_POINT="0004f440" NAME="FUN_0004f440" LIBRARY_FUNCTION="n">
            <RETURN_TYPE DATATYPE="undefined" />
            <ADDRESS_RANGE START="0004f440" END="0004f473" />
            <TYPEINFO_CMT>stale signature</TYPEINFO_CMT>
            <STACK_FRAME LOCAL_VAR_SIZE="0x0" PARAM_OFFSET="0x0" RETURN_ADDR_SIZE="0x0" />
            <REGISTER_VAR NAME="old_param" REGISTER="R0" DATATYPE="undefined" />
        </FUNCTION>
    </FUNCTIONS>
</PROGRAM>
"""


def _setup(tmp_path, xml_content, flash_content):
    xml_path = tmp_path / "test.xml"
    flash_path = tmp_path / "flash.txt"
    xml_path.write_text(xml_content)
    flash_path.write_text(flash_content)
    return xml_path, flash_path


def test_enrich_updates_name_and_injects_type_info(tmp_path):
    xml_path, flash_path = _setup(tmp_path, _MINIMAL_XML, _FLASH_ONE_FUNC)
    enrich_reference_xml(xml_path, flash_path)
    root = etree.parse(str(xml_path)).getroot()

    fn = root.find(".//FUNCTION[@ENTRY_POINT='0004f440']")
    assert fn is not None
    assert fn.get("NAME") == "ps16_divu32_16"

    rt = fn.find("RETURN_TYPE")
    assert rt is not None
    assert rt.get("DATATYPE") == "uint16_t"
    assert rt.get("DATATYPE_NAMESPACE") == "/stdint.h"
    assert rt.get("SIZE") == "0x2"

    ti = fn.find("TYPEINFO_CMT")
    assert ti is not None
    assert "ps16_divu32_16" in ti.text

    rvs = fn.findall("REGISTER_VAR")
    assert len(rvs) == 2
    assert rvs[0].get("REGISTER") == "R0"
    assert rvs[0].get("NAME") == "l"
    assert rvs[0].get("DATATYPE") == "uint32_t"
    assert rvs[1].get("REGISTER") == "R1"
    assert rvs[1].get("NAME") == "r"
    assert rvs[1].get("DATATYPE") == "uint16_t"


def test_enrich_dtd_child_order(tmp_path):
    xml_path, flash_path = _setup(tmp_path, _MINIMAL_XML, _FLASH_ONE_FUNC)
    enrich_reference_xml(xml_path, flash_path)
    fn = etree.parse(str(xml_path)).getroot().find(".//FUNCTION[@ENTRY_POINT='0004f440']")
    tags = [c.tag for c in fn]
    assert tags.index("RETURN_TYPE") < tags.index("ADDRESS_RANGE")
    assert tags.index("TYPEINFO_CMT") < tags.index("STACK_FRAME")
    sf_idx = tags.index("STACK_FRAME")
    assert all(i > sf_idx for i, t in enumerate(tags) if t == "REGISTER_VAR")


def test_enrich_replaces_stale_type_annotations(tmp_path):
    xml_path, flash_path = _setup(tmp_path, _XML_WITH_STALE_TYPEINFO, _FLASH_ONE_FUNC)
    enrich_reference_xml(xml_path, flash_path)
    fn = etree.parse(str(xml_path)).getroot().find(".//FUNCTION[@ENTRY_POINT='0004f440']")
    assert fn.find("TYPEINFO_CMT").text != "stale signature"
    assert fn.find("RETURN_TYPE").get("DATATYPE") == "uint16_t"
    assert len(fn.findall("REGISTER_VAR")) == 2


def test_enrich_adds_missing_function(tmp_path):
    xml_path, flash_path = _setup(tmp_path, _MINIMAL_XML, _FLASH_MISSING_FUNC)
    enrich_reference_xml(xml_path, flash_path)
    root = etree.parse(str(xml_path)).getroot()

    fn = root.find(".//FUNCTION[@ENTRY_POINT='0001533c']")
    assert fn is not None
    assert fn.get("NAME") == "adc_run"

    ar = fn.find("ADDRESS_RANGE")
    assert ar.get("START") == "0001533c"
    assert ar.get("END") == "00015373"  # 0x1533c + 0x38 - 1 = 0x15373

    rvs = fn.findall("REGISTER_VAR")
    assert len(rvs) == 2   # ch → R0, result → R1


def test_enrich_updates_symbol_name(tmp_path):
    xml_path, flash_path = _setup(tmp_path, _MINIMAL_XML, _FLASH_ONE_FUNC)
    enrich_reference_xml(xml_path, flash_path)
    sym = etree.parse(str(xml_path)).getroot().find(".//SYMBOL[@ADDRESS='0004f440']")
    assert sym is not None
    assert sym.get("NAME") == "ps16_divu32_16"


def test_enrich_adds_new_symbol(tmp_path):
    xml_path, flash_path = _setup(tmp_path, _MINIMAL_XML, _FLASH_MISSING_FUNC)
    enrich_reference_xml(xml_path, flash_path)
    sym = etree.parse(str(xml_path)).getroot().find(".//SYMBOL[@ADDRESS='0001533c']")
    assert sym is not None
    assert sym.get("NAME") == "adc_run"
    assert sym.get("SOURCE_TYPE") == "USER_DEFINED"
    assert sym.get("TYPE") == "global"
