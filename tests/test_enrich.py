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
