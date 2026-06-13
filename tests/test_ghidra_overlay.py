import pytest
from rom_analyzer.ghidra_overlay import _parse_type_str, _ParsedType


# --- scalars ---

def test_scalar_uint8():
    assert _parse_type_str("uint8_t") == _ParsedType("uint8_t", 0, [])

def test_scalar_uint16():
    assert _parse_type_str("uint16_t") == _ParsedType("uint16_t", 0, [])

def test_scalar_uint32():
    assert _parse_type_str("uint32_t") == _ParsedType("uint32_t", 0, [])

def test_scalar_void():
    assert _parse_type_str("void") == _ParsedType("void", 0, [])

def test_scalar_int():
    assert _parse_type_str("int") == _ParsedType("int", 0, [])

def test_scalar_unsigned():
    assert _parse_type_str("unsigned") == _ParsedType("unsigned", 0, [])

def test_scalar_int8():
    # int8_t aliases to uint8_t (Ghidra ByteDataType is signed)
    assert _parse_type_str("int8_t") == _ParsedType("uint8_t", 0, [])

def test_g8t_alias():
    assert _parse_type_str("g8_t") == _ParsedType("uint8_t", 0, [])

def test_pointer_keyword():
    assert _parse_type_str("pointer") == _ParsedType("void", 1, [])

def test_undefined_star():
    assert _parse_type_str("undefined *") == _ParsedType("void", 1, [])


# --- pointers ---

def test_single_pointer():
    assert _parse_type_str("uint8_t *") == _ParsedType("uint8_t", 1, [])

def test_double_pointer():
    assert _parse_type_str("uint8_t * *") == _ParsedType("uint8_t", 2, [])

def test_void_pointer():
    assert _parse_type_str("void *") == _ParsedType("void", 1, [])


# --- const stripping ---

def test_const_scalar():
    assert _parse_type_str("const uint8_t") == _ParsedType("uint8_t", 0, [])

def test_const_pointer():
    assert _parse_type_str("const uint16_t *") == _ParsedType("uint16_t", 1, [])

def test_const_double_pointer():
    assert _parse_type_str("const uint8_t * *") == _ParsedType("uint8_t", 2, [])


# --- struct types ---

def test_struct_pointer():
    r = _parse_type_str("const struct cylinder_bank *")
    assert r == _ParsedType("cylinder_bank", 1, [], is_struct=True)

def test_struct_no_const():
    r = _parse_type_str("struct map8_desc *")
    assert r == _ParsedType("map8_desc", 1, [], is_struct=True)

def test_struct_double_pointer():
    r = _parse_type_str("const struct map8_desc * *")
    assert r == _ParsedType("map8_desc", 2, [], is_struct=True)

def test_bare_struct_name():
    # data_type field in symbols can be a bare struct name without "struct" prefix
    r = _parse_type_str("axis_desc")
    assert r is not None
    assert r.base == "axis_desc"
    assert r.pointer_depth == 0


# --- arrays ---

def test_1d_array():
    assert _parse_type_str("uint16_t[8]") == _ParsedType("uint16_t", 0, [8])

def test_1d_array_uint8():
    assert _parse_type_str("uint8_t[12]") == _ParsedType("uint8_t", 0, [12])

def test_2d_array():
    assert _parse_type_str("uint16_t[17][16]") == _ParsedType("uint16_t", 0, [17, 16])

def test_array_of_pointers():
    # void *[476] → pointer_depth=1, array_dims=[476]
    assert _parse_type_str("void *[476]") == _ParsedType("void", 1, [476])

def test_array_of_uint8_pointers():
    assert _parse_type_str("uint8_t *[256]") == _ParsedType("uint8_t", 1, [256])


# --- edge cases ---

def test_empty_string_returns_none():
    assert _parse_type_str("") is None

def test_whitespace_only_returns_none():
    assert _parse_type_str("   ") is None

def test_unknown_name_returns_parsed():
    # Unknown names pass through — _resolve_type will attempt a struct lookup
    r = _parse_type_str("run_state_flags_bits")
    assert r is not None
    assert r.base == "run_state_flags_bits"
