"""Tests for enrich.py: signature parser, type mapper, register allocator, XML enricher."""
from pathlib import Path

import pytest
from lxml import etree

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
