"""Tests for colt_flash.txt and colt_map.txt parsers."""
from pathlib import Path

import pytest

from rom_analyzer.parsers import parse_colt_flash, parse_colt_map


def test_parse_colt_flash_basic_entries(fixtures_dir):
    entries = list(parse_colt_flash(fixtures_dir / "tiny_colt_flash.txt"))
    by_name = {e.name: e for e in entries}
    assert "flash_password" in by_name
    assert by_name["flash_password"].address == 0x84
    assert by_name["flash_password"].size == 0x10
    assert by_name["flash_password"].is_function is False
    assert "flash_default_mut_enabled_flags" in by_name
    assert by_name["flash_default_mut_enabled_flags"].address == 0x200
    assert by_name["flash_default_mut_enabled_flags"].size == 1
    assert by_name["flash_default_mut_enabled_flags"].is_function is False
    assert "flash_fuel_map_rpm_axis" in by_name
    assert by_name["flash_fuel_map_rpm_axis"].address == 0xb2fa
    assert by_name["flash_fuel_map_rpm_axis"].size == 2
    assert by_name["flash_fuel_map_rpm_axis"].is_function is False


def test_parse_colt_flash_function_entries(fixtures_dir):
    entries = list(parse_colt_flash(fixtures_dir / "tiny_colt_flash.txt"))
    by_name = {e.name: e for e in entries}
    assert "rom_crc_check_step" in by_name
    assert by_name["rom_crc_check_step"].address == 0x1524c
    assert by_name["rom_crc_check_step"].size == 0xb0
    assert by_name["rom_crc_check_step"].is_function is True
    assert "adc_run" in by_name
    assert by_name["adc_run"].address == 0x1533c
    assert by_name["adc_run"].is_function is True


def test_parse_colt_flash_skips_unused_areas(fixtures_dir):
    entries = list(parse_colt_flash(fixtures_dir / "tiny_colt_flash.txt"))
    names = {e.name for e in entries}
    assert not any("Unused" in n for n in names)
    assert not any(n.startswith("/*") for n in names)


def test_parse_colt_map_basic_entries(fixtures_dir):
    entries = list(parse_colt_map(fixtures_dir / "tiny_colt_map.txt"))
    by_name = {e.name: e for e in entries}
    assert "eeprom.block" in by_name
    assert by_name["eeprom.block"].address == 0x804010
    assert by_name["eeprom.block"].fp_offset == -16368
    assert by_name["eeprom.block"].is_function is False
    assert "engine_rpm" in by_name
    assert by_name["engine_rpm"].address == 0x804e5c
    assert by_name["engine_rpm"].fp_offset == -7588
    assert "ram_start" in by_name
    assert by_name["ram_start"].address == 0x804000


def test_parse_colt_map_skips_comment_blocks(fixtures_dir):
    entries = list(parse_colt_map(fixtures_dir / "tiny_colt_map.txt"))
    assert len(entries) == 3


def test_parse_colt_map_strips_inline_comments(fixtures_dir):
    entries = list(parse_colt_map(fixtures_dir / "tiny_colt_map.txt"))
    by_name = {e.name: e for e in entries}
    assert by_name["eeprom.block"].name == "eeprom.block"


def test_parse_colt_flash_pointer_returning_function(tmp_path):
    content = "0x001000\t0x20\tvoid *foo_factory(int n);\n"
    p = tmp_path / "flash.txt"
    p.write_text(content)
    entries = list(parse_colt_flash(p))
    assert len(entries) == 1
    assert entries[0].name == "foo_factory"
    assert entries[0].is_function is True
