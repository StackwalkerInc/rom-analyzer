"""Pure Python tests for obd_analysis + obd_std_pids — no Ghidra, no ROM required."""

import struct

import pytest


# ---------------------------------------------------------------------------
# Helpers shared across tasks
# ---------------------------------------------------------------------------

def _bcd_encode(p_code: int) -> bytes:
    """Encode a decimal P-code integer (e.g. 100 → P0100) as big-endian BCD uint16."""
    d3 = (p_code // 1000) & 0xF
    d2 = (p_code // 100) % 10 & 0xF
    d1 = (p_code // 10) % 10 & 0xF
    d0 = p_code % 10 & 0xF
    return struct.pack(">H", (d3 << 12) | (d2 << 8) | (d1 << 4) | d0)


def _make_rom(patches: dict[int, bytes], size: int = 0x20000) -> bytes:
    rom = bytearray(size)
    for addr, data in patches.items():
        rom[addr: addr + len(data)] = data
    return bytes(rom)


# ---------------------------------------------------------------------------
# Task 1: STD_PIDS / STD_DTC_NAMES
# ---------------------------------------------------------------------------

class TestStdPids:
    def test_mode1_pid0c_is_engine_rpm(self):
        from rom_analyzer.obd_std_pids import STD_PIDS
        assert STD_PIDS[(1, 0x0C)] == "engine_rpm"

    def test_mode1_pid0d_is_vehicle_speed(self):
        from rom_analyzer.obd_std_pids import STD_PIDS
        assert STD_PIDS[(1, 0x0D)] == "vehicle_speed_kmh"

    def test_mode1_pid05_is_coolant_temp(self):
        from rom_analyzer.obd_std_pids import STD_PIDS
        assert STD_PIDS[(1, 0x05)] == "coolant_temp_c"

    def test_mode1_pid04_is_engine_load(self):
        from rom_analyzer.obd_std_pids import STD_PIDS
        assert STD_PIDS[(1, 0x04)] == "calculated_engine_load"

    def test_mode1_pid11_is_throttle(self):
        from rom_analyzer.obd_std_pids import STD_PIDS
        assert STD_PIDS[(1, 0x11)] == "throttle_position_pct"

    def test_unknown_mode_pid_missing(self):
        from rom_analyzer.obd_std_pids import STD_PIDS
        assert (0x18, 0x01) not in STD_PIDS  # OEM mode 18 not in J1979


class TestStdDtcNames:
    def test_p0100_is_maf(self):
        from rom_analyzer.obd_std_pids import STD_DTC_NAMES
        assert STD_DTC_NAMES[100] == "maf_circuit_malfunction"

    def test_p0300_is_random_misfire(self):
        from rom_analyzer.obd_std_pids import STD_DTC_NAMES
        assert STD_DTC_NAMES[300] == "random_multiple_cylinder_misfire"

    def test_p0301_is_cyl1_misfire(self):
        from rom_analyzer.obd_std_pids import STD_DTC_NAMES
        assert STD_DTC_NAMES[301] == "misfire_cylinder1"

    def test_p0420_is_catalyst(self):
        from rom_analyzer.obd_std_pids import STD_DTC_NAMES
        assert STD_DTC_NAMES[420] == "catalyst_efficiency_below_threshold_b1"

    def test_unknown_code_missing(self):
        from rom_analyzer.obd_std_pids import STD_DTC_NAMES
        assert 9999 not in STD_DTC_NAMES


# ---------------------------------------------------------------------------
# Task 2: parse_dtc_table + _bcd_to_int
# ---------------------------------------------------------------------------

class TestBcdToInt:
    def test_p0100(self):
        from rom_analyzer.obd_analysis import _bcd_to_int
        assert _bcd_to_int(0x0100) == 100

    def test_p0300(self):
        from rom_analyzer.obd_analysis import _bcd_to_int
        assert _bcd_to_int(0x0300) == 300

    def test_p1234(self):
        from rom_analyzer.obd_analysis import _bcd_to_int
        assert _bcd_to_int(0x1234) == 1234

    def test_zero(self):
        from rom_analyzer.obd_analysis import _bcd_to_int
        assert _bcd_to_int(0x0000) == 0


class TestParseDtcTable:
    TABLE_ADDR = 0x1000

    def test_single_entry_at_word0_bit0(self):
        from rom_analyzer.obd_analysis import parse_dtc_table
        rom = _make_rom({self.TABLE_ADDR: _bcd_encode(100)})
        entries = parse_dtc_table(rom, self.TABLE_ADDR)
        assert len(entries) == 1
        e = entries[0]
        assert e.word == 0
        assert e.bit == 0
        assert e.p_code == 100
        assert e.p_code_str == "P0100"

    def test_zero_entries_filtered(self):
        from rom_analyzer.obd_analysis import parse_dtc_table
        rom = _make_rom({})
        entries = parse_dtc_table(rom, self.TABLE_ADDR)
        assert entries == []

    def test_word_bit_index_mapping(self):
        # word=1, bit=2 → offset within table = (1*16 + 2) * 2 = 36 bytes
        from rom_analyzer.obd_analysis import parse_dtc_table
        offset = self.TABLE_ADDR + (1 * 16 + 2) * 2
        rom = _make_rom({offset: _bcd_encode(300)})
        entries = parse_dtc_table(rom, self.TABLE_ADDR)
        assert len(entries) == 1
        assert entries[0].word == 1
        assert entries[0].bit == 2
        assert entries[0].p_code == 300

    def test_std_name_known_code(self):
        from rom_analyzer.obd_analysis import parse_dtc_table
        rom = _make_rom({self.TABLE_ADDR: _bcd_encode(100)})
        entries = parse_dtc_table(rom, self.TABLE_ADDR)
        assert entries[0].std_name == "maf_circuit_malfunction"

    def test_std_name_unknown_code_is_none(self):
        from rom_analyzer.obd_analysis import parse_dtc_table
        rom = _make_rom({self.TABLE_ADDR: _bcd_encode(9999)})
        entries = parse_dtc_table(rom, self.TABLE_ADDR)
        assert entries[0].std_name is None

    def test_setters_initially_empty(self):
        from rom_analyzer.obd_analysis import parse_dtc_table
        rom = _make_rom({self.TABLE_ADDR: _bcd_encode(100)})
        entries = parse_dtc_table(rom, self.TABLE_ADDR)
        assert entries[0].setters == []

    def test_last_cell_word16_bit15(self):
        # word=16, bit=15 → offset = (16*16 + 15) * 2 = 542
        from rom_analyzer.obd_analysis import parse_dtc_table
        offset = self.TABLE_ADDR + (16 * 16 + 15) * 2
        rom = _make_rom({offset: _bcd_encode(200)})
        entries = parse_dtc_table(rom, self.TABLE_ADDR)
        assert len(entries) == 1
        assert entries[0].word == 16
        assert entries[0].bit == 15
