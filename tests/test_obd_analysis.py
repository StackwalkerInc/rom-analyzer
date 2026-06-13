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
