"""OBD PID + DTC analysis — dataclasses, Phase 1 DTC decode, Phase 2+3 orchestration."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from rom_analyzer.obd_std_pids import STD_DTC_NAMES, STD_PIDS

if TYPE_CHECKING:
    pass


@dataclass
class OBDPidEntry:
    mode: int
    pid: int
    ram_addr: int
    ram_size: int
    std_name: str | None
    confidence: str
    source: str = "obd_pid_trace"


@dataclass
class DTCSetterInfo:
    call_site_addr: int
    caller_addr: int
    caller_name: str | None
    is_set: bool


@dataclass
class DTCEntry:
    word: int
    bit: int
    p_code: int
    p_code_str: str
    std_name: str | None
    setters: list[DTCSetterInfo] = field(default_factory=list)


@dataclass
class OBDAnalysis:
    pid_entries: list[OBDPidEntry]
    dtc_entries: list[DTCEntry]


def _bcd_to_int(raw: int) -> int:
    """Decode a 4-digit BCD-encoded uint16 to a decimal integer (e.g. 0x0100 → 100)."""
    return (
        ((raw >> 12) & 0xF) * 1000
        + ((raw >> 8) & 0xF) * 100
        + ((raw >> 4) & 0xF) * 10
        + (raw & 0xF)
    )


def _mask_to_bit(mask: int) -> int | None:
    """Return the bit position of a single-bit mask, or None if mask is not a power of 2."""
    if mask <= 0 or (mask & (mask - 1)) != 0:
        return None
    return mask.bit_length() - 1


def parse_dtc_table(rom_bytes: bytes, table_addr: int) -> list[DTCEntry]:
    """Parse flash_trouble_code_table[17][16] from ROM bytes.

    Each cell is a big-endian uint16 BCD-encoded P-code.
    Zero cells are unused and filtered out.
    """
    entries = []
    for word in range(17):
        for bit in range(16):
            offset = table_addr + (word * 16 + bit) * 2
            if offset + 2 > len(rom_bytes):
                break
            (raw,) = struct.unpack_from(">H", rom_bytes, offset)
            if raw == 0:
                continue
            p_code = _bcd_to_int(raw)
            entries.append(DTCEntry(
                word=word,
                bit=bit,
                p_code=p_code,
                p_code_str=f"P{p_code:04d}",
                std_name=STD_DTC_NAMES.get(p_code),
            ))
    return entries


def run_obd_analysis(
    project,
    prog_name: str,
    rom_bytes: bytes,
    dtc_table_addr: int,
    handler_entries: list[tuple[int, int]],
    set_addr: int | None,
    reset_addr: int | None,
) -> OBDAnalysis:
    """Orchestrate all three OBD analysis phases and return an OBDAnalysis result.

    handler_entries: list of (mode_byte, function_entry_address) for PID dispatchers.
    set_addr / reset_addr: resolved addresses of probably_set_dtc / probably_reset_dtc.
    """
    from rom_analyzer.ghidra import fetch_dtc_call_sites, fetch_pid_dispatch_entries

    # Phase 1: parse DTC table from ROM bytes (pure Python)
    dtc_entries = parse_dtc_table(rom_bytes, dtc_table_addr)

    # Phase 2: trace PID handler entry points via Ghidra instruction walk
    pid_raw = fetch_pid_dispatch_entries(project, prog_name, handler_entries)
    pid_entries = [
        OBDPidEntry(
            mode=r["mode"],
            pid=r["pid"],
            ram_addr=r["ram_addr"],
            ram_size=r["ram_size"],
            confidence=r["confidence"],
            std_name=STD_PIDS.get((r["mode"], r["pid"])),
        )
        for r in pid_raw
    ]

    # Phase 3: enumerate DTC setter/resetter call sites via Ghidra xref
    if set_addr is not None or reset_addr is not None:
        call_sites = fetch_dtc_call_sites(
            project, prog_name,
            set_addr or 0,
            reset_addr or 0,
        )
        dtc_by_key: dict[tuple[int, int], DTCEntry] = {
            (e.word, e.bit): e for e in dtc_entries
        }
        for cs in call_sites:
            mask = cs.get("mask")
            idx = cs.get("idx")
            if mask is None or idx is None:
                continue
            bit = _mask_to_bit(mask)
            if bit is None:
                continue
            entry = dtc_by_key.get((idx, bit))
            if entry is None:
                continue
            entry.setters.append(DTCSetterInfo(
                call_site_addr=cs["call_site"],
                caller_addr=cs["caller_addr"],
                caller_name=cs.get("caller_name"),
                is_set=cs["is_set"],
            ))

    return OBDAnalysis(pid_entries=pid_entries, dtc_entries=dtc_entries)
