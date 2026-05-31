"""Unit tests for mut_table.py — no Ghidra required."""

import struct
from unittest.mock import patch

import pytest

from rom_analyzer.data_refs import DataRef, DataRefType
from rom_analyzer.ghidra import HeadlessRun
from rom_analyzer.mut_table import (
    MutTableResult,
    find_mut_table_in_run,
    mut_table_to_propagated_symbol,
)
from rom_analyzer.types import MatchedFunction


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rom(patches: dict[int, bytes], size: int = 0x80000) -> bytes:
    """Return a zero-filled ROM with specific bytes patched at given addresses."""
    rom = bytearray(size)
    for addr, data in patches.items():
        rom[addr : addr + len(data)] = data
    return bytes(rom)


def _make_run(func_entry: int, refs: list[DataRef]) -> HeadlessRun:
    return HeadlessRun(
        functions=[{"name": "get_mut_pointer", "entry": hex(func_entry)}],
        symbols=[],
        ram_refs=[],
        rom_crc_check_step=None,
        data_refs={func_entry: refs},
        callees={},
    )


def _make_match(ref_addr: int, new_addr: int) -> MatchedFunction:
    return MatchedFunction(
        ref_name="get_mut_pointer",
        ref_address=ref_addr,
        new_address=new_addr,
        similarity=1.0,
        source="mut_table",
    )


# Known Z27AG addresses / values used across tests.
SIZE_ADDR = 0x0130AC   # address of flash_mut_variables_table_size
TABLE_ADDR = 0x03B4F4  # address of flash_mut_variables_table[0]
TABLE_SIZE = 476
RAM_PTR = 0x00804E00   # first void* entry in the table (a RAM address)
FUNC_ENTRY = 0x011844  # get_mut_pointer entry in Z27AG


# ---------------------------------------------------------------------------
# Nominal case
# ---------------------------------------------------------------------------

def test_find_mut_table_nominal():
    """Two READ refs — one size, one table base — resolved correctly."""
    rom = _make_rom({
        SIZE_ADDR: struct.pack(">H", TABLE_SIZE),
        TABLE_ADDR: struct.pack(">I", RAM_PTR),
    })
    refs = [
        DataRef(instruction_offset=0, referenced_address=SIZE_ADDR, ref_type=DataRefType.READ),
        DataRef(instruction_offset=4, referenced_address=TABLE_ADDR, ref_type=DataRefType.READ),
    ]
    run = _make_run(FUNC_ENTRY, refs)
    matches = [_make_match(FUNC_ENTRY, FUNC_ENTRY)]

    # Patch triplet scan so it agrees, keeping it out of the test scope.
    with patch("rom_analyzer.mut_table.find_mut_table_by_triplet", return_value=TABLE_ADDR):
        result = find_mut_table_in_run(matches, run, rom)

    assert result == MutTableResult(
        table_address=TABLE_ADDR,
        table_size=TABLE_SIZE,
        size_address=SIZE_ADDR,
        triplet_mismatch=False,
    )


# ---------------------------------------------------------------------------
# Failure: get_mut_pointer not in matches
# ---------------------------------------------------------------------------

def test_find_mut_table_no_get_mut_pointer_match():
    """`get_mut_pointer` absent from matches → None."""
    rom = _make_rom({})
    run = _make_run(FUNC_ENTRY, [])
    matches = [MatchedFunction("other_func", 0x1000, 0x1000, 1.0, "vt_diff")]

    assert find_mut_table_in_run(matches, run, rom) is None


# ---------------------------------------------------------------------------
# Failure: all refs are SCALAR
# ---------------------------------------------------------------------------

def test_find_mut_table_only_scalar_refs():
    """SCALAR refs are filtered; no READ refs remaining → None."""
    rom = _make_rom({
        SIZE_ADDR: struct.pack(">H", TABLE_SIZE),
        TABLE_ADDR: struct.pack(">I", RAM_PTR),
    })
    refs = [
        DataRef(instruction_offset=0, referenced_address=SIZE_ADDR, ref_type=DataRefType.SCALAR),
        DataRef(instruction_offset=4, referenced_address=TABLE_ADDR, ref_type=DataRefType.SCALAR),
    ]
    run = _make_run(FUNC_ENTRY, refs)
    matches = [_make_match(FUNC_ENTRY, FUNC_ENTRY)]

    assert find_mut_table_in_run(matches, run, rom) is None


# ---------------------------------------------------------------------------
# Failure: ambiguous — both READ refs ≥ 0x20000 (can't identify size ref)
# ---------------------------------------------------------------------------

def test_find_mut_table_ambiguous_refs():
    """Both READ refs in the table region; discrimination fails → None."""
    TABLE_A = 0x030000
    TABLE_B = 0x040000
    rom = _make_rom({
        TABLE_A: struct.pack(">I", RAM_PTR),
        TABLE_B: struct.pack(">I", RAM_PTR),
    })
    refs = [
        DataRef(instruction_offset=0, referenced_address=TABLE_A, ref_type=DataRefType.READ),
        DataRef(instruction_offset=4, referenced_address=TABLE_B, ref_type=DataRefType.READ),
    ]
    run = _make_run(FUNC_ENTRY, refs)
    matches = [_make_match(FUNC_ENTRY, FUNC_ENTRY)]

    assert find_mut_table_in_run(matches, run, rom) is None


# ---------------------------------------------------------------------------
# Soft cross-validation mismatch: result returned but triplet_mismatch=True
# ---------------------------------------------------------------------------

def test_find_mut_table_triplet_mismatch_sets_flag():
    """Triplet scan disagrees with data-ref result → result returned with triplet_mismatch=True."""
    DIFFERENT_ADDR = 0x03C000
    rom = _make_rom({
        SIZE_ADDR: struct.pack(">H", TABLE_SIZE),
        TABLE_ADDR: struct.pack(">I", RAM_PTR),
    })
    refs = [
        DataRef(instruction_offset=0, referenced_address=SIZE_ADDR, ref_type=DataRefType.READ),
        DataRef(instruction_offset=4, referenced_address=TABLE_ADDR, ref_type=DataRefType.READ),
    ]
    run = _make_run(FUNC_ENTRY, refs)
    matches = [_make_match(FUNC_ENTRY, FUNC_ENTRY)]

    with patch("rom_analyzer.mut_table.find_mut_table_by_triplet", return_value=DIFFERENT_ADDR):
        result = find_mut_table_in_run(matches, run, rom)

    assert result is not None
    assert result.table_address == TABLE_ADDR
    assert result.table_size == TABLE_SIZE
    assert result.triplet_mismatch is True


# ---------------------------------------------------------------------------
# mut_table_to_propagated_symbol
# ---------------------------------------------------------------------------

def test_mut_table_to_propagated_symbol():
    result = MutTableResult(
        table_address=TABLE_ADDR,
        table_size=TABLE_SIZE,
        size_address=SIZE_ADDR,
    )
    sym = mut_table_to_propagated_symbol(result, ref_table_addr=0x03B4F4)
    assert sym.name == "flash_mut_variables_table"
    assert sym.new_address == TABLE_ADDR
    assert sym.category == "data"
    assert sym.confidence == "high"
    assert sym.source == "mut_table_data_refs"
