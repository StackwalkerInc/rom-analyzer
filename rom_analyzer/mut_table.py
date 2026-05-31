"""Identify flash_mut_variables_table in a new ROM via get_mut_pointer data refs."""

import struct
from dataclasses import dataclass

from rom_analyzer.callgraph import find_mut_table_by_triplet
from rom_analyzer.data_refs import DataRefType
from rom_analyzer.ghidra import HeadlessRun
from rom_analyzer.types import MatchedFunction, PropagatedSymbol

_SIZE_ADDR_MAX = 0x20000          # scalars / config region ceiling
_RAM_PTR_LO = 0x00800000          # lowest valid M32R ECU RAM address
_RAM_PTR_HI = 0x00C00000          # upper bound (exclusive)
_SIZE_MIN = 50                    # smallest plausible MUT table size
_SIZE_MAX = 2000                  # largest plausible MUT table size


@dataclass(frozen=True)
class MutTableResult:
    table_address: int   # address of flash_mut_variables_table in the new ROM
    table_size: int      # N: number of void* entries
    size_address: int    # address of flash_mut_variables_table_size
    triplet_mismatch: bool = False  # True when byte-triplet scan disagrees


def find_mut_table_in_run(
    matches: list[MatchedFunction],
    new_run: HeadlessRun,
    rom_bytes: bytes,
) -> MutTableResult | None:
    """Locate flash_mut_variables_table by reading get_mut_pointer's data refs.

    Returns None if get_mut_pointer isn't in matches, data refs are missing,
    or the two flash refs can't be unambiguously classified.
    """
    gmp = next((m for m in matches if m.ref_name == "get_mut_pointer"), None)
    if gmp is None:
        return None

    read_refs = [
        r for r in new_run.data_refs.get(gmp.new_address, [])
        if r.ref_type == DataRefType.READ
    ]

    size_candidates: list[tuple] = []   # (DataRef, int size_value)
    table_candidates: list = []         # DataRef

    for r in read_refs:
        addr = r.referenced_address
        if addr < _SIZE_ADDR_MAX and addr + 2 <= len(rom_bytes):
            val = struct.unpack_from(">H", rom_bytes, addr)[0]
            if _SIZE_MIN <= val <= _SIZE_MAX:
                size_candidates.append((r, val))
        elif addr >= _SIZE_ADDR_MAX and addr + 4 <= len(rom_bytes):
            val = struct.unpack_from(">I", rom_bytes, addr)[0]
            if _RAM_PTR_LO <= val < _RAM_PTR_HI:
                table_candidates.append(r)

    if len(size_candidates) != 1 or len(table_candidates) != 1:
        return None

    size_ref, table_size = size_candidates[0]
    table_ref = table_candidates[0]

    triplet_addr = find_mut_table_by_triplet(rom_bytes)
    mismatch = triplet_addr is not None and triplet_addr != table_ref.referenced_address

    return MutTableResult(
        table_address=table_ref.referenced_address,
        table_size=table_size,
        size_address=size_ref.referenced_address,
        triplet_mismatch=mismatch,
    )


def mut_table_to_propagated_symbol(
    result: MutTableResult,
    ref_table_addr: int,
) -> PropagatedSymbol:
    """Wrap a MutTableResult as a PropagatedSymbol for emit_description_ld."""
    return PropagatedSymbol(
        name="flash_mut_variables_table",
        ref_address=ref_table_addr,
        new_address=result.table_address,
        category="data",
        confidence="high",
        source="mut_table_data_refs",
        score=1.0,
    )
