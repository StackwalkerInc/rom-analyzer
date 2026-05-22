import pytest

from rom_analyzer.crc import (
    CrcExtractionError,
    Instruction,
    extract_crc_region,
)
from rom_analyzer.types import CrcRegion


def _instr(mnem: str, *operands: str) -> Instruction:
    return Instruction(mnemonic=mnem, operands=tuple(operands))


def test_extract_crc_region_full_and_partial_modes():
    instrs = [
        _instr("seth", "r1", "#0x8"),
        _instr("add3", "r1", "r1", "#0"),
        _instr("cmpu", "r2", "r1"),
        _instr("bc", "LAB_END"),
        _instr("seth", "r2", "#0x0"),
        _instr("add3", "r2", "r2", "#0"),
        _instr("st", "r2", "@(-8360,fp)"),
        _instr("bra", "LAB_OUT"),
        _instr("seth", "r0", "#0x8"),
        _instr("add3", "r0", "r0", "#0"),
        _instr("cmpu", "r1", "r0"),
        _instr("bc", "LAB_END2"),
        _instr("seth", "r1", "#0x1"),
        _instr("add3", "r1", "r1", "#0"),
        _instr("st", "r1", "@(-8360,fp)"),
    ]

    region = extract_crc_region(instrs)

    assert region == CrcRegion(
        full_start=0x00000, full_end=0x80000,
        partial_start=0x10000, partial_end=0x80000,
    )


def test_extract_crc_region_raises_when_idiom_missing():
    instrs = [_instr("ldi", "r0", "#0")]
    with pytest.raises(CrcExtractionError):
        extract_crc_region(instrs)


def test_extract_crc_region_raises_on_swapped_branch_order():
    # Same shape as the working test but with the full/partial branches swapped.
    # Expected: CrcExtractionError because partial_start (0x00000)
    # would not be > full_start (0x10000).
    instrs = [
        _instr("seth", "r1", "#0x8"),
        _instr("add3", "r1", "r1", "#0"),
        _instr("cmpu", "r2", "r1"),
        _instr("bc", "LAB_END"),
        _instr("seth", "r2", "#0x1"),   # partial-mode start (0x10000) seen first
        _instr("add3", "r2", "r2", "#0"),
        _instr("st", "r2", "@(-8360,fp)"),
        _instr("bra", "LAB_OUT"),
        _instr("seth", "r0", "#0x8"),
        _instr("add3", "r0", "r0", "#0"),
        _instr("cmpu", "r1", "r0"),
        _instr("bc", "LAB_END2"),
        _instr("seth", "r1", "#0x0"),   # full-mode start (0x00000) seen second
        _instr("add3", "r1", "r1", "#0"),
        _instr("st", "r1", "@(-8360,fp)"),
    ]

    with pytest.raises(CrcExtractionError):
        extract_crc_region(instrs)
