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


def test_extract_crc_region_outlander_60000_bound():
    """Outlander ROM: seth #6 + add3 #0 builds 0x60000; cmpu has ptr first, bound second.

    Matches actual disassembly at e900-e91c:
      seth r1,#0x6  /  add3 r1,r1,#0   → bound = 0x60000
      ld   r2,@(-8056,fp)               → load ptr
      cmpu r2,r1  → bc                 → carry if ptr < 0x60000
      seth r2,#0x0 / add3 r2,r2,#0 / st → reset ptr to start
    """
    instrs = [
        # Branch 1: flag == '\0', wraps to start at 0x0
        _instr("SETH", "R1", "#0x6"),
        _instr("ADD3", "R1", "R1", "#0"),       # R1 = 0x60000
        _instr("LD",   "R2", "@(-8056,fp)"),    # R2 = current ptr
        _instr("CMPU", "R2", "R1"),              # ptr < bound → bc continue; bound is SECOND
        _instr("BC",   "0xe944"),
        _instr("LDI",  "R8", "#1"),
        _instr("NOP"),
        _instr("SETH", "R2", "#0x0"),
        _instr("ADD3", "R2", "R2", "#0"),        # start = 0x0
        _instr("ST",   "R2", "@(-8056,fp)"),
        # Branch 2: flag != '\0', wraps to start at 0x200
        _instr("SETH", "R1", "#0x6"),
        _instr("ADD3", "R1", "R1", "#0"),
        _instr("LD",   "R2", "@(-8056,fp)"),
        _instr("CMPU", "R2", "R1"),
        _instr("BC",   "0xe960"),
        _instr("LDI",  "R8", "#1"),
        _instr("SETH", "R2", "#0x0"),
        _instr("ADD3", "R2", "R2", "#0x200"),    # start = 0x200
        _instr("ST",   "R2", "@(-8056,fp)"),
    ]
    region = extract_crc_region(instrs)
    assert region == CrcRegion(
        full_start=0x0, full_end=0x60000,
        partial_start=0x200, partial_end=0x60000,
    )


def test_extract_crc_region_seth_add3_negative_l():
    """SETH #6 + ADD3 #0xffff produces 0x5ffff (sign-extended l), not 0x6ffff."""
    instrs = [
        # Branch 1: SETH/ADD3 for 0x5ffff with l=0xffff (sign-extended = -1)
        _instr("seth", "r1", "#0x6"),
        _instr("add3", "r1", "r1", "#0xffff"),  # l_sext = -1 → 0x60000 - 1 = 0x5ffff
        _instr("ld",   "r2", "@(r13,-8)"),
        _instr("cmpu", "r1", "r2"),              # R1 first → exclusive_end = 0x5ffff+1
        _instr("bnc",  "SKIP1"),
        _instr("seth", "r3", "#0x0"),
        _instr("add3", "r3", "r3", "#0x0"),      # start = 0x0
        _instr("st",   "r3", "@(r13,-8)"),
        # Branch 2
        _instr("seth", "r4", "#0x6"),
        _instr("add3", "r4", "r4", "#0xffff"),
        _instr("ld",   "r5", "@(r13,-8)"),
        _instr("cmpu", "r4", "r5"),
        _instr("bnc",  "SKIP2"),
        _instr("seth", "r6", "#0x0"),
        _instr("add3", "r6", "r6", "#0x200"),    # start = 0x200
        _instr("st",   "r6", "@(r13,-8)"),
    ]
    region = extract_crc_region(instrs)
    assert region == CrcRegion(
        full_start=0x0, full_end=0x60000,
        partial_start=0x200, partial_end=0x60000,
    )


def test_extract_crc_region_uppercase_mnemonics():
    """Ghidra returns uppercase mnemonics (SETH, ADD3, ST); extraction must work case-insensitively."""
    instrs = [
        _instr("SETH", "R4", "0x8"),
        _instr("ADD3", "R4", "R4", "0x0"),
        _instr("CMPU", "R2", "R4"),
        _instr("BC", "LAB_END"),
        _instr("SETH", "R5", "0x0"),
        _instr("ADD3", "R5", "R5", "0x0"),
        _instr("ST", "R5", "@(-8360,fp)"),
        _instr("BRA", "LAB_OUT"),
        _instr("SETH", "R0", "0x8"),
        _instr("ADD3", "R0", "R0", "0x0"),
        _instr("CMPU", "R1", "R0"),
        _instr("BC", "LAB_END2"),
        _instr("SETH", "R1", "0x1"),
        _instr("ADD3", "R1", "R1", "0x0"),
        _instr("ST", "R1", "@(-8360,fp)"),
    ]

    region = extract_crc_region(instrs)

    assert region == CrcRegion(
        full_start=0x00000, full_end=0x80000,
        partial_start=0x10000, partial_end=0x80000,
    )
