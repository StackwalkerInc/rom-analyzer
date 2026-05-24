"""Locate the rom_crc_check_step idiom and extract its [start, end) bounds.

We recognise two constant-load idioms:

1. SETH/ADD3 pair — 32-bit immediate:
       seth  Rx, #H
       add3  Rx, Rx, #L   (L is a *signed* 16-bit immediate)
   value = (H << 16) + sign_extend16(L)

2. LD24 — 24-bit zero-extended immediate:
       ld24  Rx, #imm24

Algorithm
---------
In rom_crc_check_step the CRC-region end bound appears via one of the above
patterns *twice* (once per branch of the full/partial mode flag test).  The
wrap-around start address for each mode is loaded once and stored to an
fp-slot via ST.

To extract the exclusive end we inspect the CMPU instruction that immediately
follows each bound load:
 • If the loaded register is the FIRST  operand of CMPU ("bound < ptr" check)
   the exclusive end is bound + 1.
 • If the loaded register is the SECOND operand of CMPU ("ptr < bound" check)
   the exclusive end equals the bound value directly.

Z27AG example:  bound = 0x80000, CMPU Rptr, Rbound → exclusive end = 0x80000
Outlander example: bound = 0x5ffff, CMPU Rbound, Rptr → exclusive end = 0x60000
"""

from collections import Counter
from dataclasses import dataclass

from rom_analyzer.types import CrcRegion


class CrcExtractionError(Exception):
    """Raised when the rom_crc_check_step idiom cannot be recognised."""


@dataclass(frozen=True)
class Instruction:
    mnemonic: str
    operands: tuple[str, ...]


def _parse_imm(operand: str) -> int:
    s = operand.lstrip("#").strip()
    return int(s, 0)


@dataclass(frozen=True)
class _ConstLoad:
    index: int    # instruction index of the load (SETH for pairs, LD24 for singles)
    value: int    # constructed 32-bit value
    reg: str      # destination register (lowercased, no spaces)
    width: int    # instructions consumed: 2 for SETH/ADD3, 1 for LD24


def _collect_constants(instrs: list[Instruction]) -> list[_ConstLoad]:
    """Find all immediate constant loads: SETH/ADD3 pairs and LD24."""
    result: list[_ConstLoad] = []
    i = 0
    while i < len(instrs):
        a = instrs[i]
        mnem = a.mnemonic.lower()

        # ── SETH + ADD3 pair ────────────────────────────────────────────────
        if (mnem == "seth" and
                i + 1 < len(instrs) and
                instrs[i + 1].mnemonic.lower() == "add3"):
            b = instrs[i + 1]
            if (len(a.operands) >= 2 and len(b.operands) >= 3 and
                    a.operands[0].lower() == b.operands[0].lower() == b.operands[1].lower()):
                try:
                    h = _parse_imm(a.operands[1])
                    l_raw = _parse_imm(b.operands[2])
                    # ADD3 immediate is sign-extended 16-bit; handle both
                    # "#-1" (Python -1) and "#0xffff" (Python 65535) representations.
                    l16 = l_raw & 0xFFFF
                    l_sext = l16 - 0x10000 if l16 >= 0x8000 else l16
                    value = (h << 16) + l_sext
                    result.append(_ConstLoad(i, value, a.operands[0].lower(), 2))
                    i += 2
                    continue
                except ValueError:
                    pass

        # ── LD24 ─────────────────────────────────────────────────────────────
        if mnem == "ld24" and len(a.operands) >= 2:
            try:
                value = _parse_imm(a.operands[1])
                result.append(_ConstLoad(i, value, a.operands[0].lower(), 1))
                i += 1
                continue
            except ValueError:
                # Operand rendered as a symbol name by Ghidra; skip.
                pass

        i += 1
    return result


def _find_exclusive_end(
    instrs: list[Instruction],
    loads: list[_ConstLoad],
    end_bound: int,
) -> int:
    """Determine the exclusive CRC end from the CMPU following the bound load.

    Searches up to 4 instructions after the first end-bound load.
    Falls back to end_bound itself (the Z27AG / "ptr < bound" convention)
    if no CMPU is found in the window.
    """
    for load in loads:
        if load.value != end_bound:
            continue
        start = load.index + load.width
        for j in range(start, min(start + 4, len(instrs))):
            mnem = instrs[j].mnemonic.lower()
            if mnem in ("cmpu", "cmp"):
                ops = instrs[j].operands
                if (len(ops) >= 2 and
                        ops[0].lower().replace(" ", "") == load.reg.replace(" ", "")):
                    # Bound register is FIRST operand: "bound < ptr" → exclusive end = bound + 1
                    return end_bound + 1
                # Bound register is second operand (or not found): "ptr < bound"
                return end_bound
        break  # inspect only the first occurrence of end_bound
    return end_bound  # safe default


def extract_crc_region(instrs: list[Instruction]) -> CrcRegion:
    """Extract CrcRegion from a flat instruction stream of rom_crc_check_step.

    Handles both Z27AG-style (SETH/ADD3, 0x80000 end) and Outlander-style
    (LD24, 0x5ffff comparison → 0x60000 exclusive end).

    Steps:
      1. Collect all constant loads (SETH/ADD3 pairs and LD24).
      2. End bound  = the unique value that appears at least twice.
      3. Exclusive end = inferred from CMPU operand order after the bound load.
      4. Start values = non-end-bound constants followed by an ST instruction.
    """
    loads = _collect_constants(instrs)
    if not loads:
        raise CrcExtractionError(
            "No immediate constant loads (seth/add3 or ld24) found in instruction stream"
        )

    counts = Counter(ld.value for ld in loads)
    repeated = [v for v, c in counts.items() if c >= 2]
    if not repeated:
        raise CrcExtractionError(
            f"No constant value appears ≥2 times (expected end bound in both branches); "
            f"values found: {[hex(v) for v in sorted(counts)]}"
        )

    end_bound = max(repeated)
    exclusive_end = _find_exclusive_end(instrs, loads, end_bound)

    starts: list[int] = []
    for load in loads:
        if load.value == end_bound:
            continue
        search_from = load.index + load.width
        for j in range(search_from, min(search_from + 4, len(instrs))):
            if instrs[j].mnemonic.lower() == "st":
                starts.append(load.value)
                break

    if len(starts) < 2:
        raise CrcExtractionError(
            f"Expected two wrap-around start constants stored to fp slot; "
            f"got {[hex(v) for v in starts]}. "
            f"Loads: {[(hex(ld.value), ld.index) for ld in loads]}"
        )

    full_start, partial_start = starts[0], starts[1]
    if full_start > partial_start:
        raise CrcExtractionError(
            f"Branch ordering sanity check failed: expected full_start "
            f"({full_start:#x}) <= partial_start ({partial_start:#x}); "
            f"Ghidra may have decoded branches in reverse order."
        )
    return CrcRegion(
        full_start=full_start, full_end=exclusive_end,
        partial_start=partial_start, partial_end=exclusive_end,
    )
