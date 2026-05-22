"""Locate the rom_crc_check_step idiom and extract its [start, end) bounds.

We recognize the M32R 32-bit immediate-load pair:
    seth  Rx, #H
    add3  Rx, Rx, #L
which constructs `Rx = (H << 16) | L`.

In rom_crc_check_step, two such pairs appear inside each branch of the
flash_rom_crc_check_full_flash test:
- one provides the end (0x80000 in both modes)
- one provides the wrap-around start (0x00000 for full, 0x10000 for partial)
"""

from dataclasses import dataclass

from rom_analyzer.types import CrcRegion


class CrcExtractionError(Exception):
    """Raised when the rom_crc_check_step idiom cannot be recognized."""


@dataclass(frozen=True)
class Instruction:
    mnemonic: str
    operands: tuple[str, ...]


def _parse_imm(operand: str) -> int:
    s = operand.lstrip("#").strip()
    return int(s, 0)


def _collect_imm_pairs(instrs: list[Instruction]) -> list[tuple[int, int]]:
    """Find consecutive (seth Rx,#H ; add3 Rx,Rx,#L) pairs.

    Returns list of (index_of_seth, constructed_value).
    """
    pairs: list[tuple[int, int]] = []
    for i in range(len(instrs) - 1):
        a, b = instrs[i], instrs[i + 1]
        if a.mnemonic != "seth" or b.mnemonic != "add3":
            continue
        if len(a.operands) < 2 or len(b.operands) < 3:
            continue
        if a.operands[0] != b.operands[0] or a.operands[0] != b.operands[1]:
            continue
        try:
            h = _parse_imm(a.operands[1])
            l = _parse_imm(b.operands[2])
        except ValueError:
            continue
        pairs.append((i, (h << 16) | l))
    return pairs


def extract_crc_region(instrs: list[Instruction]) -> CrcRegion:
    """Extract CrcRegion from a flat instruction stream of rom_crc_check_step.

    Algorithm: collect all (seth/add3) pair-constructed constants in order.
    The first appearance of 0x80000 is the shared end; the next two distinct
    constants stored via `st ...,@(...,fp)` are the wrap-around starts for
    full and partial modes. In rom_crc_check_step the full-flash branch
    appears first (flag-true / non-zero path of the byte flag), so the first
    wrap-around start is the full-mode start (0x00000) and the second is
    the partial-mode start (0x10000).

    Caveats:
    - "First st wins" — for each non-0x80000 pair, the very next `st`
      instruction in source order is assumed to be the fp-slot store for
      that constant. An unrelated spill `st` between the pair and the
      intended store would silently capture the wrong value. This holds
      for the Z27AG rom_crc_check_step but a future ROM with reordered
      compilation may need tighter recognition (e.g., filter to `st`
      ops with operand `@(-NNNN,fp)`).
    - Branch ordering assumption — Ghidra's default decoded order is
      expected to place the full-flash branch before the partial branch.
      See `extract_crc_region` for a runtime sanity check.
    """
    pairs = _collect_imm_pairs(instrs)
    end_values = [v for _, v in pairs if v == 0x80000]
    if len(end_values) < 2:
        raise CrcExtractionError(
            f"Expected at least two seth/add3 pairs constructing 0x80000; got {pairs}"
        )

    starts: list[int] = []
    for i, v in pairs:
        if v == 0x80000:
            continue
        for j in range(i + 2, len(instrs)):
            if instrs[j].mnemonic == "st":
                starts.append(v)
                break

    if len(starts) < 2:
        raise CrcExtractionError(
            f"Expected two wrap-around start constants stored to fp slot; got {starts}"
        )

    full_start, partial_start = starts[0], starts[1]
    if not (full_start < partial_start):
        raise CrcExtractionError(
            f"Branch ordering sanity check failed: expected full_start "
            f"({full_start:#x}) < partial_start ({partial_start:#x}); "
            f"Ghidra may have decoded branches in reverse order."
        )
    return CrcRegion(
        full_start=full_start, full_end=0x80000,
        partial_start=partial_start, partial_end=0x80000,
    )
