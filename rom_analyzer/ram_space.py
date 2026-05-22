"""Find free RAM gaps from the set of referenced RAM addresses."""

from rom_analyzer.types import RamFreeBlock

RAM_START = 0x804000
RAM_END = 0x820000


def find_free_ram_blocks(
    referenced: set[int],
    min_length: int = 4,
    large_gap_threshold: int = 1024,
) -> list[RamFreeBlock]:
    """Return contiguous unreferenced gaps in [RAM_START, RAM_END).

    Gaps >= large_gap_threshold are flagged with a note hinting at
    stack/DMA regions. Returned list is sorted by start.
    """
    in_range = sorted(a for a in referenced if RAM_START <= a < RAM_END)
    boundary_starts = [RAM_START] + [a + 1 for a in in_range]
    boundary_ends = in_range + [RAM_END]

    blocks: list[RamFreeBlock] = []
    for gs, ge in zip(boundary_starts, boundary_ends):
        if ge - gs < min_length:
            continue
        note = (
            f"suspicious_large_gap — possible stack/DMA region, verify"
            if ge - gs >= large_gap_threshold
            else ""
        )
        blocks.append(RamFreeBlock(start=gs, end=ge, length=ge - gs, note=note))
    return blocks
