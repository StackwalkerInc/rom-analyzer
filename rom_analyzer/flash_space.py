"""Scan flash for runs of unprogrammed bytes and classify by CRC band."""

from rom_analyzer.types import CrcBand, CrcRegion, FlashFreeBlock


def find_free_blocks(
    rom: bytes,
    crc: CrcRegion,
    min_length: int = 64,
    alignment: int = 16,
    pad_value: int = 0xFF,
) -> list[FlashFreeBlock]:
    """Find aligned runs of `pad_value` of length >= min_length.

    Returns blocks classified into three CRC-coverage bands:
        partial_crc:    [crc.partial_start, crc.partial_end)
        full_crc_only:  [crc.full_start, crc.partial_start)
        unprotected:    everything outside [crc.full_start, crc.full_end)
    """
    blocks: list[FlashFreeBlock] = []
    i = 0
    n = len(rom)
    while i < n:
        if rom[i] != pad_value:
            i += 1
            continue
        run_start = i
        while i < n and rom[i] == pad_value:
            i += 1
        run_end = i

        aligned_end = run_end & ~(alignment - 1)
        if aligned_end - run_start < min_length:
            continue

        band = _classify(run_start, crc)
        blocks.append(
            FlashFreeBlock(
                band=band,
                start=run_start,
                end=aligned_end,
                length=aligned_end - run_start,
            )
        )

    return blocks


def _classify(start: int, crc: CrcRegion) -> CrcBand:
    if crc.partial_start <= start < crc.partial_end:
        return "partial_crc"
    if crc.full_start <= start < crc.partial_start:
        return "full_crc_only"
    return "unprotected"
