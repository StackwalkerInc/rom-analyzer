from rom_analyzer.flash_space import find_free_blocks
from rom_analyzer.types import CrcRegion, FlashFreeBlock


def _build(rom_size: int = 0xC0000) -> bytearray:
    return bytearray(b"\x00" * rom_size)


def test_finds_aligned_ff_runs_meeting_min_length():
    rom = _build()
    rom[0x4f9a8:0x4fa00] = b"\xFF" * 88
    rom[0x100:0x140] = b"\xFF" * 64

    crc = CrcRegion(0x0, 0x80000, 0x10000, 0x80000)
    blocks = find_free_blocks(rom, crc, min_length=64, alignment=16)

    by_start = {b.start: b for b in blocks}
    assert FlashFreeBlock("unprotected", 0x4f9a8, 0x4fa00, 88) in blocks or (
        any(b.start <= 0x4f9a8 and b.end >= 0x4fa00 for b in blocks)
    )
    assert FlashFreeBlock("full_crc_only", 0x100, 0x140, 64) in blocks


def test_classifies_into_three_bands():
    rom = _build()
    rom[0x500:0x600] = b"\xFF" * 256
    rom[0x20000:0x20100] = b"\xFF" * 256
    rom[0x90000:0x90100] = b"\xFF" * 256

    crc = CrcRegion(0x0, 0x80000, 0x10000, 0x80000)
    blocks = find_free_blocks(rom, crc, min_length=64, alignment=16)

    bands = {b.band for b in blocks}
    assert bands == {"full_crc_only", "partial_crc", "unprotected"}


def test_drops_runs_below_min_length():
    rom = _build()
    rom[0x80100:0x80120] = b"\xFF" * 32

    crc = CrcRegion(0x0, 0x80000, 0x10000, 0x80000)
    blocks = find_free_blocks(rom, crc, min_length=64, alignment=16)

    assert blocks == []
