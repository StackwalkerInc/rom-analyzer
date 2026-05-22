from rom_analyzer.ram_space import find_free_ram_blocks
from rom_analyzer.types import RamFreeBlock

RAM_START = 0x804000
RAM_END = 0x820000


def test_finds_gaps_between_referenced_addresses():
    refs = {RAM_START + 0, RAM_START + 4, RAM_START + 32}
    blocks = find_free_ram_blocks(refs, min_length=4, large_gap_threshold=1024)

    by_start = {b.start: b for b in blocks}
    assert RamFreeBlock(start=RAM_START + 1, end=RAM_START + 4, length=3, note="") not in blocks  # below min_length
    assert any(b.start == RAM_START + 5 and b.end == RAM_START + 32 for b in blocks)


def test_marks_large_gaps_as_suspicious():
    # Only one reference at the start of RAM — huge gap
    refs = {RAM_START}
    blocks = find_free_ram_blocks(refs, min_length=4, large_gap_threshold=1024)

    large = [b for b in blocks if b.length >= 1024]
    assert all("suspicious_large_gap" in b.note for b in large)


def test_no_references_returns_one_giant_gap():
    blocks = find_free_ram_blocks(set(), min_length=4, large_gap_threshold=1024)
    assert len(blocks) == 1
    assert blocks[0].start == RAM_START
    assert blocks[0].end == RAM_END
    assert "suspicious_large_gap" in blocks[0].note
