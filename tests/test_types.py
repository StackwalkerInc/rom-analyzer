import pytest

from rom_analyzer.types import (
    ConfidenceTier,
    CrcBand,
    CrcRegion,
    FlashFreeBlock,
    MatchedFunction,
    PropagatedSymbol,
    RamFreeBlock,
    ReferenceSymbol,
    SymbolCategory,
)


def test_reference_symbol_is_frozen():
    s = ReferenceSymbol(name="adc_run", address=0x1533c, category="function")
    with pytest.raises(Exception):
        s.address = 0  # type: ignore[misc]


def test_crc_region_holds_full_and_partial_bounds():
    r = CrcRegion(full_start=0, full_end=0x80000,
                  partial_start=0x10000, partial_end=0x80000)
    assert r.full_end - r.full_start == 0x80000
    assert r.partial_end - r.partial_start == 0x70000


def test_flash_free_block_length_matches_endpoints():
    b = FlashFreeBlock(band="unprotected", start=0x80000, end=0x80040, length=64)
    assert b.length == b.end - b.start
