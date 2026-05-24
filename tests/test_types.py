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


def test_propagated_symbol_carries_source_and_score():
    s = PropagatedSymbol(
        name="adc_run", ref_address=0x1533c, new_address=0x15400,
        category="function", confidence="high",
        source="vt_diff", score=0.97,
    )
    assert s.source == "vt_diff"
    assert s.score == pytest.approx(0.97)


def test_propagated_symbol_source_defaults_to_empty():
    s = PropagatedSymbol(
        name="adc_run", ref_address=0x1533c, new_address=0x15400,
        category="function", confidence="high",
    )
    assert s.source == ""
    assert s.score == 0.0
