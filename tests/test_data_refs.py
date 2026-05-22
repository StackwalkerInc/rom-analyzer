from rom_analyzer.data_refs import DataRef, propagate_data_labels
from rom_analyzer.types import MatchedFunction, ReferenceSymbol


def _mk_ref(offset: int, addr: int, label: str | None) -> DataRef:
    return DataRef(instruction_offset=offset, referenced_address=addr, label=label)


def test_propagate_data_labels_exact_offset_match():
    ref_refs = {0x1000: [_mk_ref(0, 0xabcd, None), _mk_ref(8, 0x1234, "flash_x")]}
    new_refs = {0x2000: [_mk_ref(0, 0xabcd, None), _mk_ref(8, 0x5678, None)]}
    matches = [MatchedFunction("func", 0x1000, 0x2000, similarity=0.97)]
    ref_syms = {0x1234: ReferenceSymbol("flash_x", 0x1234, "data")}
    result = propagate_data_labels(ref_refs, new_refs, matches, ref_syms)
    assert len(result) == 1
    assert result[0].name == "flash_x"
    assert result[0].ref_address == 0x1234
    assert result[0].new_address == 0x5678
    assert result[0].confidence == "high"
    assert result[0].category == "data"


def test_propagate_data_labels_sliding_window():
    ref_refs = {0x1000: [_mk_ref(8, 0x1234, "flash_y")]}
    new_refs = {0x2000: [_mk_ref(12, 0x5678, None)]}
    matches = [MatchedFunction("func", 0x1000, 0x2000, similarity=0.80)]
    ref_syms = {0x1234: ReferenceSymbol("flash_y", 0x1234, "data")}
    result = propagate_data_labels(ref_refs, new_refs, matches, ref_syms, window_bytes=8)
    assert len(result) == 1
    assert result[0].name == "flash_y"
    assert result[0].new_address == 0x5678


def test_propagate_data_labels_skips_outside_window():
    ref_refs = {0x1000: [_mk_ref(8, 0x1234, "flash_z")]}
    new_refs = {0x2000: [_mk_ref(24, 0x5678, None)]}
    matches = [MatchedFunction("func", 0x1000, 0x2000, similarity=0.80)]
    ref_syms = {0x1234: ReferenceSymbol("flash_z", 0x1234, "data")}
    result = propagate_data_labels(ref_refs, new_refs, matches, ref_syms, window_bytes=8)
    assert result == []


def test_propagate_data_labels_skips_low_confidence():
    ref_refs = {0x1000: [_mk_ref(0, 0x1234, "flash_q")]}
    new_refs = {0x2000: [_mk_ref(0, 0x5678, None)]}
    matches = [MatchedFunction("func", 0x1000, 0x2000, similarity=0.50)]
    ref_syms = {0x1234: ReferenceSymbol("flash_q", 0x1234, "data")}
    result = propagate_data_labels(ref_refs, new_refs, matches, ref_syms)
    assert result == []


def test_propagate_data_labels_skips_ram_refs():
    ref_refs = {0x1000: [_mk_ref(0, 0x804e5c, "engine_rpm")]}
    new_refs = {0x2000: [_mk_ref(0, 0x804e5c, None)]}
    matches = [MatchedFunction("func", 0x1000, 0x2000, similarity=0.97)]
    ref_syms = {0x804e5c: ReferenceSymbol("engine_rpm", 0x804e5c, "ram_global")}
    result = propagate_data_labels(ref_refs, new_refs, matches, ref_syms)
    assert result == []


def test_propagate_data_labels_confidence_downgrade_on_conflict():
    ref_refs = {
        0x1000: [_mk_ref(0, 0x1234, "flash_m")],
        0x3000: [_mk_ref(0, 0x1234, "flash_m")],
    }
    new_refs = {
        0x2000: [_mk_ref(0, 0x5678, None)],
        0x4000: [_mk_ref(0, 0x9abc, None)],
    }
    matches = [
        MatchedFunction("f1", 0x1000, 0x2000, similarity=0.97),
        MatchedFunction("f2", 0x3000, 0x4000, similarity=0.97),
    ]
    ref_syms = {0x1234: ReferenceSymbol("flash_m", 0x1234, "data")}
    result = propagate_data_labels(ref_refs, new_refs, matches, ref_syms)
    assert len(result) == 1
    assert result[0].name == "flash_m"
    assert result[0].confidence == "low"
