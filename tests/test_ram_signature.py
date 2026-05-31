import pytest

from rom_analyzer.data_refs import DataRef, DataRefType
from rom_analyzer.ram_signature import build_ram_signatures, match_by_ram_signature
from rom_analyzer.types import MatchedFunction, ReferenceSymbol


def _ref(offset: int, addr: int) -> DataRef:
    return DataRef(instruction_offset=offset, referenced_address=addr,
                   ref_type=DataRefType.READ)


def _match(ref_addr: int, new_addr: int, sim: float = 0.97) -> MatchedFunction:
    return MatchedFunction("f", ref_addr, new_addr, sim, "vt_diff")


def _sym(name: str, addr: int) -> ReferenceSymbol:
    return ReferenceSymbol(name, addr, "ram_global")


# --- build_ram_signatures ---

def test_build_signatures_basic():
    refs = {
        0x1000: [_ref(0, 0x804010), _ref(4, 0x804020), _ref(8, 0x804030)],
        0x2000: [_ref(0, 0x804040), _ref(4, 0x804050)],
    }
    label_map = {
        0x804010: "rpm", 0x804020: "load", 0x804030: "tps",
        0x804040: "iat", 0x804050: "ect",
    }
    result = build_ram_signatures(refs, label_map)
    assert result[0x1000] == frozenset({"rpm", "load", "tps"})
    assert result[0x2000] == frozenset({"iat", "ect"})


def test_build_signatures_unlabeled_excluded():
    refs = {0x1000: [_ref(0, 0x804010), _ref(4, 0x804099)]}
    label_map = {0x804010: "rpm"}  # 0x804099 absent
    result = build_ram_signatures(refs, label_map)
    assert result[0x1000] == frozenset({"rpm"})


def test_build_signatures_empty_no_entry():
    refs = {0x1000: [_ref(0, 0x804099)]}
    label_map = {}  # nothing resolvable
    result = build_ram_signatures(refs, label_map)
    assert 0x1000 not in result


# --- match_by_ram_signature ---

def test_match_clean():
    ref_sigs = {0x1000: frozenset({"rpm", "load", "tps", "duty"})}
    new_sigs = {0x5000: frozenset({"rpm", "load", "tps", "duty"})}
    result = match_by_ram_signature(ref_sigs, new_sigs, [], {0x1000: _sym("calc", 0x1000)})
    assert len(result) == 1
    assert result[0].ref_address == 0x1000
    assert result[0].new_address == 0x5000
    assert result[0].source == "ram_signature"
    assert result[0].similarity == pytest.approx(1.0)
    assert result[0].ref_name == "calc"


def test_match_below_jaccard():
    # shared=3, union=7 → Jaccard≈0.43, below default 0.6
    ref_sigs = {0x1000: frozenset({"rpm", "load", "tps", "duty", "ect", "iat", "baro"})}
    new_sigs = {0x5000: frozenset({"rpm", "load", "tps"})}
    result = match_by_ram_signature(ref_sigs, new_sigs, [], {})
    assert result == []


def test_match_below_min_shared():
    # Jaccard=1.0 but only 2 names → below min_shared=3
    ref_sigs = {0x1000: frozenset({"rpm", "load"})}
    new_sigs = {0x5000: frozenset({"rpm", "load"})}
    result = match_by_ram_signature(ref_sigs, new_sigs, [], {})
    assert result == []


def test_match_already_matched_ref_skipped():
    ref_sigs = {0x1000: frozenset({"rpm", "load", "tps", "duty"})}
    new_sigs = {0x5000: frozenset({"rpm", "load", "tps", "duty"})}
    existing = [_match(0x1000, 0x9000)]  # ref 0x1000 already matched
    result = match_by_ram_signature(ref_sigs, new_sigs, existing, {})
    assert result == []


def test_match_already_matched_new_skipped():
    ref_sigs = {0x1000: frozenset({"rpm", "load", "tps", "duty"})}
    new_sigs = {0x5000: frozenset({"rpm", "load", "tps", "duty"})}
    existing = [_match(0x9999, 0x5000)]  # new 0x5000 already matched
    result = match_by_ram_signature(ref_sigs, new_sigs, existing, {})
    assert result == []


def test_match_ambiguous_ref_side():
    # one ref func ties against two new funcs at the same Jaccard → no match
    sig = frozenset({"rpm", "load", "tps", "duty"})
    ref_sigs = {0x1000: sig}
    new_sigs = {0x5000: sig, 0x6000: sig}
    result = match_by_ram_signature(ref_sigs, new_sigs, [], {0x1000: _sym("calc", 0x1000)})
    assert result == []


def test_match_ambiguous_new_side():
    # two ref funcs both match one new func at the same Jaccard → no match
    sig = frozenset({"rpm", "load", "tps", "duty"})
    ref_sigs = {0x1000: sig, 0x2000: sig}
    new_sigs = {0x5000: sig}
    result = match_by_ram_signature(
        ref_sigs, new_sigs, [],
        {0x1000: _sym("calc_a", 0x1000), 0x2000: _sym("calc_b", 0x2000)},
    )
    assert result == []
