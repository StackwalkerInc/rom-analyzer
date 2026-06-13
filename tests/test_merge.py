from rom_analyzer.merge import (
    SOURCE_PRIORITY, CONFIDENCE_RANK, match_rank, merge_matches,
    arbitrate_symbols, Disagreement,
)
from rom_analyzer.types import MatchedFunction, PropagatedSymbol


def _m(name, new_addr, sim=1.0, source="vt_diff", ref="a"):
    return MatchedFunction(ref_name=name, ref_address=0x1000, new_address=new_addr,
                           similarity=sim, source=source, reference=ref)


def test_source_priority_known_tiers():
    assert SOURCE_PRIORITY["bytecode_identity"] > SOURCE_PRIORITY["vt_diff"]
    assert SOURCE_PRIORITY["vector_table"] > SOURCE_PRIORITY["callgraph_bfs"]


def test_match_rank_orders_by_source_then_similarity_then_priority():
    hi = _m("f", 0x20, sim=0.8, source="bytecode_identity", ref="a")
    lo = _m("f", 0x20, sim=0.99, source="vt_diff", ref="a")
    assert match_rank(hi, {}) > match_rank(lo, {})  # source tier dominates
    a = _m("f", 0x20, sim=0.9, source="vt_diff", ref="a")
    b = _m("f", 0x20, sim=0.9, source="vt_diff", ref="b")
    assert match_rank(b, {"a": 1, "b": 9}) > match_rank(a, {"a": 1, "b": 9})


def test_merge_matches_picks_best_per_new_address():
    r1 = [_m("f", 0x20, sim=0.7, source="vt_diff", ref="a")]
    r2 = [_m("g", 0x20, sim=0.95, source="bytecode_identity", ref="b")]
    merged = merge_matches([r1, r2], {"a": 0, "b": 0})
    assert len(merged) == 1
    assert merged[0].ref_name == "g"
    assert merged[0].reference == "b"


def test_merge_matches_keeps_distinct_addresses():
    merged = merge_matches([[_m("f", 0x20)], [_m("g", 0x30)]], {})
    assert {m.new_address for m in merged} == {0x20, 0x30}


def _s(name, new_addr, conf="high", ref="a", cat="function"):
    return PropagatedSymbol(name=name, ref_address=0x1, new_address=new_addr,
                            category=cat, confidence=conf, reference=ref)


def test_arbitrate_symbols_agreement_no_disagreement():
    syms = [_s("foo", 0x40, ref="a"), _s("foo", 0x40, ref="b")]
    final, disagreements = arbitrate_symbols(syms, {"a": 0, "b": 0})
    assert len(final) == 1
    assert final[0].name == "foo"
    assert disagreements == []


def test_arbitrate_symbols_disagreement_recorded_winner_by_confidence():
    syms = [_s("foo", 0x40, conf="low", ref="a"),
            _s("bar", 0x40, conf="high", ref="b")]
    final, disagreements = arbitrate_symbols(syms, {"a": 0, "b": 0})
    assert len(final) == 1
    assert final[0].name == "bar"
    assert len(disagreements) == 1
    d = disagreements[0]
    assert d.new_address == 0x40
    assert d.winner == "bar"
    assert ("a", "foo") in d.candidates and ("b", "bar") in d.candidates


def test_arbitrate_symbols_winner_by_priority_when_confidence_ties():
    syms = [_s("foo", 0x40, conf="high", ref="a"),
            _s("bar", 0x40, conf="high", ref="b")]
    final, _ = arbitrate_symbols(syms, {"a": 1, "b": 9})
    assert final[0].name == "bar"


def test_confidence_rank_orders_tiers():
    assert CONFIDENCE_RANK["high"] > CONFIDENCE_RANK["medium"] > CONFIDENCE_RANK["low"]
