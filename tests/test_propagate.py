from rom_analyzer.propagate import propagate_function_labels, tier_for_score
from rom_analyzer.types import MatchedFunction, PropagatedSymbol, ReferenceSymbol


def test_tier_for_score():
    assert tier_for_score(0.99) == "high"
    assert tier_for_score(0.80) == "medium"
    assert tier_for_score(0.50) == "low"


def test_propagate_function_labels_only_emits_for_function_symbols():
    ref_symbols = [
        ReferenceSymbol("adc_run", 0x1533c, "function"),
        ReferenceSymbol("flash_fuel_map_rpm_axis", 0xb2fa, "data"),
        ReferenceSymbol("engine_rpm", 0x804e5c, "ram_global"),
    ]
    matches = [
        MatchedFunction(ref_name="adc_run", ref_address=0x1533c,
                        new_address=0x15400, similarity=0.97),
    ]

    propagated = propagate_function_labels(ref_symbols, matches)

    assert propagated == [
        PropagatedSymbol(
            name="adc_run", ref_address=0x1533c, new_address=0x15400,
            category="function", confidence="high",
        )
    ]


def test_propagate_function_labels_drops_low_confidence_without_force():
    ref_symbols = [ReferenceSymbol("foo", 0x1000, "function")]
    matches = [MatchedFunction("foo", 0x1000, 0x1100, similarity=0.55)]
    assert propagate_function_labels(ref_symbols, matches) == []


def test_propagate_function_labels_includes_low_confidence_when_forced():
    ref_symbols = [ReferenceSymbol("foo", 0x1000, "function")]
    matches = [MatchedFunction("foo", 0x1000, 0x1100, similarity=0.55)]
    out = propagate_function_labels(ref_symbols, matches, force=True)
    assert len(out) == 1
    assert out[0].confidence == "low"
