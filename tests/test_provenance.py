from rom_analyzer.propagate import apply_reference_provenance
from rom_analyzer.types import PropagatedSymbol


def _s(cat, conf="high"):
    return PropagatedSymbol(name="x", ref_address=0x1, new_address=0x2,
                            category=cat, confidence=conf)


def test_same_family_stamps_reference_keeps_confidence():
    out = apply_reference_provenance([_s("data", "high")],
                                     reference="33520003", family_match=True)
    assert out[0].reference == "33520003"
    assert out[0].family_match is True
    assert out[0].confidence == "high"


def test_cross_family_downgrades_data_and_ram():
    out = apply_reference_provenance(
        [_s("data", "high"), _s("ram_global", "medium")],
        reference="47110032", family_match=False,
    )
    assert all(s.confidence == "low" for s in out)
    assert all(s.family_match is False for s in out)
    assert all(s.reference == "47110032" for s in out)


def test_cross_family_leaves_functions_untouched():
    out = apply_reference_provenance([_s("function", "high")],
                                     reference="47110032", family_match=False)
    assert out[0].confidence == "high"      # functions are cross-family safe
    assert out[0].family_match is True      # not a cross-family-risky label
    assert out[0].reference == "47110032"
