from rom_analyzer.types import MatchedFunction, PropagatedSymbol


def test_matched_function_reference_defaults_empty():
    m = MatchedFunction(ref_name="f", ref_address=0x10, new_address=0x20, similarity=1.0)
    assert m.reference == ""


def test_matched_function_reference_settable():
    m = MatchedFunction(ref_name="f", ref_address=0x10, new_address=0x20,
                        similarity=1.0, reference="47110032")
    assert m.reference == "47110032"


def test_propagated_symbol_provenance_defaults():
    s = PropagatedSymbol(name="x", ref_address=0x1, new_address=0x2,
                         category="function", confidence="high")
    assert s.reference == ""
    assert s.family_match is True


def test_propagated_symbol_provenance_settable():
    s = PropagatedSymbol(name="x", ref_address=0x1, new_address=0x2,
                         category="data", confidence="low",
                         reference="35740031", family_match=False)
    assert s.reference == "35740031"
    assert s.family_match is False
