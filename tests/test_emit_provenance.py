from rom_analyzer.emit_ld import emit_description_ld, emit_reference_conflicts_md
from rom_analyzer.merge import Disagreement
from rom_analyzer.types import PropagatedSymbol


def _s(name, addr, cat="function", ref="", fam=True, conf="high"):
    return PropagatedSymbol(name=name, ref_address=0x1, new_address=addr,
                            category=cat, confidence=conf, reference=ref,
                            family_match=fam)


def test_description_ld_default_has_no_provenance_comment():
    out = emit_description_ld([_s("foo", 0x100, ref="33520003")],
                              source_rom="r.bin", reference_name="33520003",
                              variant="m32r:2:fp8000", match_summary="1/1")
    assert "foo = 0x100;\n" in out
    assert "/* from" not in out  # backward-compatible default


def test_description_ld_show_provenance_adds_origin_comment():
    out = emit_description_ld([_s("foo", 0x100, ref="47110032")],
                              source_rom="r.bin", reference_name="multi",
                              variant="m32r:2:fp8000", match_summary="1/1",
                              show_provenance=True)
    assert "foo = 0x100;  /* from 47110032 */" in out


def test_description_ld_cross_family_data_gets_verify_comment():
    out = emit_description_ld(
        [_s("cvt_map", 0x4a2c0, cat="data", ref="35740031", fam=False, conf="low")],
        source_rom="r.bin", reference_name="multi", variant="m32r:2:fp8000",
        match_summary="1/1", show_provenance=True)
    assert "/* VERIFY: cross-family from 35740031 */" in out


def test_conflicts_md_empty_sections():
    md = emit_reference_conflicts_md([], [])
    assert "## Disagreements" in md
    assert "## Cross-family VERIFY" in md
    assert md.count("_None._") == 2


def test_conflicts_md_lists_disagreement_and_cross_family():
    dis = [Disagreement(new_address=0x40, candidates=[("a", "foo"), ("b", "bar")],
                        winner="bar")]
    xfam = [_s("cvt_map", 0x4a2c0, cat="data", ref="35740031", fam=False, conf="low")]
    md = emit_reference_conflicts_md(dis, xfam)
    assert "0x40" in md and "bar" in md and "a:foo" in md
    assert "cvt_map" in md and "35740031" in md
