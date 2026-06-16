from rom_analyzer.enrich import (
    LabelCandidate, ReconcileItem, is_auto_name, is_placeholder,
    classify, Classified,
)


def test_is_auto_name():
    for n in ("FUN_0001bf4c", "LAB_00012345", "DAT_0000abcd", "SUB_00010000",
              "icu_isr_07", "isr_vector_04"):
        assert is_auto_name(n), n
    for n in ("sio_dma_reset", "tacho_set", "main_loop"):
        assert not is_auto_name(n), n


def test_is_placeholder():
    for n in ("call1bf28", "reset_call10000", "fp12962_u16", "ret0_145ec",
              "nop19308", "get_fp5379b7"):
        assert is_placeholder(n), n
    for n in ("sio_dma_reset", "get_starter_input", "update_fast_outputs"):
        assert not is_placeholder(n), n


def test_label_candidate_corroborating_sources_defaults_to_source():
    c = LabelCandidate(target="X", direction="forward", address=0x100,
                       category="function", current=None, proposed="my_fn",
                       source="33520003")
    assert c.corroborating_sources == ["33520003"]


def test_label_candidate_explicit_corroborating_sources():
    c = LabelCandidate(target="X", direction="forward", address=0x100,
                       category="function", current=None, proposed="my_fn",
                       source="33520003",
                       corroborating_sources=["33520003", "30200003"])
    assert c.corroborating_sources == ["33520003", "30200003"]


def test_label_candidate_and_reconcile_item_construct():
    c = LabelCandidate(target="33520003", direction="back", address=0x804d5e,
                       category="ram_global", current="fp12962_u16",
                       proposed="tacho_output_state", source="e5090011",
                       evidence="usage-equiv: written in matched fn 0x14ed8")
    assert c.address == 0x804d5e and c.direction == "back"
    assert c.corroborating_sources == ["e5090011"]
    it = ReconcileItem(target=c.target, direction=c.direction, address=c.address,
                       category=c.category, current=c.current, proposed=c.proposed,
                       source=c.source, evidence=c.evidence, verdict="proposed")
    assert it.verdict == "proposed" and it.target == "33520003"


def _cand(addr, cat, current, proposed, direction="forward", source="33520003"):
    return LabelCandidate(target="X", direction=direction, address=addr,
                          category=cat, current=current, proposed=proposed,
                          source=source)


def test_classify_new_function_is_auto():
    cands = [_cand(0x10000, "function", None, "sio_dma_reset")]
    out = classify(cands, erased=set())
    assert [c.proposed for c in out.auto] == ["sio_dma_reset"]
    assert out.review == []


def test_classify_drops_auto_names_and_erased():
    cands = [
        _cand(0x10000, "function", None, "FUN_00010000"),   # auto-name -> drop
        _cand(0x49ef0, "function", None, "real_name"),      # erased -> drop
    ]
    out = classify(cands, erased={0x49ef0})
    assert out.auto == [] and out.review == []


def test_classify_name_conflict_is_review():
    cands = [_cand(0x14c44, "function", "update_fuel_pressure_solenoid_out",
                   "update_fast_outputs")]
    out = classify(cands, erased=set())
    assert out.auto == []
    assert len(out.review) == 1 and out.review[0].address == 0x14c44


def test_classify_ram_data_always_review():
    cands = [
        _cand(0x804d5e, "ram_global", "fp12962_u16", "tacho_output_state"),
        _cand(0x5000, "data", None, "flash_new_table"),  # even a data gap -> review
    ]
    out = classify(cands, erased=set())
    assert out.auto == []
    assert {c.category for c in out.review} == {"ram_global", "data"}


def test_classify_agreement_not_listed():
    # same name already present -> neither auto nor review
    cands = [_cand(0x10000, "function", "sio_dma_reset", "sio_dma_reset")]
    out = classify(cands, erased=set())
    assert out.auto == [] and out.review == []


from rom_analyzer.enrich import auto_resolve


def _rev(current, proposed, target="39670016", source="33520003"):
    return LabelCandidate(target=target, direction="back", address=0x100,
                          category="function", current=current, proposed=proposed,
                          source=source)


def test_authority_wins_by_priority():
    # source 33520003 has higher priority than target 39670016 -> propose source name
    prio = {"33520003": 100, "39670016": 90}
    name, verdict = auto_resolve(_rev("update_fuel_pressure_solenoid_out",
                                      "update_fast_outputs"), prio)
    assert name == "update_fast_outputs" and verdict == "proposed"


def test_lower_priority_source_keeps_target():
    # source lower priority and both names real -> keep target
    prio = {"33520003": 100, "e5090011": 30}
    name, verdict = auto_resolve(
        _rev("get_starter_input", "some_other_real_name",
             target="33520003", source="e5090011"), prio)
    assert verdict == "keep"


def test_keep_sio_prefix():
    prio = {"47110032": 50, "39670016": 90}
    c = _rev("sio1_tx_process_check", "si1_request_transmit_checked",
             target="39670016", source="47110032")
    name, verdict = auto_resolve(c, prio)
    assert verdict == "keep"  # hold sio0/sio1 prefix on target


def test_descriptive_beats_placeholder_regardless_of_priority():
    # target has placeholder, source (even lower priority) has real name
    prio = {"33520003": 100, "e5090011": 30}
    c = _rev("call18520", "camshaft_position_sensor_interrupt_handler",
             target="33520003", source="e5090011")
    name, verdict = auto_resolve(c, prio)
    assert name == "camshaft_position_sensor_interrupt_handler"
    assert verdict == "proposed"


import tomllib
from pathlib import Path
from rom_analyzer.enrich import (
    build_reconcile_items, write_reconcile, read_reconcile, apply_verdicts,
)
from rom_analyzer.annotations_io import (
    AnnotationStore, AnnotationFunction, AnnotationSymbol,
)


def test_build_items_fills_proposed_and_verdict():
    prio = {"33520003": 100, "39670016": 90}
    rev = [LabelCandidate(target="39670016", direction="back", address=0x100,
                          category="function", current="call100",
                          proposed="real_fn", source="33520003")]
    items = build_reconcile_items(rev, prio)
    assert items[0].verdict == "proposed" and items[0].proposed == "real_fn"


def test_reconcile_roundtrip(tmp_path):
    items = [ReconcileItem(target="33520003", direction="back", address=0x804d5e,
                           category="ram_global", current="fp12962_u16",
                           proposed="tacho_output_state", source="e5090011",
                           evidence="usage-equiv", verdict="proposed")]
    p = tmp_path / "r.toml"
    write_reconcile(p, items)
    data = tomllib.loads(p.read_text())
    assert data["item"][0]["address"] == "0x804d5e"
    back = read_reconcile(p)
    assert back[0].address == 0x804d5e and back[0].verdict == "proposed"


def test_apply_verdicts_rename_keep_drop_custom():
    store = AnnotationStore(schema_version=1, rom_id="t", rom_sha256="",
        symbols=[AnnotationSymbol(name="fp12962_u16", address=0x804d5e,
                                  category="ram_global")],
        functions=[AnnotationFunction(name="call100", entry_point=0x100)])
    items = [
        ReconcileItem("t", "back", 0x804d5e, "ram_global", "fp12962_u16",
                      "tacho_output_state", "e5090011", "", "proposed"),
        ReconcileItem("t", "back", 0x100, "function", "call100",
                      "real_fn", "33520003", "", "keep"),
    ]
    n = apply_verdicts(store, items, target="t")
    by_addr = {s.address: s.name for s in store.symbols}
    fn = {f.entry_point: f.name for f in store.functions}
    assert by_addr[0x804d5e] == "tacho_output_state"   # proposed applied
    assert fn[0x100] == "call100"                        # keep -> unchanged
    assert n == 1


def test_apply_verdict_gap_add():
    store = AnnotationStore(schema_version=1, rom_id="t", rom_sha256="",
                            symbols=[], functions=[])
    items = [ReconcileItem("t", "forward", 0x200, "function", None,
                           "new_fn", "33520003", "", "proposed")]
    apply_verdicts(store, items, target="t")
    assert any(f.entry_point == 0x200 and f.name == "new_fn"
               for f in store.functions)


from rom_analyzer.enrich import gather_candidates
from rom_analyzer.types import MatchedFunction


def test_gather_forward_and_back_function_candidates():
    # one matched function pair: new 0x200 <-> ref 0x10000
    matches = [MatchedFunction(ref_name="sio_dma_reset", ref_address=0x10000,
                               new_address=0x200, similarity=1.0)]
    new_fns = {0x200: "call200"}          # new ref's own name at 0x200
    ref_fns = {0x10000: "sio_dma_reset"}  # source ref's name
    cands = gather_candidates(
        new_id="cs7a", ref_id="33520003", matches=matches,
        new_fn_names=new_fns, ref_fn_names=ref_fns)
    fwd = [c for c in cands if c.direction == "forward"]
    back = [c for c in cands if c.direction == "back"]
    # forward: ref name onto new (target=cs7a)
    assert fwd[0].target == "cs7a" and fwd[0].proposed == "sio_dma_reset"
    assert fwd[0].current == "call200" and fwd[0].address == 0x200
    # back: new name onto ref (target=33520003)
    assert back[0].target == "33520003" and back[0].proposed == "call200"
    assert back[0].current == "sio_dma_reset" and back[0].address == 0x10000


from rom_analyzer.enrich import is_generic


def test_is_generic():
    for n in ("out", "in", "x", "tmp", "data", "value", "fn", "abc"):
        assert is_generic(n), n
    for n in ("sio_dma_reset", "tacho_set", "main", "popi", "max16", "sqrt"):
        assert not is_generic(n), n


def test_classify_generic_gap_goes_to_review_not_auto():
    # a NEW function gap with a too-generic proposed name must be reviewed,
    # not silently auto-applied (the "out" regression)
    cands = [
        _cand(0x3a200, "function", None, "out"),               # generic gap -> review
        _cand(0x10000, "function", None, "sio_dma_reset"),     # real gap -> auto
    ]
    out = classify(cands, erased=set())
    assert [c.proposed for c in out.auto] == ["sio_dma_reset"]
    assert [c.proposed for c in out.review] == ["out"]
