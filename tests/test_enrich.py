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


def test_label_candidate_and_reconcile_item_construct():
    c = LabelCandidate(target="33520003", direction="back", address=0x804d5e,
                       category="ram_global", current="fp12962_u16",
                       proposed="tacho_output_state", source="e5090011",
                       evidence="usage-equiv: written in matched fn 0x14ed8")
    assert c.address == 0x804d5e and c.direction == "back"
    it = ReconcileItem(**vars(c), verdict="proposed")
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
