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


def test_reconcile_item_corroborated_by_defaults_empty():
    it = ReconcileItem(target="X", direction="forward", address=0x100,
                       category="function", current=None, proposed="fn",
                       source="33520003", evidence="", verdict="proposed")
    assert it.corroborated_by == []


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
    assert back[0].corroborated_by == []


def test_reconcile_roundtrip_with_corroboration(tmp_path):
    items = [ReconcileItem(target="33520003", direction="back", address=0x804d5e,
                           category="ram_global", current="fp12962_u16",
                           proposed="tacho_output_state", source="e5090011",
                           evidence="usage-equiv", verdict="proposed",
                           corroborated_by=["39670016", "30200003"])]
    p = tmp_path / "r.toml"
    write_reconcile(p, items)
    data = tomllib.loads(p.read_text())
    assert data["item"][0]["corroborated_by"] == ["39670016", "30200003"]
    back = read_reconcile(p)
    assert back[0].corroborated_by == ["39670016", "30200003"]


def test_reconcile_roundtrip_no_corroboration_not_emitted(tmp_path):
    items = [ReconcileItem(target="33520003", direction="back", address=0x804d5e,
                           category="ram_global", current="fp12962_u16",
                           proposed="tacho_output_state", source="e5090011",
                           evidence="usage-equiv", verdict="proposed")]
    p = tmp_path / "r.toml"
    write_reconcile(p, items)
    data = tomllib.loads(p.read_text())
    assert "corroborated_by" not in data["item"][0]
    back = read_reconcile(p)
    assert back[0].corroborated_by == []


def test_reconcile_backward_compat_missing_field(tmp_path):
    old_toml = (
        '[[item]]\ntarget = "33520003"\ndirection = "back"\naddress = "0x804d5e"\n'
        'category = "ram_global"\ncurrent = "fp12962_u16"\nproposed = "tacho_output_state"\n'
        'source = "e5090011"\nevidence = "usage-equiv"\nverdict = "proposed"\n'
    )
    p = tmp_path / "old.toml"
    p.write_text(old_toml)
    items = read_reconcile(p)
    assert items[0].corroborated_by == []


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


def test_gather_skips_back_candidate_when_name_already_exists_in_target():
    # 47110032 already has main_loop at 0x4e130; a VTSession match that pairs
    # 47110032:0xa54 with 39670016:main_loop should NOT produce a back candidate
    # that would rename reset_interrupt_handler_helper to main_loop.
    matches = [MatchedFunction(ref_name="reset_interrupt_handler_helper",
                               ref_address=0xa54, new_address=0x1000, similarity=0.90)]
    new_fns = {0x1000: "main_loop", 0x9000: "something_else"}
    ref_fns = {0xa54: "reset_interrupt_handler_helper", 0x4e130: "main_loop"}
    cands = gather_candidates(
        new_id="39670016", ref_id="47110032", matches=matches,
        new_fn_names=new_fns, ref_fn_names=ref_fns)
    back = [c for c in cands if c.direction == "back"]
    assert not back, "back candidate must be suppressed: main_loop already exists in 47110032 at 0x4e130"


def test_gather_skips_forward_candidate_when_name_already_exists_in_target():
    # Mirror of the back test: if the ref's proposed name already lives in the
    # new ROM at a different address, don't forward it.
    matches = [MatchedFunction(ref_name="main_loop", ref_address=0x4e130,
                               new_address=0x5000, similarity=0.85)]
    new_fns = {0x5000: "something", 0x1000: "main_loop"}  # main_loop already at 0x1000
    ref_fns = {0x4e130: "main_loop"}
    cands = gather_candidates(
        new_id="39670016", ref_id="47110032", matches=matches,
        new_fn_names=new_fns, ref_fn_names=ref_fns)
    fwd = [c for c in cands if c.direction == "forward"]
    assert not fwd, "forward candidate must be suppressed: main_loop already exists in 39670016 at 0x1000"


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


from rom_analyzer.enrich import merge_candidates


def _mc(target, address, proposed, source, category="function",
        current=None, direction="forward", evidence=""):
    return LabelCandidate(target=target, direction=direction, address=address,
                          category=category, current=current, proposed=proposed,
                          source=source, evidence=evidence)


def test_merge_single_source_passthrough():
    c = _mc("X", 0x100, "my_fn", "33520003", evidence="sim=0.90")
    result = merge_candidates([c], priority={"33520003": 100})
    assert len(result) == 1
    assert result[0].proposed == "my_fn"
    assert result[0].corroborating_sources == ["33520003"]


def test_merge_same_name_consensus_collapses():
    prio = {"33520003": 100, "30200003": 40, "c7280010": 35}
    cands = [
        _mc("X", 0x100, "real_fn", "33520003", evidence="sim=0.90"),
        _mc("X", 0x100, "real_fn", "30200003", evidence="sim=0.80"),
        _mc("X", 0x100, "real_fn", "c7280010", evidence="sim=0.82"),
    ]
    result = merge_candidates(cands, prio)
    assert len(result) == 1
    r = result[0]
    assert r.proposed == "real_fn"
    assert r.source == "33520003"
    assert set(r.corroborating_sources) == {"33520003", "30200003", "c7280010"}
    assert "sim=0.90" in r.evidence and "sim=0.80" in r.evidence


def test_merge_conflict_authority_wins():
    prio = {"33520003": 100, "30200003": 40}
    cands = [
        _mc("X", 0x100, "authority_name", "33520003"),
        _mc("X", 0x100, "other_name", "30200003"),
    ]
    result = merge_candidates(cands, prio)
    assert len(result) == 1
    assert result[0].proposed == "authority_name"
    assert result[0].source == "33520003"
    # 30200003 voted for the losing name — not in corroborating_sources
    assert result[0].corroborating_sources == ["33520003"]


def test_merge_conflict_majority_beats_authority():
    # 3 votes vs 1: majority wins even if the single vote is from the top authority
    prio = {"33520003": 100, "a": 30, "b": 35, "c": 40}
    cands = [
        _mc("X", 0x100, "authority_name", "33520003"),
        _mc("X", 0x100, "majority_name", "a"),
        _mc("X", 0x100, "majority_name", "b"),
        _mc("X", 0x100, "majority_name", "c"),
    ]
    result = merge_candidates(cands, prio)
    assert result[0].proposed == "majority_name"
    # 33520003 voted for loser — NOT in corroborating_sources
    assert "33520003" not in result[0].corroborating_sources
    assert set(result[0].corroborating_sources) == {"a", "b", "c"}


def test_merge_tie_broken_by_priority():
    # 1 vote each; higher-priority source wins
    prio = {"33520003": 100, "30200003": 40}
    cands = [
        _mc("X", 0x100, "high_prio_name", "33520003"),
        _mc("X", 0x100, "low_prio_name", "30200003"),
    ]
    result = merge_candidates(cands, prio)
    assert result[0].proposed == "high_prio_name"


def test_merge_preserves_different_addresses():
    prio = {"33520003": 100, "30200003": 40}
    cands = [
        _mc("X", 0x100, "fn_a", "33520003"),
        _mc("X", 0x200, "fn_b", "30200003"),
    ]
    result = merge_candidates(cands, prio)
    assert len(result) == 2
    addrs = {r.address for r in result}
    assert addrs == {0x100, 0x200}


def test_merge_different_targets_not_collapsed():
    prio = {"33520003": 100, "30200003": 40}
    cands = [
        _mc("A", 0x100, "fn_a", "33520003"),
        _mc("B", 0x100, "fn_b", "30200003"),
    ]
    result = merge_candidates(cands, prio)
    assert len(result) == 2


def test_merge_empty_input():
    assert merge_candidates([], priority={}) == []


from rom_analyzer.enrich import _authority_agrees


def test_authority_agrees_top_in_sources():
    prio = {"33520003": 100, "39670016": 90, "30200003": 40}
    assert _authority_agrees(["33520003", "30200003"], prio) is True


def test_authority_agrees_top_not_in_sources():
    prio = {"33520003": 100, "39670016": 90, "30200003": 40}
    assert _authority_agrees(["30200003", "39670016"], prio) is False


def test_authority_agrees_empty_sources_returns_false():
    assert _authority_agrees([], {"33520003": 100}) is False


def test_authority_agrees_empty_priority_returns_false():
    assert _authority_agrees(["33520003"], {}) is False


def test_classify_authority_backed_conflict_auto_applied():
    prio = {"33520003": 100, "30200003": 40}
    c = LabelCandidate(
        target="X", direction="forward", address=0x100,
        category="function", current="call100", proposed="real_fn",
        source="33520003", corroborating_sources=["33520003", "30200003"],
    )
    out = classify([c], erased=set(), priority=prio)
    assert len(out.auto) == 1 and out.auto[0].proposed == "real_fn"
    assert out.review == []


def test_classify_conflict_without_authority_stays_review():
    prio = {"33520003": 100, "30200003": 40}
    c = LabelCandidate(
        target="X", direction="forward", address=0x100,
        category="function", current="call100", proposed="other_fn",
        source="30200003", corroborating_sources=["30200003"],
    )
    out = classify([c], erased=set(), priority=prio)
    assert out.auto == []
    assert len(out.review) == 1


def test_classify_authority_rule_skipped_for_ram_global():
    # Authority rule only fires for functions; RAM/data always go to review
    prio = {"33520003": 100}
    c = LabelCandidate(
        target="X", direction="forward", address=0x100,
        category="ram_global", current="fp100", proposed="real_var",
        source="33520003", corroborating_sources=["33520003"],
    )
    out = classify([c], erased=set(), priority=prio)
    assert out.auto == []
    assert len(out.review) == 1


def test_classify_erased_address_drops_before_authority_rule():
    # Candidate is dropped entirely when its address is in erased,
    # before any rule fires (including authority rule).
    prio = {"33520003": 100}
    c = LabelCandidate(
        target="X", direction="forward", address=0x100,
        category="function", current="call100", proposed="real_fn",
        source="33520003", corroborating_sources=["33520003"],
    )
    out = classify([c], erased={0x100}, priority=prio)
    assert out.auto == [] and out.review == []


def test_classify_no_priority_arg_authority_rule_inactive():
    # Backward compat: callers that don't pass priority still work
    c = LabelCandidate(
        target="X", direction="forward", address=0x100,
        category="function", current="call100", proposed="real_fn",
        source="33520003", corroborating_sources=["33520003"],
    )
    out = classify([c], erased=set())  # no priority kwarg
    assert out.auto == []
    assert len(out.review) == 1


def test_build_items_noop_keep_filtered():
    # auto_resolve: current="real_existing_name" (not placeholder),
    # proposed="call100" (placeholder from low-priority source)
    # → descriptive beats placeholder → keep current → proposed becomes "real_existing_name"
    # → proposed == current → filtered out
    prio = {"33520003": 100, "e5090011": 30}
    rev = [LabelCandidate(
        target="33520003", direction="back", address=0x100,
        category="function", current="real_existing_name",
        proposed="call100",   # placeholder from low-priority source
        source="e5090011",
    )]
    items = build_reconcile_items(rev, prio)
    assert items == []


def test_build_items_genuine_conflict_not_filtered():
    prio = {"33520003": 100, "e5090011": 30}
    rev = [LabelCandidate(
        target="39670016", direction="forward", address=0x100,
        category="function", current="old_name",
        proposed="new_name", source="33520003",
    )]
    items = build_reconcile_items(rev, prio)
    assert len(items) == 1
    assert items[0].proposed == "new_name"


def test_build_items_corroborated_by_populated():
    prio = {"33520003": 100, "30200003": 40}
    c = LabelCandidate(
        target="X", direction="forward", address=0x100,
        category="function", current="call100", proposed="real_fn",
        source="33520003", corroborating_sources=["33520003", "30200003"],
    )
    items = build_reconcile_items([c], prio)
    assert len(items) == 1
    assert items[0].corroborated_by == ["30200003"]
    assert items[0].source == "33520003"
