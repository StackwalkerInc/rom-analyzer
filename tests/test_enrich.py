from rom_analyzer.enrich import (
    LabelCandidate, ReconcileItem, is_auto_name, is_placeholder,
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
