from rom_analyzer.emit_ld import emit_mode23_binding_line
from rom_analyzer.mode23_bindings import (
    SpliceResolution,
    resolve_nearest_site,
    resolve_unique_site,
    decode_ldi_r0_before,
    CanSiteBinding,
    SLOT12_NAME,
    SLOT15_NAME,
    resolve_can_call_sites,
)


def test_emit_high_confidence_is_plain_assignment():
    line = emit_mode23_binding_line(
        "obd_rest_handler_injection_location",
        SpliceResolution(address=0x5f100, confidence="high"),
    )
    assert line == "obd_rest_handler_injection_location = 0x5f100;\n"


def test_emit_low_confidence_is_verify_comment():
    line = emit_mode23_binding_line(
        "obd_rest_handler_injection_location",
        SpliceResolution(address=0x5f100, confidence="low"),
    )
    assert line == (
        "/* VERIFY: obd_rest_handler_injection_location = 0x5f100; "
        "(low confidence — confirm in Ghidra) */\n"
    )


def test_emit_unresolved_is_verify_comment_without_address():
    line = emit_mode23_binding_line(
        "obd_rest_handler_injection_location",
        SpliceResolution(address=None, confidence="low"),
    )
    assert line == (
        "/* VERIFY: obd_rest_handler_injection_location = <unresolved> "
        "(no matching call site — locate manually) */\n"
    )


def test_resolve_unique_site_one_is_high():
    assert resolve_unique_site([0x49abc]) == SpliceResolution(address=0x49abc, confidence="high")


def test_resolve_unique_site_multiple_is_low_first():
    res = resolve_unique_site([0x200, 0x100, 0x300])
    assert res.address == 0x100
    assert res.confidence == "low"


def test_resolve_unique_site_none_is_unresolved():
    res = resolve_unique_site([])
    assert res.address is None
    assert res.confidence == "low"


def test_resolve_unique_site_dedupes():
    assert resolve_unique_site([0x100, 0x100]) == SpliceResolution(address=0x100, confidence="high")


def test_resolve_nearest_site_none_is_unresolved():
    res = resolve_nearest_site([], 0x5ef34)
    assert res.address is None
    assert res.confidence == "low"


def test_resolve_nearest_site_exact_hit_is_high():
    res = resolve_nearest_site([0x10, 0x5ef34, 0x99], 0x5ef34)
    assert res == SpliceResolution(address=0x5ef34, confidence="high")


def test_resolve_nearest_site_single_is_high():
    res = resolve_nearest_site([0x5ef00], 0x5ef34)
    assert res == SpliceResolution(address=0x5ef00, confidence="high")


def test_resolve_nearest_site_multiple_no_exact_is_medium_nearest():
    # 0x180 is closer to 0x170 than 0x100 is.
    res = resolve_nearest_site([0x100, 0x180], 0x170)
    assert res.address == 0x180
    assert res.confidence == "medium"


def test_resolve_can_call_sites_happy_two_callers_slots_2_and_1():
    bindings, verify = resolve_can_call_sites(
        callers=[0x49dc4, 0x49e9c],
        slot_of={0x49dc4: 2, 0x49e9c: 1},
    )
    by_name = {b.name: b for b in bindings}
    assert by_name[SLOT12_NAME].resolution.address == 0x49dc4
    assert by_name[SLOT12_NAME].resolution.confidence == "high"
    assert by_name[SLOT15_NAME].resolution.address == 0x49e9c
    assert by_name[SLOT15_NAME].resolution.confidence == "high"
    assert verify == "/* VERIFY: canrx12 slot=2, canrx15 slot=1 (matches hardcoded trampoline) */\n"


def test_resolve_can_call_sites_wrong_number_of_callers_is_low_and_flagged():
    bindings, verify = resolve_can_call_sites(callers=[0x49dc4], slot_of={0x49dc4: 2})
    assert all(b.resolution.confidence == "low" for b in bindings)
    assert verify.startswith("/* VERIFY: expected 2")


def test_resolve_can_call_sites_unexpected_slots_is_low_and_flagged():
    bindings, verify = resolve_can_call_sites(
        callers=[0x49dc4, 0x49e9c], slot_of={0x49dc4: 2, 0x49e9c: 3},
    )
    assert all(b.resolution.confidence == "low" for b in bindings)
    assert verify.startswith("/* VERIFY: expected 2")
    names = {b.name for b in bindings}
    assert names == {SLOT12_NAME, SLOT15_NAME}


def test_resolve_can_call_sites_missing_slot_is_low_and_flagged():
    bindings, verify = resolve_can_call_sites(
        callers=[0x49dc4, 0x49e9c], slot_of={0x49dc4: 2, 0x49e9c: None},
    )
    assert all(b.resolution.confidence == "low" for b in bindings)
    assert verify.startswith("/* VERIFY: expected 2")


def test_decode_ldi_r0_before_finds_immediate_just_before_call():
    rom = bytes([0x60, 0x02, 0xf0, 0x00, 0xfe, 0x00, 0x00, 0x94])
    assert decode_ldi_r0_before(rom, call_site=4) == 2


def test_decode_ldi_r0_before_short_bl_site():
    rom = bytes([0x60, 0x01, 0xf0, 0x00, 0x7e, 0x5e, 0xf0, 0x00])
    assert decode_ldi_r0_before(rom, call_site=4) == 1


def test_decode_ldi_r0_before_returns_none_when_absent():
    rom = bytes([0xf0, 0x00, 0xf0, 0x00, 0xfe, 0x00, 0x00, 0x94])
    assert decode_ldi_r0_before(rom, call_site=4) is None


def test_decode_ldi_r0_before_ignores_ldi_to_other_register():
    rom = bytes([0x61, 0x02, 0xf0, 0x00, 0xfe, 0x00, 0x00, 0x94])
    assert decode_ldi_r0_before(rom, call_site=4) is None
