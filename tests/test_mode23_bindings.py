from rom_analyzer.mode23_bindings import (
    CallSite,
    SpliceResolution,
    resolve_splice_site,
)


def test_unique_call_to_target_is_high_confidence():
    sites = [
        CallSite(address=0x4a100, target=0x12000),
        CallSite(address=0x4a120, target=0x4a014),  # the call we want
        CallSite(address=0x4a140, target=0x9000),
    ]
    res = resolve_splice_site(sites, acceptable_targets={0x4a014})
    assert res == SpliceResolution(address=0x4a120, confidence="high")


def test_no_call_to_target_is_unresolved_low():
    sites = [CallSite(address=0x4a100, target=0x12000)]
    res = resolve_splice_site(sites, acceptable_targets={0x4a014})
    assert res.address is None
    assert res.confidence == "low"


def test_multiple_calls_to_target_is_ambiguous_low():
    sites = [
        CallSite(address=0x4a120, target=0x4a014),
        CallSite(address=0x4a160, target=0x4a014),
    ]
    res = resolve_splice_site(sites, acceptable_targets={0x4a014})
    # First by address, but flagged low so a human verifies.
    assert res.address == 0x4a120
    assert res.confidence == "low"


def test_empty_targets_is_unresolved():
    sites = [CallSite(address=0x4a120, target=0x4a014)]
    res = resolve_splice_site(sites, acceptable_targets=set())
    assert res.address is None
    assert res.confidence == "low"


from rom_analyzer.mode23_bindings import resolve_unique_site, resolve_nearest_site
from rom_analyzer.emit_ld import emit_mode23_binding_line
from rom_analyzer.mode23_bindings import SpliceResolution


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
