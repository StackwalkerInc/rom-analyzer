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
