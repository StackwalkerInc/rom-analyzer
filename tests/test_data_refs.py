import pytest

from rom_analyzer.data_refs import DataRef, DataRefType, propagate_data_labels
from rom_analyzer.types import MatchedFunction, ReferenceSymbol


def _mk_ref(offset: int, addr: int, label: str | None,
            ref_type: DataRefType = DataRefType.READ) -> DataRef:
    return DataRef(instruction_offset=offset, referenced_address=addr,
                   label=label, ref_type=ref_type)


def test_propagate_data_labels_exact_offset_match():
    ref_refs = {0x1000: [_mk_ref(0, 0xabcd, None), _mk_ref(8, 0x1234, "flash_x")]}
    new_refs = {0x2000: [_mk_ref(0, 0xabcd, None), _mk_ref(8, 0x5678, None)]}
    matches = [MatchedFunction("func", 0x1000, 0x2000, similarity=0.97)]
    ref_syms = {0x1234: ReferenceSymbol("flash_x", 0x1234, "data")}
    result = propagate_data_labels(ref_refs, new_refs, matches, ref_syms)
    assert len(result) == 1
    assert result[0].name == "flash_x"
    assert result[0].ref_address == 0x1234
    assert result[0].new_address == 0x5678
    assert result[0].confidence == "high"
    assert result[0].category == "data"
    assert result[0].source == "data_refs"
    assert result[0].score == pytest.approx(1.0)


def test_propagate_data_labels_sliding_window():
    ref_refs = {0x1000: [_mk_ref(8, 0x1234, "flash_y")]}
    new_refs = {0x2000: [_mk_ref(12, 0x5678, None)]}
    matches = [MatchedFunction("func", 0x1000, 0x2000, similarity=0.80)]
    ref_syms = {0x1234: ReferenceSymbol("flash_y", 0x1234, "data")}
    result = propagate_data_labels(ref_refs, new_refs, matches, ref_syms, window_bytes=8)
    assert len(result) == 1
    assert result[0].name == "flash_y"
    assert result[0].new_address == 0x5678
    assert result[0].source == "data_refs"


def test_propagate_data_labels_skips_outside_window():
    ref_refs = {0x1000: [_mk_ref(8, 0x1234, "flash_z")]}
    new_refs = {0x2000: [_mk_ref(24, 0x5678, None)]}
    matches = [MatchedFunction("func", 0x1000, 0x2000, similarity=0.80)]
    ref_syms = {0x1234: ReferenceSymbol("flash_z", 0x1234, "data")}
    result = propagate_data_labels(ref_refs, new_refs, matches, ref_syms, window_bytes=8)
    assert result == []


def test_propagate_data_labels_skips_low_confidence():
    ref_refs = {0x1000: [_mk_ref(0, 0x1234, "flash_q")]}
    new_refs = {0x2000: [_mk_ref(0, 0x5678, None)]}
    matches = [MatchedFunction("func", 0x1000, 0x2000, similarity=0.50)]
    ref_syms = {0x1234: ReferenceSymbol("flash_q", 0x1234, "data")}
    result = propagate_data_labels(ref_refs, new_refs, matches, ref_syms)
    assert result == []


def test_propagate_data_labels_skips_ram_refs():
    ref_refs = {0x1000: [_mk_ref(0, 0x804e5c, "engine_rpm")]}
    new_refs = {0x2000: [_mk_ref(0, 0x804e5c, None)]}
    matches = [MatchedFunction("func", 0x1000, 0x2000, similarity=0.97)]
    ref_syms = {0x804e5c: ReferenceSymbol("engine_rpm", 0x804e5c, "ram_global")}
    result = propagate_data_labels(ref_refs, new_refs, matches, ref_syms)
    assert result == []


def test_propagate_data_labels_skips_scalar_ref_in_new_rom():
    """A data label must not be propagated to the new ROM when the matched data
    reference there is a scalar/computed reference (e.g. Ghidra marking an LDI
    Rd, #imm immediate as a ROM address) rather than a genuine memory read.

    Concrete case: Z27AG flash_injector_latency_scaling lives at 0x0800 (value
    0x000F = 15).  The outlander's matched function uses LDI R1, #0x0800 to load
    the constant 2048 — not a flash table pointer.  Ghidra's scalar-reference
    analysis creates a READ-type reference from that instruction to address 0x0800.
    Without this guard, propagate_data_labels would incorrectly label 0x0800 in
    the outlander project, making Ghidra display "flash_injector_latency_scaling"
    on the LDI operand (which reads 0x000F from that address) instead of showing
    the actual constant 2048.
    """
    ref_refs = {0x10000: [_mk_ref(24, 0x0800, "flash_injector_latency_scaling",
                                  DataRefType.READ)]}
    # Outlander function has LDI R1, #0x0800 — Ghidra marks it as READ to 0x0800.
    new_refs = {0x20000: [_mk_ref(24, 0x0800, None, DataRefType.SCALAR)]}
    matches = [MatchedFunction("update_tio5_duty", 0x10000, 0x20000, similarity=0.97)]
    ref_syms = {0x0800: ReferenceSymbol("flash_injector_latency_scaling", 0x0800, "data")}
    result = propagate_data_labels(ref_refs, new_refs, matches, ref_syms)
    assert result == [], (
        "flash_injector_latency_scaling must not be propagated when the new ROM's "
        "matching data reference is a scalar/computed ref, not a genuine read"
    )


def test_propagate_data_labels_keeps_genuine_read_in_new_rom():
    """Propagation must still work when the new ROM's data ref is a genuine read."""
    ref_refs = {0x10000: [_mk_ref(24, 0x0800, "flash_injector_latency_scaling",
                                  DataRefType.READ)]}
    new_refs = {0x20000: [_mk_ref(24, 0x0800, None, DataRefType.READ)]}
    matches = [MatchedFunction("some_func", 0x10000, 0x20000, similarity=0.97)]
    ref_syms = {0x0800: ReferenceSymbol("flash_injector_latency_scaling", 0x0800, "data")}
    result = propagate_data_labels(ref_refs, new_refs, matches, ref_syms)
    assert len(result) == 1
    assert result[0].name == "flash_injector_latency_scaling"
    assert result[0].new_address == 0x0800


def test_propagate_data_labels_confidence_downgrade_on_conflict():
    ref_refs = {
        0x1000: [_mk_ref(0, 0x1234, "flash_m")],
        0x3000: [_mk_ref(0, 0x1234, "flash_m")],
    }
    new_refs = {
        0x2000: [_mk_ref(0, 0x5678, None)],
        0x4000: [_mk_ref(0, 0x9abc, None)],
    }
    matches = [
        MatchedFunction("f1", 0x1000, 0x2000, similarity=0.97),
        MatchedFunction("f2", 0x3000, 0x4000, similarity=0.97),
    ]
    ref_syms = {0x1234: ReferenceSymbol("flash_m", 0x1234, "data")}
    result = propagate_data_labels(ref_refs, new_refs, matches, ref_syms)
    assert len(result) == 1
    assert result[0].name == "flash_m"
    assert result[0].confidence == "low"


def test_scalar_symmetric_propagated():
    """Both ref and new use LDI (SCALAR) at the same offset — should propagate
    with source='data_refs_scalar'."""
    ref_refs = {0x1000: [_mk_ref(8, 0xb2fa, "flash_fuel_map_rpm_axis",
                                 DataRefType.SCALAR)]}
    new_refs = {0x2000: [_mk_ref(8, 0xc350, None, DataRefType.SCALAR)]}
    matches = [MatchedFunction("fuel_map_reader", 0x1000, 0x2000, similarity=0.90)]
    ref_syms = {0xb2fa: ReferenceSymbol("flash_fuel_map_rpm_axis", 0xb2fa, "data")}
    result = propagate_data_labels(ref_refs, new_refs, matches, ref_syms)
    assert len(result) == 1
    assert result[0].name == "flash_fuel_map_rpm_axis"
    assert result[0].new_address == 0xc350
    assert result[0].source == "data_refs_scalar"
    assert result[0].confidence == "high"


def test_scalar_asymmetric_blocked():
    """ref=READ, new=SCALAR — the asymmetric case must stay blocked (existing behaviour)."""
    ref_refs = {0x1000: [_mk_ref(8, 0xb2fa, "flash_fuel_map_rpm_axis",
                                 DataRefType.READ)]}
    new_refs = {0x2000: [_mk_ref(8, 0xc350, None, DataRefType.SCALAR)]}
    matches = [MatchedFunction("fuel_map_reader", 0x1000, 0x2000, similarity=0.90)]
    ref_syms = {0xb2fa: ReferenceSymbol("flash_fuel_map_rpm_axis", 0xb2fa, "data")}
    result = propagate_data_labels(ref_refs, new_refs, matches, ref_syms)
    assert result == []


def test_scalar_read_takes_precedence():
    """Same symbol found by READ path (one function) AND SCALAR path (another)
    — final source must be 'data_refs', not 'data_refs_scalar'."""
    ref_refs = {
        0x1000: [_mk_ref(8, 0xb2fa, "flash_fuel_map_rpm_axis", DataRefType.READ)],
        0x3000: [_mk_ref(8, 0xb2fa, "flash_fuel_map_rpm_axis", DataRefType.SCALAR)],
    }
    new_refs = {
        0x2000: [_mk_ref(8, 0xc350, None, DataRefType.READ)],
        0x4000: [_mk_ref(8, 0xc350, None, DataRefType.SCALAR)],
    }
    matches = [
        MatchedFunction("f1", 0x1000, 0x2000, similarity=0.90),
        MatchedFunction("f2", 0x3000, 0x4000, similarity=0.90),
    ]
    ref_syms = {0xb2fa: ReferenceSymbol("flash_fuel_map_rpm_axis", 0xb2fa, "data")}
    result = propagate_data_labels(ref_refs, new_refs, matches, ref_syms)
    assert len(result) == 1
    assert result[0].name == "flash_fuel_map_rpm_axis"
    assert result[0].new_address == 0xc350
    assert result[0].source == "data_refs"


def test_scalar_window_applies():
    """Symmetric SCALAR match within the sliding window (offset differs by 2)
    must still propagate."""
    ref_refs = {0x1000: [_mk_ref(8, 0xb2fa, "flash_boost_map_rpm_axis",
                                 DataRefType.SCALAR)]}
    new_refs = {0x2000: [_mk_ref(10, 0xd4a0, None, DataRefType.SCALAR)]}
    matches = [MatchedFunction("boost_reader", 0x1000, 0x2000, similarity=0.85)]
    ref_syms = {0xb2fa: ReferenceSymbol("flash_boost_map_rpm_axis", 0xb2fa, "data")}
    result = propagate_data_labels(ref_refs, new_refs, matches, ref_syms,
                                   window_bytes=8)
    assert len(result) == 1
    assert result[0].name == "flash_boost_map_rpm_axis"
    assert result[0].new_address == 0xd4a0
    assert result[0].source == "data_refs_scalar"
