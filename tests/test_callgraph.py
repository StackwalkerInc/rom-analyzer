"""Unit tests for callgraph.py — all pure-Python, no Ghidra required."""

import struct

import pytest

from rom_analyzer.callgraph import (
    _find_mut_table,
    _func_size,
    _lcs_align,
    _size_ratio_ok,
    bootstrap_anchors,
    bfs_preseed,
    gap_fill,
)
from rom_analyzer.ghidra import HeadlessRun
from rom_analyzer.types import MatchedFunction, ReferenceSymbol


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_run(func_entries: list[int],
              callees: dict[int, list[int]] | None = None,
              data_refs: dict | None = None,
              symbols: list[dict] | None = None) -> HeadlessRun:
    """Build a minimal HeadlessRun from integer entry addresses."""
    functions = [{"name": f"FUN_{e:x}", "entry": hex(e)} for e in func_entries]
    return HeadlessRun(
        functions=functions,
        symbols=symbols or [],
        ram_refs=[],
        rom_crc_check_step=None,
        data_refs=data_refs or {},
        callees=callees or {},
    )


# ---------------------------------------------------------------------------
# _func_size
# ---------------------------------------------------------------------------

def test_func_size_basic():
    run = _make_run([0x100, 0x200, 0x300])
    assert _func_size(0x100, run) == 0x100
    assert _func_size(0x200, run) == 0x100


def test_func_size_last_function_returns_zero():
    run = _make_run([0x100, 0x200])
    assert _func_size(0x200, run) == 0


def test_func_size_unknown_entry():
    run = _make_run([0x100, 0x200])
    assert _func_size(0x999, run) == 0


# ---------------------------------------------------------------------------
# _size_ratio_ok
# ---------------------------------------------------------------------------

def test_size_ratio_ok_equal_sizes():
    ref = _make_run([0x100, 0x200])   # func at 0x100 is 0x100 bytes
    new = _make_run([0x200, 0x300])   # func at 0x200 is 0x100 bytes
    assert _size_ratio_ok(0x100, 0x200, ref, new, tolerance=0.4)


def test_size_ratio_ok_within_tolerance():
    ref = _make_run([0x100, 0x200])   # size 0x100
    new = _make_run([0x200, 0x2A0])   # size 0xA0 — ratio 0xA0/0x100 = 0.625 ≥ 0.6
    assert _size_ratio_ok(0x100, 0x200, ref, new, tolerance=0.4)


def test_size_ratio_ok_exceeds_tolerance():
    ref = _make_run([0x100, 0x200])   # size 0x100
    new = _make_run([0x200, 0x230])   # size 0x30 — ratio 0x30/0x100 = 0.188 < 0.6
    assert not _size_ratio_ok(0x100, 0x200, ref, new, tolerance=0.4)


def test_size_ratio_ok_unknown_size_passes():
    ref = _make_run([0x100])          # last function: size = 0 (unknown)
    new = _make_run([0x200, 0x300])
    assert _size_ratio_ok(0x100, 0x200, ref, new)


# ---------------------------------------------------------------------------
# _lcs_align
# ---------------------------------------------------------------------------

def _make_pair_runs(ref_sizes: list[int], new_sizes: list[int]):
    """Build two runs with functions at addresses 0x100, 0x200, ..."""
    def _entries(sizes):
        entries = [0x100]
        for s in sizes:
            entries.append(entries[-1] + s)
        return entries

    ref_entries = _entries(ref_sizes)
    new_entries = _entries(new_sizes)
    ref_run = _make_run(ref_entries)
    new_run = _make_run(new_entries)
    ref_callees = ref_entries[:-1]
    new_callees = new_entries[:-1]
    return ref_run, new_run, ref_callees, new_callees


def test_lcs_align_exact_match():
    ref_run, new_run, ref_c, new_c = _make_pair_runs(
        [0x100, 0x100, 0x100],
        [0x100, 0x100, 0x100],
    )
    pairs = _lcs_align(ref_c, new_c, ref_run, new_run)
    assert len(pairs) == 3
    for (r, n), r_exp, n_exp in zip(pairs, ref_c, new_c):
        assert r == r_exp and n == n_exp


def test_lcs_align_extra_in_ref():
    """Ref has a tiny CAN-init function (0x10 bytes) that new lacks."""
    ref_run, new_run, ref_c, new_c = _make_pair_runs(
        [0x100, 0x10, 0x100, 0x200],   # ref: startup, can_init (tiny), init_sw, main_loop
        [0x100,        0x100, 0x200],   # new: startup, init_sw, main_loop
    )
    pairs = _lcs_align(ref_c, new_c, ref_run, new_run)
    # can_init (size 0x10) should be skipped; others match in order
    assert len(pairs) == 3
    assert pairs[0] == (ref_c[0], new_c[0])   # startup
    assert pairs[1] == (ref_c[2], new_c[1])   # init_sw (skipped can_init)
    assert pairs[2] == (ref_c[3], new_c[2])   # main_loop


def test_lcs_align_extra_in_new():
    """New has an extra function that ref lacks."""
    ref_run, new_run, ref_c, new_c = _make_pair_runs(
        [0x100, 0x100, 0x200],
        [0x100, 0x10, 0x100, 0x200],
    )
    pairs = _lcs_align(ref_c, new_c, ref_run, new_run)
    assert len(pairs) == 3
    assert pairs[0] == (ref_c[0], new_c[0])
    assert pairs[1] == (ref_c[1], new_c[2])
    assert pairs[2] == (ref_c[2], new_c[3])


def test_lcs_align_size_filter_prevents_misalignment():
    """A completely incompatible size at position 0 should not pair."""
    ref_run, new_run, ref_c, new_c = _make_pair_runs(
        [0x1000, 0x100],   # ref: huge, normal
        [0x10,   0x100],   # new: tiny (incompatible with huge), normal
    )
    pairs = _lcs_align(ref_c, new_c, ref_run, new_run)
    # Only the second pair (both 0x100) should match
    assert len(pairs) == 1
    assert pairs[0] == (ref_c[1], new_c[1])


def test_lcs_align_empty_lists():
    ref_run = _make_run([0x100, 0x200])
    new_run = _make_run([0x200, 0x300])
    assert _lcs_align([], [], ref_run, new_run) == []
    assert _lcs_align([0x100], [], ref_run, new_run) == []
    assert _lcs_align([], [0x200], ref_run, new_run) == []


# ---------------------------------------------------------------------------
# _find_mut_table
# ---------------------------------------------------------------------------

def _make_rom_with_mut_table(table_base: int, rom_size: int = 0x80000) -> bytes:
    """Build a synthetic ROM with the MUT invariant-cell pattern."""
    rom = bytearray(rom_size)
    pid_base = table_base + 0x200
    a = 0x86  # rom_version0 HIGH_BYTE last-byte
    # PID 0x80
    struct.pack_into(">I", rom, pid_base,     0x00805400 | a)
    # PID 0x81
    struct.pack_into(">I", rom, pid_base + 4, 0x00805400 | ((a + 1) & 0xFF))
    # PID 0x82
    struct.pack_into(">I", rom, pid_base + 8, 0x00805400 | ((a + 3) & 0xFF))
    return bytes(rom)


def test_find_mut_table_known_colt_address():
    rom = _make_rom_with_mut_table(0x3b4f4)
    result = _find_mut_table(rom)
    assert result == 0x3b4f4


def test_find_mut_table_outlander_address():
    rom = _make_rom_with_mut_table(0x39bf4)
    result = _find_mut_table(rom)
    assert result == 0x39bf4


def test_find_mut_table_no_match_returns_none():
    rom = bytes(0x80000)
    assert _find_mut_table(rom) is None


def test_find_mut_table_wrong_prefix_no_match():
    """Entries that start with 0x01 0x80 instead of 0x00 0x80 should not match."""
    rom = bytearray(0x80000)
    pid_base = 0x3b6f4
    struct.pack_into(">I", rom, pid_base,     0x01805486)
    struct.pack_into(">I", rom, pid_base + 4, 0x01805487)
    struct.pack_into(">I", rom, pid_base + 8, 0x01805489)
    assert _find_mut_table(bytes(rom)) is None


def test_find_mut_table_wrong_gap_no_match():
    """A+2 gap (not A+3) should not match."""
    rom = bytearray(0x80000)
    pid_base = 0x3b6f4
    struct.pack_into(">I", rom, pid_base,     0x00805486)
    struct.pack_into(">I", rom, pid_base + 4, 0x00805487)
    struct.pack_into(">I", rom, pid_base + 8, 0x00805488)  # A+2, not A+3
    assert _find_mut_table(bytes(rom)) is None


# ---------------------------------------------------------------------------
# bootstrap_anchors
# ---------------------------------------------------------------------------

def test_bootstrap_vector_table_single_callee():
    """Reset handler with one callee → main anchor at 1.0 similarity."""
    reset_ref = 0x1000
    reset_new = 0x0800
    main_ref  = 0x2000
    main_new  = 0x1800

    ref_bytes = bytearray(0x80000)
    new_bytes = bytearray(0x40000)
    struct.pack_into(">I", ref_bytes, 0, reset_ref)
    struct.pack_into(">I", new_bytes, 0, reset_new)

    ref_run = _make_run(
        [reset_ref, main_ref, main_ref + 0x500],
        callees={reset_ref: [main_ref]},
    )
    new_run = _make_run(
        [reset_new, main_new, main_new + 0x500],
        callees={reset_new: [main_new]},
    )

    anchors = bootstrap_anchors(bytes(ref_bytes), bytes(new_bytes),
                                ref_run, new_run, ref_symbols_by_name={})
    names = {a.ref_name for a in anchors}
    assert "reset_interrupt_handler" in names
    assert "main" in names
    main_anchor = next(a for a in anchors if a.ref_name == "main")
    assert main_anchor.ref_address == main_ref
    assert main_anchor.new_address == main_new
    assert main_anchor.similarity == 1.0
    assert main_anchor.source == "vector_table"


def test_bootstrap_vector_table_multi_callee_picks_largest():
    """Multiple callees → largest by size is chosen as main."""
    reset_ref = 0x1000
    reset_new = 0x0800

    ref_bytes = bytearray(0x80000)
    new_bytes = bytearray(0x40000)
    struct.pack_into(">I", ref_bytes, 0, reset_ref)
    struct.pack_into(">I", new_bytes, 0, reset_new)

    # ref: reset → [small_helper=0x1100 (size 0x10), main=0x1200 (size 0x500)]
    ref_run = _make_run(
        [reset_ref, 0x1100, 0x1110, 0x1200, 0x1700],
        callees={reset_ref: [0x1100, 0x1200]},
    )
    # new: reset → [small_helper=0x900 (size 0x10), main=0xA00 (size 0x500)]
    new_run = _make_run(
        [reset_new, 0x900, 0x910, 0xA00, 0xF00],
        callees={reset_new: [0x900, 0xA00]},
    )

    anchors = bootstrap_anchors(bytes(ref_bytes), bytes(new_bytes),
                                ref_run, new_run, ref_symbols_by_name={})
    main_anchor = next((a for a in anchors if a.ref_name == "main"), None)
    assert main_anchor is not None
    assert main_anchor.ref_address == 0x1200
    assert main_anchor.new_address == 0xA00
    assert main_anchor.similarity == 0.9  # degraded: multiple candidates


def test_bootstrap_bad_reset_vector_skipped():
    """Reset vector pointing outside ROM range produces no anchors."""
    ref_bytes = bytearray(0x1000)
    new_bytes = bytearray(0x1000)
    struct.pack_into(">I", ref_bytes, 0, 0xDEADBEEF)  # way out of range
    struct.pack_into(">I", new_bytes, 0, 0xDEADBEEF)

    ref_run = _make_run([0x100, 0x200])
    new_run = _make_run([0x100, 0x200])
    anchors = bootstrap_anchors(bytes(ref_bytes), bytes(new_bytes),
                                ref_run, new_run, ref_symbols_by_name={})
    assert anchors == []


# ---------------------------------------------------------------------------
# bfs_preseed
# ---------------------------------------------------------------------------

def test_bfs_preseed_depth_limit():
    """BFS must not descend more than MAX_BFS_DEPTH=3 hops."""
    # Build a chain: anchor → f1 → f2 → f3 → f4 (depth 4, should be excluded)
    ref_run = _make_run(
        [0x100, 0x200, 0x300, 0x400, 0x500, 0x600],
        callees={
            0x100: [0x200],
            0x200: [0x300],
            0x300: [0x400],
            0x400: [0x500],   # depth 4 from anchor
        },
    )
    new_run = _make_run(
        [0x100, 0x200, 0x300, 0x400, 0x500, 0x600],
        callees={
            0x100: [0x200],
            0x200: [0x300],
            0x300: [0x400],
            0x400: [0x500],
        },
    )

    from rom_analyzer.types import ReferenceSymbol
    ref_symbols_by_addr = {
        addr: ReferenceSymbol(f"fn_{addr:x}", addr, "function")
        for addr in [0x100, 0x200, 0x300, 0x400, 0x500]
    }

    anchor = MatchedFunction("anchor", 0x100, 0x100, 1.0, "vector_table")
    overlays, matches = bfs_preseed([anchor], ref_run, new_run, ref_symbols_by_addr)

    discovered = {m.ref_address for m in matches}
    # Depth 1: 0x200 ✓, Depth 2: 0x300 ✓, Depth 3: 0x400 ✓, Depth 4: 0x500 ✗
    assert 0x200 in discovered
    assert 0x300 in discovered
    assert 0x400 in discovered
    assert 0x500 not in discovered


def test_bfs_preseed_produces_overlays_only_for_named():
    """Overlay symbols only emitted when ref symbol has a name."""
    ref_run = _make_run(
        [0x100, 0x200, 0x300],
        callees={0x100: [0x200, 0x300]},
    )
    new_run = _make_run(
        [0x100, 0x200, 0x300],
        callees={0x100: [0x200, 0x300]},
    )

    # Only 0x200 has a named symbol; 0x300 is unnamed
    ref_symbols_by_addr = {
        0x200: ReferenceSymbol("init_hw", 0x200, "function"),
    }
    anchor = MatchedFunction("main", 0x100, 0x100, 1.0, "vector_table")
    overlays, matches = bfs_preseed([anchor], ref_run, new_run, ref_symbols_by_addr)

    assert len(overlays) == 1
    assert overlays[0].name == "init_hw"
    assert overlays[0].address == 0x200  # new ROM address
    # Unnamed function still visited (queued) but produces no overlay
    assert len(matches) == 1


# ---------------------------------------------------------------------------
# gap_fill
# ---------------------------------------------------------------------------

def test_gap_fill_basic():
    """Caller matched → its unmatched callee gets filled."""
    ref_run = _make_run(
        [0x100, 0x200, 0x300, 0x400],
        callees={0x100: [0x200, 0x300]},
    )
    new_run = _make_run(
        [0x100, 0x200, 0x300, 0x400],
        callees={0x100: [0x200, 0x300]},
    )
    existing = [
        MatchedFunction("main", 0x100, 0x100, 1.0, "vector_table"),
        MatchedFunction("init_hw", 0x200, 0x200, 0.9, "ghidriff"),
        # 0x300 not matched yet
    ]
    results = gap_fill(ref_run, new_run, existing)
    assert any(m.ref_address == 0x300 and m.new_address == 0x300 for m in results)


def test_gap_fill_iterative():
    """Gap-fill propagates through multiple layers in successive iterations."""
    ref_run = _make_run(
        [0x100, 0x200, 0x300, 0x400, 0x500],
        callees={
            0x100: [0x200],
            0x200: [0x300],
            0x300: [0x400],
        },
    )
    new_run = _make_run(
        [0x100, 0x200, 0x300, 0x400, 0x500],
        callees={
            0x100: [0x200],
            0x200: [0x300],
            0x300: [0x400],
        },
    )
    existing = [MatchedFunction("main", 0x100, 0x100, 1.0, "vector_table")]
    results = gap_fill(ref_run, new_run, existing)
    matched_ref = {m.ref_address for m in results}
    assert 0x200 in matched_ref
    assert 0x300 in matched_ref
    assert 0x400 in matched_ref


def test_gap_fill_no_double_match():
    """A new_address already matched must not be claimed a second time."""
    ref_run = _make_run(
        [0x100, 0x200, 0x300, 0x400],
        callees={
            0x100: [0x200, 0x300],
        },
    )
    new_run = _make_run(
        [0x100, 0x200, 0x300, 0x400],
        callees={
            0x100: [0x200, 0x300],
        },
    )
    existing = [
        MatchedFunction("main", 0x100, 0x100, 1.0, "vector_table"),
        MatchedFunction("init_hw", 0x200, 0x200, 1.0, "ghidriff"),
        # 0x300 already occupies new_address=0x300 by another ref
        MatchedFunction("other", 0x999, 0x300, 1.0, "ghidriff"),
    ]
    results = gap_fill(ref_run, new_run, existing)
    # ref 0x300 should not be matched to new 0x300 (already taken)
    assert not any(m.new_address == 0x300 and m.ref_address == 0x300 for m in results)


def test_gap_fill_source_tag():
    ref_run = _make_run([0x100, 0x200, 0x300], callees={0x100: [0x200]})
    new_run = _make_run([0x100, 0x200, 0x300], callees={0x100: [0x200]})
    existing = [MatchedFunction("main", 0x100, 0x100, 1.0, "vector_table")]
    results = gap_fill(ref_run, new_run, existing)
    assert all(m.source == "callgraph_gap" for m in results)
