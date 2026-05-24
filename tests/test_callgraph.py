"""Unit tests for callgraph.py — all pure-Python, no Ghidra required."""

import struct

import pytest

from rom_analyzer.callgraph import (
    _bytecode_jaccard,
    _decode_bra_target,
    _find_dtc_table,
    _find_fault_bitmask_table,
    _find_mut_table,
    _find_unique_aligned,
    _func_size,
    _lcs_align,
    _size_ratio_ok,
    _DTC_INVARIANT,
    _DTC_INVARIANT_OFFSET,
    _FAULT_BITMASK,
    bootstrap_anchors,
    bfs_preseed,
    bytecode_identity_match,
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
# _bytecode_jaccard
# ---------------------------------------------------------------------------

def test_bytecode_jaccard_identical():
    body = bytes([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17])
    rom = _make_rom_with_functions({0x100: body, 0x200: body})
    assert _bytecode_jaccard(rom, 0x100, 8, rom, 0x200, 8) == 1.0


def test_bytecode_jaccard_disjoint():
    body_a = bytes([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17])
    body_b = bytes([0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7])
    ref_rom = _make_rom_with_functions({0x100: body_a})
    new_rom = _make_rom_with_functions({0x200: body_b})
    assert _bytecode_jaccard(ref_rom, 0x100, 8, new_rom, 0x200, 8) == 0.0


def test_bytecode_jaccard_partial_overlap():
    # 3 of 4 grams shared → Jaccard = 3/5 = 0.6
    body_a = bytes([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F])
    body_b = bytes([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1A, 0x1B, 0xF0, 0xF1, 0xF2, 0xF3])
    ref_rom = _make_rom_with_functions({0x100: body_a})
    new_rom = _make_rom_with_functions({0x200: body_b})
    assert _bytecode_jaccard(ref_rom, 0x100, 16, new_rom, 0x200, 16) == pytest.approx(3 / 5)


def test_bytecode_jaccard_zero_size_returns_neutral():
    rom = bytes(0x400)
    assert _bytecode_jaccard(rom, 0x100, 0, rom, 0x200, 8) == 0.5
    assert _bytecode_jaccard(rom, 0x100, 8, rom, 0x200, 0) == 0.5


# ---------------------------------------------------------------------------
# _decode_bra_target
# ---------------------------------------------------------------------------

def _encode_bra(target: int, pos: int = 0) -> bytes:
    """Encode an M32R 32-bit bra at instruction position pos targeting target."""
    disp24 = (target - pos) >> 2
    if disp24 < 0:
        disp24 &= 0xFFFFFF  # two's complement 24-bit
    return bytes([0xFF, (disp24 >> 16) & 0xFF, (disp24 >> 8) & 0xFF, disp24 & 0xFF])


def test_decode_bra_colt_reset():
    """Colt ROM: ff 00 6d a0 → 0x1b680 (reset_interrupt_handler)."""
    rom = bytearray(0x80000)
    rom[0:4] = b"\xff\x00\x6d\xa0"
    assert _decode_bra_target(bytes(rom), 0) == 0x1b680


def test_decode_bra_outlander_reset():
    """Outlander ROM: ff 00 4f 18 → 0x13c60 (reset_interrupt_handler)."""
    rom = bytearray(0x80000)
    rom[0:4] = b"\xff\x00\x4f\x18"
    assert _decode_bra_target(bytes(rom), 0) == 0x13c60


def test_decode_bra_roundtrip():
    """Encoding a target and decoding it returns the original target."""
    for target in (0x100, 0x1b680, 0x13c60, 0x7FFC):
        rom = bytearray(0x80000)
        rom[0:4] = _encode_bra(target)
        assert _decode_bra_target(bytes(rom), 0) == target


def test_decode_bra_not_ff_opcode():
    """If first byte is not 0xFF, returns None."""
    rom = bytearray(0x80000)
    rom[0:4] = b"\xDE\xAD\xBE\xEF"
    assert _decode_bra_target(bytes(rom), 0) is None


def test_decode_bra_target_out_of_range():
    """Target beyond ROM size returns None."""
    rom = bytearray(0x100)  # very small ROM
    rom[0:4] = b"\xff\x00\x6d\xa0"  # target 0x1b680 > 0x100
    assert _decode_bra_target(bytes(rom), 0) is None


def test_decode_bra_too_short():
    """Buffer too short to hold a 4-byte instruction returns None."""
    assert _decode_bra_target(b"\xff\x00\x01", 0) is None


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
    ref_bytes[0:4] = _encode_bra(reset_ref)
    new_bytes[0:4] = _encode_bra(reset_new)

    ref_run = _make_run(
        [reset_ref, main_ref, main_ref + 0x500],
        callees={reset_ref: [main_ref]},
    )
    new_run = _make_run(
        [reset_new, main_new, main_new + 0x500],
        callees={reset_new: [main_new]},
    )

    ref_syms_by_addr = {reset_ref: ReferenceSymbol("reset_interrupt_handler", reset_ref, "function")}
    anchors = bootstrap_anchors(bytes(ref_bytes), bytes(new_bytes),
                                ref_run, new_run, ref_symbols_by_name={},
                                ref_symbols_by_addr=ref_syms_by_addr)
    names = {a.ref_name for a in anchors}
    assert "reset_interrupt_handler" in names
    assert "main" in names
    main_anchor = next(a for a in anchors if a.ref_name == "main")
    assert main_anchor.ref_address == main_ref
    assert main_anchor.new_address == main_new
    assert main_anchor.similarity == 0.9
    assert main_anchor.source == "vector_table"


def test_bootstrap_vector_table_multi_callee_picks_largest():
    """Multiple callees → largest by size is chosen as main."""
    reset_ref = 0x1000
    reset_new = 0x0800

    ref_bytes = bytearray(0x80000)
    new_bytes = bytearray(0x40000)
    ref_bytes[0:4] = _encode_bra(reset_ref)
    new_bytes[0:4] = _encode_bra(reset_new)
    ref_syms_by_addr = {reset_ref: ReferenceSymbol("reset_interrupt_handler", reset_ref, "function")}

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
                                ref_run, new_run, ref_symbols_by_name={},
                                ref_symbols_by_addr=ref_syms_by_addr)
    main_anchor = next((a for a in anchors if a.ref_name == "main"), None)
    assert main_anchor is not None
    assert main_anchor.ref_address == 0x1200
    assert main_anchor.new_address == 0xA00
    assert main_anchor.similarity == 0.9  # degraded: multiple candidates


def test_bootstrap_bad_reset_vector_skipped():
    """No bra instruction at offset 0 produces no anchors."""
    ref_bytes = bytearray(0x1000)  # all zeros — first byte 0x00, not 0xFF
    new_bytes = bytearray(0x1000)

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
# bfs_preseed — bytecode gate
# ---------------------------------------------------------------------------

def test_bfs_preseed_rejects_dissimilar_callees():
    """BFS must not pair callees whose bytecodes are completely unrelated."""
    ref_body = bytes([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F])
    new_body = bytes([0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
                      0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF])
    ref_bytes = _make_rom_with_functions({0x100: bytes(16), 0x200: ref_body})
    new_bytes = _make_rom_with_functions({0x100: bytes(16), 0x200: new_body})

    ref_run = _make_run([0x100, 0x200, 0x210], callees={0x100: [0x200]})
    new_run = _make_run([0x100, 0x200, 0x210], callees={0x100: [0x200]})
    ref_symbols_by_addr = {0x200: ReferenceSymbol("target_func", 0x200, "function")}
    anchor = MatchedFunction("main", 0x100, 0x100, 1.0, "vector_table")

    _, matches_no_bytes = bfs_preseed([anchor], ref_run, new_run, ref_symbols_by_addr)
    assert len(matches_no_bytes) == 1  # without bytes: pair accepted (old behaviour)

    _, matches_with_bytes = bfs_preseed(
        [anchor], ref_run, new_run, ref_symbols_by_addr,
        ref_bytes=ref_bytes, new_bytes=new_bytes,
    )
    assert len(matches_with_bytes) == 0  # with bytes: rejected (Jaccard == 0)


def test_bfs_preseed_accepts_similar_callees():
    """BFS keeps callee pairs with ≥15% bytecode overlap."""
    shared   = bytes([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F])
    # One 4-byte gram differs → intersection 3, union 5, Jaccard = 0.6 ≥ 0.15
    similar  = bytes([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                      0x18, 0x19, 0x1A, 0x1B, 0xF0, 0xF1, 0xF2, 0xF3])
    ref_bytes = _make_rom_with_functions({0x100: bytes(16), 0x200: shared})
    new_bytes = _make_rom_with_functions({0x100: bytes(16), 0x200: similar})

    ref_run = _make_run([0x100, 0x200, 0x210], callees={0x100: [0x200]})
    new_run = _make_run([0x100, 0x200, 0x210], callees={0x100: [0x200]})
    ref_symbols_by_addr = {0x200: ReferenceSymbol("target_func", 0x200, "function")}
    anchor = MatchedFunction("main", 0x100, 0x100, 1.0, "vector_table")

    _, matches = bfs_preseed(
        [anchor], ref_run, new_run, ref_symbols_by_addr,
        ref_bytes=ref_bytes, new_bytes=new_bytes,
    )
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
        MatchedFunction("init_hw", 0x200, 0x200, 0.9, "vt_diff"),
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
        MatchedFunction("init_hw", 0x200, 0x200, 1.0, "vt_diff"),
        # 0x300 already occupies new_address=0x300 by another ref
        MatchedFunction("other", 0x999, 0x300, 1.0, "vt_diff"),
    ]
    results = gap_fill(ref_run, new_run, existing)
    # ref 0x300 should not be matched to new 0x300 (already taken)
    assert not any(m.new_address == 0x300 and m.ref_address == 0x300 for m in results)


def test_gap_fill_rejects_dissimilar_callees():
    """Gap-fill must not pair callees whose bytecodes are completely unrelated."""
    ref_body = bytes([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F])
    new_body = bytes([0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
                      0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF])
    ref_bytes = _make_rom_with_functions({0x100: bytes(16), 0x200: ref_body})
    new_bytes = _make_rom_with_functions({0x100: bytes(16), 0x200: new_body})

    ref_run = _make_run([0x100, 0x200, 0x210], callees={0x100: [0x200]})
    new_run = _make_run([0x100, 0x200, 0x210], callees={0x100: [0x200]})
    existing = [MatchedFunction("main", 0x100, 0x100, 1.0, "vector_table")]

    results_no_bytes = gap_fill(ref_run, new_run, existing)
    assert any(m.ref_address == 0x200 for m in results_no_bytes)  # old behaviour

    results_with_bytes = gap_fill(ref_run, new_run, existing,
                                   ref_bytes=ref_bytes, new_bytes=new_bytes)
    assert not any(m.ref_address == 0x200 for m in results_with_bytes)  # rejected


def test_gap_fill_source_tag():
    ref_run = _make_run([0x100, 0x200, 0x300], callees={0x100: [0x200]})
    new_run = _make_run([0x100, 0x200, 0x300], callees={0x100: [0x200]})
    existing = [MatchedFunction("main", 0x100, 0x100, 1.0, "vector_table")]
    results = gap_fill(ref_run, new_run, existing)
    assert all(m.source == "callgraph_gap" for m in results)


# ---------------------------------------------------------------------------
# bootstrap_anchors — multi-entry vector table
# ---------------------------------------------------------------------------

def test_bootstrap_vector_table_multi_entry():
    """Multiple distinct ISR handlers in the vector table each get an anchor."""
    reset_ref  = 0x1000
    isr1_ref   = 0x2000
    isr2_ref   = 0x3000
    reset_new  = 0x0800
    isr1_new   = 0x1800
    isr2_new   = 0x2800

    ref_bytes = bytearray(0x80000)
    new_bytes = bytearray(0x80000)
    ref_bytes[0:4]  = _encode_bra(reset_ref,  pos=0)   # slot 0
    ref_bytes[4:8]  = _encode_bra(isr1_ref,   pos=4)   # slot 1
    ref_bytes[8:12] = _encode_bra(isr2_ref,   pos=8)   # slot 2
    new_bytes[0:4]  = _encode_bra(reset_new,  pos=0)
    new_bytes[4:8]  = _encode_bra(isr1_new,   pos=4)
    new_bytes[8:12] = _encode_bra(isr2_new,   pos=8)

    ref_syms_by_addr = {
        reset_ref: ReferenceSymbol("reset_interrupt_handler", reset_ref, "function"),
        isr1_ref:  ReferenceSymbol("timer_isr",               isr1_ref,  "function"),
        isr2_ref:  ReferenceSymbol("serial_isr",              isr2_ref,  "function"),
    }
    ref_run = _make_run([reset_ref, isr1_ref, isr2_ref, reset_ref + 0x8000])
    new_run = _make_run([reset_new, isr1_new, isr2_new, reset_new + 0x8000])

    anchors = bootstrap_anchors(bytes(ref_bytes), bytes(new_bytes),
                                ref_run, new_run, ref_symbols_by_name={},
                                ref_symbols_by_addr=ref_syms_by_addr)
    ref_names = {a.ref_name for a in anchors}
    assert "reset_interrupt_handler" in ref_names
    assert "timer_isr" in ref_names
    assert "serial_isr" in ref_names
    assert all(a.source == "vector_table" for a in anchors if a.ref_name != "main")


def test_bootstrap_vector_table_deduplicates_default_isr():
    """Multiple slots pointing to the same default ISR emit only one anchor."""
    reset_ref    = 0x1000
    default_ref  = 0x2000  # same handler in 5 slots
    reset_new    = 0x0800
    default_new  = 0x1800

    ref_bytes = bytearray(0x80000)
    new_bytes = bytearray(0x80000)
    ref_bytes[0:4] = _encode_bra(reset_ref)
    new_bytes[0:4] = _encode_bra(reset_new)
    for slot in range(1, 6):         # slots 1–5 all point to the same default
        pos = slot * 4
        ref_bytes[pos: pos + 4] = _encode_bra(default_ref, pos=pos)
        new_bytes[pos: pos + 4] = _encode_bra(default_new, pos=pos)

    ref_run = _make_run([reset_ref, default_ref, default_ref + 0x100])
    new_run = _make_run([reset_new, default_new, default_new + 0x100])

    anchors = bootstrap_anchors(bytes(ref_bytes), bytes(new_bytes),
                                ref_run, new_run, ref_symbols_by_name={},
                                ref_symbols_by_addr={})
    # default_isr should appear exactly once despite 5 slots pointing there
    default_anchors = [a for a in anchors if a.ref_address == default_ref]
    assert len(default_anchors) == 1


def test_bootstrap_vector_table_skips_chain_entries():
    """Entries targeting < 0x200 (vector-table self-references) are ignored."""
    reset_ref = 0x1000
    reset_new = 0x0800

    ref_bytes = bytearray(0x80000)
    new_bytes = bytearray(0x80000)
    ref_bytes[0:4] = _encode_bra(reset_ref)
    new_bytes[0:4] = _encode_bra(reset_new)
    # slot 1 → chain into vector table (target = 0x08, < 0x200)
    ref_bytes[4:8] = _encode_bra(0x08, pos=4)
    new_bytes[4:8] = _encode_bra(0x08, pos=4)

    ref_run = _make_run([reset_ref, reset_ref + 0x100])
    new_run = _make_run([reset_new, reset_new + 0x100])

    anchors = bootstrap_anchors(bytes(ref_bytes), bytes(new_bytes),
                                ref_run, new_run, ref_symbols_by_name={},
                                ref_symbols_by_addr={})
    # Chain entry at slot 1 must not produce an anchor
    ref_addrs = {a.ref_address for a in anchors}
    assert 0x08 not in ref_addrs


# ---------------------------------------------------------------------------
# bytecode_identity_match
# ---------------------------------------------------------------------------

def _make_rom_with_functions(func_map: dict[int, bytes], rom_size: int = 0x10000) -> bytes:
    """Build a ROM with known byte sequences at given function addresses."""
    rom = bytearray(rom_size)
    for addr, body in func_map.items():
        rom[addr: addr + len(body)] = body
    return bytes(rom)


def test_bytecode_identity_exact_match():
    """Identical function bytes at different addresses are matched even if the
    new function entry is not in new_run.functions (full-ROM scan)."""
    body = bytes([0x70, 0xE0, 0x00, 0x01,   # 8-byte synthetic function body
                  0x10, 0x00, 0x20, 0x03])
    ref_bytes = _make_rom_with_functions({0x1000: body})
    new_bytes = _make_rom_with_functions({0x2000: body})

    ref_run = _make_run([0x1000, 0x1000 + len(body)])
    new_run = _make_run([])          # new ROM: Ghidra detected no functions
    ref_syms_by_addr = {0x1000: ReferenceSymbol("my_func", 0x1000, "function")}

    results = bytecode_identity_match(
        ref_bytes, new_bytes, ref_run, new_run, [], ref_syms_by_addr
    )
    assert len(results) == 1
    assert results[0].ref_address == 0x1000
    assert results[0].new_address == 0x2000
    assert results[0].ref_name == "my_func"
    assert results[0].similarity == 1.0
    assert results[0].source == "bytecode_identity"


def test_bytecode_identity_ambiguous_skipped():
    """If the byte sequence appears at two aligned positions, it is not matched."""
    body = bytes([0x70, 0xE0, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])
    ref_bytes = _make_rom_with_functions({0x1000: body})
    # Place body at two 4-byte-aligned positions in new ROM
    new_bytes = _make_rom_with_functions({0x2000: body, 0x3000: body})

    ref_run = _make_run([0x1000, 0x1000 + len(body)])
    new_run = _make_run([])

    results = bytecode_identity_match(ref_bytes, new_bytes, ref_run, new_run, [], {})
    assert results == []


def test_bytecode_identity_skips_already_matched():
    """Functions already in existing_matches are not re-matched."""
    body = bytes([0x70, 0xE0, 0x00, 0x01, 0x10, 0x00, 0x20, 0x03])
    ref_bytes = _make_rom_with_functions({0x1000: body})
    new_bytes = _make_rom_with_functions({0x2000: body})

    ref_run = _make_run([0x1000, 0x1000 + len(body)])
    new_run = _make_run([0x2000, 0x2000 + len(body)])

    existing = [MatchedFunction("my_func", 0x1000, 0x2000, 0.9, "vt_diff")]
    results = bytecode_identity_match(ref_bytes, new_bytes, ref_run, new_run, existing, {})
    assert results == []


def test_bytecode_identity_min_size_respected():
    """Functions smaller than min_size are never matched (false-positive risk)."""
    tiny = bytes([0x70, 0xE0, 0x00, 0x01])  # 4 bytes
    ref_bytes = _make_rom_with_functions({0x1000: tiny})
    new_bytes = _make_rom_with_functions({0x2000: tiny})

    ref_run = _make_run([0x1000, 0x1000 + len(tiny)])
    new_run = _make_run([])

    results = bytecode_identity_match(
        ref_bytes, new_bytes, ref_run, new_run, [], {}, min_size=8
    )
    assert results == []


# ---------------------------------------------------------------------------
# _find_unique_aligned
# ---------------------------------------------------------------------------

def test_find_unique_aligned_found():
    haystack = bytearray(0x100)
    needle = bytes([0xAA, 0xBB, 0xCC, 0xDD])
    haystack[0x40:0x44] = needle   # 0x40 is 4-byte aligned
    assert _find_unique_aligned(bytes(haystack), needle) == 0x40


def test_find_unique_aligned_unaligned_not_counted():
    """Occurrence at unaligned offset is invisible."""
    haystack = bytearray(0x100)
    needle = bytes([0xAA, 0xBB, 0xCC, 0xDD])
    haystack[0x41:0x45] = needle   # 0x41 is NOT 4-byte aligned
    assert _find_unique_aligned(bytes(haystack), needle) is None


def test_find_unique_aligned_ambiguous():
    haystack = bytearray(0x100)
    needle = bytes([0xAA, 0xBB, 0xCC, 0xDD])
    haystack[0x10:0x14] = needle
    haystack[0x20:0x24] = needle
    assert _find_unique_aligned(bytes(haystack), needle) is None


def test_find_unique_aligned_not_found():
    haystack = bytes(0x100)
    assert _find_unique_aligned(haystack, bytes([0xFF, 0xFF, 0xFF, 0xFF])) is None


# ---------------------------------------------------------------------------
# _find_dtc_table / _find_fault_bitmask_table
# ---------------------------------------------------------------------------

def test_find_dtc_table_found():
    rom = bytearray(0x20000)
    base = 0x12948
    rom[base + _DTC_INVARIANT_OFFSET: base + _DTC_INVARIANT_OFFSET + len(_DTC_INVARIANT)] = _DTC_INVARIANT
    assert _find_dtc_table(bytes(rom)) == base


def test_find_dtc_table_not_found():
    rom = bytes(0x20000)
    assert _find_dtc_table(rom) is None


def test_find_dtc_table_ambiguous():
    rom = bytearray(0x30000)
    for base in (0x10000, 0x20000):
        rom[base + _DTC_INVARIANT_OFFSET: base + _DTC_INVARIANT_OFFSET + len(_DTC_INVARIANT)] = _DTC_INVARIANT
    assert _find_dtc_table(bytes(rom)) is None


def test_find_fault_bitmask_found():
    rom = bytearray(0x20000)
    addr = 0x12bf0
    rom[addr: addr + len(_FAULT_BITMASK)] = _FAULT_BITMASK
    assert _find_fault_bitmask_table(bytes(rom)) == addr


def test_find_fault_bitmask_not_found():
    assert _find_fault_bitmask_table(bytes(0x1000)) is None


def test_find_fault_bitmask_ambiguous():
    rom = bytearray(0x30000)
    for addr in (0x10000, 0x20000):
        rom[addr: addr + len(_FAULT_BITMASK)] = _FAULT_BITMASK
    assert _find_fault_bitmask_table(bytes(rom)) is None


# ---------------------------------------------------------------------------
# _bootstrap_dtc_bitmask (via bootstrap_anchors)
# ---------------------------------------------------------------------------

def _make_rom_with_dtc_and_bitmask(dtc_base: int, bitmask_addr: int,
                                    func_addr: int, rom_size: int = 0x20000) -> bytes:
    """Build a fake ROM with the DTC invariant and fault bitmask placed at known addresses,
    and a Ghidra-style data ref at func_addr pointing to dtc_base."""
    rom = bytearray(rom_size)
    rom[dtc_base + _DTC_INVARIANT_OFFSET:
        dtc_base + _DTC_INVARIANT_OFFSET + len(_DTC_INVARIANT)] = _DTC_INVARIANT
    rom[bitmask_addr: bitmask_addr + len(_FAULT_BITMASK)] = _FAULT_BITMASK
    return bytes(rom)


def test_bootstrap_dtc_bitmask_produces_anchor():
    from rom_analyzer.data_refs import DataRef

    ref_dtc_base = 0x12948
    ref_bitmask = 0x12bf0
    ref_handler = 0x5000
    ref_handler2 = 0x6000

    new_dtc_base = 0xc378
    new_bitmask = 0xc5e0
    new_handler = 0x4800
    new_handler2 = 0x5800

    ref_rom = _make_rom_with_dtc_and_bitmask(ref_dtc_base, ref_bitmask, ref_handler)
    new_rom = _make_rom_with_dtc_and_bitmask(new_dtc_base, new_bitmask, new_handler)

    ref_run = _make_run(
        [ref_handler, ref_handler2, ref_handler + 0x100],
        data_refs={
            ref_handler: [DataRef(0, ref_dtc_base, "flash_trouble_code_table")],
            ref_handler2: [DataRef(0, ref_bitmask, "fault_bitmask_table")],
        },
    )
    new_run = _make_run(
        [new_handler, new_handler2, new_handler + 0x100],
        data_refs={
            new_handler: [DataRef(0, new_dtc_base)],
            new_handler2: [DataRef(0, new_bitmask)],
        },
    )

    # Supply a ref ROM with no vector-table BRA instructions so only dtc_table anchors come through
    ref_rom_clean = bytearray(len(ref_rom))
    ref_rom_clean[ref_dtc_base + _DTC_INVARIANT_OFFSET:
                  ref_dtc_base + _DTC_INVARIANT_OFFSET + len(_DTC_INVARIANT)] = _DTC_INVARIANT
    ref_rom_clean[ref_bitmask: ref_bitmask + len(_FAULT_BITMASK)] = _FAULT_BITMASK

    new_rom_clean = bytearray(len(new_rom))
    new_rom_clean[new_dtc_base + _DTC_INVARIANT_OFFSET:
                  new_dtc_base + _DTC_INVARIANT_OFFSET + len(_DTC_INVARIANT)] = _DTC_INVARIANT
    new_rom_clean[new_bitmask: new_bitmask + len(_FAULT_BITMASK)] = _FAULT_BITMASK

    from rom_analyzer.types import ReferenceSymbol
    ref_sym = ReferenceSymbol("check_fault_codes", ref_handler, "function")
    ref_sym2 = ReferenceSymbol("fault_bitmask_lookup", ref_handler2, "function")
    ref_symbols_by_addr = {ref_handler: ref_sym, ref_handler2: ref_sym2}

    anchors = bootstrap_anchors(bytes(ref_rom_clean), bytes(new_rom_clean),
                                ref_run, new_run,
                                ref_symbols_by_name={},
                                ref_symbols_by_addr=ref_symbols_by_addr)

    dtc_anchors = [a for a in anchors if a.source == "dtc_table"]
    assert len(dtc_anchors) == 2
    handler_anchor = next(a for a in dtc_anchors if a.ref_address == ref_handler)
    assert handler_anchor.new_address == new_handler
    assert handler_anchor.ref_name == "check_fault_codes"
    bitmask_anchor = next(a for a in dtc_anchors if a.ref_address == ref_handler2)
    assert bitmask_anchor.new_address == new_handler2
