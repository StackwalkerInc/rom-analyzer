"""Tests for SID-based CAN slot enrichment (pure logic; no Ghidra)."""

from rom_analyzer.can_slots import (
    CAN_SID_NAMES,
    CanSlot,
    analyze_can_slots,
    decode_can_sids,
    find_ld24_immediates,
    locate_sid_tables,
    propose_handler_name,
    sid_semantic,
)


def _encode_sid_tables(sid0_addr, sid1_addr, sids, size):
    """Build a ROM bytearray with sid0/sid1 expected-value tables for `sids`."""
    rom = bytearray(b"\x00" * size)
    for i, sid in enumerate(sids):
        rom[sid0_addr + i] = (sid >> 6) & 0x1F
        rom[sid1_addr + i] = sid & 0x3F
    return rom


# ---- decode_can_sids ----

def test_decode_sid_formula():
    # SID = (sid0 & 0x1f) << 6 | (sid1 & 0x3f); slot0 = 0x04,0x39 -> 0x139
    rom = _encode_sid_tables(0x100, 0x200, [0x139, 0x13d, 0x231], 0x300)
    got = decode_can_sids(rom, 0x100, 0x200, count=3)
    assert got == [(0, 0x139), (1, 0x13d), (2, 0x231)]


def test_decode_masks_high_bits():
    rom = bytearray(b"\x00" * 0x300)
    rom[0x100] = 0xE4  # high bits should be masked: 0xE4 & 0x1f = 0x04
    rom[0x200] = 0xF9  # 0xf9 & 0x3f = 0x39
    assert decode_can_sids(rom, 0x100, 0x200, count=1) == [(0, 0x139)]


# ---- sid_semantic ----

def test_sid_semantic_known_and_unknown():
    assert sid_semantic(0x231) == "abs"
    assert sid_semantic(0x2f1) == "eps"
    assert sid_semantic(0x300) == "asc"
    assert sid_semantic(0x443) == "ac"
    assert sid_semantic(0x570) is None  # decoded but no known semantic


def test_sid_dictionary_has_core_messages():
    for sid in (0x139, 0x13d, 0x14d, 0x231, 0x2f1, 0x300, 0x443):
        assert sid in CAN_SID_NAMES


# ---- find_ld24_immediates ----

def test_find_ld24_immediates():
    # ld24 r5,0x11924 = e5 01 19 24 ; ld24 r0,0x11cf4 = e0 01 1c f4
    blob = bytes.fromhex("e5011924") + bytes.fromhex("e0011cf4") + bytes.fromhex("00000000")
    rom = bytearray(0x20000)
    rom[0x100:0x100 + len(blob)] = blob
    imms = find_ld24_immediates(bytes(rom), 0x100, window=len(blob))
    assert 0x11924 in imms and 0x11cf4 in imms


# ---- locate_sid_tables (brute-force pick by known-SID hit count) ----

def test_locate_sid_tables_picks_value_pair_over_pointer_pair():
    size = 0x20000
    rom = bytearray(size)
    # real value tables (decode to known SIDs)
    sid0_v, sid1_v = 0x11cf4, 0x11d04
    real = [0x139, 0x13d, 0x14d, 0x152, 0x231, 0x2f1]
    for i, s in enumerate(real):
        rom[sid0_v + i] = (s >> 6) & 0x1F
        rom[sid1_v + i] = s & 0x3F
    # decoy pointer tables (decode to junk)
    sid0_p, sid1_p = 0x11924, 0x11964
    for i in range(6):
        rom[sid0_p + i] = 0x80
        rom[sid1_p + i] = 0x11
    # function blob with all four ld24s
    fn = 0x19ea4
    for off, addr in ((0, sid0_p), (4, sid0_v), (8, sid1_p), (12, sid1_v)):
        rom[fn + off] = 0xE0
        rom[fn + off + 1 : fn + off + 4] = addr.to_bytes(3, "big")
    a, b, score = locate_sid_tables(bytes(rom), fn, count=6)
    assert (a, b) == (sid0_v, sid1_v)
    assert score >= 4  # at least 4 of the 6 are known SIDs


# ---- analyze_can_slots (end-to-end pure) ----

def test_analyze_can_slots_attaches_semantics_and_handlers():
    size = 0x20000
    rom = bytearray(size)
    sid0_v, sid1_v = 0x11cf4, 0x11d04
    sids = [0x139, 0x231, 0x570]  # apps_tps, abs, unknown
    for i, s in enumerate(sids):
        rom[sid0_v + i] = (s >> 6) & 0x1F
        rom[sid1_v + i] = s & 0x3F
    fn = 0x19ea4
    rom[fn] = 0xE0; rom[fn + 1 : fn + 4] = sid0_v.to_bytes(3, "big")
    rom[fn + 4] = 0xE0; rom[fn + 5 : fn + 8] = sid1_v.to_bytes(3, "big")
    handlers = {0: (0x48800, None), 1: (0x48ef0, None), 2: (0x48f50, 0x48a00)}
    slots = analyze_can_slots(bytes(rom), fn, handlers, count=3)
    by_slot = {s.slot: s for s in slots}
    assert by_slot[0].sid == 0x139 and by_slot[0].semantic == "apps_tps"
    assert by_slot[1].sid == 0x231 and by_slot[1].semantic == "abs"
    assert by_slot[1].rx_handler == 0x48ef0
    assert by_slot[2].sid == 0x570 and by_slot[2].semantic is None
    assert by_slot[2].tx_handler == 0x48a00


# ---- propose_handler_name ----

def test_propose_handler_name():
    assert propose_handler_name(7, "abs", "rx") == "can0_slot7_abs_rx_update"
    assert propose_handler_name(11, None, "rx") == "can0_slot11_rx_update"
    assert propose_handler_name(2, "dash_revolutions_odometer_coolant", "tx") == \
        "can0_slot2_dash_revolutions_odometer_coolant_tx_update"


# ---- emit_can_slots_toml ----

def test_emit_can_slots_toml():
    import tomllib
    from rom_analyzer.emit_ld import emit_can_slots_toml
    slots = [
        CanSlot(slot=7, sid=0x231, semantic="abs", rx_handler=0x48ef0, tx_handler=None),
        CanSlot(slot=11, sid=0x570, semantic=None, rx_handler=0x48f50, tx_handler=None),
    ]
    data = tomllib.loads(emit_can_slots_toml(slots))
    rows = {r["slot"]: r for r in data["slot"]}
    assert rows[7]["sid"] == "0x231" and rows[7]["semantic"] == "abs"
    assert rows[7]["rx_name"] == "can0_slot7_abs_rx_update"
    assert "semantic" not in rows[11]              # unknown SID -> no semantic
    assert rows[11]["rx_name"] == "can0_slot11_rx_update"
