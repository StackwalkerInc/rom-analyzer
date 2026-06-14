"""SID-based CAN slot enrichment.

The Mitsubishi M32R ECUs configure 16 CAN0 receive/transmit mailboxes ("slots").
Each slot's 11-bit standard identifier (SID) is held in two flash byte tables
that `can0_slot_check_sid(slot)` validates against the live mailbox registers:

    SID = (sid0_table[slot] & 0x1f) << 6 | (sid1_table[slot] & 0x3f)

The slot *index* shifts between ROM revisions/families (e.g. the ABS message
0x231 is slot 7 on 33520003 but slot 8 on 30200003), but the SID is stable and
its meaning is public (ABS, EPS, ASC, AC, ...). This module decodes a ROM's
per-slot SIDs and assigns semantic names by SID — the reliable cross-ROM key —
rather than by handler bytecode (which produces false friends, since every
`can0_slotN_rx_update` handler shares the same code shape).

All logic here is pure: given `can0_slot_check_sid`'s entry address, the SID
tables and values are read straight from the ROM bytes. The two flash table
addresses are recovered from the function's `ld24` immediates and disambiguated
by brute force (the correct pair decodes to the most known SIDs).
"""

from __future__ import annotations

from dataclasses import dataclass

# SID -> semantic name (direction-agnostic; the rx/tx handler supplies direction).
# Sourced from the hand-decoded 33520003 can.txt message map.
CAN_SID_NAMES: dict[int, str] = {
    0x139: "apps_tps",
    0x13d: "rpm",
    0x14d: "dash_revolutions_odometer_coolant",
    0x152: "trip_computer",
    0x159: "engine_flaggy",
    0x210: "rpm_apps",
    0x312: "asc_torques",
    0x7e8: "obd_tool",   # engine -> tool (tx)
    0x7e0: "obd_tool",   # tool -> engine (rx)
    0x1b1: "engine_rx_1b1",
    0x231: "abs",
    0x2f1: "eps",
    0x300: "asc",
    0x443: "ac",
}


@dataclass
class CanSlot:
    slot: int
    sid: int
    semantic: str | None
    rx_handler: int | None = None
    tx_handler: int | None = None


def decode_can_sids(
    rom_bytes: bytes, sid0_addr: int, sid1_addr: int, count: int = 16
) -> list[tuple[int, int]]:
    """Decode `count` per-slot SIDs from the two flash byte tables."""
    out: list[tuple[int, int]] = []
    for slot in range(count):
        if sid0_addr + slot >= len(rom_bytes) or sid1_addr + slot >= len(rom_bytes):
            break
        sid0 = rom_bytes[sid0_addr + slot] & 0x1F
        sid1 = rom_bytes[sid1_addr + slot] & 0x3F
        out.append((slot, (sid0 << 6) | sid1))
    return out


def sid_semantic(sid: int) -> str | None:
    """Return the known semantic name for a CAN SID, or None."""
    return CAN_SID_NAMES.get(sid)


def find_ld24_immediates(
    rom_bytes: bytes, func_addr: int, window: int = 0x80
) -> list[int]:
    """Collect M32R `ld24` immediates within `window` bytes of `func_addr`.

    `ld24 Rd, #imm24` is a 32-bit, word-aligned instruction encoded as
    0xE0|reg in the top byte followed by a big-endian 24-bit immediate.
    Returns flash-range immediates (< len(rom)) in encounter order, de-duped.
    """
    imms: list[int] = []
    seen: set[int] = set()
    end = min(func_addr + window, len(rom_bytes) - 3)
    for off in range(func_addr, end, 4):
        if (rom_bytes[off] & 0xF0) == 0xE0:
            imm = int.from_bytes(rom_bytes[off + 1 : off + 4], "big")
            if imm < len(rom_bytes) and imm not in seen:
                seen.add(imm)
                imms.append(imm)
    return imms


def _score_table_pair(rom_bytes: bytes, a: int, b: int, count: int) -> int:
    """How many of the `count` SIDs decoded from (a, b) are known messages."""
    return sum(1 for _, sid in decode_can_sids(rom_bytes, a, b, count)
               if sid in CAN_SID_NAMES)


def locate_sid_tables(
    rom_bytes: bytes, check_sid_addr: int, count: int = 16
) -> tuple[int | None, int | None, int]:
    """Find the (sid0_table, sid1_table) addresses used by can0_slot_check_sid.

    Brute-forces ordered pairs of the function's ld24 immediates and returns the
    pair whose decoded SIDs match the most known messages. Self-validating: the
    pointer tables (which hold register addresses, not SID bytes) score ~0.
    Returns (sid0_addr, sid1_addr, score); (None, None, 0) if nothing scores.
    """
    imms = find_ld24_immediates(rom_bytes, check_sid_addr)
    best: tuple[int | None, int | None, int] = (None, None, 0)
    for a in imms:
        for b in imms:
            if a == b:
                continue
            score = _score_table_pair(rom_bytes, a, b, count)
            if score > best[2]:
                best = (a, b, score)
    return best


def analyze_can_slots(
    rom_bytes: bytes,
    check_sid_addr: int,
    slot_handlers: dict[int, tuple[int | None, int | None]] | None = None,
    count: int = 16,
) -> list[CanSlot]:
    """Decode per-slot SIDs, attach semantics and (optional) handler addresses.

    `slot_handlers` maps slot index -> (rx_handler_addr, tx_handler_addr).
    Returns an empty list if the SID tables can't be located.
    """
    sid0, sid1, _ = locate_sid_tables(rom_bytes, check_sid_addr, count)
    if sid0 is None or sid1 is None:
        return []
    handlers = slot_handlers or {}
    slots: list[CanSlot] = []
    for slot, sid in decode_can_sids(rom_bytes, sid0, sid1, count):
        rx, tx = handlers.get(slot, (None, None))
        slots.append(CanSlot(
            slot=slot, sid=sid, semantic=sid_semantic(sid),
            rx_handler=rx, tx_handler=tx,
        ))
    return slots


def propose_handler_name(slot: int, semantic: str | None, direction: str) -> str:
    """Suggest a semantic handler name, e.g. can0_slot7_abs_rx_update.

    Falls back to the plain can0_slot{N}_{dir}_update when the SID is unknown.
    """
    if semantic:
        return f"can0_slot{slot}_{semantic}_{direction}_update"
    return f"can0_slot{slot}_{direction}_update"
