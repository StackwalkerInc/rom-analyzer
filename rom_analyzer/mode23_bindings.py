"""Resolve mode-0x23 code splice sites by instruction anchoring.

The function-entry and RAM binding symbols (canrx12_15_process,
can0_slot5_tx_update, sio0_* buffers, canrx12_data, cantx5_data0) already ride
the normal reference-XML propagation pipeline.  Only the two mid-function call
sites the patch hijacks need anchoring, because nothing references a mid-stream
code address as data.
"""

from dataclasses import dataclass

from rom_analyzer.types import ConfidenceTier


@dataclass(frozen=True)
class SpliceResolution:
    address: int | None
    confidence: ConfidenceTier


def resolve_unique_site(sites: list[int]) -> SpliceResolution:
    """Resolve a splice from candidate addresses where exactly one is expected.

    Exactly one (after de-dup) -> high. More than one -> low (lowest address;
    a human disambiguates). None -> unresolved, low.
    """
    s = sorted(set(sites))
    if len(s) == 1:
        return SpliceResolution(address=s[0], confidence="high")
    if len(s) > 1:
        return SpliceResolution(address=s[0], confidence="low")
    return SpliceResolution(address=None, confidence="low")


def decode_ldi_r0_before(rom: bytes, call_site: int, max_back: int = 12) -> int | None:
    """Return the #imm of the nearest `ldi r0,#imm8` preceding `call_site`.

    M32R 16-bit `ldi Rdest,#imm8` is `0110 dddd iiii iiii`; for r0 the first byte
    is 0x60 and the second is the immediate. Scans backward in 2-byte steps up to
    `max_back` bytes. Returns None if no `ldi r0` is found. Raw-byte fallback for
    when the Ghidra listing path (fetch_r0_imm_before) yields nothing.
    """
    lo = max(call_site - max_back, 0)
    for off in range(call_site - 2, lo - 1, -2):
        if off + 1 >= len(rom):
            continue
        if rom[off] == 0x60:  # ldi r0,#imm8
            return rom[off + 1]
    return None


def resolve_nearest_site(sites: list[int], expected: int) -> SpliceResolution:
    """Resolve a splice from candidates, preferring the one nearest `expected`.

    Exact hit on `expected` -> high. Exactly one candidate -> high. Multiple with
    no exact hit -> the nearest (ties broken by lower address), medium confidence.
    None -> unresolved, low.
    """
    s = sorted(set(sites))
    if not s:
        return SpliceResolution(address=None, confidence="low")
    if expected in s:
        return SpliceResolution(address=expected, confidence="high")
    if len(s) == 1:
        return SpliceResolution(address=s[0], confidence="high")
    nearest = min(s, key=lambda a: (abs(a - expected), a))
    return SpliceResolution(address=nearest, confidence="medium")
