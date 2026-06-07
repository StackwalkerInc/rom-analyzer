"""Resolve mode-0x23 code splice sites by instruction anchoring.

The function-entry and RAM binding symbols (canrx12_15_process,
can0_slot5_tx_update, sio0_* buffers, canrx12_data, cantx5_data0) already ride
the normal reference-XML propagation pipeline.  Only the two mid-function call
sites the patch hijacks need anchoring, because nothing references a mid-stream
code address as data.

This module is pure (no Ghidra): the caller fetches call sites via
ghidra.fetch_call_sites and passes them here.
"""

from dataclasses import dataclass

from rom_analyzer.types import ConfidenceTier


@dataclass(frozen=True)
class CallSite:
    """A call instruction inside a function and its resolved target address."""
    address: int
    target: int


@dataclass(frozen=True)
class SpliceResolution:
    address: int | None
    confidence: ConfidenceTier


def resolve_splice_site(
    call_sites: list[CallSite],
    acceptable_targets: set[int],
) -> SpliceResolution:
    """Find the call whose target is one of acceptable_targets.

    Exactly one match  -> high confidence.
    More than one match -> low confidence (first by address; human verifies).
    No match / no targets -> unresolved, low confidence.
    """
    if not acceptable_targets:
        return SpliceResolution(address=None, confidence="low")

    hits = sorted(
        (cs for cs in call_sites if cs.target in acceptable_targets),
        key=lambda cs: cs.address,
    )
    if len(hits) == 1:
        return SpliceResolution(address=hits[0].address, confidence="high")
    if len(hits) > 1:
        return SpliceResolution(address=hits[0].address, confidence="low")
    return SpliceResolution(address=None, confidence="low")


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
