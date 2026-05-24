"""Propagate symbols from a reference Ghidra DB to a new ROM via VT diff matches.

v1 handles function-entry labels only. Data label and RAM global propagation
require Ghidra disassembly context and is handled at integration time in cli.py.
"""

from rom_analyzer.types import (
    ConfidenceTier,
    MatchedFunction,
    PropagatedSymbol,
    ReferenceSymbol,
)


HIGH_THRESHOLD = 0.95
MEDIUM_THRESHOLD = 0.70


def tier_for_score(score: float) -> ConfidenceTier:
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"


def propagate_function_labels(
    ref_symbols: list[ReferenceSymbol],
    matches: list[MatchedFunction],
    force: bool = False,
) -> list[PropagatedSymbol]:
    """For each high/medium-confidence match, emit a PropagatedSymbol for the
    function-entry label. Low-confidence matches are skipped unless force=True.
    """
    by_addr = {s.address: s for s in ref_symbols if s.category == "function"}

    out: list[PropagatedSymbol] = []
    for m in matches:
        sym = by_addr.get(m.ref_address)
        # ref_name is the canonical name set at match time.  Prefer it over
        # sym.name so that vector_table matches emit "main" rather than the
        # Ghidra auto-generated "FUN_0001b810" that would be in ref_symbols.
        # Fall back to sym.name only when ref_name is blank.
        name = m.ref_name or (sym.name if sym is not None else None)
        if not name:
            continue
        tier = tier_for_score(m.similarity)
        if tier == "low" and not force:
            continue
        out.append(
            PropagatedSymbol(
                name=name,
                ref_address=m.ref_address,
                new_address=m.new_address,
                category="function",
                confidence=tier,
            )
        )
    return out
