"""Propagate symbols from a reference Ghidra DB to a new ROM via ghidriff matches.

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
        if sym is None:
            continue
        tier = tier_for_score(m.similarity)
        if tier == "low" and not force:
            continue
        out.append(
            PropagatedSymbol(
                name=sym.name,
                ref_address=m.ref_address,
                new_address=m.new_address,
                category="function",
                confidence=tier,
            )
        )
    return out
