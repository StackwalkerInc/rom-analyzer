"""Cross-reference arbitration.

Merge matches and propagated symbols from multiple references into one result,
recording disagreements (different names proposed for the same target address).
"""

from __future__ import annotations

from dataclasses import dataclass

from rom_analyzer.types import MatchedFunction, PropagatedSymbol

# Structural ROM-invariant sources override bytecode-comparison matches; within
# a tier, higher similarity wins. (Moved here from cli.py so cli and the merge
# layer share one definition.)
SOURCE_PRIORITY = {
    "vector_table": 3, "icu_vector_table": 3,
    "bytecode_identity": 2, "mut_table": 2,
    "callgraph_bfs": 1, "callgraph_gap": 1, "vt_diff": 0,
}

CONFIDENCE_RANK = {
    "verified": 5, "high": 4, "medium": 3, "inferred": 2, "low": 1, "auto": 0,
}


def match_rank(m: MatchedFunction, priority: dict[str, int]) -> tuple:
    """Rank a match: source tier, then similarity, then registry priority."""
    return (SOURCE_PRIORITY.get(m.source, 0), m.similarity,
            priority.get(m.reference, 0))


def merge_matches(
    results: list[list[MatchedFunction]],
    priority: dict[str, int],
) -> list[MatchedFunction]:
    """Union all references' matches keyed by target new_address; keep the
    highest-ranked match at each address. Feeds the single-source passes
    (CRC/MUT/OBD/mode23), which only need the best match per target address."""
    best: dict[int, MatchedFunction] = {}
    for matches in results:
        for m in matches:
            if (m.new_address not in best
                    or match_rank(m, priority) > match_rank(best[m.new_address], priority)):
                best[m.new_address] = m
    return list(best.values())


@dataclass(frozen=True)
class Disagreement:
    new_address: int
    candidates: list[tuple[str, str]]   # (reference_id, name), sorted
    winner: str


def _symbol_rank(s: PropagatedSymbol, priority: dict[str, int]) -> tuple:
    return (CONFIDENCE_RANK.get(s.confidence, 0), priority.get(s.reference, 0), s.score)


def arbitrate_symbols(
    symbols: list[PropagatedSymbol],
    priority: dict[str, int],
) -> tuple[list[PropagatedSymbol], list[Disagreement]]:
    """Dedup propagated symbols by target new_address. Highest-ranked wins
    (confidence tier, then registry priority, then score). Addresses where
    references proposed DIFFERENT names are recorded as Disagreements.
    Agreement (same name from several references) is not a conflict."""
    by_addr: dict[int, list[PropagatedSymbol]] = {}
    for s in symbols:
        by_addr.setdefault(s.new_address, []).append(s)

    final: list[PropagatedSymbol] = []
    disagreements: list[Disagreement] = []
    for addr, group in sorted(by_addr.items()):
        winner = max(group, key=lambda s: _symbol_rank(s, priority))
        final.append(winner)
        if len({s.name for s in group}) > 1:
            disagreements.append(Disagreement(
                new_address=addr,
                candidates=sorted((s.reference, s.name) for s in group),
                winner=winner.name,
            ))
    return final, disagreements
