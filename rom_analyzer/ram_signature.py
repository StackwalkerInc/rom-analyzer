"""RAM-signature function matching.

Matches unmatched functions by the set of named RAM variables they access.
"""

from rom_analyzer.data_refs import DataRef
from rom_analyzer.types import MatchedFunction, ReferenceSymbol


def build_ram_signatures(
    ram_data_refs_by_func: dict[int, list[DataRef]],
    label_map: dict[int, str],
) -> dict[int, frozenset[str]]:
    """Build RAM variable signatures for each function.

    Args:
        ram_data_refs_by_func: Mapping of function address to list of RAM data refs.
        label_map: Mapping of RAM address to variable name.

    Returns:
        Mapping of function address to frozenset of variable names accessed by that function.
        Functions accessing no labeled variables are excluded.
    """
    result: dict[int, frozenset[str]] = {}
    for func_addr, refs in ram_data_refs_by_func.items():
        names = frozenset(
            label_map[r.referenced_address]
            for r in refs
            if r.referenced_address in label_map
        )
        if names:
            result[func_addr] = names
    return result


def match_by_ram_signature(
    ref_sigs: dict[int, frozenset[str]],
    new_sigs: dict[int, frozenset[str]],
    existing_matches: list[MatchedFunction],
    ref_symbols_by_addr: dict[int, ReferenceSymbol],
    min_shared: int = 3,
    min_jaccard: float = 0.6,
) -> list[MatchedFunction]:
    """Match functions by RAM variable signature similarity.

    Args:
        ref_sigs: RAM signatures from reference ROM (func_addr -> set of var names).
        new_sigs: RAM signatures from new ROM (func_addr -> set of var names).
        existing_matches: Already-matched functions to exclude from signature matching.
        ref_symbols_by_addr: Reference symbols (for validation).
        min_shared: Minimum shared variables required to consider a match.
        min_jaccard: Minimum Jaccard similarity (0.0-1.0) for candidate matches.

    Returns:
        List of new MatchedFunction objects found by signature similarity.
    """
    raise NotImplementedError
