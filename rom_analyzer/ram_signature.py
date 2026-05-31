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
    already_ref = {m.ref_address for m in existing_matches}
    already_new = {m.new_address for m in existing_matches}

    # ref_addr → [(jaccard, new_addr)]
    ref_candidates: dict[int, list[tuple[float, int]]] = {}
    for ref_addr, ref_sig in ref_sigs.items():
        if ref_addr in already_ref:
            continue
        for new_addr, new_sig in new_sigs.items():
            if new_addr in already_new:
                continue
            shared = ref_sig & new_sig
            if len(shared) < min_shared:
                continue
            j = len(shared) / len(ref_sig | new_sig)
            if j < min_jaccard:
                continue
            ref_candidates.setdefault(ref_addr, []).append((j, new_addr))

    # Resolve ref-side ties → new_addr → [(best_jaccard, ref_addr)]
    new_to_best: dict[int, list[tuple[float, int]]] = {}
    for ref_addr, cands in ref_candidates.items():
        best_j = max(j for j, _ in cands)
        best_new = [na for j, na in cands if j == best_j]
        if len(best_new) > 1:
            continue  # ambiguous: multiple new funcs tied for this ref func
        new_addr = best_new[0]
        new_to_best.setdefault(new_addr, []).append((best_j, ref_addr))

    results: list[MatchedFunction] = []
    for new_addr, ref_cands in new_to_best.items():
        best_j = max(j for j, _ in ref_cands)
        best_refs = [ra for j, ra in ref_cands if j == best_j]
        if len(best_refs) > 1:
            continue  # ambiguous: multiple ref funcs tied for this new func
        ref_addr = best_refs[0]
        sym = ref_symbols_by_addr.get(ref_addr)
        ref_name = sym.name if sym else f"FUN_{ref_addr:08x}"
        results.append(MatchedFunction(
            ref_name=ref_name,
            ref_address=ref_addr,
            new_address=new_addr,
            similarity=best_j,
            source="ram_signature",
        ))

    return results
