"""Call-graph-driven function matching to supplement ghidriff.

Four phases:
  bootstrap_anchors      – anchor pairs via full vector table + MUT table
  bfs_preseed            – BFS from anchors; produces overlays for the new ROM
                           before ghidriff runs, improving named-match output
  gap_fill               – iteratively fills ghidriff misses using structural position
  bytecode_identity_match – exact-bytecode hash match for small/unchanged functions
"""

import hashlib
import struct
from collections import deque

from rom_analyzer.ghidra import HeadlessRun
from rom_analyzer.types import MatchedFunction, ReferenceSymbol


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _func_size(entry: int, run: HeadlessRun) -> int:
    """Approximate function size as distance to next function entry."""
    entries = sorted(int(f["entry"], 16) for f in run.functions)
    try:
        idx = entries.index(entry)
    except ValueError:
        return 0
    if idx + 1 >= len(entries):
        return 0
    return entries[idx + 1] - entry


def _size_ratio_ok(ref_addr: int, new_addr: int,
                   ref_run: HeadlessRun, new_run: HeadlessRun,
                   tolerance: float = 0.4) -> bool:
    ref_sz = _func_size(ref_addr, ref_run)
    new_sz = _func_size(new_addr, new_run)
    if ref_sz == 0 or new_sz == 0:
        return True  # unknown size: don't reject
    return min(ref_sz, new_sz) / max(ref_sz, new_sz) >= (1.0 - tolerance)


def _name_for(addr: int, run: HeadlessRun) -> str | None:
    for s in run.symbols:
        if s.get("source") in ("USER_DEFINED", "ANALYSIS") and s.get("type") == "Function":
            if int(s["address"], 16) == addr:
                return s["name"]
    return None


def _lcs_align(ref_callees: list[int], new_callees: list[int],
               ref_run: HeadlessRun, new_run: HeadlessRun,
               size_tol: float = 0.4) -> list[tuple[int, int]]:
    """Align callee lists via LCS on size-ratio compatibility.

    Returns matched (ref_addr, new_addr) pairs in call-order. Items with no
    size-compatible partner (e.g. CAN init present in one ROM only) are skipped
    rather than causing downstream misalignment.
    """
    n, m = len(ref_callees), len(new_callees)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            if _size_ratio_ok(ref_callees[i - 1], new_callees[j - 1],
                              ref_run, new_run, size_tol):
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

    pairs: list[tuple[int, int]] = []
    i, j = n, m
    while i > 0 and j > 0:
        if _size_ratio_ok(ref_callees[i - 1], new_callees[j - 1],
                          ref_run, new_run, size_tol):
            pairs.append((ref_callees[i - 1], new_callees[j - 1]))
            i -= 1
            j -= 1
        elif dp[i - 1][j] >= dp[i][j - 1]:
            i -= 1
        else:
            j -= 1
    return list(reversed(pairs))


# ---------------------------------------------------------------------------
# Phase 1 — Bootstrap anchors
# ---------------------------------------------------------------------------

def _find_mut_table(rom_bytes: bytes) -> int | None:
    """Scan for the invariant PID-0x80..0x82 triplet; return the table base.

    The three consecutive 4-byte entries at table_base + 0x200 (PID 0x80–0x82)
    always contain big-endian RAM pointers with this pattern:
      [0x00, 0x80, X, A], [0x00, 0x80, X, A+1], [0x00, 0x80, X, A+3]

    The +3 gap (not +2) is the diagnostic: it encodes the uint16 boundary
    between rom_version0 (bytes A, A+1) and rom_version1 (bytes A+2, A+3),
    where PID 0x82 maps to the LOW byte of rom_version1 at A+3.
    """
    for candidate in range(0, len(rom_bytes) - 0x210, 4):
        base = candidate - 0x200
        if base < 0:
            continue
        e0 = rom_bytes[candidate:candidate + 4]
        e1 = rom_bytes[candidate + 4:candidate + 8]
        e2 = rom_bytes[candidate + 8:candidate + 12]
        if (e0[0] == 0x00 and e0[1] == 0x80
                and e1[0] == 0x00 and e1[1] == 0x80
                and e2[0] == 0x00 and e2[1] == 0x80
                and e1[2] == e0[2] and e2[2] == e0[2]
                and e1[3] == (e0[3] + 1) & 0xFF
                and e2[3] == (e0[3] + 3) & 0xFF):
            return base
    return None


def _find_handler_for_table(run: HeadlessRun, table_addr: int) -> int | None:
    """Return entry of the function whose data_refs include table_addr."""
    for func_entry, refs in run.data_refs.items():
        if any(r.referenced_address == table_addr for r in refs):
            return func_entry
    return None


def _decode_bra_target(rom_bytes: bytes, pos: int) -> int | None:
    """Decode an M32R 32-bit bra instruction at pos and return the target offset.

    M32R bra (GI-format): opcode 0xFF | disp24 (big-endian, 3 bytes).
    Target = pos + SignExt(disp24) << 2.
    Returns None if the byte at pos is not 0xFF (not a bra).
    """
    if pos + 4 > len(rom_bytes):
        return None
    if rom_bytes[pos] != 0xFF:
        return None
    disp24 = (rom_bytes[pos + 1] << 16) | (rom_bytes[pos + 2] << 8) | rom_bytes[pos + 3]
    if disp24 & 0x800000:
        disp24 -= 0x1000000
    target = pos + (disp24 << 2)
    if not (0 < target < len(rom_bytes)):
        return None
    return target


def _bootstrap_vector_table(ref_bytes: bytes, new_bytes: bytes,
                              ref_run: HeadlessRun, new_run: HeadlessRun,
                              ref_symbols_by_addr: dict,
                              ) -> list[MatchedFunction]:
    """Decode all 64 M32R vector table entries; emit one anchor per distinct handler pair.

    Entries that target < 0x200 are chain/stub entries pointing within the table
    itself and are skipped.  Duplicate handler addresses (e.g. the default ISR
    occupying slots 16–31) are deduplicated — only the first slot is emitted.
    """
    anchors: list[MatchedFunction] = []
    seen_ref: set[int] = set()
    seen_new: set[int] = set()

    for i in range(64):
        pos = i * 4
        ref_target = _decode_bra_target(ref_bytes, pos)
        new_target = _decode_bra_target(new_bytes, pos)
        if ref_target is None or new_target is None:
            continue
        # Skip chain entries that loop back within the vector table region.
        if ref_target < 0x200 or new_target < 0x200:
            continue
        # Skip duplicate handlers (same handler referenced by multiple vector slots).
        if ref_target in seen_ref or new_target in seen_new:
            continue
        seen_ref.add(ref_target)
        seen_new.add(new_target)

        sym = ref_symbols_by_addr.get(ref_target)
        name = sym.name if sym else _name_for(ref_target, ref_run) or f"isr_vector_{i:02d}"
        anchors.append(MatchedFunction(name, ref_target, new_target, 1.0, "vector_table"))

    if not anchors:
        return []

    # Derive main from reset handler's (slot 0) callees.
    reset_ref = anchors[0].ref_address
    reset_new = anchors[0].new_address
    ref_mains = ref_run.callees.get(reset_ref, [])
    new_mains = new_run.callees.get(reset_new, [])
    if ref_mains and new_mains:
        best_ref = max(ref_mains, key=lambda a: _func_size(a, ref_run))
        best_new = max(new_mains, key=lambda a: _func_size(a, new_run))
        if best_ref not in seen_ref and best_new not in seen_new:
            sim = 1.0 if (len(ref_mains) == 1 and len(new_mains) == 1) else 0.9
            anchors.append(MatchedFunction("main", best_ref, best_new, sim, "vector_table"))

    return anchors


def _bootstrap_mut_table(ref_bytes: bytes, new_bytes: bytes,
                          ref_run: HeadlessRun, new_run: HeadlessRun,
                          ref_symbols_by_name: dict,
                          ) -> list[MatchedFunction]:
    ref_sym = ref_symbols_by_name.get("flash_mut_variables_table")
    if ref_sym is None:
        return []

    new_table_addr = _find_mut_table(new_bytes)
    if new_table_addr is None:
        return []

    ref_handler = _find_handler_for_table(ref_run, ref_sym.address)
    new_handler = _find_handler_for_table(new_run, new_table_addr)
    if ref_handler is None or new_handler is None:
        return []

    name = _name_for(ref_handler, ref_run) or "get_mut_pointer"
    return [MatchedFunction(name, ref_handler, new_handler, 1.0, "mut_table")]


def bootstrap_anchors(ref_bytes: bytes, new_bytes: bytes,
                       ref_run: HeadlessRun, new_run: HeadlessRun,
                       ref_symbols_by_name: dict,
                       ref_symbols_by_addr: dict | None = None,
                       ) -> list[MatchedFunction]:
    """Phase 1: produce anchor pairs via full vector table and MUT variables table."""
    if ref_symbols_by_addr is None:
        ref_symbols_by_addr = {v.address: v for v in ref_symbols_by_name.values()}
    anchors = _bootstrap_vector_table(ref_bytes, new_bytes, ref_run, new_run,
                                      ref_symbols_by_addr)
    anchors += _bootstrap_mut_table(ref_bytes, new_bytes, ref_run, new_run,
                                     ref_symbols_by_name)
    return anchors


# ---------------------------------------------------------------------------
# Phase 2 — BFS pre-seed
# ---------------------------------------------------------------------------

_MAX_BFS_DEPTH = 3


def bfs_preseed(anchors: list[MatchedFunction],
                ref_run: HeadlessRun,
                new_run: HeadlessRun,
                ref_symbols_by_addr: dict,
                ) -> tuple[list[ReferenceSymbol], list[MatchedFunction]]:
    """Phase 2: BFS from anchors to discover overlay symbols for the new ROM.

    Returns:
        new_overlays – ReferenceSymbol list to apply to new ROM's Ghidra project
                       before ghidriff runs (improves named-match output)
        new_matches  – MatchedFunction list to merge with ghidriff's output
    """
    queue: deque[tuple[int, int, int]] = deque(
        (a.ref_address, a.new_address, 0) for a in anchors
    )
    matched: set[tuple[int, int]] = {(a.ref_address, a.new_address) for a in anchors}
    new_overlays: list[ReferenceSymbol] = []
    new_matches: list[MatchedFunction] = []

    while queue:
        ref_addr, new_addr, depth = queue.popleft()
        if depth >= _MAX_BFS_DEPTH:
            continue

        ref_callees = ref_run.callees.get(ref_addr, [])
        new_callees = new_run.callees.get(new_addr, [])
        pairs = _lcs_align(ref_callees, new_callees, ref_run, new_run)

        for ref_callee, new_callee in pairs:
            if (ref_callee, new_callee) in matched:
                continue
            matched.add((ref_callee, new_callee))

            sym = ref_symbols_by_addr.get(ref_callee)
            if sym:
                new_overlays.append(
                    ReferenceSymbol(name=sym.name, address=new_callee,
                                    category=sym.category)
                )
                new_matches.append(
                    MatchedFunction(sym.name, ref_callee, new_callee,
                                    0.8, "callgraph_bfs")
                )
            queue.append((ref_callee, new_callee, depth + 1))

    return new_overlays, new_matches


# ---------------------------------------------------------------------------
# Phase 3 — Gap-fill
# ---------------------------------------------------------------------------

def gap_fill(ref_run: HeadlessRun,
             new_run: HeadlessRun,
             existing_matches: list[MatchedFunction],
             ) -> list[MatchedFunction]:
    """Phase 3: recover unmatched functions via structural call-graph position.

    Iterates until convergence: each pass may unlock the next call-graph layer.
    A function f is identified as f' when f's caller is already matched to f's
    caller', and the LCS alignment of their callee lists pairs f with f'.
    """
    matched_ref: dict[int, int] = {m.ref_address: m.new_address
                                    for m in existing_matches}
    matched_new: set[int] = {m.new_address for m in existing_matches}
    results: list[MatchedFunction] = []
    changed = True

    while changed:
        changed = False
        for ref_caller, ref_callees in ref_run.callees.items():
            new_caller = matched_ref.get(ref_caller)
            if new_caller is None:
                continue
            new_callees = new_run.callees.get(new_caller, [])
            pairs = _lcs_align(ref_callees, new_callees,
                               ref_run, new_run, size_tol=0.5)

            for ref_callee, new_callee in pairs:
                if ref_callee in matched_ref or new_callee in matched_new:
                    continue
                name = _name_for(ref_callee, ref_run)
                m = MatchedFunction(name or "", ref_callee, new_callee,
                                    0.7, "callgraph_gap")
                results.append(m)
                matched_ref[ref_callee] = new_callee
                matched_new.add(new_callee)
                changed = True

    return results


# ---------------------------------------------------------------------------
# Phase 4 — Bytecode identity
# ---------------------------------------------------------------------------

_MIN_IDENTITY_SIZE = 8   # bytes; below this, false-positive risk is too high


def bytecode_identity_match(
        ref_bytes: bytes, new_bytes: bytes,
        ref_run: HeadlessRun, new_run: HeadlessRun,
        existing_matches: list[MatchedFunction],
        ref_symbols_by_addr: dict,
        min_size: int = _MIN_IDENTITY_SIZE,
) -> list[MatchedFunction]:
    """Phase 4: exact-bytecode hash match for small/unchanged functions.

    Computes SHA-256 over each function's byte span (entry → next entry).
    A ref function is matched to the unique new function with the same hash;
    ambiguous hashes (multiple new functions identical to each other) are
    skipped to avoid false positives among interchangeable stubs.
    """
    already_ref = {m.ref_address for m in existing_matches}
    already_new = {m.new_address for m in existing_matches}

    # Build size map for new ROM functions.
    new_entries = sorted(int(f["entry"], 16) for f in new_run.functions)
    new_size: dict[int, int] = {}
    for i, addr in enumerate(new_entries):
        if i + 1 < len(new_entries):
            new_size[addr] = new_entries[i + 1] - addr

    # hash → list[new_addr] — drop hashes with multiple matches (ambiguous).
    hash_to_new: dict[bytes, list[int]] = {}
    for addr, sz in new_size.items():
        if sz < min_size or addr + sz > len(new_bytes):
            continue
        h = hashlib.sha256(new_bytes[addr: addr + sz]).digest()
        hash_to_new.setdefault(h, []).append(addr)
    unique_new: dict[bytes, int] = {
        h: addrs[0] for h, addrs in hash_to_new.items() if len(addrs) == 1
    }

    results: list[MatchedFunction] = []
    ref_entries = sorted(int(f["entry"], 16) for f in ref_run.functions)
    for i, ref_addr in enumerate(ref_entries):
        if ref_addr in already_ref:
            continue
        sz = ref_entries[i + 1] - ref_addr if i + 1 < len(ref_entries) else 0
        if sz < min_size or ref_addr + sz > len(ref_bytes):
            continue
        h = hashlib.sha256(ref_bytes[ref_addr: ref_addr + sz]).digest()
        new_addr = unique_new.get(h)
        if new_addr is None or new_addr in already_new:
            continue
        sym = ref_symbols_by_addr.get(ref_addr)
        name = (sym.name if sym else None) or _name_for(ref_addr, ref_run) or ""
        results.append(MatchedFunction(name, ref_addr, new_addr, 1.0, "bytecode_identity"))
        already_ref.add(ref_addr)
        already_new.add(new_addr)

    return results
