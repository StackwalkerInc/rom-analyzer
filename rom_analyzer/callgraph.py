"""Call-graph-driven function matching to supplement VTSession diff.

Four phases:
  bootstrap_anchors      – anchor pairs via full vector table + MUT table
  bfs_preseed            – BFS from anchors; produces overlays for the new ROM
                           before VT diff runs, improving named-match output
  gap_fill               – iteratively fills VT diff misses using structural position
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


def _find_bra_tail_call(rom_bytes: bytes, func_start: int, func_size: int,
                        exclude: set[int]) -> int | None:
    """Scan the body of a function for the last BRA that jumps outside it.

    M32R functions that tail-call their successor do so with a plain BRA at the
    very end of their body.  Ghidra does not always tag these as CALL references,
    so they are invisible to callees-based analysis.  This scans the body at
    4-byte alignment and returns the last BRA target that:
      - Falls outside [func_start, func_start + func_size)
      - Is not already in *exclude* (e.g. vector-table handler addresses)
      - Looks like a plausible entry point (4-byte aligned, > 0x200)
    Returns None if no such target is found.
    """
    if func_size <= 0:
        return None
    last_target: int | None = None
    end = func_start + func_size
    for pos in range(func_start, end, 4):
        target = _decode_bra_target(rom_bytes, pos)
        if target is None:
            continue
        if func_start <= target < end:
            continue  # intra-function branch
        if target < 0x200:
            continue
        if target % 4 != 0:
            continue
        if target in exclude:
            continue
        last_target = target
    return last_target


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

    # Derive main from reset handler's (slot 0).
    # Prefer callee-list (BL/JL calls); fall back to tail-call BRA scan when
    # the reset handler reaches main via a plain BRA (which Ghidra doesn't
    # always expose as a CALL reference).
    reset_ref = anchors[0].ref_address
    reset_new = anchors[0].new_address

    def _best_main_candidate(run: HeadlessRun, rom_bytes: bytes,
                              reset_addr: int) -> int | None:
        sz = _func_size(reset_addr, run)
        result = _find_bra_tail_call(rom_bytes, reset_addr, sz, seen_ref | seen_new)
        if result is not None:
            return result
        callees = run.callees.get(reset_addr, [])
        outside = [a for a in callees if a not in seen_ref and a not in seen_new]
        return max(outside, key=lambda a: _func_size(a, run)) if outside else None

    best_ref = _best_main_candidate(ref_run, ref_bytes, reset_ref)
    best_new = _best_main_candidate(new_run, new_bytes, reset_new)
    if (best_ref is not None and best_new is not None
            and best_ref not in seen_ref and best_new not in seen_new):
        anchors.append(MatchedFunction("main", best_ref, best_new, 0.9, "vector_table"))

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


# DTC table invariant: rows 4-6 (offset +0x80 from table base), 96 bytes.
# 17×16 uint16_t table; each row is 32 bytes. Rows 4-6 contain invariant Mitsubishi
# fault codes shared across all M32R ECU variants.
_DTC_INVARIANT_OFFSET = 0x80
_DTC_INVARIANT = bytes.fromhex(
    "1715175017910705"
    "1751074007650760"
    "0755075007150720"
    "0710179507251600"
    "0340033501150000"
    "0225011001000000"
    "0000000005130622"
    "0000032501050500"
    "0000130011021101"
    "0660000000000000"
    "0000122701900000"
    "1515000000000000"
)

# Fault bitmask constant: 32 bytes, identical across all M32R variants.
# Bit-weight lookup used by the DTC storage/scan routines.
_FAULT_BITMASK = bytes.fromhex(
    "8000400020001000"
    "0800040002000100"
    "0080004000200010"
    "0008000400020001"
)


def _find_dtc_table(rom_bytes: bytes) -> int | None:
    """Locate flash_trouble_code_table via its invariant rows 4-6 (96 bytes at +0x80).

    Returns the table base address, or None if the pattern is absent or ambiguous.
    """
    pos = rom_bytes.find(_DTC_INVARIANT)
    if pos == -1:
        return None
    if rom_bytes.find(_DTC_INVARIANT, pos + 1) != -1:
        return None  # ambiguous
    base = pos - _DTC_INVARIANT_OFFSET
    return base if base >= 0 else None


def _find_fault_bitmask_table(rom_bytes: bytes) -> int | None:
    """Locate the fault bitmask constant table via exact 32-byte match."""
    pos = rom_bytes.find(_FAULT_BITMASK)
    if pos == -1:
        return None
    if rom_bytes.find(_FAULT_BITMASK, pos + 1) != -1:
        return None  # ambiguous
    return pos


def _bootstrap_dtc_bitmask(
    ref_bytes: bytes, new_bytes: bytes,
    ref_run: HeadlessRun, new_run: HeadlessRun,
    ref_symbols_by_addr: dict,
) -> list[MatchedFunction]:
    """Phase 1 supplement: anchor pairs via DTC table and fault bitmask handlers."""
    anchors: list[MatchedFunction] = []
    seen_ref: set[int] = set()
    seen_new: set[int] = set()

    table_pairs = [
        (_find_dtc_table(ref_bytes), _find_dtc_table(new_bytes)),
        (_find_fault_bitmask_table(ref_bytes), _find_fault_bitmask_table(new_bytes)),
    ]

    for ref_table, new_table in table_pairs:
        if ref_table is None or new_table is None:
            continue
        ref_handler = _find_handler_for_table(ref_run, ref_table)
        new_handler = _find_handler_for_table(new_run, new_table)
        if ref_handler is None or new_handler is None:
            continue
        if ref_handler in seen_ref or new_handler in seen_new:
            continue
        seen_ref.add(ref_handler)
        seen_new.add(new_handler)
        sym = ref_symbols_by_addr.get(ref_handler)
        name = (sym.name if sym else None) or _name_for(ref_handler, ref_run) or "dtc_handler"
        anchors.append(MatchedFunction(name, ref_handler, new_handler, 1.0, "dtc_table"))

    return anchors


def bootstrap_anchors(ref_bytes: bytes, new_bytes: bytes,
                       ref_run: HeadlessRun, new_run: HeadlessRun,
                       ref_symbols_by_name: dict,
                       ref_symbols_by_addr: dict | None = None,
                       ) -> list[MatchedFunction]:
    """Phase 1: produce anchor pairs via vector table, MUT table, and DTC/bitmask tables."""
    if ref_symbols_by_addr is None:
        ref_symbols_by_addr = {v.address: v for v in ref_symbols_by_name.values()}
    anchors = _bootstrap_vector_table(ref_bytes, new_bytes, ref_run, new_run,
                                      ref_symbols_by_addr)
    anchors += _bootstrap_mut_table(ref_bytes, new_bytes, ref_run, new_run,
                                     ref_symbols_by_name)
    anchors += _bootstrap_dtc_bitmask(ref_bytes, new_bytes, ref_run, new_run,
                                       ref_symbols_by_addr)
    return anchors


# ---------------------------------------------------------------------------
# Phase 2 — BFS pre-seed
# ---------------------------------------------------------------------------

_MAX_BFS_DEPTH = 3
_MIN_CALLEE_SIMILARITY = 0.15  # Jaccard threshold: reject clearly unrelated callee pairs


def _bytecode_jaccard(
    ref_bytes: bytes, ref_addr: int, ref_sz: int,
    new_bytes: bytes, new_addr: int, new_sz: int,
    ngram: int = 4,
) -> float:
    """Approximate Jaccard similarity on non-overlapping 4-byte n-gram sets.

    Returns a neutral 0.5 when bounds are unknown (size == 0) or out of range,
    so callers that skip the check on unknown sizes don't need special-casing here.
    """
    if ref_sz == 0 or new_sz == 0:
        return 0.5
    if ref_addr + ref_sz > len(ref_bytes) or new_addr + new_sz > len(new_bytes):
        return 0.5
    ref_grams: set[bytes] = {
        ref_bytes[ref_addr + i: ref_addr + i + ngram]
        for i in range(0, ref_sz - ngram + 1, ngram)
    }
    new_grams: set[bytes] = {
        new_bytes[new_addr + i: new_addr + i + ngram]
        for i in range(0, new_sz - ngram + 1, ngram)
    }
    union = len(ref_grams | new_grams)
    return len(ref_grams & new_grams) / union if union else 1.0


def bfs_preseed(anchors: list[MatchedFunction],
                ref_run: HeadlessRun,
                new_run: HeadlessRun,
                ref_symbols_by_addr: dict,
                ref_bytes: bytes | None = None,
                new_bytes: bytes | None = None,
                ) -> tuple[list[ReferenceSymbol], list[MatchedFunction]]:
    """Phase 2: BFS from anchors to discover overlay symbols for the new ROM.

    Returns:
        new_overlays – ReferenceSymbol list to apply to new ROM's Ghidra project
                       before VT diff runs (improves named-match output)
        new_matches  – MatchedFunction list to merge with VT diff output
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
            if ref_bytes is not None and new_bytes is not None:
                ref_sz = _func_size(ref_callee, ref_run)
                new_sz = _func_size(new_callee, new_run)
                if _bytecode_jaccard(ref_bytes, ref_callee, ref_sz,
                                     new_bytes, new_callee, new_sz) < _MIN_CALLEE_SIMILARITY:
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
             ref_bytes: bytes | None = None,
             new_bytes: bytes | None = None,
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
                if ref_bytes is not None and new_bytes is not None:
                    ref_sz = _func_size(ref_callee, ref_run)
                    new_sz = _func_size(new_callee, new_run)
                    if _bytecode_jaccard(ref_bytes, ref_callee, ref_sz,
                                         new_bytes, new_callee, new_sz) < _MIN_CALLEE_SIMILARITY:
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

_MIN_IDENTITY_SIZE = 8    # bytes; below this, false-positive risk is too high
_MAX_IDENTITY_SIZE = 128  # bytes; larger functions almost always differ across ROMs


def _find_unique_aligned(haystack: bytes, needle: bytes, alignment: int = 4) -> int | None:
    """Return the single alignment-byte-aligned occurrence of needle in haystack.

    Returns None if needle occurs zero times or more than once at aligned positions.
    """
    found: int | None = None
    pos = 0
    while pos <= len(haystack) - len(needle):
        idx = haystack.find(needle, pos)
        if idx == -1:
            break
        if idx % alignment == 0:
            if found is not None:
                return None  # ambiguous
            found = idx
        pos = idx + 1
    return found


def bytecode_identity_match(
        ref_bytes: bytes, new_bytes: bytes,
        ref_run: HeadlessRun, new_run: HeadlessRun,
        existing_matches: list[MatchedFunction],
        ref_symbols_by_addr: dict,
        min_size: int = _MIN_IDENTITY_SIZE,
        max_size: int = _MAX_IDENTITY_SIZE,
) -> list[MatchedFunction]:
    """Phase 4: exact-bytecode match for small/unchanged functions.

    Scans the entire new ROM for each unmatched ref function's byte sequence
    (at 4-byte M32R alignment).  A match is accepted only when the sequence
    appears exactly once in the new ROM — duplicates are ambiguous and skipped.

    Searching the full ROM rather than just Ghidra-detected function entries
    handles small leaf functions that the auto-analyser may not have discovered.
    """
    already_ref = {m.ref_address for m in existing_matches}
    already_new = {m.new_address for m in existing_matches}

    ref_entries = sorted(int(f["entry"], 16) for f in ref_run.functions)

    results: list[MatchedFunction] = []
    for i, ref_addr in enumerate(ref_entries):
        if ref_addr in already_ref:
            continue
        sz = ref_entries[i + 1] - ref_addr if i + 1 < len(ref_entries) else 0
        if sz < min_size or sz > max_size or ref_addr + sz > len(ref_bytes):
            continue
        body = ref_bytes[ref_addr: ref_addr + sz]
        new_addr = _find_unique_aligned(new_bytes, body)
        if new_addr is None or new_addr in already_new:
            continue
        sym = ref_symbols_by_addr.get(ref_addr)
        name = (sym.name if sym else None) or _name_for(ref_addr, ref_run) or ""
        results.append(MatchedFunction(name, ref_addr, new_addr, 1.0, "bytecode_identity"))
        already_ref.add(ref_addr)
        already_new.add(new_addr)

    return results
