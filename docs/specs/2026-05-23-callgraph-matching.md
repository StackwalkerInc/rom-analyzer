# Call-Graph-Driven Function Matching

**Status:** Design  
**Context:** rom-analyzer v0.2 ships ghidriff cross-ROM diff. Failures occur
where bytecode similarity drops below ghidriff's threshold even though the
logical function is identical — different peripheral addresses, different
calibration table dimensions, different feature sets.

---

## Problem

ghidriff scores matches by bytecode / decompile similarity. Cross-family diffs
(e.g. Colt Z27AG vs Outlander CU2W) have high bytecode divergence:

- Peripheral register addresses differ (MCU variant)
- Calibration table sizes differ (different tuning maps)
- One ROM has CAN initialization; the other doesn't

The current pipeline has no fallback when similarity < threshold. The result is
a missed match even though the function's *structural role* is identical.

---

## Design Overview

Three phases, each feeding into the next:

```
Import reference ROM → HeadlessRun (+ callees + data_refs for ROM addrs)
Import new ROM       → HeadlessRun (+ callees + data_refs for ROM addrs)
          ↓
[Phase 1] Multi-source bootstrap
          → guaranteed anchor pairs from two independent sources:
            (a) vector table  →  reset_handler, main
            (b) MUT table     →  get_mut_pointer (or mut_request_data_or_actuators)
          ↓
[Phase 2] BFS pre-seed
          → additional ReferenceSymbol overlays applied to new ROM
            before ghidriff runs, improving named-match output
          ↓
ghidriff diff
          ↓
[Phase 3] Gap-fill
          → structural matching for ghidriff misses
          ↓
Propagate symbols (existing)
```

Phases 1–3 live in a new `callgraph.py` module. The only Ghidra-side addition is
`_ordered_callees()` in `ghidra.py`.

---

## Data Structures

### HeadlessRun extension

```python
@dataclass
class HeadlessRun:
    functions: list[dict]
    symbols: list[dict]
    ram_refs: list[int]
    rom_crc_check_step: dict | None
    data_refs: dict[int, list[DataRef]]   # existing
    callees: dict[int, list[int]]          # NEW: func entry → ordered callee entries
```

`callees` maps each function's entry address to an ordered list of callee entry
addresses, ordered by first-call-site address within the function body.

### MatchedFunction extension

```python
@dataclass
class MatchedFunction:
    ref_name: str
    ref_address: int
    new_address: int
    similarity: float
    source: str = "ghidriff"
    # source values: "ghidriff" | "vector_table" | "mut_table"
    #                | "callgraph_bfs" | "callgraph_gap"
```

`source` is surfaced in `match-report.md` and informs downstream confidence.

---

## Phase 1 — Bootstrap Anchors

Two independent anchor sources, both exploiting structural invariants rather
than bytecode similarity.

### 1a. Vector Table

The M32R reset vector is at ROM byte offset 0 (big-endian uint32). It points
to `reset_interrupt_handler`. That function's only callee is `main`.

```python
def _bootstrap_vector_table(ref_bytes, new_bytes, ref_run, new_run):
    ref_reset = struct.unpack_from(">I", ref_bytes, 0)[0]
    new_reset = struct.unpack_from(">I", new_bytes, 0)[0]

    anchors = [MatchedFunction("reset_interrupt_handler",
                               ref_reset, new_reset, 1.0, "vector_table")]

    ref_mains = ref_run.callees.get(ref_reset, [])
    new_mains = new_run.callees.get(new_reset, [])
    if len(ref_mains) == 1 and len(new_mains) == 1:
        anchors.append(MatchedFunction("main",
                                       ref_mains[0], new_mains[0], 1.0,
                                       "vector_table"))
    elif ref_mains and new_mains:
        # Multiple callees: pick largest by size (main is always the big one)
        best_ref = max(ref_mains, key=lambda a: _func_size(a, ref_run))
        best_new = max(new_mains, key=lambda a: _func_size(a, new_run))
        anchors.append(MatchedFunction("main",
                                       best_ref, best_new, 0.9,
                                       "vector_table"))
    return anchors
```

Failure guard: if the address at offset 0 falls outside the ROM's code range,
log a warning and skip (don't produce a wrong anchor).

### 1b. MUT Variables Table

The MUT diagnostic protocol defines a variable table (`flash_mut_variables_table`)
with fixed-PID slots. PIDs 0x80–0x82 always map to `rom_version` bytes, making
entries at table offset `+0x200` invariant in structure across all ECU families:

```
table[0x80]:  0x00 0x80 <hi> <A>      →  HIGH_BYTE_OF(rom_version0)
table[0x81]:  0x00 0x80 <hi> <A+1>    →  LOW_BYTE_OF(rom_version0)
table[0x82]:  0x00 0x80 <hi> <A+3>    →  LOW_BYTE_OF(rom_version1)
```

The `+3` gap (not `+2`) is the invariant — it encodes the uint16 boundary
between `rom_version0` and `rom_version1` in RAM. The leading `0x00 0x80`
bytes encode the RAM address space prefix common to all these ECUs.

**Finding the table in the reference ROM:** `flash_mut_variables_table` is a
named symbol in `colt_flash.txt`. Its address is directly available as a
`ReferenceSymbol` after loading reference data.

**Finding the table in the new ROM:**

```python
def _find_mut_table(rom_bytes: bytes) -> int | None:
    """Scan for the invariant PID-0x80 cell triplet at table_base + 0x200."""
    for candidate in range(0, len(rom_bytes) - 0x20C, 4):
        base = candidate - 0x200
        if base < 0:
            continue
        e0 = rom_bytes[candidate:candidate+4]
        e1 = rom_bytes[candidate+4:candidate+8]
        e2 = rom_bytes[candidate+8:candidate+12]
        if (e0[0] == 0x00 and e0[1] == 0x80 and
            e1[0] == 0x00 and e1[1] == 0x80 and
            e2[0] == 0x00 and e2[1] == 0x80 and
            e1[2] == e0[2] and e2[2] == e0[2] and   # same hi byte
            e1[3] == e0[3] + 1 and                   # +1
            e2[3] == e0[3] + 3):                     # +3 (uint16 boundary)
            return base
    return None
```

**Finding the MUT handler via data_refs:**

`data_refs` already collects all ROM-address references (addresses < 0x80000)
from every analyzed function. The MUT table (at `0x3b4f4` in Colt,
`0x39bf4` in Outlander) is a ROM address, so the function that loads it shows
up in `data_refs`.

```python
def _find_handler_for_table(run: HeadlessRun, table_addr: int) -> int | None:
    for func_entry, refs in run.data_refs.items():
        if any(r.referenced_address == table_addr for r in refs):
            return func_entry
    return None
```

**Combining into an anchor:**

```python
def _bootstrap_mut_table(ref_bytes, new_bytes, ref_run, new_run,
                          ref_symbols_by_name):
    ref_sym = ref_symbols_by_name.get("flash_mut_variables_table")
    if ref_sym is None:
        return []

    new_table = _find_mut_table(new_bytes)
    if new_table is None:
        return []

    ref_handler = _find_handler_for_table(ref_run, ref_sym.address)
    new_handler = _find_handler_for_table(new_run, new_table)
    if ref_handler is None or new_handler is None:
        return []

    name = _name_for(ref_handler, ref_run) or "get_mut_pointer"
    return [MatchedFunction(name, ref_handler, new_handler, 1.0, "mut_table")]
```

---

## Phase 2 — BFS Pre-Seed

**Goal:** Walk the call graph from anchors to produce overlay symbols for the
new ROM before ghidriff runs.

### Callee List Alignment

Strict positional zip breaks when one ROM has an extra function (e.g. Colt has
CAN initialization, Outlander doesn't). Use LCS-based sequence alignment
instead: the longest common subsequence where two callees are "compatible" if
their size ratio is acceptable.

```
Colt:      [startup, init_hw, init_can, init_sw, main_loop]
Outlander: [startup, init_hw,           init_sw, main_loop]

LCS:       [startup, init_hw,           init_sw, main_loop]
Skipped:                       init_can
```

`init_can` is simply dropped from the pairing rather than causing downstream
misalignment. `init_sw` still correctly maps to `init_sw`.

```python
def _lcs_align(ref_callees: list[int], new_callees: list[int],
               ref_run, new_run, size_tol=0.4) -> list[tuple[int, int]]:
    """Return matched (ref, new) pairs via LCS on size-ratio compatibility."""
    n, m = len(ref_callees), len(new_callees)
    # dp[i][j] = length of LCS for ref[:i], new[:j]
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            if _size_ratio_ok(ref_callees[i-1], new_callees[j-1],
                              ref_run, new_run, size_tol):
                dp[i][j] = dp[i-1][j-1] + 1
            else:
                dp[i][j] = max(dp[i-1][j], dp[i][j-1])

    # Backtrack
    pairs = []
    i, j = n, m
    while i > 0 and j > 0:
        if _size_ratio_ok(ref_callees[i-1], new_callees[j-1],
                          ref_run, new_run, size_tol):
            pairs.append((ref_callees[i-1], new_callees[j-1]))
            i -= 1; j -= 1
        elif dp[i-1][j] >= dp[i][j-1]:
            i -= 1
        else:
            j -= 1
    return list(reversed(pairs))
```

### BFS Algorithm

```python
MAX_BFS_DEPTH = 3

def bfs_preseed(anchors, ref_run, new_run, ref_symbols_by_addr):
    queue = deque((a.ref_address, a.new_address, 0) for a in anchors)
    matched = {(a.ref_address, a.new_address) for a in anchors}
    new_overlays = []
    new_matches = []

    while queue:
        ref_addr, new_addr, depth = queue.popleft()
        if depth >= MAX_BFS_DEPTH:
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
                new_overlays.append(ReferenceSymbol(
                    name=sym.name, address=new_callee, category=sym.category))
                new_matches.append(MatchedFunction(
                    sym.name, ref_callee, new_callee, 0.8, "callgraph_bfs"))

            queue.append((ref_callee, new_callee, depth + 1))

    return new_overlays, new_matches
```

`new_overlays` are applied to the new ROM's Ghidra program via `_overlay_symbols`
before `analyze_project`. `new_matches` are merged with ghidriff's output.

---

## Phase 3 — Post-Ghidriff Gap-Fill

**Goal:** Recover remaining unmatched functions using structural position after
ghidriff has run.

**Predicate:** Reference function `f` is identified in the new ROM at position
`k` in matched-caller `c`'s callee list when:
1. `c` is already matched to `c'`
2. `f` is at position `k` in `c`'s callees (from LCS alignment of `c` and `c'`)
3. The candidate `f'` at position `k` in `c'`'s callees is unmatched
4. Size ratio ≥ 0.5 (looser; two structural constraints already bound it)

```python
def gap_fill(ref_run, new_run, existing_matches):
    matched_ref = {m.ref_address: m.new_address for m in existing_matches}
    matched_new = {m.new_address for m in existing_matches}
    results = []
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
                results.append(MatchedFunction(
                    name or "", ref_callee, new_callee, 0.7, "callgraph_gap"))
                matched_ref[ref_callee] = new_callee
                matched_new.add(new_callee)
                changed = True

    return results
```

Iterates until no new matches are found — each pass unlocks the next call-graph
layer.

---

## Callees Extraction in Ghidra

Add to `_dump_program` in `ghidra.py`:

```python
def _ordered_callees(func, ref_mgr, func_mgr) -> list[int]:
    """Return callee entry addresses ordered by first call-site in func body."""
    seen: dict[int, int] = {}   # callee_entry → first source offset
    body = func.getBody()
    for ref in ref_mgr.getReferenceIterator(body.getMinAddress()):
        if not body.contains(ref.getFromAddress()):
            continue
        if not ref.getReferenceType().isCall():
            continue
        target = ref.getToAddress()
        if target is None:
            continue
        callee = func_mgr.getFunctionContaining(target)
        if callee is None:
            continue
        entry = int(callee.getEntryPoint().getOffset())
        src_offset = int(ref.getFromAddress().getOffset())
        if entry not in seen or src_offset < seen[entry]:
            seen[entry] = src_offset
    return [k for k, _ in sorted(seen.items(), key=lambda kv: kv[1])]
```

Self-calls are excluded because `func_mgr.getFunctionContaining(target)` will
return the same function, and we filter `entry == func.getEntryPoint()` out
at usage sites where needed.

---

## Helper: `_func_size`

Used by size-ratio checks and largest-callee selection:

```python
def _func_size(entry: int, run: HeadlessRun) -> int:
    entries = sorted(f["entry"] for f in run.functions
                     if int(f["entry"], 16) >= entry)
    idx = entries.index(entry) if entry in entries else -1
    if idx < 0 or idx + 1 >= len(entries):
        return 0
    return entries[idx + 1] - entries[idx]
```

`run.functions` stores entries as hex strings; caller converts as needed.

---

## Integration Points

| Step | File | Change |
|------|------|--------|
| Extract callees | `ghidra.py` / `_dump_program` | `_ordered_callees()` + `callees` field |
| HeadlessRun | `ghidra.py` | `callees: dict[int, list[int]] = field(default_factory=dict)` |
| MatchedFunction | `types.py` | `source: str = "ghidriff"` |
| Phase 1 bootstrap | `callgraph.py` (new) | `bootstrap_anchors()` calls 1a + 1b |
| Phase 2 BFS | `callgraph.py` (new) | `bfs_preseed()` |
| Phase 3 gap-fill | `callgraph.py` (new) | `gap_fill()` |
| Pipeline wiring | `cli.py` | call phases, merge match lists, pass BFS overlays before ghidriff |
| Reporting | `cli.py` | `match-report.md` breakdown by `source` |

The pipeline in `cli.py` gains two new steps relative to v0.2:

```python
# After both import_and_dump calls, before run_ghidriff:
anchors = bootstrap_anchors(ref_bytes, new_bytes, ref_run, new_run,
                            ref_symbols_by_name)
bfs_overlays, bfs_matches = bfs_preseed(anchors, ref_run, new_run,
                                         ref_symbols_by_addr)
apply_symbols_to_project(..., bfs_overlays)   # reuse existing helper

# After run_ghidriff:
all_matches = ghidriff_matches + anchors + bfs_matches
gap_matches = gap_fill(ref_run, new_run, all_matches)
all_matches += gap_matches
```

`ref_bytes` and `new_bytes` are the raw ROM bytes read from file (already
available in `cli.py` for the CRC scan; no extra I/O needed).

---

## Testing

**Unit tests (no Ghidra), all in `tests/test_callgraph.py`:**

| Test | Covers |
|------|--------|
| `test_find_mut_table_known` | Pattern scanner finds table at `0x3b4f4 - 0x200 = 0x3b2f4`... wait, `0x3b4f4` is the table base, PIDs at `+0x200 = 0x3b6f4`. Scanner finds the table base. |
| `test_find_mut_table_offset_variants` | Scanner handles table not at 4-byte alignment edge |
| `test_find_mut_table_no_match` | Returns `None` on synthetic bytes with no signature |
| `test_bootstrap_vector_single_callee` | Reset handler with one callee → `main` anchor |
| `test_bootstrap_vector_multi_callee` | Multiple callees → picks largest |
| `test_lcs_align_extra_in_ref` | Colt has CAN init, Outlander doesn't → CAN skipped, others aligned |
| `test_lcs_align_extra_in_new` | New ROM has extra helper → extra skipped |
| `test_lcs_align_size_filter` | Incompatible size ratio forces gap, prevents misalignment |
| `test_bfs_depth_limit` | BFS stops at depth 3 even with deep call graph |
| `test_gap_fill_one_pass` | Single caller with two callees, one pre-matched → other filled |
| `test_gap_fill_iterative` | Second-layer functions discovered on second iteration |

**E2E:** existing `e2e` marker; full pipeline test exercises all three phases
with real Colt + Outlander ROMs and asserts that `main` appears in the output
`match-report.md` with `source=vector_table`.

---

## Expected Impact

Based on the Colt→Outlander run (792 ghidriff matches, `main` missed):

- Phase 1 adds ~3 guaranteed anchors (`reset_interrupt_handler`, `main`,
  `get_mut_pointer` / MUT handler)
- Phase 2 adds ~30–80 named overlays (functions directly called by anchors and
  named in `colt_flash.txt`)
- Phase 3 adds ~50–150 gap-fills (one call-graph layer past Phase 2)

The primary concrete fix: `main` is always found via the vector table, regardless
of bytecode divergence.
