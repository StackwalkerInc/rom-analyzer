# Enrich dedup + consensus auto-apply design

**Date:** 2026-06-16

## Problem

`rom-analyzer enrich <id>` cross-matches against N reference ROMs and collects a flat
list of `LabelCandidate` objects before writing `<id>.reconcile.toml`. Three bugs arise
from processing that flat list without merging per-address:

1. **Same-name duplicates.** When K references all propose the same name for the same
   `(target, address)`, the reconcile file contains K identical entries. (71 such cases
   for 39670016.)

2. **Conflicting-name duplicates.** When references propose *different* names for the
   same address, each entry appears separately with no cross-source resolution. (23 cases.)

3. **`current == proposed` noise.** `auto_resolve` can return `(cur, "keep")` — keeping
   the current name — which produces ReconcileItems where `proposed == current`. These
   595 entries are pure no-ops: the reviewer has nothing to decide and no alternative name
   to see. They dilute the file significantly.

Additionally, multi-source agreement is not exploited: four references unanimously
proposing `peripherals_reinit_and_detect_stall` for a placeholder-named gap carries much
higher confidence than a single-reference proposal, but both routes today produce identical
output.

## Solution overview

Four targeted changes, all confined to `enrich.py` and the `enrich` command in `cli.py`:

1. Add `corroborating_sources: list[str]` to `LabelCandidate` and `ReconcileItem`.
2. New `merge_candidates()` function collapses `all_candidates` before `classify`.
3. `classify` gains one new authority-backed auto-apply rule for conflicts.
4. `build_reconcile_items` drops no-op `proposed == current` entries.

## Data model

### `LabelCandidate`

Add one field:

```python
corroborating_sources: list[str] = field(default_factory=list)
```

`source: str` is kept as the **winning/primary source** (the highest-priority ref that
proposed the winning name). It continues to be the sole input to `auto_resolve`'s priority
lookup. `corroborating_sources` lists every ref that contributed to the merged candidate,
regardless of which name they voted for.

On construction (inside `gather_candidates`), `corroborating_sources` defaults to
`[source]` — a single-source candidate is its own corroboration.

### `ReconcileItem`

Add one field:

```python
corroborated_by: list[str] = field(default_factory=list)
```

Emitted to TOML only when non-empty (i.e. when there were additional sources beyond
the primary). `apply_verdicts` does not use this field.

## `merge_candidates` — new function in `enrich.py`

Signature:

```python
def merge_candidates(
    candidates: list[LabelCandidate],
    priority: dict[str, int],
) -> list[LabelCandidate]:
```

Called once in the `enrich` command, immediately after `all_candidates` is assembled
and before `classify`.

**Algorithm per `(target, address, category)` group:**

1. Single-candidate groups: set `corroborating_sources = [source]` and pass through.
2. Multi-candidate groups:
   a. Tally votes: count how many sources propose each distinct name.
   b. Winning name = most votes; ties broken by highest `priority` value among the
      sources backing each tied name.
   c. Winning source = highest-priority source among those that proposed the winner.
   d. Evidence = all individual evidence strings joined with `"; "`.
   e. `corroborating_sources` = all sources in the group (regardless of vote).
   f. Return one `LabelCandidate` with the merged fields; `current` taken from any
      candidate in the group (they are all the same address in the same target).

## Extended `classify` — authority auto-apply for conflicts

`_authority_agrees(sources, priority)` is a new private helper:

```python
def _authority_agrees(sources: list[str], priority: dict[str, int]) -> bool:
    if not priority:
        return False
    top = max(priority, key=priority.get)
    return top in sources
```

Returns `True` when the globally highest-priority ref (by registry) is among the
corroborating sources — i.e. it endorsed the winning name.

New rule in `classify`, inserted inside the `category == "function"` branch,
**before** the existing `current is None` gap check:

```python
if (c.current is not None
        and not is_auto_name(c.proposed)
        and not is_generic(c.proposed)
        and c.address not in erased
        and _authority_agrees(c.corroborating_sources, priority)):
    auto.append(c)
    continue
```

This means: a conflict where the highest-priority reference agrees with the proposed
name is auto-applied without going to review. All other guards (erased flash, auto-name,
generic) still apply.

The existing gap rule (`c.current is None`) and review-bucket rules are unchanged.

## No-op filter in `build_reconcile_items`

After calling `auto_resolve`:

```python
proposed, verdict = auto_resolve(c, priority)
if proposed == (c.current or ""):
    continue
```

This drops every item where the resolved best name equals the current name. These entries
have verdict `"keep"` and nothing for the reviewer to act on. `apply_verdicts` is
unaffected.

## TOML format

`write_reconcile` emits `corroborated_by` only when the list has at least one entry
(i.e. when there were additional corroborating sources beyond the primary `source`).
`read_reconcile` reads it with `r.get("corroborated_by", [])` for backward compat with
existing files.

Example for a 4-way consensus:

```toml
[[item]]
target = "39670016"
direction = "forward"
address = "0x1c068"
category = "function"
current = "call4e0bc"
proposed = "peripherals_reinit_and_detect_stall"
source = "33520003"
corroborated_by = ["30200003", "c7280010", "e5090011"]
evidence = "bytecode match sim=0.90; bytecode match sim=0.80; bytecode match sim=0.82; bytecode match sim=0.81"
verdict = "proposed"
```

## Expected impact on 39670016

| Before | After |
|--------|-------|
| 1190 review items | ~522 review items (71 same-name dups collapsed, 595 no-ops dropped, 23 conflict dups collapsed to 1 each) |
| 0 authority-consensus auto-applies | Items where 33520003 endorses the winner → auto-applied directly |
| No corroboration info | `corroborated_by` field shows multi-source confidence |

Exact numbers depend on which collapsed conflict items pass the authority-agrees gate.

## Files changed

- `rom_analyzer/enrich.py` — `LabelCandidate`, `ReconcileItem`, `_authority_agrees`,
  `merge_candidates`, `classify`, `build_reconcile_items`, `write_reconcile`,
  `read_reconcile`
- `rom_analyzer/cli.py` — `enrich` command: call `merge_candidates` before `classify`
- `tests/` — update/add unit tests for `merge_candidates`, extended `classify`,
  no-op filter, and TOML round-trip
