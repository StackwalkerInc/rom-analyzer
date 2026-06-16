# Enrich Dedup + Consensus Auto-Apply Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse multi-source candidates into one per address, auto-apply when the highest-priority reference endorses the winner, and eliminate `current == proposed` no-op entries from reconcile files.

**Architecture:** Four layered changes to `enrich.py` applied in order — data model → merge step → classify extension → output filter — with the CLI wired last. All logic is unit-tested; the CLI change is thin.

**Tech Stack:** Python 3.12, `dataclasses`, `tomllib`/`tomli_w`, `pytest`

---

## File map

| File | Changes |
|------|---------|
| `rom_analyzer/enrich.py` | All logic: `LabelCandidate`, `ReconcileItem`, `merge_candidates`, `_authority_agrees`, `classify`, `build_reconcile_items`, `write_reconcile`, `read_reconcile` |
| `rom_analyzer/cli.py` | Import and call `merge_candidates` in `enrich` command; pass `priority` to `classify` |
| `tests/test_enrich.py` | New and updated tests for every changed function |

---

## Task 1: Add `corroborating_sources` to `LabelCandidate`

**Files:**
- Modify: `rom_analyzer/enrich.py:11` (imports), `rom_analyzer/enrich.py:49-58` (`LabelCandidate`)
- Test: `tests/test_enrich.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_enrich.py`:

```python
def test_label_candidate_corroborating_sources_defaults_to_source():
    c = LabelCandidate(target="X", direction="forward", address=0x100,
                       category="function", current=None, proposed="my_fn",
                       source="33520003")
    assert c.corroborating_sources == ["33520003"]


def test_label_candidate_explicit_corroborating_sources():
    c = LabelCandidate(target="X", direction="forward", address=0x100,
                       category="function", current=None, proposed="my_fn",
                       source="33520003",
                       corroborating_sources=["33520003", "30200003"])
    assert c.corroborating_sources == ["33520003", "30200003"]
```

Also update `test_label_candidate_and_reconcile_item_construct` — after the change `**vars(c)` will include `corroborating_sources` which `ReconcileItem` doesn't accept yet, so use explicit construction:

```python
def test_label_candidate_and_reconcile_item_construct():
    c = LabelCandidate(target="33520003", direction="back", address=0x804d5e,
                       category="ram_global", current="fp12962_u16",
                       proposed="tacho_output_state", source="e5090011",
                       evidence="usage-equiv: written in matched fn 0x14ed8")
    assert c.address == 0x804d5e and c.direction == "back"
    assert c.corroborating_sources == ["e5090011"]
    it = ReconcileItem(target=c.target, direction=c.direction, address=c.address,
                       category=c.category, current=c.current, proposed=c.proposed,
                       source=c.source, evidence=c.evidence, verdict="proposed")
    assert it.verdict == "proposed" and it.target == "33520003"
```

- [ ] **Step 2: Run to verify failure**

```
cd /Users/amarkelov/claude-hobby/rom-analyzer
.venv/bin/pytest tests/test_enrich.py::test_label_candidate_corroborating_sources_defaults_to_source -xvs
```

Expected: `AttributeError: 'LabelCandidate' object has no attribute 'corroborating_sources'`

- [ ] **Step 3: Implement**

In `rom_analyzer/enrich.py`, change the `dataclasses` import:

```python
from dataclasses import dataclass, field
```

Change `LabelCandidate`:

```python
@dataclass
class LabelCandidate:
    target: str
    direction: str
    address: int
    category: str
    current: str | None
    proposed: str
    source: str
    evidence: str = ""
    corroborating_sources: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.corroborating_sources:
            self.corroborating_sources = [self.source]
```

- [ ] **Step 4: Run tests**

```
.venv/bin/pytest tests/test_enrich.py -xvs
```

Expected: all 21 pass (19 existing + 2 new).

- [ ] **Step 5: Commit**

```bash
git add rom_analyzer/enrich.py tests/test_enrich.py
git commit -m "feat(enrich): add corroborating_sources to LabelCandidate"
```

---

## Task 2: Add `corroborated_by` to `ReconcileItem` + update TOML I/O

**Files:**
- Modify: `rom_analyzer/enrich.py` — `ReconcileItem`, `write_reconcile`, `read_reconcile`, `build_reconcile_items`
- Test: `tests/test_enrich.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_enrich.py`:

```python
def test_reconcile_item_corroborated_by_defaults_empty():
    it = ReconcileItem(target="X", direction="forward", address=0x100,
                       category="function", current=None, proposed="fn",
                       source="33520003", evidence="", verdict="proposed")
    assert it.corroborated_by == []


def test_reconcile_roundtrip_with_corroboration(tmp_path):
    items = [ReconcileItem(target="33520003", direction="back", address=0x804d5e,
                           category="ram_global", current="fp12962_u16",
                           proposed="tacho_output_state", source="e5090011",
                           evidence="usage-equiv", verdict="proposed",
                           corroborated_by=["39670016", "30200003"])]
    p = tmp_path / "r.toml"
    write_reconcile(p, items)
    data = tomllib.loads(p.read_text())
    assert data["item"][0]["corroborated_by"] == ["39670016", "30200003"]
    back = read_reconcile(p)
    assert back[0].corroborated_by == ["39670016", "30200003"]


def test_reconcile_roundtrip_no_corroboration_not_emitted(tmp_path):
    items = [ReconcileItem(target="33520003", direction="back", address=0x804d5e,
                           category="ram_global", current="fp12962_u16",
                           proposed="tacho_output_state", source="e5090011",
                           evidence="usage-equiv", verdict="proposed")]
    p = tmp_path / "r.toml"
    write_reconcile(p, items)
    data = tomllib.loads(p.read_text())
    assert "corroborated_by" not in data["item"][0]
    back = read_reconcile(p)
    assert back[0].corroborated_by == []


def test_reconcile_backward_compat_missing_field(tmp_path):
    old_toml = (
        '[[item]]\ntarget = "33520003"\ndirection = "back"\naddress = "0x804d5e"\n'
        'category = "ram_global"\ncurrent = "fp12962_u16"\nproposed = "tacho_output_state"\n'
        'source = "e5090011"\nevidence = "usage-equiv"\nverdict = "proposed"\n'
    )
    p = tmp_path / "old.toml"
    p.write_text(old_toml)
    items = read_reconcile(p)
    assert items[0].corroborated_by == []
```

Also update the existing `test_reconcile_roundtrip` to check the field:

```python
def test_reconcile_roundtrip(tmp_path):
    items = [ReconcileItem(target="33520003", direction="back", address=0x804d5e,
                           category="ram_global", current="fp12962_u16",
                           proposed="tacho_output_state", source="e5090011",
                           evidence="usage-equiv", verdict="proposed")]
    p = tmp_path / "r.toml"
    write_reconcile(p, items)
    data = tomllib.loads(p.read_text())
    assert data["item"][0]["address"] == "0x804d5e"
    back = read_reconcile(p)
    assert back[0].address == 0x804d5e and back[0].verdict == "proposed"
    assert back[0].corroborated_by == []
```

- [ ] **Step 2: Run to verify failure**

```
.venv/bin/pytest tests/test_enrich.py::test_reconcile_item_corroborated_by_defaults_empty -xvs
```

Expected: `TypeError: ReconcileItem.__init__() got an unexpected keyword argument 'corroborated_by'` or `AttributeError`.

- [ ] **Step 3: Implement**

Change `ReconcileItem` in `rom_analyzer/enrich.py`:

```python
@dataclass
class ReconcileItem:
    target: str
    direction: str
    address: int
    category: str
    current: str | None
    proposed: str
    source: str
    evidence: str
    verdict: str       # "proposed" | "keep" | "drop" | <custom-name>
    corroborated_by: list[str] = field(default_factory=list)
```

Change `write_reconcile`:

```python
def write_reconcile(path: Path, items: list[ReconcileItem]) -> None:
    rows = []
    for i in items:
        row = {
            "target": i.target, "direction": i.direction,
            "address": f"0x{i.address:x}", "category": i.category,
            "current": i.current or "", "proposed": i.proposed,
            "source": i.source, "evidence": i.evidence, "verdict": i.verdict,
        }
        if i.corroborated_by:
            row["corroborated_by"] = i.corroborated_by
        rows.append(row)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(tomli_w.dumps({"item": rows}))
```

Change `read_reconcile`:

```python
def read_reconcile(path: Path) -> list[ReconcileItem]:
    data = tomllib.loads(Path(path).read_text())
    out: list[ReconcileItem] = []
    for r in data.get("item", []):
        out.append(ReconcileItem(
            target=r["target"], direction=r["direction"],
            address=int(r["address"], 16), category=r["category"],
            current=r["current"] or None, proposed=r["proposed"],
            source=r["source"], evidence=r.get("evidence", ""),
            verdict=r["verdict"],
            corroborated_by=r.get("corroborated_by", []),
        ))
    return out
```

Change `build_reconcile_items` to thread the new field through:

```python
def build_reconcile_items(review: list[LabelCandidate],
                          priority: dict[str, int]) -> list[ReconcileItem]:
    """Turn REVIEW candidates into ReconcileItems with auto-resolved verdicts."""
    items: list[ReconcileItem] = []
    for c in review:
        proposed, verdict = auto_resolve(c, priority)
        corroborated_by = [s for s in c.corroborating_sources if s != c.source]
        items.append(ReconcileItem(
            target=c.target, direction=c.direction, address=c.address,
            category=c.category, current=c.current, proposed=proposed,
            source=c.source, evidence=c.evidence, verdict=verdict,
            corroborated_by=corroborated_by,
        ))
    items.sort(key=lambda i: (i.target, i.address))
    return items
```

- [ ] **Step 4: Run tests**

```
.venv/bin/pytest tests/test_enrich.py -xvs
```

Expected: all 25 pass.

- [ ] **Step 5: Commit**

```bash
git add rom_analyzer/enrich.py tests/test_enrich.py
git commit -m "feat(enrich): add corroborated_by to ReconcileItem, update TOML I/O"
```

---

## Task 3: Implement `merge_candidates`

**Files:**
- Modify: `rom_analyzer/enrich.py` — add `merge_candidates` after `gather_candidates`
- Test: `tests/test_enrich.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_enrich.py`:

```python
from rom_analyzer.enrich import merge_candidates


def _mc(target, address, proposed, source, category="function",
        current=None, direction="forward", evidence=""):
    return LabelCandidate(target=target, direction=direction, address=address,
                          category=category, current=current, proposed=proposed,
                          source=source, evidence=evidence)


def test_merge_single_source_passthrough():
    c = _mc("X", 0x100, "my_fn", "33520003", evidence="sim=0.90")
    result = merge_candidates([c], priority={"33520003": 100})
    assert len(result) == 1
    assert result[0].proposed == "my_fn"
    assert result[0].corroborating_sources == ["33520003"]


def test_merge_same_name_consensus_collapses():
    prio = {"33520003": 100, "30200003": 40, "c7280010": 35}
    cands = [
        _mc("X", 0x100, "real_fn", "33520003", evidence="sim=0.90"),
        _mc("X", 0x100, "real_fn", "30200003", evidence="sim=0.80"),
        _mc("X", 0x100, "real_fn", "c7280010", evidence="sim=0.82"),
    ]
    result = merge_candidates(cands, prio)
    assert len(result) == 1
    r = result[0]
    assert r.proposed == "real_fn"
    assert r.source == "33520003"
    assert set(r.corroborating_sources) == {"33520003", "30200003", "c7280010"}
    assert "sim=0.90" in r.evidence and "sim=0.80" in r.evidence


def test_merge_conflict_authority_wins():
    prio = {"33520003": 100, "30200003": 40}
    cands = [
        _mc("X", 0x100, "authority_name", "33520003"),
        _mc("X", 0x100, "other_name", "30200003"),
    ]
    result = merge_candidates(cands, prio)
    assert len(result) == 1
    assert result[0].proposed == "authority_name"
    assert result[0].source == "33520003"
    # 30200003 voted for the losing name — not in corroborating_sources
    assert result[0].corroborating_sources == ["33520003"]


def test_merge_conflict_majority_beats_authority():
    # 3 votes vs 1: majority wins even if the single vote is from the top authority
    prio = {"33520003": 100, "a": 30, "b": 35, "c": 40}
    cands = [
        _mc("X", 0x100, "authority_name", "33520003"),
        _mc("X", 0x100, "majority_name", "a"),
        _mc("X", 0x100, "majority_name", "b"),
        _mc("X", 0x100, "majority_name", "c"),
    ]
    result = merge_candidates(cands, prio)
    assert result[0].proposed == "majority_name"
    # 33520003 voted for loser → NOT in corroborating_sources
    assert "33520003" not in result[0].corroborating_sources
    assert set(result[0].corroborating_sources) == {"a", "b", "c"}


def test_merge_tie_broken_by_priority():
    # 1 vote each; higher-priority source wins
    prio = {"33520003": 100, "30200003": 40}
    cands = [
        _mc("X", 0x100, "high_prio_name", "33520003"),
        _mc("X", 0x100, "low_prio_name", "30200003"),
    ]
    result = merge_candidates(cands, prio)
    assert result[0].proposed == "high_prio_name"


def test_merge_preserves_different_addresses():
    prio = {"33520003": 100, "30200003": 40}
    cands = [
        _mc("X", 0x100, "fn_a", "33520003"),
        _mc("X", 0x200, "fn_b", "30200003"),
    ]
    result = merge_candidates(cands, prio)
    assert len(result) == 2
    addrs = {r.address for r in result}
    assert addrs == {0x100, 0x200}


def test_merge_different_targets_not_collapsed():
    prio = {"33520003": 100, "30200003": 40}
    cands = [
        _mc("A", 0x100, "fn_a", "33520003"),
        _mc("B", 0x100, "fn_b", "30200003"),
    ]
    result = merge_candidates(cands, prio)
    assert len(result) == 2
```

- [ ] **Step 2: Run to verify failure**

```
.venv/bin/pytest tests/test_enrich.py::test_merge_single_source_passthrough -xvs
```

Expected: `ImportError: cannot import name 'merge_candidates'`

- [ ] **Step 3: Implement**

Add after `gather_candidates` in `rom_analyzer/enrich.py`:

```python
def merge_candidates(
    candidates: list[LabelCandidate],
    priority: dict[str, int],
) -> list[LabelCandidate]:
    """Collapse candidates with the same (target, address, category) into one.

    Name selection: majority vote; ties broken by highest-priority source.
    corroborating_sources contains only sources that voted for the winning name.
    Sources that voted for losing names contribute only to evidence.
    """
    from collections import defaultdict

    groups: dict[tuple, list[LabelCandidate]] = defaultdict(list)
    for c in candidates:
        groups[(c.target, c.address, c.category)].append(c)

    result: list[LabelCandidate] = []
    for group in groups.values():
        if len(group) == 1:
            result.append(group[0])
            continue

        # Tally votes: name → list of sources that proposed it
        votes: dict[str, list[str]] = defaultdict(list)
        for c in group:
            votes[c.proposed].append(c.source)

        # Winner: most votes; tie-break by highest priority among backing sources
        def _score(item: tuple[str, list[str]]) -> tuple[int, int]:
            _, sources = item
            return (len(sources), max(priority.get(s, 0) for s in sources))

        winning_name, agreeing_sources = max(votes.items(), key=_score)

        # Primary source = highest-priority source among those backing the winner
        winning_source = max(agreeing_sources, key=lambda s: priority.get(s, 0))

        combined_evidence = "; ".join(c.evidence for c in group if c.evidence)

        result.append(LabelCandidate(
            target=group[0].target,
            direction=group[0].direction,
            address=group[0].address,
            category=group[0].category,
            current=group[0].current,
            proposed=winning_name,
            source=winning_source,
            evidence=combined_evidence,
            corroborating_sources=list(agreeing_sources),
        ))

    return result
```

- [ ] **Step 4: Run tests**

```
.venv/bin/pytest tests/test_enrich.py -xvs
```

Expected: all 33 pass.

- [ ] **Step 5: Commit**

```bash
git add rom_analyzer/enrich.py tests/test_enrich.py
git commit -m "feat(enrich): add merge_candidates to collapse multi-source duplicates"
```

---

## Task 4: Add `_authority_agrees` + extend `classify` with authority auto-apply

**Files:**
- Modify: `rom_analyzer/enrich.py` — add `_authority_agrees`, update `classify` signature and body
- Test: `tests/test_enrich.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_enrich.py`:

```python
from rom_analyzer.enrich import _authority_agrees


def test_authority_agrees_top_in_sources():
    prio = {"33520003": 100, "39670016": 90, "30200003": 40}
    assert _authority_agrees(["33520003", "30200003"], prio) is True


def test_authority_agrees_top_not_in_sources():
    prio = {"33520003": 100, "39670016": 90, "30200003": 40}
    assert _authority_agrees(["30200003", "39670016"], prio) is False


def test_authority_agrees_empty_sources_returns_false():
    assert _authority_agrees([], {"33520003": 100}) is False


def test_authority_agrees_empty_priority_returns_false():
    assert _authority_agrees(["33520003"], {}) is False


def test_classify_authority_backed_conflict_auto_applied():
    prio = {"33520003": 100, "30200003": 40}
    c = LabelCandidate(
        target="X", direction="forward", address=0x100,
        category="function", current="call100", proposed="real_fn",
        source="33520003", corroborating_sources=["33520003", "30200003"],
    )
    out = classify([c], erased=set(), priority=prio)
    assert len(out.auto) == 1 and out.auto[0].proposed == "real_fn"
    assert out.review == []


def test_classify_conflict_without_authority_stays_review():
    prio = {"33520003": 100, "30200003": 40}
    c = LabelCandidate(
        target="X", direction="forward", address=0x100,
        category="function", current="call100", proposed="other_fn",
        source="30200003", corroborating_sources=["30200003"],
    )
    out = classify([c], erased=set(), priority=prio)
    assert out.auto == []
    assert len(out.review) == 1


def test_classify_authority_rule_skipped_for_ram_global():
    # Authority rule only fires for functions; RAM/data always go to review
    prio = {"33520003": 100}
    c = LabelCandidate(
        target="X", direction="forward", address=0x100,
        category="ram_global", current="fp100", proposed="real_var",
        source="33520003", corroborating_sources=["33520003"],
    )
    out = classify([c], erased=set(), priority=prio)
    assert out.auto == []
    assert len(out.review) == 1


def test_classify_authority_rule_skipped_for_erased():
    prio = {"33520003": 100}
    c = LabelCandidate(
        target="X", direction="forward", address=0x100,
        category="function", current="call100", proposed="real_fn",
        source="33520003", corroborating_sources=["33520003"],
    )
    out = classify([c], erased={0x100}, priority=prio)
    assert out.auto == [] and out.review == []


def test_classify_no_priority_arg_authority_rule_inactive():
    # Backward compat: callers that don't pass priority still work
    c = LabelCandidate(
        target="X", direction="forward", address=0x100,
        category="function", current="call100", proposed="real_fn",
        source="33520003", corroborating_sources=["33520003"],
    )
    out = classify([c], erased=set())  # no priority kwarg
    assert out.auto == []
    assert len(out.review) == 1
```

- [ ] **Step 2: Run to verify failure**

```
.venv/bin/pytest tests/test_enrich.py::test_authority_agrees_top_in_sources -xvs
```

Expected: `ImportError: cannot import name '_authority_agrees'`

- [ ] **Step 3: Implement**

Add `_authority_agrees` before `classify` in `rom_analyzer/enrich.py`:

```python
def _authority_agrees(sources: list[str], priority: dict[str, int]) -> bool:
    """True if the globally highest-priority reference is among the sources."""
    if not priority or not sources:
        return False
    top = max(priority, key=priority.get)
    return top in sources
```

Update `classify` signature and add the new rule:

```python
def classify(candidates: list[LabelCandidate], erased: set[int],
             priority: dict[str, int] | None = None) -> Classified:
    """Split candidates into auto-apply / review / drop.

    AUTO  : a new function (gap, current is None), real non-generic name, entry
            not erased; OR a conflict where the highest-priority reference endorses
            the proposed name.
    DROP  : auto-names anywhere; functions whose entry is in erased flash.
    REVIEW: name conflicts without authority endorsement; all RAM/data candidates.
    Agreement (current == proposed) is neither auto nor review.
    """
    auto: list[LabelCandidate] = []
    review: list[LabelCandidate] = []
    for c in candidates:
        if is_auto_name(c.proposed):
            continue
        if c.current == c.proposed:
            continue  # agreement / corroboration
        if c.category == "function":
            if c.address in erased:
                continue  # typo landing in 0xFF
            # Authority-backed conflict: highest-priority ref endorses proposed name
            if (c.current is not None
                    and not is_generic(c.proposed)
                    and priority is not None
                    and _authority_agrees(c.corroborating_sources, priority)):
                auto.append(c)
                continue
            if c.current is None:
                if is_generic(c.proposed):
                    review.append(c)
                else:
                    auto.append(c)  # new function gap
            else:
                review.append(c)   # genuine fn name conflict
        else:
            review.append(c)       # RAM/data always reviewed
    return Classified(auto=auto, review=review)
```

- [ ] **Step 4: Run tests**

```
.venv/bin/pytest tests/test_enrich.py -xvs
```

Expected: all 42 pass.

- [ ] **Step 5: Commit**

```bash
git add rom_analyzer/enrich.py tests/test_enrich.py
git commit -m "feat(enrich): authority-backed consensus auto-applies without review"
```

---

## Task 5: Filter `current == proposed` no-ops in `build_reconcile_items`

**Files:**
- Modify: `rom_analyzer/enrich.py` — `build_reconcile_items`
- Test: `tests/test_enrich.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_enrich.py`:

```python
def test_build_items_noop_keep_filtered():
    # auto_resolve picks placeholder over real name → keep current → proposed==current → drop
    prio = {"33520003": 100, "e5090011": 30}
    rev = [LabelCandidate(
        target="33520003", direction="back", address=0x100,
        category="function", current="real_existing_name",
        proposed="call100",   # placeholder from low-priority source
        source="e5090011",
    )]
    # auto_resolve: cur_ph=False, prop_ph=True → keep current → proposed becomes "real_existing_name"
    items = build_reconcile_items(rev, prio)
    assert items == []


def test_build_items_genuine_conflict_not_filtered():
    prio = {"33520003": 100, "e5090011": 30}
    rev = [LabelCandidate(
        target="39670016", direction="forward", address=0x100,
        category="function", current="old_name",
        proposed="new_name", source="33520003",
    )]
    items = build_reconcile_items(rev, prio)
    assert len(items) == 1
    assert items[0].proposed == "new_name"


def test_build_items_corroborated_by_populated():
    prio = {"33520003": 100, "30200003": 40}
    c = LabelCandidate(
        target="X", direction="forward", address=0x100,
        category="function", current="call100", proposed="real_fn",
        source="33520003", corroborating_sources=["33520003", "30200003"],
    )
    items = build_reconcile_items([c], prio)
    assert len(items) == 1
    assert items[0].corroborated_by == ["30200003"]
    assert items[0].source == "33520003"
```

- [ ] **Step 2: Run to verify failure**

```
.venv/bin/pytest tests/test_enrich.py::test_build_items_noop_keep_filtered -xvs
```

Expected: `AssertionError` — the item is currently emitted instead of filtered.

- [ ] **Step 3: Implement**

Update `build_reconcile_items` in `rom_analyzer/enrich.py`:

```python
def build_reconcile_items(review: list[LabelCandidate],
                          priority: dict[str, int]) -> list[ReconcileItem]:
    """Turn REVIEW candidates into ReconcileItems with auto-resolved verdicts."""
    items: list[ReconcileItem] = []
    for c in review:
        proposed, verdict = auto_resolve(c, priority)
        if proposed == (c.current or ""):
            continue  # resolved name equals current — nothing to decide
        corroborated_by = [s for s in c.corroborating_sources if s != c.source]
        items.append(ReconcileItem(
            target=c.target, direction=c.direction, address=c.address,
            category=c.category, current=c.current, proposed=proposed,
            source=c.source, evidence=c.evidence, verdict=verdict,
            corroborated_by=corroborated_by,
        ))
    items.sort(key=lambda i: (i.target, i.address))
    return items
```

- [ ] **Step 4: Run tests**

```
.venv/bin/pytest tests/test_enrich.py -xvs
```

Expected: all 45 pass.

- [ ] **Step 5: Commit**

```bash
git add rom_analyzer/enrich.py tests/test_enrich.py
git commit -m "fix(enrich): drop no-op keep items from reconcile output"
```

---

## Task 6: Wire `merge_candidates` into the `enrich` CLI command

**Files:**
- Modify: `rom_analyzer/cli.py` — `enrich` command

- [ ] **Step 1: Update imports and wire the call**

In `rom_analyzer/cli.py`, find this import:

```python
from rom_analyzer.enrich import (
    LabelCandidate, gather_candidates, classify, build_reconcile_items, write_reconcile,
    read_reconcile, apply_verdicts,
```

Add `merge_candidates` to the import:

```python
from rom_analyzer.enrich import (
    LabelCandidate, gather_candidates, merge_candidates, classify,
    build_reconcile_items, write_reconcile, read_reconcile, apply_verdicts,
```

- [ ] **Step 2: Insert `merge_candidates` call**

In the `enrich` command, find the line after the cross-match loop that assembles `all_candidates`:

```python
        all_candidates.extend(cands)
        click.echo(f"   {len(cands)} candidates from {ref.id}")

    # Compute erased-address sets per target ROM (keyed by target id)
```

Insert between them:

```python
        all_candidates.extend(cands)
        click.echo(f"   {len(cands)} candidates from {ref.id}")

        all_candidates = merge_candidates(all_candidates, priority)
        click.echo(f"   → {len(all_candidates)} after merge")

    # Compute erased-address sets per target ROM (keyed by target id)
```

Wait — that inserts inside the loop. The merge should happen once, after the loop. Find the blank line after the loop ends (after the last `click.echo` for the last ref) and insert after it:

```python
        click.echo(f"   {len(cands)} candidates from {ref.id}")

        # ← loop ends here

        all_candidates = merge_candidates(all_candidates, priority)
        click.echo(f"Merged: {len(all_candidates)} unique (target, address) candidates")

        # Compute erased-address sets per target ROM (keyed by target id)
```

- [ ] **Step 3: Pass `priority` to `classify`**

Find the classify call in the enrich command:

```python
            classified = classify(group, erased=erased_by_target.get(tid, set()))
```

Change it to:

```python
            classified = classify(group, erased=erased_by_target.get(tid, set()),
                                  priority=priority)
```

- [ ] **Step 4: Run the full test suite**

```
.venv/bin/pytest tests/ -x -q
```

Expected: all tests pass. (The CLI change has no unit tests of its own; correctness is covered by the enrich.py unit tests.)

- [ ] **Step 5: Commit**

```bash
git add rom_analyzer/cli.py
git commit -m "feat(cli): wire merge_candidates and authority priority into enrich command"
```
