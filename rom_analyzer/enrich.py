"""Reference enrichment: classify cross-match labels, auto-resolve, reconcile.

Drives the propose -> review -> apply cycle for cross-pollinating references.
Pure logic here; the Ghidra cross-match lives in cli.py and feeds this module
LabelCandidate lists.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Ghidra auto-generated names (no human meaning) — never propagate these.
_AUTO_RE = re.compile(r"^(FUN|LAB|DAT|SUB)_[0-9a-fA-F]+$|^(icu_isr|isr_vector)_\d+$")
# Address-derived placeholder names a real name should beat.
_PLACEHOLDER_RE = re.compile(
    r"(^|_)(call|nop|ret\d*|reset_call|sub)[0-9a-fA-F_]{4,}(?=_|$|[^a-zA-Z0-9_])"   # callNNNN, nopNNNN, ret0_NNNN, subNNNN
    r"|(^|_)fp[0-9a-fA-F]{3,}(_|$)"                                                    # fpNNNN_*, get_fpNNNN
)


# Real-looking but meaningless names that should never silently fill a gap
# (they slip past the auto-name / placeholder filters — e.g. "out").
_JUNK_NAMES = frozenset({
    "out", "in", "tmp", "temp", "foo", "bar", "data", "val", "value", "ptr",
    "ret", "end", "sub", "fn", "func", "stub", "todo", "tbd", "unknown", "x",
})


def is_auto_name(name: str) -> bool:
    """True for Ghidra auto-generated names with no human meaning."""
    return bool(_AUTO_RE.match(name))


def is_generic(name: str) -> bool:
    """True for names too generic to auto-apply (<=3 chars or a bare junk word).

    These pass is_auto_name/is_placeholder but carry no domain meaning (e.g.
    "out"); they must be reviewed, not silently applied as a gap-fill.
    """
    return len(name) <= 3 or name.lower() in _JUNK_NAMES


def is_placeholder(name: str) -> bool:
    """True for address-derived placeholder names (callNNNN, fpNNNN_*, retN_*)."""
    return bool(_PLACEHOLDER_RE.search(name))


@dataclass
class LabelCandidate:
    target: str        # reference id being modified
    direction: str     # "forward" (into new) | "back" (into existing)
    address: int
    category: str      # "function" | "data" | "ram_global"
    current: str | None  # target's existing name at address; None if a gap
    proposed: str      # candidate name from the source reference
    source: str        # source reference id (provenance)
    evidence: str = ""
    corroborating_sources: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.corroborating_sources:
            self.corroborating_sources = [self.source]


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


@dataclass
class Classified:
    auto: list[LabelCandidate]    # new functions, safe to apply now
    review: list[LabelCandidate]  # conflicts + RAM/data, need verdicts


def classify(candidates: list[LabelCandidate], erased: set[int]) -> Classified:
    """Split candidates into auto-apply / review / drop.

    AUTO  : a new function (gap, current is None), real non-generic name, entry
            not erased.
    DROP  : auto-names anywhere; functions whose entry is in erased flash.
    REVIEW: name conflicts (current set and differs from proposed); all RAM/data
            candidates (raw-offset data is filtered upstream; what arrives here
            already passed usage-equivalence).
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
            if c.current is None:
                if is_generic(c.proposed):
                    review.append(c)   # too generic to auto-apply — review it
                else:
                    auto.append(c)     # new function gap — cross-family safe
            else:
                review.append(c)       # genuine fn name conflict
        else:
            review.append(c)           # RAM/data always reviewed
    return Classified(auto=auto, review=review)


def auto_resolve(c: LabelCandidate, priority: dict[str, int]) -> tuple[str, str]:
    """Suggest (proposed_name, default_verdict) for a REVIEW candidate.

    Rules, in order:
      1. Keep target's sio0/sio1 prefix (deliberately standardised) -> keep.
      2. Descriptive beats placeholder, regardless of priority.
      3. Authority by registry priority: higher-priority side's name wins; if the
         target already outranks the source and has a real name, keep target.
    """
    cur = c.current or ""
    # 1. hold sio prefix on the target
    if cur.startswith(("sio0", "sio1")):
        return cur, "keep"
    # 2. descriptive beats placeholder
    cur_ph = is_placeholder(cur) or not cur
    prop_ph = is_placeholder(c.proposed)
    if cur_ph and not prop_ph:
        return c.proposed, "proposed"
    if prop_ph and not cur_ph:
        return cur, "keep"
    # 3. authority by priority
    if priority.get(c.source, 0) > priority.get(c.target, 0):
        return c.proposed, "proposed"
    return cur, "keep"


# ---------------------------------------------------------------------------
# File I/O and verdict application
# ---------------------------------------------------------------------------

import tomllib
from dataclasses import replace
from pathlib import Path

import tomli_w

from rom_analyzer.annotations_io import AnnotationFunction, AnnotationStore, AnnotationSymbol


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
    # group by target then address for readable review
    items.sort(key=lambda i: (i.target, i.address))
    return items


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


def _resolved_name(item: ReconcileItem) -> str | None:
    """Final name for an item, or None to leave/skip."""
    if item.verdict == "proposed":
        return item.proposed
    if item.verdict == "keep":
        return None
    if item.verdict == "drop":
        return None
    return item.verdict  # custom name


def apply_verdicts(store: AnnotationStore, items: list[ReconcileItem],
                   target: str) -> int:
    """Apply this target's reconcile verdicts to its AnnotationStore in place.

    Renames existing entries, or adds a new one for a gap (current is None) when
    the verdict yields a name. Returns the number of mutations.
    """
    fn_by_addr = {f.entry_point: i for i, f in enumerate(store.functions)}
    sym_by_addr = {s.address: i for i, s in enumerate(store.symbols)}
    n = 0
    for it in items:
        if it.target != target:
            continue
        name = _resolved_name(it)
        if name is None:
            continue
        if it.category == "function":
            if it.address in fn_by_addr:
                idx = fn_by_addr[it.address]
                if store.functions[idx].name != name:
                    store.functions[idx] = replace(store.functions[idx], name=name)
                    n += 1
            elif it.current is None:
                store.functions.append(AnnotationFunction(
                    name=name, entry_point=it.address, confidence="medium",
                    source=f"xref:{it.source}"))
                n += 1
        else:
            if it.address in sym_by_addr:
                idx = sym_by_addr[it.address]
                if store.symbols[idx].name != name:
                    store.symbols[idx] = replace(store.symbols[idx], name=name)
                    n += 1
            elif it.current is None:
                store.symbols.append(AnnotationSymbol(
                    name=name, address=it.address, category=it.category,
                    confidence="medium", source=f"xref:{it.source}"))
                n += 1
    return n


# ---------------------------------------------------------------------------
# Cross-match candidate gathering
# ---------------------------------------------------------------------------

from rom_analyzer.types import MatchedFunction


def gather_candidates(
    new_id: str, ref_id: str,
    matches: list[MatchedFunction],
    new_fn_names: dict[int, str],
    ref_fn_names: dict[int, str],
    ram_data_candidates: list[LabelCandidate] | None = None,
) -> list[LabelCandidate]:
    """Build forward + back function LabelCandidates from one cross-match.

    forward: the reference's name applied onto the new ref's address.
    back:    the new ref's name applied onto the reference's address.
    `ram_data_candidates` (already usage-equivalence-filtered, both directions)
    are appended as-is.
    """
    out: list[LabelCandidate] = []
    for m in matches:
        ref_name = ref_fn_names.get(m.ref_address, m.ref_name)
        new_name = new_fn_names.get(m.new_address)
        if ref_name:
            out.append(LabelCandidate(
                target=new_id, direction="forward", address=m.new_address,
                category="function", current=new_name, proposed=ref_name,
                source=ref_id, evidence=f"bytecode match sim={m.similarity:.2f}"))
        if new_name:
            out.append(LabelCandidate(
                target=ref_id, direction="back", address=m.ref_address,
                category="function", current=ref_fn_names.get(m.ref_address),
                proposed=new_name, source=new_id,
                evidence=f"bytecode match sim={m.similarity:.2f}"))
    if ram_data_candidates:
        out.extend(ram_data_candidates)
    return out


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
