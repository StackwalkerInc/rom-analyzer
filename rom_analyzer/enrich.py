"""Reference enrichment: classify cross-match labels, auto-resolve, reconcile.

Drives the propose -> review -> apply cycle for cross-pollinating references.
Pure logic here; the Ghidra cross-match lives in cli.py and feeds this module
LabelCandidate lists.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Ghidra auto-generated names (no human meaning) — never propagate these.
_AUTO_RE = re.compile(r"^(FUN|LAB|DAT|SUB)_[0-9a-fA-F]+$|^(icu_isr|isr_vector)_\d+$")
# Address-derived placeholder names a real name should beat.
_PLACEHOLDER_RE = re.compile(
    r"(^|_)(call|nop|ret\d*|reset_call|sub)[0-9a-fA-F_]{2,}(?=_|$|[^a-zA-Z0-9_])"   # callNNNN, nopNNNN, ret0_NNNN, subNNNN
    r"|(^|_)fp[0-9a-fA-F]{3,}(_|$)"                                                    # fpNNNN_*, get_fpNNNN
)


def is_auto_name(name: str) -> bool:
    """True for Ghidra auto-generated names with no human meaning."""
    return bool(_AUTO_RE.match(name))


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


@dataclass
class Classified:
    auto: list[LabelCandidate]    # new functions, safe to apply now
    review: list[LabelCandidate]  # conflicts + RAM/data, need verdicts


def classify(candidates: list[LabelCandidate], erased: set[int]) -> Classified:
    """Split candidates into auto-apply / review / drop.

    AUTO  : a new function (gap, current is None), real name, entry not erased.
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
                auto.append(c)         # new function gap — cross-family safe
            else:
                review.append(c)       # genuine fn name conflict
        else:
            review.append(c)           # RAM/data always reviewed
    return Classified(auto=auto, review=review)
