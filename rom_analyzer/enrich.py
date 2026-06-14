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
