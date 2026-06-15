# rom_analyzer/agent_enrich.py
"""Pure Python state management for the agent-enrich agentic naming loop.

No Ghidra imports — this module is unit-testable in CI without a JVM.
"""
from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class QueueEntry:
    rom: str
    address: str           # hex string, e.g. "0x1a3f0"
    current_name: str
    prog_name: str         # Ghidra program name (from ghidriff_program_name)
    named_neighbor_count: int
    priority: int          # = named_neighbor_count; updated on rescore
    neighbor_addresses: list[str] = field(default_factory=list)
    item_type: str = field(default="function")   # "function" | "variable"
    category: str = field(default="")            # "ram_global" | "data" (variables only)
    sibling_addresses: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rom": self.rom,
            "address": self.address,
            "current_name": self.current_name,
            "prog_name": self.prog_name,
            "named_neighbor_count": self.named_neighbor_count,
            "priority": self.priority,
            "neighbor_addresses": self.neighbor_addresses,
            "item_type": self.item_type,
            "category": self.category,
            "sibling_addresses": self.sibling_addresses,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "QueueEntry":
        return cls(
            rom=d["rom"],
            address=d["address"],
            current_name=d["current_name"],
            prog_name=d.get("prog_name", ""),
            named_neighbor_count=d["named_neighbor_count"],
            priority=d["priority"],
            neighbor_addresses=d.get("neighbor_addresses", []),
            item_type=d.get("item_type", "function"),
            category=d.get("category", ""),
            sibling_addresses=d.get("sibling_addresses", []),
        )


def load_queue(state_dir: Path) -> list[QueueEntry]:
    """Load and return queue sorted descending by priority. Returns [] if absent."""
    path = Path(state_dir) / "queue.json"
    if not path.exists():
        return []
    entries = [QueueEntry.from_dict(d) for d in json.loads(path.read_text())]
    entries.sort(key=lambda e: e.priority, reverse=True)
    return entries


def save_queue(state_dir: Path, queue: list[QueueEntry]) -> None:
    path = Path(state_dir) / "queue.json"
    path.write_text(json.dumps([e.to_dict() for e in queue], indent=2))


def load_yield_history(state_dir: Path) -> list[dict]:
    path = Path(state_dir) / "yield_history.json"
    if not path.exists():
        return []
    return json.loads(path.read_text())


def append_yield(state_dir: Path, round_num: int, applied: int, review: int) -> None:
    history = load_yield_history(state_dir)
    history.append({"round": round_num, "applied": applied, "review": review})
    (Path(state_dir) / "yield_history.json").write_text(json.dumps(history, indent=2))


def pop_batch(
    queue: list[QueueEntry], k: int
) -> tuple[list[QueueEntry], list[QueueEntry]]:
    """Return (batch, remaining). Queue must already be sorted descending by priority."""
    return queue[:k], queue[k:]


def rescore_neighbors(
    queue: list[QueueEntry], newly_named: set[str]
) -> list[QueueEntry]:
    """Increment priority for entries whose neighbor_addresses overlap newly_named.

    newly_named: hex address strings (e.g. {"0x1a3f0"}) just confirmed this round.
    Returns a new list sorted descending by priority.
    """
    updated = []
    for entry in queue:
        gain = len(set(entry.neighbor_addresses) & newly_named)
        if gain > 0:
            updated.append(dataclasses.replace(
                entry,
                named_neighbor_count=entry.named_neighbor_count + gain,
                priority=entry.priority + gain,
            ))
        else:
            updated.append(entry)
    updated.sort(key=lambda e: e.priority, reverse=True)
    return updated


def check_stop_condition(
    state_dir: Path,
    window: int = 3,
    threshold: int = 2,
) -> bool:
    """Return True if the last `window` rounds each applied fewer than `threshold` names."""
    history = load_yield_history(state_dir)
    if len(history) < window:
        return False
    recent = history[-window:]
    return all(r["applied"] < threshold for r in recent)


def is_done(state_dir: Path) -> bool:
    return (Path(state_dir) / "done").exists()


def write_done(state_dir: Path) -> None:
    (Path(state_dir) / "done").touch()


def load_var_queue(state_dir: Path) -> list[QueueEntry]:
    """Load variable queue sorted descending by priority. Returns [] if absent."""
    path = Path(state_dir) / "queue_vars.json"
    if not path.exists():
        return []
    entries = [QueueEntry.from_dict(d) for d in json.loads(path.read_text())]
    entries.sort(key=lambda e: e.priority, reverse=True)
    return entries


def save_var_queue(state_dir: Path, queue: list[QueueEntry]) -> None:
    path = Path(state_dir) / "queue_vars.json"
    path.write_text(json.dumps([e.to_dict() for e in queue], indent=2))


def rescore_var_neighbors(
    queue: list[QueueEntry],
    newly_named: set[str],
    newly_named_vars: set[str],
) -> list[QueueEntry]:
    """Rescore variable queue entries using two boost signals.

    newly_named: hex addresses of functions named this round. Boosts entries whose
        neighbor_addresses (which store named-function EPs only, not variable
        addresses) overlap this set. Passing variable addresses here is harmless
        because function EPs (flash, 0x10000+) and variable addresses (RAM,
        0x804000+) do not overlap in M32R ECU ROMs.
    newly_named_vars: hex addresses of variables named this round. Boosts entries
        whose sibling_addresses overlap this set (sibling proximity boost).
    """
    updated = []
    gains = []
    for entry in queue:
        gain = len(set(entry.neighbor_addresses) & newly_named)
        sibling_gain = len(set(entry.sibling_addresses) & newly_named_vars)
        total_gain = gain + sibling_gain
        if total_gain > 0:
            updated.append(dataclasses.replace(
                entry,
                named_neighbor_count=entry.named_neighbor_count + total_gain,
                priority=entry.priority + total_gain,
            ))
        else:
            updated.append(entry)
        gains.append(total_gain)
    # Sort by priority descending; among ties, entries that received a boost this round come first.
    paired = sorted(zip(updated, gains), key=lambda t: (t[0].priority, t[1]), reverse=True)
    return [e for e, _ in paired]


def load_var_yield_history(state_dir: Path) -> list[dict]:
    path = Path(state_dir) / "yield_history_vars.json"
    if not path.exists():
        return []
    return json.loads(path.read_text())


def append_var_yield(
    state_dir: Path, round_num: int, vars_applied: int, vars_review: int
) -> None:
    history = load_var_yield_history(state_dir)
    history.append({"round": round_num, "vars_applied": vars_applied, "vars_review": vars_review})
    (Path(state_dir) / "yield_history_vars.json").write_text(json.dumps(history, indent=2))


def check_var_stop_condition(
    state_dir: Path,
    window: int = 3,
    threshold: int = 2,
) -> bool:
    """Return True if last `window` var rounds each applied fewer than `threshold` names."""
    history = load_var_yield_history(state_dir)
    if len(history) < window:
        return False
    recent = history[-window:]
    return all(r["vars_applied"] < threshold for r in recent)


def is_var_done(state_dir: Path) -> bool:
    return (Path(state_dir) / "done_vars").exists()


def write_var_done(state_dir: Path) -> None:
    (Path(state_dir) / "done_vars").touch()
