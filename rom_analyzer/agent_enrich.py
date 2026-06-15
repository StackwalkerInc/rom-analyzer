# rom_analyzer/agent_enrich.py
"""Pure Python state management for the agent-enrich agentic naming loop.

No Ghidra imports — this module is unit-testable in CI without a JVM.
"""
from __future__ import annotations

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

    def to_dict(self) -> dict:
        return {
            "rom": self.rom,
            "address": self.address,
            "current_name": self.current_name,
            "prog_name": self.prog_name,
            "named_neighbor_count": self.named_neighbor_count,
            "priority": self.priority,
            "neighbor_addresses": self.neighbor_addresses,
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
            updated.append(QueueEntry(
                rom=entry.rom,
                address=entry.address,
                current_name=entry.current_name,
                prog_name=entry.prog_name,
                named_neighbor_count=entry.named_neighbor_count + gain,
                priority=entry.priority + gain,
                neighbor_addresses=entry.neighbor_addresses,
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
