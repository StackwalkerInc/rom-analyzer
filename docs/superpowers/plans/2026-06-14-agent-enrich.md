# Agent-Enrich Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an agentic LLM naming loop that iteratively names unknown and placeholder-named functions across all reference ROMs using Claude Code subagents driven by Ghidra decompiler output.

**Architecture:** A Claude Code skill (`/agent-enrich`) orchestrates one round per invocation — it pops a batch from a priority queue, runs a PyGhidra decompile script, spawns parallel analysis subagents that propose names, applies high-confidence results via a PyGhidra apply script, and updates state files. `/loop /agent-enrich` repeats this until yield drops below threshold. All state is externalized to `agent_enrich_state/` so each round starts with a fresh context.

**Tech Stack:** Python 3.11+, PyGhidra (in-process Ghidra JVM), `rom_analyzer` package (`annotations_io`, `enrich`, `ghidra`, `registry`, `types`), `tomli-w` (already a project dep), Claude Code Agent tool for subagents.

---

## File Map

| File | Action | Purpose |
|---|---|---|
| `rom_analyzer/agent_enrich.py` | Create | Pure Python: queue data model, scoring, yield tracking, stop condition |
| `tests/test_agent_enrich.py` | Create | Unit tests for the above (no Ghidra needed) |
| `rom_analyzer/ghidra.py` | Modify | Add `fetch_callees_of` and `fetch_function_name` helpers |
| `scripts/agent_enrich_init.py` | Create | One-time setup: load all ROMs into Ghidra, enumerate candidates, write `queue.json` |
| `scripts/agent_enrich_decompile.py` | Create | Batch decompile: reads `batch.json`, writes `ctx_{rom}_{addr}.json` per entry |
| `scripts/agent_enrich_apply.py` | Create | Name application: reads `result_*.json`, applies high-confidence to Ghidra + JSON, routes medium/low to `reconcile.toml` |
| `.claude/skills/agent-enrich/SKILL.md` | Create | Claude Code skill: one-round orchestrator |
| `agent_enrich_state/` | Runtime dir | Gitignored state: `queue.json`, `yield_history.json`, `ctx_*`, `result_*`, `done` |

---

## Task 1: Pure Python Core

**Files:**
- Create: `rom_analyzer/agent_enrich.py`
- Create: `tests/test_agent_enrich.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_agent_enrich.py
import json
import pytest
from pathlib import Path
from rom_analyzer.agent_enrich import (
    QueueEntry, load_queue, save_queue,
    load_yield_history, append_yield,
    pop_batch, rescore_neighbors, check_stop_condition, is_done, write_done,
)


@pytest.fixture
def state_dir(tmp_path):
    return tmp_path


def make_entry(address, priority, neighbors=None):
    return QueueEntry(
        rom="33520003",
        address=address,
        current_name=f"FUN_{address[2:].upper().zfill(8)}",
        prog_name="test.bin",
        named_neighbor_count=priority,
        priority=priority,
        neighbor_addresses=neighbors or [],
    )


def test_save_load_queue_roundtrip(state_dir):
    q = [make_entry("0x1a3f0", 8), make_entry("0x2b800", 3)]
    save_queue(state_dir, q)
    loaded = load_queue(state_dir)
    assert len(loaded) == 2
    assert loaded[0].address == "0x1a3f0"
    assert loaded[0].priority == 8
    assert loaded[1].address == "0x2b800"


def test_load_queue_sorted_descending(state_dir):
    q = [make_entry("0x100", 2), make_entry("0x200", 9), make_entry("0x300", 5)]
    save_queue(state_dir, q)
    loaded = load_queue(state_dir)
    priorities = [e.priority for e in loaded]
    assert priorities == sorted(priorities, reverse=True)


def test_load_queue_empty(state_dir):
    assert load_queue(state_dir) == []


def test_append_yield(state_dir):
    append_yield(state_dir, 1, applied=14, review=6)
    append_yield(state_dir, 2, applied=9, review=4)
    history = load_yield_history(state_dir)
    assert len(history) == 2
    assert history[0] == {"round": 1, "applied": 14, "review": 6}
    assert history[1] == {"round": 2, "applied": 9, "review": 4}


def test_pop_batch_full(state_dir):
    q = [make_entry(f"0x{i:x}", i) for i in range(30, 0, -1)]
    batch, remaining = pop_batch(q, k=20)
    assert len(batch) == 20
    assert len(remaining) == 10
    assert batch[0].priority == 30


def test_pop_batch_smaller_than_k(state_dir):
    q = [make_entry("0x100", 5), make_entry("0x200", 3)]
    batch, remaining = pop_batch(q, k=20)
    assert len(batch) == 2
    assert len(remaining) == 0


def test_rescore_neighbors_increments_affected(state_dir):
    q = [
        make_entry("0x100", 2, neighbors=["0x999", "0xabc"]),
        make_entry("0x200", 3, neighbors=["0x111", "0x222"]),
        make_entry("0x300", 1, neighbors=["0xabc", "0xdef"]),
    ]
    # 0xabc was just named
    updated = rescore_neighbors(q, newly_named={"0xabc"})
    by_addr = {e.address: e for e in updated}
    assert by_addr["0x100"].priority == 3   # had 0xabc → +1
    assert by_addr["0x200"].priority == 3   # no overlap → unchanged
    assert by_addr["0x300"].priority == 2   # had 0xabc → +1


def test_rescore_keeps_sort_order(state_dir):
    q = [make_entry("0x100", 5), make_entry("0x200", 1, neighbors=["0xabc"])]
    updated = rescore_neighbors(q, newly_named={"0xabc"})
    # 0x200 went from 1 → 2; 0x100 stays at 5 → 0x100 still first
    assert updated[0].address == "0x100"
    assert updated[1].address == "0x200"


def test_check_stop_false_not_enough_history(state_dir):
    append_yield(state_dir, 1, applied=1, review=0)
    append_yield(state_dir, 2, applied=0, review=0)
    # window=3, only 2 entries → not enough
    assert check_stop_condition(state_dir, window=3, threshold=2) is False


def test_check_stop_true(state_dir):
    append_yield(state_dir, 1, applied=1, review=0)
    append_yield(state_dir, 2, applied=0, review=0)
    append_yield(state_dir, 3, applied=1, review=0)
    # all 3 rounds had applied < 2 → stop
    assert check_stop_condition(state_dir, window=3, threshold=2) is True


def test_check_stop_false_recent_good_round(state_dir):
    append_yield(state_dir, 1, applied=1, review=0)
    append_yield(state_dir, 2, applied=0, review=0)
    append_yield(state_dir, 3, applied=5, review=2)
    # last round had 5 ≥ 2 → continue
    assert check_stop_condition(state_dir, window=3, threshold=2) is False


def test_done_sentinel(state_dir):
    assert not is_done(state_dir)
    write_done(state_dir)
    assert is_done(state_dir)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/amarkelov/claude-hobby/rom-analyzer
.venv/bin/pytest tests/test_agent_enrich.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError` or `ImportError` for `rom_analyzer.agent_enrich`.

- [ ] **Step 3: Implement `rom_analyzer/agent_enrich.py`**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
.venv/bin/pytest tests/test_agent_enrich.py -v
```

Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add rom_analyzer/agent_enrich.py tests/test_agent_enrich.py
git commit -m "feat: agent_enrich pure Python core (queue, scoring, yield, stop)"
```

---

## Task 2: Ghidra Helpers — `fetch_callees_of` and `fetch_function_name`

**Files:**
- Modify: `rom_analyzer/ghidra.py` (add two functions after `fetch_callers_of` at line ~396)

- [ ] **Step 1: Add `fetch_callees_of` after `fetch_callers_of`**

Open `rom_analyzer/ghidra.py` and insert after the `fetch_callers_of` function (after line ~396):

```python
def fetch_callees_of(
    project,
    prog_name: str,
    function_address: int,
) -> list[int]:
    """Return entry-point addresses of functions called by the function at function_address.

    Uses the function body's outgoing CALL references. Addresses masked to uint32,
    sorted, de-duplicated. Returns [] if no function exists at function_address.
    """
    import pyghidra

    with pyghidra.program_context(project, f"/{prog_name}") as program:
        func_mgr = program.getFunctionManager()
        af = program.getAddressFactory().getDefaultAddressSpace()
        addr = af.getAddress(function_address)
        func = func_mgr.getFunctionAt(addr)
        if func is None:
            return []
        body = func.getBody()
        ref_mgr = program.getReferenceManager()
        out: set[int] = set()
        for ref in ref_mgr.getReferencesFromBody(body):
            if ref.getReferenceType().isCall():
                target = ref.getToAddress()
                target_func = func_mgr.getFunctionAt(target)
                if target_func is not None:
                    out.add(int(target_func.getEntryPoint().getOffset()) & 0xFFFFFFFF)
        return sorted(out)


def fetch_function_name(
    project,
    prog_name: str,
    entry_point: int,
) -> str | None:
    """Return the Ghidra name of the function at entry_point, or None if absent."""
    import pyghidra

    with pyghidra.program_context(project, f"/{prog_name}") as program:
        func_mgr = program.getFunctionManager()
        af = program.getAddressFactory().getDefaultAddressSpace()
        addr = af.getAddress(entry_point)
        func = func_mgr.getFunctionAt(addr)
        if func is None:
            return None
        return str(func.getName())
```

- [ ] **Step 2: Verify ghidra.py still imports cleanly**

```bash
.venv/bin/python -c "from rom_analyzer.ghidra import fetch_callees_of, fetch_function_name; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add rom_analyzer/ghidra.py
git commit -m "feat: add fetch_callees_of and fetch_function_name to ghidra.py"
```

---

## Task 3: Initialization Script

**Files:**
- Create: `scripts/agent_enrich_init.py`

This script loads all reference ROMs into the shared Ghidra project, applies annotations, enumerates naming candidates, counts named neighbors, and writes `agent_enrich_state/queue.json`.

- [ ] **Step 1: Create `scripts/agent_enrich_init.py`**

```python
#!/usr/bin/env python3
"""One-time initialization for the agent-enrich loop.

Loads all available reference ROMs into the shared Ghidra project, applies
annotations, enumerates naming candidates (FUN_XXXX and placeholder-named
functions), scores each by named-neighbor count, and writes
agent_enrich_state/queue.json.

Usage:
    .venv/bin/python scripts/agent_enrich_init.py [--force]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

GHIDRA_HOME = Path("/opt/homebrew/opt/ghidra/libexec")
PROJ_DIR = Path.home() / "rom-analyzer-projects"
PROJ_NAME = "rom-analyzer"
REGISTRY = REPO / "reference" / "registry.toml"
STATE_DIR = REPO / "agent_enrich_state"

LANG_DEFAULTS = {
    "fp8000": "m32r:2:fp8000",
    "default": "m32r:2:default",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true",
                        help="Overwrite existing queue.json if present")
    parser.add_argument("--ghidra-home", type=Path, default=GHIDRA_HOME)
    parser.add_argument("--project-dir", type=Path, default=PROJ_DIR)
    parser.add_argument("--project-name", default=PROJ_NAME)
    args = parser.parse_args()

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    queue_path = STATE_DIR / "queue.json"
    yield_path = STATE_DIR / "yield_history.json"

    if queue_path.exists() and not args.force:
        print(f"queue.json already exists at {queue_path}. Use --force to overwrite.")
        sys.exit(0)

    from rom_analyzer.registry import load_registry, partition_available
    from rom_analyzer.annotations_io import load_annotations
    from rom_analyzer.enrich import is_auto_name, is_placeholder
    from rom_analyzer.agent_enrich import QueueEntry, save_queue
    from rom_analyzer.ghidra import (
        setup_environment, _import_program, _overlay_from_annotations,
        ghidriff_program_name, fetch_callers_of, fetch_callees_of,
        fetch_function_name, fetch_function_entry,
    )

    setup_environment(args.ghidra_home)
    import pyghidra
    pyghidra.start()

    entries = load_registry(REGISTRY)
    available, missing = partition_available(entries)
    if missing:
        print(f"Skipping {len(missing)} entries with missing ROMs: "
              f"{[e.id for e in missing]}")

    project_path = args.project_dir / args.project_name
    project = pyghidra.open_project(args.project_dir, args.project_name, create=True)

    # Build per-ROM annotation sets and import programs into Ghidra.
    rom_annotations: dict[str, set[int]] = {}   # rom_id → set of all entry points in JSON
    rom_placeholders: dict[str, set[int]] = {}  # rom_id → placeholder entry points
    rom_prog_names: dict[str, str] = {}

    with project:
        from ghidra.program.util import GhidraProgramUtilities

        for entry in available:
            store = load_annotations(entry.json_path)
            all_eps = {f.entry_point for f in store.functions}
            placeholder_eps = {
                f.entry_point for f in store.functions
                if is_auto_name(f.name) or is_placeholder(f.name)
            }
            rom_annotations[entry.id] = all_eps
            rom_placeholders[entry.id] = placeholder_eps

            prog_name = ghidriff_program_name(entry.rom_path)
            rom_prog_names[entry.id] = prog_name
            lang_id = LANG_DEFAULTS.get(entry.variant, "m32r:2:fp8000")

            print(f"[{entry.id}] Importing {entry.rom_path.name} as {prog_name}")
            _import_program(project, entry.rom_path, prog_name, lang_id)

            with pyghidra.program_context(project, f"/{prog_name}") as program:
                if GhidraProgramUtilities.shouldAskToAnalyze(program):
                    print(f"[{entry.id}] Running Ghidra analysis...")
                    pyghidra.analyze(program)
                    program.save("Analyzed", pyghidra.task_monitor())
                print(f"[{entry.id}] Applying annotations...")
                with pyghidra.transaction(program, "Apply annotations"):
                    _overlay_from_annotations(program, store)
                program.save("Annotations", pyghidra.task_monitor())

        # Enumerate candidates and build queue.
        queue: list[QueueEntry] = []
        print("Enumerating candidates...")

        for entry in available:
            prog_name = rom_prog_names[entry.id]
            all_eps = rom_annotations[entry.id]
            placeholder_eps = rom_placeholders[entry.id]

            with pyghidra.program_context(project, f"/{prog_name}") as program:
                func_mgr = program.getFunctionManager()
                af = program.getAddressFactory().getDefaultAddressSpace()

                for func in func_mgr.getFunctions(True):
                    ep = int(func.getEntryPoint().getOffset()) & 0xFFFFFFFF
                    name = str(func.getName())
                    is_fun_xx = name.startswith("FUN_") and ep not in all_eps
                    is_placeholder_entry = ep in placeholder_eps

                    if not (is_fun_xx or is_placeholder_entry):
                        continue

                    # Collect all neighbor entry points.
                    neighbor_eps: set[int] = set()
                    named_count = 0

                    # Callers: get call sites → containing function entry points.
                    ref_mgr = program.getReferenceManager()
                    target_addr = af.getAddress(ep)
                    for ref in ref_mgr.getReferencesTo(target_addr):
                        if ref.getReferenceType().isCall():
                            caller_func = func_mgr.getFunctionContaining(
                                ref.getFromAddress()
                            )
                            if caller_func is not None:
                                caller_ep = (
                                    int(caller_func.getEntryPoint().getOffset()) & 0xFFFFFFFF
                                )
                                neighbor_eps.add(caller_ep)
                                caller_name = str(caller_func.getName())
                                if not (caller_name.startswith("FUN_")
                                        or is_auto_name(caller_name)
                                        or is_placeholder(caller_name)):
                                    named_count += 1

                    # Callees: outgoing calls.
                    body = func.getBody()
                    for ref in ref_mgr.getReferencesFromBody(body):
                        if ref.getReferenceType().isCall():
                            callee_func = func_mgr.getFunctionAt(ref.getToAddress())
                            if callee_func is not None:
                                callee_ep = (
                                    int(callee_func.getEntryPoint().getOffset()) & 0xFFFFFFFF
                                )
                                neighbor_eps.add(callee_ep)
                                callee_name = str(callee_func.getName())
                                if not (callee_name.startswith("FUN_")
                                        or is_auto_name(callee_name)
                                        or is_placeholder(callee_name)):
                                    named_count += 1

                    queue.append(QueueEntry(
                        rom=entry.id,
                        address=f"0x{ep:x}",
                        current_name=name,
                        prog_name=prog_name,
                        named_neighbor_count=named_count,
                        priority=named_count,
                        neighbor_addresses=sorted(f"0x{a:x}" for a in neighbor_eps),
                    ))

    queue.sort(key=lambda e: e.priority, reverse=True)
    save_queue(STATE_DIR, queue)

    if not yield_path.exists():
        yield_path.write_text("[]")

    print(f"Done. {len(queue)} candidates written to {queue_path}")
    print(f"Top 5 by priority:")
    for e in queue[:5]:
        print(f"  [{e.rom}] {e.address} ({e.current_name}) — {e.priority} named neighbors")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run init (requires Ghidra + all ROMs)**

```bash
.venv/bin/python scripts/agent_enrich_init.py
```

Expected: prints candidate count and top-5 entries, writes `agent_enrich_state/queue.json`.

- [ ] **Step 3: Spot-check the queue**

```bash
.venv/bin/python -c "
from rom_analyzer.agent_enrich import load_queue
q = load_queue('agent_enrich_state')
print(f'Total candidates: {len(q)}')
for e in q[:10]:
    print(f'  [{e.rom}] {e.address} {e.current_name!r} priority={e.priority}')
"
```

Verify: candidates are present, priorities > 0 for entries with named neighbors, sorted descending.

- [ ] **Step 4: Commit**

```bash
git add scripts/agent_enrich_init.py
git commit -m "feat: agent_enrich_init.py — enumerate candidates, write queue.json"
```

---

## Task 4: Decompile Script

**Files:**
- Create: `scripts/agent_enrich_decompile.py`

Reads `agent_enrich_state/batch.json` (written by the orchestrator skill), opens the Ghidra project once, decompiles each function, fetches named callers/callees, writes `agent_enrich_state/ctx_{rom}_{addr}.json` per entry.

- [ ] **Step 1: Create `scripts/agent_enrich_decompile.py`**

```python
#!/usr/bin/env python3
"""Batch decompile script for agent-enrich.

Reads agent_enrich_state/batch.json, opens the shared Ghidra project, decompiles
each function, fetches named callers/callees, and writes ctx_{rom}_{addr}.json.

Usage:
    .venv/bin/python scripts/agent_enrich_decompile.py
        [--batch agent_enrich_state/batch.json]
        [--out-dir agent_enrich_state]
        [--project-dir ~/rom-analyzer-projects]
        [--project-name rom-analyzer]
        [--ghidra-home /opt/homebrew/opt/ghidra/libexec]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

GHIDRA_HOME = Path("/opt/homebrew/opt/ghidra/libexec")
PROJ_DIR = Path.home() / "rom-analyzer-projects"
PROJ_NAME = "rom-analyzer"
STATE_DIR = REPO / "agent_enrich_state"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", type=Path, default=STATE_DIR / "batch.json")
    parser.add_argument("--out-dir", type=Path, default=STATE_DIR)
    parser.add_argument("--project-dir", type=Path, default=PROJ_DIR)
    parser.add_argument("--project-name", default=PROJ_NAME)
    parser.add_argument("--ghidra-home", type=Path, default=GHIDRA_HOME)
    args = parser.parse_args()

    batch = json.loads(args.batch.read_text())
    if not batch:
        print("Empty batch, nothing to do.")
        return

    from rom_analyzer.ghidra import setup_environment
    from rom_analyzer.enrich import is_auto_name, is_placeholder

    setup_environment(args.ghidra_home)
    import pyghidra
    pyghidra.start()

    project = pyghidra.open_project(args.project_dir, args.project_name, create=False)

    written = 0
    with project:
        for item in batch:
            rom = item["rom"]
            address_str = item["address"]
            prog_name = item["prog_name"]
            current_name = item["current_name"]
            address = int(address_str, 16)

            out_path = args.out_dir / f"ctx_{rom}_{address_str[2:]}.json"

            # Decompile.
            from ghidra.app.decompiler import DecompInterface
            with pyghidra.program_context(project, f"/{prog_name}") as program:
                func_mgr = program.getFunctionManager()
                af = program.getAddressFactory().getDefaultAddressSpace()
                ref_mgr = program.getReferenceManager()

                addr = af.getAddress(address)
                func = func_mgr.getFunctionAt(addr)
                if func is None:
                    print(f"  [{rom}] {address_str}: no function at address, skipping")
                    continue

                decomp = DecompInterface()
                decomp.openProgram(program)
                result = decomp.decompileFunction(func, 30, pyghidra.task_monitor())
                decomp.dispose()
                if result is None or not result.decompileCompleted():
                    print(f"  [{rom}] {address_str}: decompilation failed, skipping")
                    continue
                decompiled = result.getDecompiledFunction().getC()

                # Named callers: call sites → containing function name (skip auto names).
                callers: list[str] = []
                caller_neighbor_eps: list[str] = []
                for ref in ref_mgr.getReferencesTo(addr):
                    if ref.getReferenceType().isCall():
                        caller_func = func_mgr.getFunctionContaining(ref.getFromAddress())
                        if caller_func is not None:
                            ep = int(caller_func.getEntryPoint().getOffset()) & 0xFFFFFFFF
                            caller_neighbor_eps.append(f"0x{ep:x}")
                            name = str(caller_func.getName())
                            if not (name.startswith("FUN_")
                                    or is_auto_name(name) or is_placeholder(name)):
                                callers.append(name)

                # Named callees: outgoing calls → callee entry name (skip auto names).
                callees: list[str] = []
                callee_neighbor_eps: list[str] = []
                body = func.getBody()
                for ref in ref_mgr.getReferencesFromBody(body):
                    if ref.getReferenceType().isCall():
                        callee_func = func_mgr.getFunctionAt(ref.getToAddress())
                        if callee_func is not None:
                            ep = int(callee_func.getEntryPoint().getOffset()) & 0xFFFFFFFF
                            callee_neighbor_eps.append(f"0x{ep:x}")
                            name = str(callee_func.getName())
                            if not (name.startswith("FUN_")
                                    or is_auto_name(name) or is_placeholder(name)):
                                callees.append(name)

            ctx = {
                "rom": rom,
                "address": address_str,
                "current_name": current_name,
                "prog_name": prog_name,
                "decompiled": decompiled,
                "callers": sorted(set(callers)),
                "callees": sorted(set(callees)),
            }
            out_path.write_text(json.dumps(ctx, indent=2))
            print(f"  [{rom}] {address_str}: wrote {out_path.name} "
                  f"({len(callers)} callers, {len(callees)} callees)")
            written += 1

    print(f"Decompiled {written}/{len(batch)} functions.")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Manual smoke test — decompile 3 candidates**

```bash
# Write a mini batch file using the top 3 queue entries.
.venv/bin/python -c "
import json
from rom_analyzer.agent_enrich import load_queue
q = load_queue('agent_enrich_state')
batch = [{'rom': e.rom, 'address': e.address, 'current_name': e.current_name, 'prog_name': e.prog_name} for e in q[:3]]
open('agent_enrich_state/batch.json', 'w').write(json.dumps(batch, indent=2))
print('Wrote batch:', batch)
"
.venv/bin/python scripts/agent_enrich_decompile.py
```

Expected: 3 `ctx_*.json` files appear in `agent_enrich_state/`. Each contains decompiled C and caller/callee lists.

```bash
ls agent_enrich_state/ctx_*.json
cat agent_enrich_state/ctx_*.json | python3 -m json.tool | head -40
```

- [ ] **Step 3: Commit**

```bash
git add scripts/agent_enrich_decompile.py
git commit -m "feat: agent_enrich_decompile.py — batch decompile with named neighbor context"
```

---

## Task 5: Apply Script

**Files:**
- Create: `scripts/agent_enrich_apply.py`

Reads all `result_*.json` files in the state dir. For high-confidence: applies name to Ghidra + updates reference JSON. For medium/low: appends to `reference/enrichment/corpus.reconcile.toml`. Writes `agent_enrich_state/applied_this_round.json` with addresses of high-confidence applications (used by orchestrator for rescore).

- [ ] **Step 1: Create `scripts/agent_enrich_apply.py`**

```python
#!/usr/bin/env python3
"""Apply agent-enrich naming results.

Reads result_*.json files from agent_enrich_state/, applies high-confidence names
to the Ghidra project and reference JSONs, routes medium/low to reconcile.toml.
Writes agent_enrich_state/applied_this_round.json with addresses confirmed this round.

Usage:
    .venv/bin/python scripts/agent_enrich_apply.py
        [--state-dir agent_enrich_state]
        [--reference-dir reference]
        [--project-dir ~/rom-analyzer-projects]
        [--project-name rom-analyzer]
        [--ghidra-home /opt/homebrew/opt/ghidra/libexec]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

GHIDRA_HOME = Path("/opt/homebrew/opt/ghidra/libexec")
PROJ_DIR = Path.home() / "rom-analyzer-projects"
PROJ_NAME = "rom-analyzer"
STATE_DIR = REPO / "agent_enrich_state"
REFERENCE_DIR = REPO / "reference"
RECONCILE_PATH = REFERENCE_DIR / "enrichment" / "corpus.reconcile.toml"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=STATE_DIR)
    parser.add_argument("--reference-dir", type=Path, default=REFERENCE_DIR)
    parser.add_argument("--project-dir", type=Path, default=PROJ_DIR)
    parser.add_argument("--project-name", default=PROJ_NAME)
    parser.add_argument("--ghidra-home", type=Path, default=GHIDRA_HOME)
    args = parser.parse_args()

    result_files = sorted(args.state_dir.glob("result_*.json"))
    if not result_files:
        print("No result files found.")
        (args.state_dir / "applied_this_round.json").write_text("[]")
        return

    results = [json.loads(f.read_text()) for f in result_files]
    high = [r for r in results if r["confidence"] == "high"]
    review = [r for r in results if r["confidence"] in ("medium", "low")]

    print(f"Results: {len(high)} high, {len(review)} medium/low")

    # --- Apply high-confidence names ---
    applied_addresses: list[str] = []

    if high:
        from rom_analyzer.ghidra import setup_environment
        from rom_analyzer.annotations_io import load_annotations, save_annotations, AnnotationFunction
        from rom_analyzer.types import PropagatedSymbol
        from rom_analyzer.registry import load_registry

        setup_environment(args.ghidra_home)
        import pyghidra
        pyghidra.start()

        registry = load_registry(args.reference_dir / "registry.toml")
        json_paths = {e.id: e.json_path for e in registry}

        project = pyghidra.open_project(args.project_dir, args.project_name, create=False)

        with project:
            # Group by rom+prog_name for efficient Ghidra access.
            by_rom: dict[str, list[dict]] = {}
            for r in high:
                by_rom.setdefault(r["rom"], []).append(r)

            for rom_id, rom_results in by_rom.items():
                prog_name = rom_results[0]["prog_name"]
                symbols = [
                    PropagatedSymbol(
                        name=r["proposed_name"],
                        ref_address=int(r["address"], 16),
                        new_address=int(r["address"], 16),
                        category="function",
                        confidence="high",
                        source="llm:agent",
                        score=1.0,
                    )
                    for r in rom_results
                ]
                from rom_analyzer.ghidra import apply_labels
                n = apply_labels(project, prog_name, symbols)
                print(f"  [{rom_id}] Applied {n} Ghidra labels")

                # Update reference JSON.
                json_path = json_paths.get(rom_id)
                if json_path and json_path.exists():
                    store = load_annotations(json_path)
                    fn_by_ep = {f.entry_point: f for f in store.functions}
                    added = 0
                    updated = 0
                    for r in rom_results:
                        ep = int(r["address"], 16)
                        if ep in fn_by_ep:
                            fn_by_ep[ep].name = r["proposed_name"]
                            fn_by_ep[ep].source = "llm:agent"
                            fn_by_ep[ep].confidence = "high"
                            updated += 1
                        else:
                            store.functions.append(AnnotationFunction(
                                name=r["proposed_name"],
                                entry_point=ep,
                                confidence="high",
                                source="llm:agent",
                            ))
                            added += 1
                        applied_addresses.append(r["address"])
                    save_annotations(json_path, store)
                    print(f"  [{rom_id}] JSON: {updated} updated, {added} added")

    # --- Route medium/low to reconcile.toml ---
    if review:
        import tomllib
        import tomli_w
        from rom_analyzer.enrich import ReconcileItem, write_reconcile, read_reconcile

        existing_items: list[ReconcileItem] = []
        if RECONCILE_PATH.exists():
            existing_items = read_reconcile(RECONCILE_PATH)

        new_items = [
            ReconcileItem(
                target=r["rom"],
                direction="forward",
                address=int(r["address"], 16),
                category="function",
                current=r.get("current_name"),
                proposed=r["proposed_name"],
                source="llm:agent",
                evidence=r.get("reasoning", ""),
                verdict="proposed",
            )
            for r in review
        ]
        write_reconcile(RECONCILE_PATH, existing_items + new_items)
        print(f"  Appended {len(new_items)} items to {RECONCILE_PATH}")

    (args.state_dir / "applied_this_round.json").write_text(
        json.dumps({
            "addresses": applied_addresses,
            "applied": len(applied_addresses),
            "review": len(review),
        }, indent=2)
    )
    print(f"Done. {len(applied_addresses)} names applied, {len(review)} queued for review.")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Write a dummy result file and run the apply script (dry smoke test)**

```bash
# Write a fake result file to verify routing (uses a placeholder address unlikely to exist).
cat > agent_enrich_state/result_33520003_faketest.json << 'EOF'
{
  "rom": "33520003",
  "address": "0x99999",
  "prog_name": "Z27AG_JDM_5MT_1860B104.bin",
  "current_name": "FUN_00099999",
  "proposed_name": "smoke_test_func",
  "confidence": "medium",
  "reasoning": "smoke test entry"
}
EOF
.venv/bin/python scripts/agent_enrich_apply.py
```

Expected: the fake entry goes to `corpus.reconcile.toml`, not applied to Ghidra or JSON. `applied_this_round.json` is `[]`.

```bash
# Clean up fake file.
rm agent_enrich_state/result_33520003_faketest.json
```

- [ ] **Step 3: Commit**

```bash
git add scripts/agent_enrich_apply.py
git commit -m "feat: agent_enrich_apply.py — apply high-confidence names, route review to reconcile.toml"
```

---

## Task 6: Agent-Enrich Skill

**Files:**
- Create: `.claude/skills/agent-enrich/SKILL.md`

This is the Claude Code skill that orchestrates one round. When invoked via `/agent-enrich`, Claude Code follows these instructions: reads state, pops batch, runs decompile script, spawns parallel analysis subagents, runs apply script, rescores queue, checks stop condition.

- [ ] **Step 1: Create `.claude/skills/agent-enrich/SKILL.md`**

```markdown
# Agent-Enrich: One-Round LLM Naming Orchestrator

Use when invoked via `/agent-enrich`. Executes one round of the agentic naming
loop: pops a batch from the candidate queue, spawns parallel analysis subagents,
applies high-confidence names, updates state.

Run `/loop /agent-enrich` to run the full autonomous loop; run `/agent-enrich`
alone to execute a single round for debugging.

**Working directory:** `/Users/amarkelov/claude-hobby/rom-analyzer`
**Python:** `.venv/bin/python`
**State dir:** `agent_enrich_state/`

---

## Pre-flight Check

- [ ] Check for done sentinel. If `agent_enrich_state/done` exists, print
  "Agent-enrich loop complete — all candidates exhausted or yield threshold reached."
  and stop.

- [ ] Check queue exists. If `agent_enrich_state/queue.json` is absent, print
  "Run `scripts/agent_enrich_init.py` first." and stop.

---

## Step 1: Read State

Read `agent_enrich_state/queue.json` and `agent_enrich_state/yield_history.json`.
Determine the next round number (length of yield_history + 1).

If queue is empty, write `agent_enrich_state/done` and stop.

---

## Step 2: Pop Batch

Take the top 20 entries (highest priority). Write them to `agent_enrich_state/batch.json`:

```json
[
  {"rom": "...", "address": "0x...", "current_name": "...", "prog_name": "..."},
  ...
]
```

---

## Step 3: Decompile Batch

Run:
```bash
.venv/bin/python scripts/agent_enrich_decompile.py
```

This reads `agent_enrich_state/batch.json` and writes `ctx_{rom}_{addr}.json` files.
Wait for it to complete. If it fails, stop and report the error.

---

## Step 4: Spawn Analysis Subagents

For each entry in the batch where a `ctx_*.json` file was produced, spawn a subagent
using the Agent tool. Spawn all subagents in parallel (run_in_background=True where
the tool supports it, otherwise use multiple Agent calls in one message).

**Subagent prompt template** (fill in `{rom}`, `{address}`, `{ctx_file}`):

> You are analyzing a function in a Mitsubishi M32R ECU ROM. Your task is to
> propose a meaningful name for this function.
>
> Read the context file: `agent_enrich_state/ctx_{rom}_{address}.json`
>
> The file contains:
> - `decompiled`: Ghidra-decompiled C source for the function
> - `callers`: names of functions that call this one
> - `callees`: names of functions this one calls
> - `current_name`: the current auto-generated name (context only)
>
> **Naming rules** (from CLAUDE.md):
> - snake_case, domain-prefixed: `sio_`, `sio0_`, `mut_`, `can_`, `obd_`,
>   `boost_`, `knock_`, `gear_`, `cruise_`, `nlts_`, `map_`, `crc_`
> - If the function manages a peripheral register, include the peripheral prefix
> - Follow sibling naming: if callers are `sio0_rx_flush` and `sio0_tx_reset`,
>   a related function is likely `sio0_*`
>
> **Confidence rules:**
> - `high`: clear domain purpose from body AND at least one named neighbor;
>   you are confident the name follows the pattern of sibling functions
> - `medium`: plausible name but only weak evidence (one named neighbor, or
>   ambiguous body behavior)
> - `low`: body is a stub / too short / all neighbors unnamed — propose a
>   structural name like `sio0_helper_{address}` rather than inventing semantics
>
> Use the `reading-m32r-machine-code` skill if you need to decode raw M32R
> instruction patterns visible in the decompiled output.
>
> Write your result to `agent_enrich_state/result_{rom}_{address}.json`:
> ```json
> {
>   "rom": "{rom}",
>   "address": "{address}",
>   "prog_name": "{prog_name}",
>   "current_name": "{current_name}",
>   "proposed_name": "snake_case_name_here",
>   "confidence": "high|medium|low",
>   "reasoning": "one sentence explaining why this name"
> }
> ```

Wait for all subagents to complete before continuing.

---

## Step 5: Apply Results

Run:
```bash
.venv/bin/python scripts/agent_enrich_apply.py
```

This reads all `result_*.json`, applies high-confidence names to Ghidra + reference
JSONs, routes medium/low to `reference/enrichment/corpus.reconcile.toml`, and writes
`agent_enrich_state/applied_this_round.json` with the list of applied addresses.

---

## Step 6: Clean Up Ephemeral Files

Delete all `ctx_*.json` and `result_*.json` files from `agent_enrich_state/`:
```bash
rm -f agent_enrich_state/ctx_*.json agent_enrich_state/result_*.json
```

---

## Step 7: Rescore Queue and Update State

Read `agent_enrich_state/applied_this_round.json` (a dict with `addresses`, `applied`, `review`).

Run the rescore + save in one Python call:
```bash
.venv/bin/python -c "
import json, sys
sys.path.insert(0, '.')
from rom_analyzer.agent_enrich import load_queue, save_queue, rescore_neighbors
summary = json.loads(open('agent_enrich_state/applied_this_round.json').read())
applied = set(summary['addresses'])
q = load_queue('agent_enrich_state')
q = rescore_neighbors(q, newly_named=applied)
save_queue('agent_enrich_state', q)
print(f'Queue rescored. {len(q)} candidates remaining.')
"
```

Remove the batch entries that were processed (those in `batch.json`) from the queue:
```bash
.venv/bin/python -c "
import json, sys
sys.path.insert(0, '.')
from rom_analyzer.agent_enrich import load_queue, save_queue, QueueEntry
batch = json.loads(open('agent_enrich_state/batch.json').read())
batch_addrs = {(e['rom'], e['address']) for e in batch}
q = load_queue('agent_enrich_state')
q = [e for e in q if (e.rom, e.address) not in batch_addrs]
save_queue('agent_enrich_state', q)
print(f'{len(batch_addrs)} entries removed. {len(q)} remaining.')
"
```

---

## Step 8: Record Yield

Read the count of applied addresses from `applied_this_round.json`.
Read the count of medium/low results (check `corpus.reconcile.toml` diff or count
result files before cleanup).

```bash
.venv/bin/python -c "
import json, sys
sys.path.insert(0, '.')
from rom_analyzer.agent_enrich import append_yield, load_yield_history
history = load_yield_history('agent_enrich_state')
round_num = len(history) + 1
summary = json.loads(open('agent_enrich_state/applied_this_round.json').read())
append_yield('agent_enrich_state', round_num, applied=summary['applied'], review=summary['review'])
print(f'Round {round_num}: applied={summary[\"applied\"]}, review={summary[\"review\"]}')
"
```

---

## Step 9: Check Stop Condition

```bash
.venv/bin/python -c "
import sys
sys.path.insert(0, '.')
from rom_analyzer.agent_enrich import check_stop_condition
stop = check_stop_condition('agent_enrich_state', window=3, threshold=2)
print('STOP' if stop else 'CONTINUE')
"
```

If output is `STOP`: write `agent_enrich_state/done` and print:
"Agent-enrich loop stopping — yield below threshold for 3 consecutive rounds."

If output is `CONTINUE`: print a summary of the round (round number, applied count,
review count, candidates remaining) and exit normally. `/loop` will re-invoke
`/agent-enrich` for the next round.

---

## Round Summary Format

Print at end of each round:
```
Round N complete: {applied} names applied, {review} queued for review, {remaining} candidates left.
Top 3 remaining by priority:
  [{rom}] {address} ({current_name}) — priority {priority}
  ...
```
```

- [ ] **Step 2: Verify the skill is discoverable**

```bash
ls .claude/skills/agent-enrich/SKILL.md
```

Expected: file exists. Confirm Claude Code lists it in available skills by starting a new session or checking `/help`.

- [ ] **Step 3: Commit**

```bash
git add .claude/skills/agent-enrich/SKILL.md
git commit -m "feat: agent-enrich Claude Code skill (one-round orchestrator)"
```

---

## Task 7: End-to-End Smoke Test

This task validates the full pipeline with a single manual round. No automated test (Ghidra required).

- [ ] **Step 1: Verify init ran and queue is non-empty**

```bash
.venv/bin/python -c "
from rom_analyzer.agent_enrich import load_queue
q = load_queue('agent_enrich_state')
assert len(q) > 0, 'Queue is empty — rerun agent_enrich_init.py'
print(f'Queue has {len(q)} candidates. Top entry: {q[0].rom} {q[0].address} ({q[0].current_name})')
"
```

- [ ] **Step 2: Run a single round manually via `/agent-enrich`**

Invoke `/agent-enrich` in the Claude Code session. Watch for:
- Batch written to `batch.json` (3–20 entries)
- Decompile script runs and produces `ctx_*.json` files
- Subagents spawn and write `result_*.json` files
- Apply script runs, high-confidence names appear in reference JSON
- Queue is updated (applied entries removed, rescored)
- Round yield logged to `yield_history.json`

- [ ] **Step 3: Verify a reference JSON was updated**

```bash
# Pick the rom from the applied addresses.
applied=$(cat agent_enrich_state/applied_this_round.json)
echo "Applied: $applied"
# Grep for llm:agent source in the reference JSONs.
grep -r '"llm:agent"' reference/*.json | head -5
```

Expected: at least one entry with `"source": "llm:agent"` in the reference JSON.

- [ ] **Step 4: Verify yield_history.json**

```bash
cat agent_enrich_state/yield_history.json
```

Expected: one entry: `[{"round": 1, "applied": N, "review": M}]`.

- [ ] **Step 5: Commit updated reference JSONs**

```bash
git add reference/*.json reference/enrichment/corpus.reconcile.toml
git commit -m "feat: first agent-enrich round — LLM-named functions applied"
```

---

## Gitignore Entry

Add `agent_enrich_state/` to the project `.gitignore` if not already present.

```bash
grep -q "agent_enrich_state" .gitignore || echo "agent_enrich_state/" >> .gitignore
git add .gitignore
git commit -m "chore: gitignore agent_enrich_state runtime dir"
```
