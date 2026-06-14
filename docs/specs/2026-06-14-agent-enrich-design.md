# Agent-Enrich: LLM-Driven Naming Loop

**Status:** Design approved  
**Date:** 2026-06-14

---

## Problem

The structural cross-matching pipeline (`rom-analyzer enrich`) exhausts what callgraph
similarity can reliably name. The residual unknowns fall into two categories:

- `FUN_XXXX` — functions Ghidra auto-discovered but that never appeared in any reference
  (`colt_flash.txt`, `z27ag_s`, or a matched cross-ROM function)
- Placeholder-named functions — entries already in the reference JSONs under address-derived
  names (`call3f2a0`, `update_fp8042`, `fp12962_u16`) that pass `is_placeholder()` or
  `is_auto_name()` in `enrich.py`

These cannot be named structurally; they require semantic reasoning over decompiled code.

---

## Solution

An agentic naming loop driven by Claude Code. The orchestrator is a Claude Code skill
(`/agent-enrich`) that dispatches analysis subagents in parallel. State is fully
externalized to files so each round starts with a clean context. `/loop /agent-enrich`
provides autonomous iteration with `/loop` managing round scheduling.

---

## Architecture

```
user: /loop /agent-enrich
         │
         ▼ (each round — fresh orchestrator context)
  /agent-enrich skill
    │  read queue.json + yield_history.json
    │  pop top-K candidates (default K=20)
    │  bash scripts/agent_enrich_decompile.py  ← PyGhidra: decompile + neighbors
    │                 writes ctx_{rom}_{addr}.json per function
    │  Agent × K (parallel analysis subagents)
    │       each: read ctx file → propose name + confidence → write result file
    │  collect result files, build terse summary, delete raw files
    │  bash scripts/agent_enrich_apply.py  ← PyGhidra: apply high-confidence names
    │  update reference JSONs (source: "llm:agent")
    │  append medium/low to reconcile.toml
    │  re-score queue neighbors, write queue.json + yield_history.json
    │  check stop condition → write done sentinel or exit normally
         │
         ▼ (/loop re-invokes via ScheduleWakeup until done sentinel)
```

### Context isolation

The orchestrator reads only file summaries (name + confidence + one-line reasoning),
never raw decompiled output. Raw context files (`ctx_*.json`) and raw result files
(`result_*.json`) are created per round and deleted after the orchestrator collects them.
Context does not accumulate across rounds.

---

## Components

| Component | Type | Responsibility |
|---|---|---|
| `skills/agent-enrich.md` | Claude Code skill | One-round orchestrator |
| `scripts/agent_enrich_init.py` | Python/PyGhidra | One-time setup: load ROMs, enumerate candidates, write `queue.json` |
| `scripts/agent_enrich_decompile.py` | Python/PyGhidra | Decompile one function + fetch named callers/callees → `ctx_*.json` |
| `scripts/agent_enrich_apply.py` | Python/PyGhidra | Apply confirmed name to Ghidra label + update reference JSON |
| `rom_analyzer/agent_enrich.py` | Pure Python | Queue scoring, yield tracking, stop condition — no Ghidra imports |
| Analysis subagents | Agent tool spawns | Read context file, propose name + confidence, write result file |
| `agent_enrich_state/` | Runtime directory | Persistent state between rounds (gitignored) |

All LLM reasoning lives in Claude Code (skill + subagents). All Ghidra I/O lives in
the thin Python scripts. `rom_analyzer/agent_enrich.py` is pure Python so it is
unit-testable without Ghidra.

---

## Data Structures

### `agent_enrich_state/queue.json`

```json
[
  {
    "rom": "33520003",
    "address": "0x1a3f0",
    "current_name": "FUN_0001a3f0",
    "named_neighbor_count": 8,
    "priority": 8
  },
  {
    "rom": "39670016",
    "address": "0x2b800",
    "current_name": "call0002b800",
    "named_neighbor_count": 3,
    "priority": 3
  }
]
```

Sorted descending by `priority`. `priority` equals `named_neighbor_count` and is
updated dynamically after each round as newly named functions raise the scores of their
still-unnamed neighbors. Functions with more named immediate neighbors are processed
first — richer context yields higher-confidence LLM proposals.

### `agent_enrich_state/yield_history.json`

```json
[
  {"round": 1, "applied": 14, "review": 6},
  {"round": 2, "applied": 9,  "review": 4},
  {"round": 3, "applied": 2,  "review": 3}
]
```

### `agent_enrich_state/ctx_{rom}_{addr}.json` (ephemeral)

```json
{
  "rom": "33520003",
  "address": "0x1a3f0",
  "current_name": "FUN_0001a3f0",
  "decompiled": "void FUN_0001a3f0(...) { ... }",
  "callers": ["sio_dma_reset", "sio0_tx_dma_init"],
  "callees": ["FUN_0001a100", "mut_log_reply_std"]
}
```

Callees that are still unnamed are included by address so the subagent knows which
neighbors are dark. Named callees provide domain anchoring.

### `agent_enrich_state/result_{rom}_{addr}.json` (ephemeral)

```json
{
  "rom": "33520003",
  "address": "0x1a3f0",
  "proposed_name": "sio0_rx_flush",
  "confidence": "high",
  "reasoning": "clears SIO0 RX FIFO; called only from sio_dma_reset and sio0_tx_dma_init at shutdown"
}
```

### `agent_enrich_state/done` (sentinel)

Empty file. Written by the skill when the stop condition is met. `/loop` checks for
it and exits.

---

## Initialization

Run once before starting the loop:

```
.venv/bin/python scripts/agent_enrich_init.py
```

Steps:
1. Open all reference ROMs in the shared Ghidra project via PyGhidra
2. Apply annotations from each `reference/*.json`
3. Enumerate candidates across all ROMs:
   - `FUN_XXXX` present in Ghidra but absent from the JSON
   - JSON entries where `is_placeholder(name) or is_auto_name(name)` (from `enrich.py`)
4. For each candidate: count named immediate neighbors (named callers + named callees in Ghidra)
5. Write sorted `queue.json`; write empty `yield_history.json`

---

## Subagent Prompt Design

Each analysis subagent receives:

> You are analyzing a function in a Mitsubishi M32R ECU ROM. Your task is to propose a
> meaningful name for this function based on its decompiled body and the names of its
> immediate callers and callees.
>
> Follow the naming conventions in CLAUDE.md: snake_case, domain-prefixed
> (`sio_`, `mut_`, `can_`, `obd_`, `boost_`, `knock_`, etc.).
>
> Confidence rules:
> - **high**: clear domain purpose from body + neighbors; follows sibling naming pattern
> - **medium**: plausible but ambiguous, or only one named neighbor
> - **low**: body too short/generic, or all neighbors unnamed — propose a structural name
>   (e.g. `sio0_helper_1a3f0`) rather than a semantic one
>
> Read `agent_enrich_state/ctx_{rom}_{addr}.json`. Write your result to
> `agent_enrich_state/result_{rom}_{addr}.json` using the schema above.

Subagents have access to CLAUDE.md (ECU domain context) and the
`reading-m32r-machine-code` skill for decoding raw instruction patterns in decompiled output.

---

## Confidence Routing

| Confidence | Action |
|---|---|
| `high` | Apply to Ghidra label + update reference JSON (`source: "llm:agent"`) |
| `medium` | Append to `reference/enrichment/corpus.reconcile.toml` with reasoning |
| `low` | Append to `reconcile.toml` flagged `/* VERIFY */`, skip JSON update |

The `llm:agent` source tag is distinguishable from `colt_flash`, `xref:*`, and `ghidra`
in provenance tracking.

---

## Stop Condition

```python
YIELD_WINDOW = 3       # consecutive rounds to check
YIELD_THRESHOLD = 2    # minimum high-confidence names per round to continue

recent = yield_history[-YIELD_WINDOW:]
if len(recent) >= YIELD_WINDOW and all(r["applied"] < YIELD_THRESHOLD for r in recent):
    write done sentinel
    exit
```

Default: three consecutive rounds each producing fewer than 2 high-confidence names → done.
Both values are configurable via CLI options on the skill.

---

## Workflow Integration

```
rom-analyzer analyze    →  build Ghidra project, match against reference
rom-analyzer enrich     →  structural cross-matching, reconcile.toml
python agent_enrich_init.py  →  build queue (one-time)
/loop /agent-enrich     →  LLM naming loop for residual unknowns
```

`agent-enrich` reads and writes the same `reference/*.json` files and appends to the
same `corpus.reconcile.toml` used by `enrich`. No new file formats introduced.

### Reused existing code

- `annotations_io.py` — `load_annotations()` / `save_annotations()` unchanged
- `enrich.py` — `is_auto_name()`, `is_placeholder()`, `is_generic()` for candidate selection
- `ghidra.py` — `decompile_function()`, `fetch_callers_of()`, `apply_labels()`
- `ghidra_overlay.py` — `_overlay_from_annotations()` for re-applying after each round
- `reference/enrichment/corpus.reconcile.toml` — appended to, not replaced

---

## What Is Not In Scope

- Naming data labels or RAM globals (functions only in this loop; data enrichment is a
  separate concern already partially handled by `enrich`)
- Multi-hop context (callers-of-callers); immediate neighbors only
- Automatic merging of medium/low candidates; those require human review via
  `apply-enrichment` as in the existing flow
- SH-2 ROMs; M32R only (same constraint as the rest of `rom-analyzer`)
