# Agent-Enrich: One-Round LLM Naming Orchestrator

Use when invoked via `/agent-enrich`. Executes one round of the agentic naming
loop: pops a batch from the function and variable candidate queues, spawns
parallel analysis subagents, applies high-confidence names, updates state.

Run `/loop /agent-enrich` to run the full autonomous loop; run `/agent-enrich`
alone to execute a single round for debugging.

**Working directory:** `/Users/amarkelov/claude-hobby/rom-analyzer`
**Python:** `.venv/bin/python`
**State dir:** `agent_enrich_state/`

---

## Pre-flight Check

- [ ] Check for done sentinels.
  - If BOTH `agent_enrich_state/done` AND `agent_enrich_state/done_vars` exist:
    print "Agent-enrich loop complete — all function and variable candidates exhausted or yield threshold reached." and stop.
  - If only `done` exists: skip function queue this round, continue with variable queue only.
  - If only `done_vars` exists: skip variable queue this round, continue with function queue only.

- [ ] Check queue exists. If `agent_enrich_state/queue.json` is absent (and `done` doesn't exist):
  print "Run `scripts/agent_enrich_init.py` first." and stop.

---

## Step 1: Read State

Read `agent_enrich_state/queue.json` and (if present) `agent_enrich_state/queue_vars.json`.
Read `agent_enrich_state/yield_history.json` and `agent_enrich_state/yield_history_vars.json`.
Determine the next round number (length of yield_history + 1).

If function queue is empty (and `done` not set): write `agent_enrich_state/done` and note it for this round.
If variable queue is empty (and `done_vars` not set): write `agent_enrich_state/done_vars` and note it.

---

## Step 2: Pop Batch

Take the top 20 function entries (highest priority) from `queue.json` (skip if `done`).
Take the top 10 variable entries (highest priority) from `queue_vars.json` (skip if `done_vars`).

Write all entries to `agent_enrich_state/batch.json` using each entry's full `to_dict()` fields
(including `item_type` and `category`):

```python
import json, sys
sys.path.insert(0, '.')
from rom_analyzer.agent_enrich import load_queue, load_var_queue

fn_queue = load_queue('agent_enrich_state')
var_queue = load_var_queue('agent_enrich_state')
fn_batch = fn_queue[:20]
var_batch = var_queue[:10]
batch = [e.to_dict() for e in fn_batch + var_batch]
open('agent_enrich_state/batch.json', 'w').write(json.dumps(batch, indent=2))
print(f"Batch: {len(fn_batch)} functions, {len(var_batch)} variables")
```

---

## Step 3: Decompile / Build Context

Run:
```bash
.venv/bin/python scripts/agent_enrich_decompile.py
```

This reads `agent_enrich_state/batch.json` and writes `ctx_{rom}_{addr}.json` files.
Function entries get decompiled C + callers/callees.
Variable entries get named readers/writers + adjacent symbols + optional writer decompile.
Wait for it to complete. If it fails, stop and report the error.

---

## Step 4: Spawn Analysis Subagents

For each entry in the batch where a `ctx_*.json` file was produced, spawn a subagent
using the Agent tool. Spawn all subagents in parallel (run_in_background=True).

**Subagent prompt for `item_type == "function"`** (fill in `{rom}`, `{address}`, `{prog_name}`, `{current_name}`):

> You are analyzing a function in a Mitsubishi M32R ECU ROM. Your task is to
> propose a meaningful name for this function.
>
> Read the context file: `agent_enrich_state/ctx_{rom}_{address_without_0x}.json`
> (strip the `0x` prefix from the address for the filename)
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
> Write your result to `agent_enrich_state/result_{rom}_{address_without_0x}.json`:
> ```json
> {
>   "rom": "{rom}",
>   "address": "{address}",
>   "prog_name": "{prog_name}",
>   "current_name": "{current_name}",
>   "item_type": "function",
>   "proposed_name": "snake_case_name_here",
>   "confidence": "high|medium|low",
>   "reasoning": "one sentence explaining why this name"
> }
> ```

**Subagent prompt for `item_type == "variable"`** (fill in `{rom}`, `{address}`, `{current_name}`, `{category}`):

> You are naming an unnamed variable in a Mitsubishi M32R ECU ROM.
>
> Read the context file: `agent_enrich_state/ctx_{rom}_{address_without_0x}.json`
> (strip the `0x` prefix from the address for the filename)
>
> The file contains:
> - `category`: "ram_global" (runtime variable, address 0x804000–0x80FFFF) or "data" (flash constant)
> - `data_type`: Ghidra's inferred type at this address (may be null)
> - `named_readers`: names of functions that read this variable
> - `named_writers`: names of functions that write this variable
> - `adjacent_symbols`: already-named symbols within ±64 bytes with their byte offsets
>   (positive offset = higher address; negative = lower address)
> - `writer_decompile`: decompiled C of the sole named writer (null if zero or multiple writers)
>
> **Naming rules:**
> - Use snake_case throughout
> - Use the domain prefix of the writer/reader set: if all readers are `boost_*`, prefix `boost_`;
>   if the sole writer is `crankshaft_isr`, it is a core engine quantity (no sub-prefix needed)
> - Match the naming cluster of adjacent symbols: if neighbors are `engine_rpm`, `engine_rpm_delayed`,
>   `engine_rpm_delta_neg`, a variable at +6 bytes is likely another `engine_rpm_*` variant
> - If the writer applies a scale factor visible in decompiled code (e.g. `>> 2`, `* 4`, `/ 100`),
>   encode that in a suffix: `_x4` means multiply by 4 to get the physical value;
>   `_raw` means ECU stores in a non-obvious unit relative to the physical quantity
> - For flash data (category "data"), prefer the `flash_` prefix convention
>   (e.g. `flash_engine_rpm_basic_axis`)
> - For RAM globals (category "ram_global"), match the pattern of adjacent ram globals directly
>
> **Confidence rules:**
> - `high`: adjacent named cluster clearly implies the name AND writer decompile confirms semantics
> - `medium`: cluster implies a name but no writer decompile, OR writer decompile implies a name
>   but no cluster context
> - `low`: only one weak signal (single unnamed neighbor, or single reader with a generic-sounding name)
>
> Write your result to `agent_enrich_state/result_{rom}_{address_without_0x}.json`:
> ```json
> {
>   "rom": "{rom}",
>   "address": "{address}",
>   "current_name": "{current_name}",
>   "item_type": "variable",
>   "category": "{category}",
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

This reads all `result_*.json`, applies high-confidence function names to `store.functions`
and variable names to `store.symbols` in the reference JSONs, applies Ghidra labels for both,
routes medium/low to `reference/enrichment/corpus.reconcile.toml`, and writes
`agent_enrich_state/applied_this_round.json`.

---

## Step 6: Clean Up Ephemeral Files

Delete all `ctx_*.json` and `result_*.json` files from `agent_enrich_state/`:
```bash
rm -f agent_enrich_state/ctx_*.json agent_enrich_state/result_*.json
```

---

## Step 7: Rescore Queues and Remove Batch

Read `agent_enrich_state/applied_this_round.json`.

**Rescore function queue** (existing logic):
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
print(f'Function queue rescored. {len(q)} candidates remaining.')
"
```

**Rescore variable queue** (new):
```bash
.venv/bin/python -c "
import json, sys
sys.path.insert(0, '.')
from rom_analyzer.agent_enrich import load_var_queue, save_var_queue, rescore_var_neighbors
summary = json.loads(open('agent_enrich_state/applied_this_round.json').read())
all_applied = set(summary['addresses'])
vars_applied = set(summary.get('vars_addresses', []))
q = load_var_queue('agent_enrich_state')
q = rescore_var_neighbors(q, newly_named=all_applied, newly_named_vars=vars_applied)
save_var_queue('agent_enrich_state', q)
print(f'Variable queue rescored. {len(q)} candidates remaining.')
"
```

**Remove processed function batch entries:**
```bash
.venv/bin/python -c "
import json, sys
sys.path.insert(0, '.')
from rom_analyzer.agent_enrich import load_queue, save_queue
batch = json.loads(open('agent_enrich_state/batch.json').read())
fn_batch_addrs = {(e['rom'], e['address']) for e in batch if e.get('item_type', 'function') == 'function'}
q = load_queue('agent_enrich_state')
q = [e for e in q if (e.rom, e.address) not in fn_batch_addrs]
save_queue('agent_enrich_state', q)
print(f'{len(fn_batch_addrs)} function entries removed. {len(q)} remaining.')
"
```

**Remove processed variable batch entries:**
```bash
.venv/bin/python -c "
import json, sys
sys.path.insert(0, '.')
from rom_analyzer.agent_enrich import load_var_queue, save_var_queue
batch = json.loads(open('agent_enrich_state/batch.json').read())
var_batch_addrs = {(e['rom'], e['address']) for e in batch if e.get('item_type') == 'variable'}
q = load_var_queue('agent_enrich_state')
q = [e for e in q if (e.rom, e.address) not in var_batch_addrs]
save_var_queue('agent_enrich_state', q)
print(f'{len(var_batch_addrs)} variable entries removed. {len(q)} remaining.')
"
```

---

## Step 8: Record Yield

**Function yield** (existing):
```bash
.venv/bin/python -c "
import json, sys
sys.path.insert(0, '.')
from rom_analyzer.agent_enrich import append_yield, load_yield_history
history = load_yield_history('agent_enrich_state')
round_num = len(history) + 1
summary = json.loads(open('agent_enrich_state/applied_this_round.json').read())
append_yield('agent_enrich_state', round_num, applied=summary['applied'], review=summary['review'])
print(f'Round {round_num} fn yield: applied={summary[\"applied\"]}, review={summary[\"review\"]}')
"
```

**Variable yield** (new):
```bash
.venv/bin/python -c "
import json, sys
sys.path.insert(0, '.')
from rom_analyzer.agent_enrich import append_var_yield, load_var_yield_history
history = load_var_yield_history('agent_enrich_state')
round_num = len(history) + 1
summary = json.loads(open('agent_enrich_state/applied_this_round.json').read())
append_var_yield('agent_enrich_state', round_num,
                 vars_applied=summary.get('vars_applied', 0),
                 vars_review=summary.get('vars_review', 0))
print(f'Round {round_num} var yield: applied={summary.get(\"vars_applied\", 0)}, review={summary.get(\"vars_review\", 0)}')
"
```

---

## Step 9: Check Stop Conditions

**Function stop:**
```bash
.venv/bin/python -c "
import sys
sys.path.insert(0, '.')
from rom_analyzer.agent_enrich import check_stop_condition
stop = check_stop_condition('agent_enrich_state', window=3, threshold=2)
print('STOP' if stop else 'CONTINUE')
"
```

If STOP and `done` not already set: write `agent_enrich_state/done` and note it.

**Variable stop:**
```bash
.venv/bin/python -c "
import sys
sys.path.insert(0, '.')
from rom_analyzer.agent_enrich import check_var_stop_condition
stop = check_var_stop_condition('agent_enrich_state', window=3, threshold=2)
print('STOP' if stop else 'CONTINUE')
"
```

If STOP and `done_vars` not already set: write `agent_enrich_state/done_vars` and note it.

If BOTH are now stopped: print
"Agent-enrich loop stopping — yield below threshold for both function and variable queues."

---

## Round Summary Format

Print at end of each round:
```
Round N complete:
  Functions: {applied} names applied, {review} queued for review, {fn_remaining} candidates left
  Variables: {vars_applied} names applied, {vars_review} queued for review, {var_remaining} candidates left

Top 3 remaining functions by priority:
  [{rom}] {address} ({current_name}) — priority {priority}
  ...

Top 3 remaining variables by priority:
  [{rom}] {address} ({current_name}) — priority {priority}
  ...
```
