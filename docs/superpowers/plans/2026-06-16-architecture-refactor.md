# Architecture Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split the monolithic `cli.py` (1,125 lines) and `ghidra.py` (935 lines) into a `ghidra/` subpackage with clear layer boundaries, a `pipeline/` subpackage with typed stage results, a `GhidraSession` class, and a consolidated `scripts/` directory — with zero logic changes.

**Architecture:** `ghidra/` splits into session/fetch/domain/overlay layers; `pipeline/` holds typed stage result dataclasses and one function per pipeline phase; `cli.py` shrinks to ~250 lines of pure orchestration. All existing `from rom_analyzer.ghidra import ...` statements continue to work via `__init__.py` re-exports.

**Tech Stack:** Python 3.11+, click, pyghidra, pytest

---

## File Map

**Created:**
- `rom_analyzer/cleanup.py` — 3 shared annotation-cleanup functions (moved from `scripts/build_reference_from_txt.py`)
- `rom_analyzer/ghidra/__init__.py` — re-exports full old `ghidra.py` surface
- `rom_analyzer/ghidra/session.py` — `HeadlessRun`, `GhidraSession`, `import_and_dump`, `setup_environment`, `ghidriff_program_name`, `apply_labels`, `apply_data_types`, `apply_mut_table_in_ghidra`, `decompile_function`
- `rom_analyzer/ghidra/fetch.py` — all `fetch_*` functions (read-only Ghidra queries)
- `rom_analyzer/ghidra/domain.py` — `fetch_pid_dispatch_entries`, `fetch_dtc_helpers_structural`, `fetch_dtc_call_sites`
- `rom_analyzer/ghidra/overlay.py` — moved from `ghidra_overlay.py` (`_ParsedType`, `_parse_type_str`, `apply_annotations`)
- `rom_analyzer/pipeline/__init__.py` — empty
- `rom_analyzer/pipeline/types.py` — `RomContext`, `ImportResult`, `ReferenceMatchResult`, `MergeResult`, `AnalysisResult`
- `rom_analyzer/pipeline/reference.py` — `import_stage()`, `match_reference()`
- `rom_analyzer/pipeline/arbitrate.py` — `arbitrate_references()`, `classify_and_apply()`
- `rom_analyzer/pipeline/post_match.py` — `post_match_analysis()`
- `rom_analyzer/pipeline/output.py` — `write_outputs()`

**Modified:**
- `rom_analyzer/cli.py` — shrinks to ~250 lines (imports stage fns, uses `GhidraSession`)
- `rom_analyzer/scripts/build_reference_from_txt.py` — imports 3 fns from `cleanup` instead of defining them
- `rom_analyzer/ghidra_overlay.py` — becomes a 3-line backward-compat shim
- `tests/test_dedup_names.py` — import path updated to `rom_analyzer.cleanup`

**Deleted:**
- `rom_analyzer/ghidra.py` — replaced by `rom_analyzer/ghidra/` package
- `rom_analyzer/scripts/__init__.py`, `build_reference_from_txt.py`, `export_annotations.py`, `import_annotations.py`, `dump_references.py`, `m32r_analysis.py` — moved to root `scripts/`

**Renamed (root `scripts/`):**
- `agent_enrich_init.py` → `enrich_init.py`
- `agent_enrich_init_vars.py` → `enrich_init_vars.py`
- `agent_enrich_decompile.py` → `enrich_decompile.py`
- `agent_enrich_apply.py` → `enrich_apply.py`
- `dma_activation_analysis.py` → `dma_activation.py`
- `check_reference_name_uniqueness.py` → `check_reference_names.py`

---

### Task 1: Create `rom_analyzer/cleanup.py`

Move the three annotation-cleanup functions out of `build_reference_from_txt.py` so `cli.py` no longer imports from a build script.

**Files:**
- Create: `rom_analyzer/cleanup.py`
- Modify: `rom_analyzer/scripts/build_reference_from_txt.py:370-458` (replace defs with import)
- Modify: `rom_analyzer/cli.py:61-63` (update import)
- Modify: `tests/test_dedup_names.py:6,60,71,80` (update import)

- [ ] **Step 1: Create `rom_analyzer/cleanup.py`**

```python
"""Annotation store cleanup utilities shared across build scripts and cli."""

from __future__ import annotations

from collections import defaultdict

from rom_analyzer.annotations_io import AnnotationStore

_SLOPPY_SOURCES = {"colt_s", "z27ag_s"}


def drop_imprecise_s_duplicates(store: AnnotationStore, tol: int = 4) -> int:
    """Remove .S-derived entries that merely duplicate a precise-source label.

    When a .S entry shares a name with a precise-source entry within `tol`
    bytes, the .S one is dropped. Returns the number removed.
    """
    precise: dict[str, list[int]] = defaultdict(list)
    for f in store.functions:
        if f.source not in _SLOPPY_SOURCES:
            precise[f.name].append(f.entry_point)
    for s in store.symbols:
        if s.source not in _SLOPPY_SOURCES:
            precise[s.name].append(s.address)

    def _artifact(name: str, addr: int, source: str) -> bool:
        return (source in _SLOPPY_SOURCES
                and any(abs(addr - pa) <= tol for pa in precise.get(name, [])))

    n0 = len(store.functions) + len(store.symbols)
    store.functions = [f for f in store.functions
                       if not _artifact(f.name, f.entry_point, f.source)]
    store.symbols = [s for s in store.symbols
                     if not _artifact(s.name, s.address, s.source)]
    return n0 - (len(store.functions) + len(store.symbols))


def drop_erased_flash_entries(
    store: AnnotationStore, rom_bytes: bytes, window: int = 8
) -> list[str]:
    """Remove FUNCTION entries whose entry point lands in erased flash (0xFF).

    Data labels are not checked — a real table can legitimately live in blank
    flash. Returns the function names removed.
    """
    def _erased(addr: int) -> bool:
        return (addr + window <= len(rom_bytes)
                and all(b == 0xFF for b in rom_bytes[addr:addr + window]))

    removed: list[str] = []
    kept_fn = []
    for f in store.functions:
        if _erased(f.entry_point):
            removed.append(f.name)
        else:
            kept_fn.append(f)
    store.functions = kept_fn
    return removed


def dedup_symbol_names(store: AnnotationStore) -> int:
    """Make every symbol/function name unique across the whole store.

    Lowest-address object keeps the canonical name; later collisions get a
    hex-address suffix. Returns the number renamed.
    """
    objs = [(f.entry_point, f) for f in store.functions]
    objs += [(s.address, s) for s in store.symbols]
    objs.sort(key=lambda t: t[0])

    used: set[str] = set()
    renamed = 0
    for addr, obj in objs:
        if obj.name not in used:
            used.add(obj.name)
            continue
        new_name = f"{obj.name}_{addr:x}"
        while new_name in used:
            new_name += "_x"
        obj.name = new_name
        used.add(new_name)
        renamed += 1
    return renamed
```

- [ ] **Step 2: Replace the 3 function bodies in `build_reference_from_txt.py` with imports**

Replace lines 370–458 (the `_SLOPPY_SOURCES` constant and three function definitions) with:

```python
from rom_analyzer.cleanup import (  # noqa: E402
    _SLOPPY_SOURCES,
    dedup_symbol_names,
    drop_erased_flash_entries,
    drop_imprecise_s_duplicates,
)
```

Place this import near the top of the file alongside the other `rom_analyzer` imports (after line 44, before `_ADDR_RE`).

- [ ] **Step 3: Update `cli.py` import (line 61-63)**

Replace:
```python
from rom_analyzer.scripts.build_reference_from_txt import (
    drop_imprecise_s_duplicates, drop_erased_flash_entries, dedup_symbol_names,
)
```
With:
```python
from rom_analyzer.cleanup import (
    drop_imprecise_s_duplicates, drop_erased_flash_entries, dedup_symbol_names,
)
```

- [ ] **Step 4: Update `tests/test_dedup_names.py` imports**

Replace all three occurrences of:
```python
from rom_analyzer.scripts.build_reference_from_txt import dedup_symbol_names
from rom_analyzer.scripts.build_reference_from_txt import drop_imprecise_s_duplicates
from rom_analyzer.scripts.build_reference_from_txt import drop_erased_flash_entries
```
With (at the top of the file, replacing the existing import on line 6):
```python
from rom_analyzer.cleanup import (
    dedup_symbol_names,
    drop_erased_flash_entries,
    drop_imprecise_s_duplicates,
)
```
And remove the three inline `from rom_analyzer.scripts...` imports inside individual test functions (lines 60, 71, 80).

- [ ] **Step 5: Run tests**

```bash
pytest tests/ -x -q
```
Expected: all tests pass (same count as before).

- [ ] **Step 6: Commit**

```bash
git add rom_analyzer/cleanup.py rom_analyzer/cli.py \
    rom_analyzer/scripts/build_reference_from_txt.py tests/test_dedup_names.py
git commit -m "refactor: extract cleanup.py from build_reference_from_txt"
```

---

### Task 2: Split `ghidra.py` into `rom_analyzer/ghidra/` subpackage

This is a pure code-split: no logic changes. Four files replace one. A backward-compat `__init__.py` ensures every existing `from rom_analyzer.ghidra import ...` continues to work.

**Files:**
- Create: `rom_analyzer/ghidra/__init__.py`
- Create: `rom_analyzer/ghidra/session.py`
- Create: `rom_analyzer/ghidra/fetch.py`
- Create: `rom_analyzer/ghidra/domain.py`
- Create: `rom_analyzer/ghidra/overlay.py`
- Modify: `rom_analyzer/ghidra_overlay.py` (becomes 3-line shim)
- Delete: `rom_analyzer/ghidra.py`

- [ ] **Step 1: Create `rom_analyzer/ghidra/overlay.py`**

Copy the full content of `rom_analyzer/ghidra_overlay.py` verbatim into `rom_analyzer/ghidra/overlay.py`. Do not change any logic.

- [ ] **Step 2: Create `rom_analyzer/ghidra/fetch.py`**

Extract all `fetch_*` functions from `ghidra.py` (lines 277–568 approximately) plus their `import pyghidra` lazy imports. The file starts with:

```python
"""Read-only Ghidra queries — fetch_* functions that open a program_context
and return Python-native data without modifying the project."""
```

Functions to include (copy verbatim from `ghidra.py`):
- `fetch_instructions_at`
- `fetch_function_entry`
- `fetch_r0_imm_before`
- `fetch_callers_of`
- `fetch_callees_of`
- `fetch_function_name`
- `fetch_data_read_sites`

- [ ] **Step 3: Create `rom_analyzer/ghidra/domain.py`**

Extract the three domain-analysis functions from `ghidra.py` (lines 482–718 approximately). The file starts with:

```python
"""Domain-specific Ghidra analyses for M32R ECU ROMs.

These functions use the Ghidra API to implement ECU-specific logic
(OBD PID dispatch, DTC helpers, DTC call sites). They are separated
from fetch.py because they embed opcode-pattern knowledge, not just
data retrieval.
"""
```

Functions to include (copy verbatim):
- `fetch_pid_dispatch_entries`
- `fetch_dtc_helpers_structural`
- `fetch_dtc_call_sites`

- [ ] **Step 4: Create `rom_analyzer/ghidra/session.py`**

Everything remaining from `ghidra.py` after removing the fetch and domain functions. This includes:
- `HeadlessRun` dataclass
- `_JDK_FALLBACK_PATHS`
- `_resolve_java_home`
- `setup_environment`
- `_hex`
- `_ordered_callees`
- `_overlay_symbols`
- `_overlay_from_annotations`
- `_dump_program`
- `ghidriff_program_name`
- `_import_program`
- `import_and_dump`
- `apply_labels`
- `apply_mut_table_in_ghidra`
- `_resolve_datatype`
- `apply_data_types`
- `decompile_function`

The file starts with:
```python
"""Ghidra session management and program import/export.

Owns the PyGhidra JVM lifecycle, ROM import, symbol overlay, and all
write-back operations (apply_labels, apply_data_types, apply_mut_table).
"""
```

Imports needed at top of `session.py`:
```python
import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from rom_analyzer.data_refs import DataRef, collect_data_refs_within, collect_ram_refs_within
from rom_analyzer.types import PropagatedSymbol, ReferenceSymbol

if TYPE_CHECKING:
    from rom_analyzer.annotations_io import AnnotationStore
    from rom_analyzer.mut_table import MutTableResult
    from rom_analyzer.types import DataTypeDefinition
```

- [ ] **Step 5: Create `rom_analyzer/ghidra/__init__.py`**

Re-export everything that was public in `ghidra.py` so all existing imports break nothing:

```python
"""rom_analyzer.ghidra — backward-compat re-exports.

All symbols that were importable from rom_analyzer.ghidra before the
package split remain importable from here.
"""

from rom_analyzer.ghidra.session import (  # noqa: F401
    HeadlessRun,
    apply_data_types,
    apply_labels,
    apply_mut_table_in_ghidra,
    decompile_function,
    ghidriff_program_name,
    import_and_dump,
    setup_environment,
)
from rom_analyzer.ghidra.fetch import (  # noqa: F401
    fetch_callees_of,
    fetch_callers_of,
    fetch_data_read_sites,
    fetch_function_entry,
    fetch_function_name,
    fetch_instructions_at,
    fetch_r0_imm_before,
)
from rom_analyzer.ghidra.domain import (  # noqa: F401
    fetch_dtc_call_sites,
    fetch_dtc_helpers_structural,
    fetch_pid_dispatch_entries,
)
```

- [ ] **Step 6: Replace `ghidra_overlay.py` with a shim**

Replace the entire content of `rom_analyzer/ghidra_overlay.py` with:
```python
# Backward-compat shim — content moved to rom_analyzer.ghidra.overlay
from rom_analyzer.ghidra.overlay import (  # noqa: F401
    _ParsedType, _parse_type_str, apply_annotations,
)
```

- [ ] **Step 7: Delete `rom_analyzer/ghidra.py`**

```bash
git rm rom_analyzer/ghidra.py
```

Python will now resolve `rom_analyzer.ghidra` as the package directory.

- [ ] **Step 8: Run tests**

```bash
pytest tests/ -x -q
```
Expected: all tests pass with the same count.

- [ ] **Step 9: Commit**

```bash
git add rom_analyzer/ghidra/ rom_analyzer/ghidra_overlay.py
git commit -m "refactor: split ghidra.py into ghidra/ subpackage (session/fetch/domain/overlay)"
```

---

### Task 3: Introduce `GhidraSession` class

Add `GhidraSession` to `ghidra/session.py` and update `cli.py` to use it. The analysis logic inside `cli.py` is unchanged — only the session setup and teardown wiring changes.

**Files:**
- Modify: `rom_analyzer/ghidra/session.py` (add class)
- Modify: `rom_analyzer/cli.py` (use `GhidraSession` in both `analyze` and `enrich`)
- Create: `tests/test_ghidra_session.py`

- [ ] **Step 1: Write failing test**

```python
# tests/test_ghidra_session.py
"""Unit tests for GhidraSession lifecycle (pyghidra mocked out)."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from rom_analyzer.ghidra.session import GhidraSession


def _make_session() -> GhidraSession:
    mock_project = MagicMock()
    return GhidraSession(project=mock_project, project_name="test-proj")


def test_prog_name_for_is_deterministic(tmp_path):
    rom = tmp_path / "test.bin"
    rom.write_bytes(b"\x00" * 16)
    session = _make_session()
    name1 = session.prog_name_for(rom)
    name2 = session.prog_name_for(rom)
    assert name1 == name2
    assert "test.bin" in name1


def test_prog_name_for_includes_sha1_prefix(tmp_path):
    rom = tmp_path / "rom.bin"
    rom.write_bytes(b"\xAB\xCD" * 8)
    session = _make_session()
    name = session.prog_name_for(rom)
    # name is "<filename>-<6-char sha1>"
    parts = name.rsplit("-", 1)
    assert len(parts) == 2
    assert len(parts[1]) == 6


def test_context_manager_calls_close():
    mock_project = MagicMock()
    session = GhidraSession(project=mock_project, project_name="p")
    with session:
        pass
    mock_project.close.assert_called_once()


def test_context_manager_calls_close_on_exception():
    mock_project = MagicMock()
    session = GhidraSession(project=mock_project, project_name="p")
    with pytest.raises(ValueError):
        with session:
            raise ValueError("boom")
    mock_project.close.assert_called_once()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_ghidra_session.py -x -q
```
Expected: `FAILED` — `GhidraSession` not yet defined.

- [ ] **Step 3: Add `GhidraSession` to `rom_analyzer/ghidra/session.py`**

Add this class at the bottom of `session.py`, after all existing functions:

```python
class GhidraSession:
    """Owns the PyGhidra JVM lifecycle and project handle.

    Use as a context manager:
        with GhidraSession.open(project_path, name, ghidra_home) as session:
            run = session.import_rom(...)
    """

    def __init__(self, project, project_name: str,
                 inline_source_annotations: bool = False) -> None:
        self.project = project
        self.project_name = project_name
        self.inline_source_annotations = inline_source_annotations

    # --- lifecycle ---

    @classmethod
    def open(
        cls,
        project_path: Path,
        project_name: str,
        ghidra_home: Path,
        *,
        clean: bool = False,
        inline_source_annotations: bool = False,
    ) -> "GhidraSession":
        """setup_environment + pyghidra.start() + open_project."""
        setup_environment(ghidra_home)
        import pyghidra
        pyghidra.start()
        if clean and project_path.exists():
            import shutil
            shutil.rmtree(project_path)
        project_path.mkdir(parents=True, exist_ok=True)
        project = pyghidra.open_project(project_path, project_name, create=True)
        return cls(project=project, project_name=project_name,
                   inline_source_annotations=inline_source_annotations)

    def close(self) -> None:
        self.project.close()

    def __enter__(self) -> "GhidraSession":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # --- program name ---

    def prog_name_for(self, rom_path: Path) -> str:
        """Return the Ghidra program name for a ROM path (filename + sha1 prefix)."""
        return ghidriff_program_name(rom_path)

    # --- import / dump ---

    def import_rom(
        self,
        rom_path: Path,
        language_id: str,
        *,
        crc_step_address: int | None = None,
        ref_symbols: "list[ReferenceSymbol] | None" = None,
        annotations_path: Path | None = None,
        collect_data_refs: bool = False,
    ) -> HeadlessRun:
        """Import ROM if not already in project; return HeadlessRun."""
        return import_and_dump(
            self.project,
            rom_path,
            language_id,
            crc_step_address=crc_step_address,
            ref_symbols_for_overlay=ref_symbols,
            annotations_path=annotations_path,
            collect_data_refs_flag=collect_data_refs,
        )

    # --- write-back ---

    def apply_labels(
        self, rom_path: Path, symbols: "list[PropagatedSymbol]"
    ) -> int:
        return apply_labels(
            self.project,
            self.prog_name_for(rom_path),
            symbols,
            add_comments=self.inline_source_annotations,
        )

    def apply_data_types(
        self, rom_path: Path, data_defs: "list[DataTypeDefinition]"
    ) -> int:
        return apply_data_types(
            self.project, self.prog_name_for(rom_path), data_defs
        )

    def apply_mut_table(self, rom_path: Path, result: "MutTableResult") -> None:
        apply_mut_table_in_ghidra(
            self.project, self.prog_name_for(rom_path), result
        )
```

Also add `GhidraSession` to `rom_analyzer/ghidra/__init__.py`:
```python
from rom_analyzer.ghidra.session import (  # noqa: F401
    GhidraSession,
    HeadlessRun,
    ...  # rest unchanged
)
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_ghidra_session.py -x -q
```
Expected: 4 passed.

- [ ] **Step 5: Update `cli.py` to use `GhidraSession`**

In `cli.py`, add the import:
```python
from rom_analyzer.ghidra import GhidraSession
```

In the `analyze` command body, replace:
```python
setup_environment(ghidra_home)
import pyghidra
pyghidra.start()

project_path = project_dir / project_name
project_path.mkdir(parents=True, exist_ok=True)
project = pyghidra.open_project(project_path, project_name, create=True)
try:
    ...
finally:
    project.close()
```
With:
```python
with GhidraSession.open(
    project_dir / project_name, project_name, ghidra_home,
    clean=clean_project,
    inline_source_annotations=inline_source_annotations,
) as session:
    project = session.project   # keep existing calls working for now
    ...
```

Do the same substitution in the `enrich` command. This leaves all inner logic identical — `project` is still used by name inside the block; we just obtain it from the session.

Also remove the `--clean-project` rmtree block (lines 360-365 in the original) from `analyze` since it moves into `GhidraSession.open`.

- [ ] **Step 6: Run all tests**

```bash
pytest tests/ -x -q
```
Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add rom_analyzer/ghidra/session.py rom_analyzer/ghidra/__init__.py \
    rom_analyzer/cli.py tests/test_ghidra_session.py
git commit -m "feat: introduce GhidraSession class; wire into cli.py"
```

---

### Task 4: Create `pipeline/types.py` — stage result dataclasses

Pure type definitions. No logic. No tests needed beyond "it imports cleanly."

**Files:**
- Create: `rom_analyzer/pipeline/__init__.py`
- Create: `rom_analyzer/pipeline/types.py`

- [ ] **Step 1: Create `rom_analyzer/pipeline/__init__.py`**

```python
# rom_analyzer/pipeline — pipeline stage functions and result types
```

- [ ] **Step 2: Create `rom_analyzer/pipeline/types.py`**

```python
"""Typed result dataclasses for each pipeline stage.

Each stage function in the pipeline/ subpackage returns one of these.
cli.py strings them together; no other module imports from pipeline/.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from rom_analyzer.types import (
    CrcRegion, FlashFreeBlock, MatchedFunction, PropagatedSymbol,
    RamFreeBlock, ReferenceSymbol,
)


@dataclass
class RomContext:
    """Immutable inputs from CLI args. Shared across all pipeline stages."""
    rom_path: Path
    rom_bytes: bytes
    language_id: str
    out_dir: Path
    target_family: str
    is_self_diff: bool
    emit_mode23: bool
    emit_obd: bool
    emit_can_slots: bool
    enrich_project: bool
    min_flash_block: int
    min_ram_block: int


@dataclass
class ImportResult:
    """Output of import_stage(): the target ROM imported into Ghidra."""
    new_run: object          # HeadlessRun — avoid circular import at type-check time
    new_prog_name: str


@dataclass
class ReferenceMatchResult:
    """Output of match_reference() for one reference ROM."""
    entry: object            # ReferenceEntry
    matches: list[MatchedFunction]
    propagated: list[PropagatedSymbol]
    ref_run: object | None   # HeadlessRun | None
    ref_symbols: list[ReferenceSymbol]
    data_labels: list[PropagatedSymbol]
    ram_labels: list[PropagatedSymbol]
    sig_matches: list[MatchedFunction]
    ram_labels_p2: list[PropagatedSymbol]
    data_labels_p2: list[PropagatedSymbol]


@dataclass
class MergeResult:
    """Output of arbitrate_references(): symbols arbitrated across all references."""
    matches: list[MatchedFunction]
    propagated: list[PropagatedSymbol]
    disagreements: list[PropagatedSymbol]
    cross_family: list[PropagatedSymbol]
    priority: dict[str, int]
    match_summary: str           # e.g. "123/456 (27.0%)"


@dataclass
class AnalysisResult:
    """Output of post_match_analysis(): CRC, free space, and optional deep passes."""
    crc: CrcRegion | None
    flash_blocks: list[FlashFreeBlock]
    ram_blocks: list[RamFreeBlock]
    mut_result: object | None    # MutTableResult | None
    obd_result: object | None    # OBDAnalysis | None
    can_slots_result: list | None
    obd_pid_text: str
    mode23_lines: list[str]
```

- [ ] **Step 3: Verify import**

```bash
python -c "from rom_analyzer.pipeline.types import RomContext, ImportResult, ReferenceMatchResult, MergeResult, AnalysisResult; print('ok')"
```
Expected: `ok`

- [ ] **Step 4: Commit**

```bash
git add rom_analyzer/pipeline/
git commit -m "feat: add pipeline/ subpackage with stage result types"
```

---

### Task 5: Extract `match_reference()` to `pipeline/reference.py`

Extract `analyze_against_reference` from `cli.py` as `match_reference()`, and add `import_stage()`. Both consume `GhidraSession` + `RomContext`.

**Files:**
- Create: `rom_analyzer/pipeline/reference.py`
- Modify: `rom_analyzer/cli.py` (remove `ReferenceResult` dataclass; call `match_reference`)

- [ ] **Step 1: Create `rom_analyzer/pipeline/reference.py`**

```python
"""Per-reference matching pipeline: import target ROM, run callgraph + VT diff +
propagation, return ReferenceMatchResult.

import_stage()   — import the target ROM into Ghidra once for all references
match_reference() — run the full matching + propagation pass for one reference
"""

from __future__ import annotations

import click

from rom_analyzer.annotations_io import load_reference_symbols
from rom_analyzer.callgraph import (
    bootstrap_anchors, bfs_preseed, bytecode_identity_match, gap_fill,
)
from rom_analyzer.data_refs import propagate_data_labels, propagate_ram_labels
from rom_analyzer.diff import run_vt_diff
from rom_analyzer.ghidra import (
    HeadlessRun, ghidriff_program_name, import_and_dump,
)
from rom_analyzer.ghidra.session import GhidraSession
from rom_analyzer.merge import match_rank
from rom_analyzer.pipeline.types import ImportResult, ReferenceMatchResult, RomContext
from rom_analyzer.propagate import apply_reference_provenance, propagate_function_labels
from rom_analyzer.ram_signature import build_ram_signatures, match_by_ram_signature
from rom_analyzer.registry import ReferenceEntry
from rom_analyzer.types import MatchedFunction, PropagatedSymbol


def import_stage(
    session: GhidraSession,
    ctx: RomContext,
    primary_entry: ReferenceEntry,
) -> ImportResult:
    """Import the target ROM into Ghidra (once, shared across all references).

    Loads primary reference symbols to extract crc_step_address before import.
    """
    ref_symbols_preview = load_reference_symbols(primary_entry.json_path)
    crc_step_addr = next(
        (s.address for s in ref_symbols_preview if s.name == "rom_crc_check_step"),
        None,
    )
    click.echo(f"[3/7] Importing new ROM into Ghidra: {ctx.rom_path}")
    new_run = session.import_rom(
        ctx.rom_path,
        ctx.language_id,
        crc_step_address=crc_step_addr,
        collect_data_refs=(not ctx.is_self_diff),
    )
    return ImportResult(
        new_run=new_run,
        new_prog_name=session.prog_name_for(ctx.rom_path),
    )


def match_reference(
    session: GhidraSession,
    ctx: RomContext,
    imported: ImportResult,
    entry: ReferenceEntry,
) -> ReferenceMatchResult:
    """Run the full matching + propagation pass for one reference ROM.

    Replaces analyze_against_reference() in cli.py. Logic is unchanged.
    """
    reference_rom = entry.rom_path
    reference = entry.json_path
    is_self_diff = ctx.is_self_diff
    project = session.project
    new_run: HeadlessRun = imported.new_run
    new_prog_name = imported.new_prog_name
    inline_source_annotations = session.inline_source_annotations
    rom_bytes = ctx.rom_bytes

    click.echo(f"[1/7] Loading reference symbols from {reference}")
    ref_symbols = load_reference_symbols(reference)
    ref_symbols_by_addr = {s.address: s for s in ref_symbols}

    crc_step_addr = next(
        (s.address for s in ref_symbols if s.name == "rom_crc_check_step"), None
    )
    if crc_step_addr is None:
        click.echo("   warning: rom_crc_check_step not in reference symbols; CRC detection skipped")

    click.echo(f"[2/7] Importing reference ROM into Ghidra: {reference_rom}")
    if not reference_rom.exists():
        click.echo(f"   warning: reference ROM not found at {reference_rom}; skipping reference import")
        ref_run = None
    else:
        ref_run = session.import_rom(
            reference_rom, ctx.language_id,
            crc_step_address=crc_step_addr,
            ref_symbols=ref_symbols,
            collect_data_refs=(not is_self_diff),
        )

    anchors: list[MatchedFunction] = []
    bfs_matches: list[MatchedFunction] = []
    ref_bytes = b""
    if not is_self_diff and ref_run is not None:
        ref_bytes = reference_rom.read_bytes()
        ref_symbols_by_name = {s.name: s for s in ref_symbols}
        anchors = bootstrap_anchors(ref_bytes, rom_bytes, ref_run, new_run,
                                    ref_symbols_by_name, ref_symbols_by_addr)
        bfs_overlays, bfs_matches = bfs_preseed(anchors, ref_run, new_run,
                                                 ref_symbols_by_addr,
                                                 ref_bytes=ref_bytes,
                                                 new_bytes=rom_bytes)
        by_src: dict[str, int] = {}
        for a in anchors:
            by_src[a.source] = by_src.get(a.source, 0) + 1
        src_str = ", ".join(f"{s}: {n}" for s, n in sorted(by_src.items()))
        click.echo(f"   call-graph anchors: {len(anchors)} ({src_str})")
        click.echo(f"   call-graph BFS overlays: {len(bfs_overlays)}")
        if bfs_overlays:
            seen_bfs: set[int] = set()
            unique_bfs = []
            for s in bfs_overlays:
                if s.address not in seen_bfs:
                    seen_bfs.add(s.address)
                    unique_bfs.append(s)
            bfs_propagated = [
                PropagatedSymbol(s.name, 0, s.address, s.category, "medium",
                                 source="callgraph_bfs", score=1.0)
                for s in unique_bfs
            ]
            session.apply_labels(ctx.rom_path, bfs_propagated)

    if is_self_diff:
        click.echo("[4/7] Self-diff detected; using identity matches")
        matches = [
            MatchedFunction(ref_name=s.name, ref_address=s.address,
                            new_address=s.address, similarity=1.0,
                            source="identity")
            for s in ref_symbols if s.category == "function"
        ]
    elif ref_run is None:
        click.echo("[4/7] Skipping diff — reference ROM unavailable")
        matches = []
    else:
        click.echo("[4/7] Diffing via Ghidra VTSession")
        ref_prog_name = ghidriff_program_name(reference_rom)
        matches = run_vt_diff(project, ref_prog_name, new_prog_name)
        gap_matches = gap_fill(ref_run, new_run, matches + anchors + bfs_matches,
                               ref_bytes=ref_bytes, new_bytes=rom_bytes)
        click.echo(f"   call-graph gap-fill: {len(gap_matches)} additional matches")
        all_matches = matches + anchors + bfs_matches + gap_matches
        identity_matches = bytecode_identity_match(
            ref_bytes, rom_bytes, ref_run, new_run, all_matches, ref_symbols_by_addr,
        )
        click.echo(f"   bytecode identity: {len(identity_matches)} additional matches")
        matches = all_matches + identity_matches

    best_by_ref: dict[int, MatchedFunction] = {}
    for m in matches:
        if m.ref_address not in best_by_ref or match_rank(m, {}) > match_rank(best_by_ref[m.ref_address], {}):
            best_by_ref[m.ref_address] = m
    matches = list(best_by_ref.values())

    best_by_new: dict[int, MatchedFunction] = {}
    for m in matches:
        if m.new_address not in best_by_new or match_rank(m, {}) > match_rank(best_by_new[m.new_address], {}):
            best_by_new[m.new_address] = m
    matches = list(best_by_new.values())

    click.echo("[5/7] Propagating symbols")
    propagated_fns = propagate_function_labels(ref_symbols, matches)

    new_ram_refs = set(new_run.ram_refs)
    if is_self_diff:
        ram_globals = [
            PropagatedSymbol(s.name, s.address, s.address, "ram_global", "high",
                             source="ram_global", score=1.0)
            for s in ref_symbols
            if s.category == "ram_global" and s.address in new_ram_refs
        ]
    else:
        ram_globals = []

    if not is_self_diff and ref_run is not None and ref_run.data_refs and new_run.data_refs:
        data_labels = propagate_data_labels(
            ref_run.data_refs, new_run.data_refs, matches, ref_symbols_by_addr
        )
        click.echo(f"   data labels propagated: {len(data_labels)}")
    elif is_self_diff:
        data_labels = [
            PropagatedSymbol(s.name, s.address, s.address, "data", "high",
                             source="identity", score=1.0)
            for s in ref_symbols if s.category == "data"
        ]
    else:
        data_labels = []

    if not is_self_diff and ref_run is not None and ref_run.ram_data_refs and new_run.ram_data_refs:
        ram_labels = propagate_ram_labels(
            ref_run.ram_data_refs, new_run.ram_data_refs, matches, ref_symbols_by_addr
        )
        click.echo(f"   ram labels propagated: {len(ram_labels)}")
    else:
        ram_labels = []

    propagated_all = propagated_fns + ram_globals + data_labels + ram_labels

    sig_matches: list[MatchedFunction] = []
    ram_labels_p2: list[PropagatedSymbol] = []
    data_labels_p2: list[PropagatedSymbol] = []
    if not is_self_diff and ref_run is not None and ref_run.ram_data_refs and new_run.ram_data_refs and ram_labels:
        click.echo("[5.25/7] RAM-signature matching")
        ref_label_map = {s.address: s.name for s in ref_symbols if s.category == "ram_global"}
        new_label_map = {ps.new_address: ps.name for ps in ram_labels}
        ref_sigs = build_ram_signatures(ref_run.ram_data_refs, ref_label_map)
        new_sigs = build_ram_signatures(new_run.ram_data_refs, new_label_map)
        sig_matches = match_by_ram_signature(ref_sigs, new_sigs, matches, ref_symbols_by_addr)
        click.echo(f"   ram-signature matches: {len(sig_matches)}")
        if sig_matches:
            extended_matches = matches + sig_matches
            fn_labels_p2 = propagate_function_labels(ref_symbols, sig_matches)
            ram_labels_p2 = propagate_ram_labels(
                ref_run.ram_data_refs, new_run.ram_data_refs,
                extended_matches, ref_symbols_by_addr,
            )
            if ref_run.data_refs and new_run.data_refs:
                data_labels_p2 = propagate_data_labels(
                    ref_run.data_refs, new_run.data_refs,
                    extended_matches, ref_symbols_by_addr,
                )
            click.echo(f"   ram labels (p2): {len(ram_labels_p2)}")
            click.echo(f"   data labels (p2): {len(data_labels_p2)}")
            propagated_all += fn_labels_p2 + ram_labels_p2 + data_labels_p2
            matches = extended_matches

    from dataclasses import replace
    matches = [replace(m, reference=entry.id) for m in matches]
    family_match = (entry.family == ctx.target_family)
    propagated_all = apply_reference_provenance(
        propagated_all, reference=entry.id, family_match=family_match)

    return ReferenceMatchResult(
        entry=entry,
        matches=matches,
        propagated=propagated_all,
        ref_run=ref_run,
        ref_symbols=ref_symbols,
        data_labels=data_labels,
        ram_labels=ram_labels,
        sig_matches=sig_matches,
        ram_labels_p2=ram_labels_p2,
        data_labels_p2=data_labels_p2,
    )
```

- [ ] **Step 2: Remove `ReferenceResult` from `cli.py` and call `match_reference`**

In `cli.py`:
1. Remove the `@dataclass class ReferenceResult:` block (lines 74–87).
2. Remove the `def analyze_against_reference(...)` function (lines 89–297).
3. Add import at top: `from rom_analyzer.pipeline.reference import import_stage, match_reference`
4. Add import: `from rom_analyzer.pipeline.types import RomContext, ImportResult, ReferenceMatchResult`

In the body of `analyze`, replace:
```python
new_run = import_and_dump(project, rom_path, language_id, ...)
...
results: list[ReferenceResult] = []
for entry in selected:
    results.append(analyze_against_reference(project, entry, language_id, ...))
```
With:
```python
ctx = RomContext(
    rom_path=rom_path, rom_bytes=rom_bytes, language_id=language_id,
    out_dir=out_dir, target_family=target_family,
    is_self_diff=_primary_is_self_diff,
    emit_mode23=emit_mode23, emit_obd=emit_obd, emit_can_slots=emit_can_slots,
    enrich_project=enrich_project,
    min_flash_block=min_flash_block, min_ram_block=min_ram_block,
)
imported = import_stage(session, ctx, primary)
results: list[ReferenceMatchResult] = []
for entry in selected:
    click.echo(f"[ref {entry.id}] matching")
    results.append(match_reference(session, ctx, imported, entry))
```

The `rom_bytes` and `new_prog_name` variables that formerly lived in `analyze` now come from `ctx.rom_bytes` and `imported.new_prog_name`. Update remaining references to them in the `analyze` body accordingly.

In `enrich`, replace the `analyze_against_reference(project, ref, ...)` call:
```python
result = analyze_against_reference(
    project, ref, language_id,
    new_entry.rom_path, rom_bytes,
    new_run, new_prog_name,
    target_family=new_entry.family,
    inline_source_annotations=inline_source_annotations,
)
```
With:
```python
result = match_reference(session, ctx, imported, ref)
```
Where `ctx` is constructed from `new_entry` fields:
```python
ctx = RomContext(
    rom_path=new_entry.rom_path, rom_bytes=rom_bytes,
    language_id=language_id, out_dir=Path(out_dir),
    target_family=new_entry.family,
    is_self_diff=False,
    emit_mode23=False, emit_obd=False, emit_can_slots=False,
    enrich_project=False,
    min_flash_block=64, min_ram_block=4,
)
imported = import_stage(session, ctx, new_entry)
```

- [ ] **Step 3: Run all tests**

```bash
pytest tests/ -x -q
```
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add rom_analyzer/pipeline/reference.py rom_analyzer/cli.py
git commit -m "refactor: extract match_reference() and import_stage() to pipeline/reference.py"
```

---

### Task 6: Extract arbitration to `pipeline/arbitrate.py`

Extract the cross-reference merge/arbitrate logic (from `analyze`) and the enrich classify/apply block (from `enrich`) into `pipeline/arbitrate.py`.

**Files:**
- Create: `rom_analyzer/pipeline/arbitrate.py`
- Modify: `rom_analyzer/cli.py`

- [ ] **Step 1: Create `rom_analyzer/pipeline/arbitrate.py`**

```python
"""Cross-reference arbitration: merge matches, pick winning symbols, apply auto verdicts."""

from __future__ import annotations

from pathlib import Path

import click

from rom_analyzer.annotations_io import AnnotationFunction, load_annotations, save_annotations
from rom_analyzer.cleanup import dedup_symbol_names, drop_erased_flash_entries, drop_imprecise_s_duplicates
from rom_analyzer.enrich import (
    LabelCandidate, ReconcileItem, build_reconcile_items, classify,
    gather_candidates, merge_candidates, write_reconcile, apply_verdicts,
)
from rom_analyzer.merge import arbitrate_symbols, merge_matches
from rom_analyzer.pipeline.types import MergeResult, ReferenceMatchResult
from rom_analyzer.registry import ReferenceEntry
from rom_analyzer.types import PropagatedSymbol


def arbitrate_references(
    results: list[ReferenceMatchResult],
    priority: dict[str, int],
) -> MergeResult:
    """Merge matches and arbitrate symbols across all reference results.

    Computes match_summary (e.g. "123/456 (27.0%)") using the primary
    reference's symbol set (results[0]).
    """
    matches = merge_matches([r.matches for r in results], priority)
    all_propagated = [s for r in results for s in r.propagated]
    propagated_all, disagreements = arbitrate_symbols(all_propagated, priority)
    cross_family = [s for s in propagated_all if not s.family_match]

    click.echo(
        f"[merge] {len(propagated_all)} symbols, "
        f"{len(disagreements)} disagreement(s), "
        f"{len(cross_family)} cross-family VERIFY"
    )

    primary_ref_symbols = results[0].ref_symbols
    named_ref_addrs = {s.address for s in primary_ref_symbols if s.category == "function"}
    matched_count = sum(1 for m in matches if m.ref_address in named_ref_addrs)
    total_ref = len(named_ref_addrs)
    match_summary = f"{matched_count}/{total_ref} ({100.0 * matched_count / max(1, total_ref):.1f}%)"

    return MergeResult(
        matches=matches,
        propagated=propagated_all,
        disagreements=disagreements,
        cross_family=cross_family,
        priority=priority,
        match_summary=match_summary,
    )


def _erased_addrs(entry: ReferenceEntry, window: int = 8) -> set[int]:
    rom = entry.rom_path.read_bytes()
    store = load_annotations(entry.json_path)
    return {
        f.entry_point
        for f in store.functions
        if f.entry_point + window <= len(rom)
        and all(b == 0xFF for b in rom[f.entry_point:f.entry_point + window])
    }


def _append_functions(store, cands: list[LabelCandidate]) -> int:
    existing = {f.entry_point for f in store.functions}
    n = 0
    for c in cands:
        if c.address not in existing:
            store.functions.append(AnnotationFunction(
                name=c.proposed, entry_point=c.address,
                confidence="medium", source=f"xref:{c.source}",
            ))
            existing.add(c.address)
            n += 1
    return n


def classify_and_apply(
    results: list[ReferenceMatchResult],
    new_entry: ReferenceEntry,
    new_fn_names: dict[int, str],
    by_id: dict[str, ReferenceEntry],
    priority: dict[str, int],
    out_dir: Path,
    rom_bytes: bytes,
) -> None:
    """Classify cross-match candidates, auto-apply gaps+renames, write reconcile.toml.

    Extracted from the enrich command body in cli.py.
    """
    all_candidates: list[LabelCandidate] = []
    for result in results:
        ref = result.entry
        ref_store = load_annotations(ref.json_path)
        ref_fn_names: dict[int, str] = {f.entry_point: f.name for f in ref_store.functions}
        cands = gather_candidates(
            new_entry.id, ref.id, result.matches,
            new_fn_names, ref_fn_names, ram_data_candidates=None,
        )
        all_candidates.extend(cands)
        click.echo(f"   {len(cands)} candidates from {ref.id}")

    all_candidates = merge_candidates(all_candidates, priority)
    click.echo(f"Merged: {len(all_candidates)} unique (target, address, category) candidates")

    target_ids = {c.target for c in all_candidates}
    erased_by_target: dict[str, set[int]] = {}
    for tid in target_ids:
        if tid == new_entry.id:
            erased_by_target[tid] = _erased_addrs(new_entry)
        elif tid in by_id:
            erased_by_target[tid] = _erased_addrs(by_id[tid])
        else:
            erased_by_target[tid] = set()

    auto_all: list[LabelCandidate] = []
    review_all: list[LabelCandidate] = []
    by_target: dict[str, list[LabelCandidate]] = {}
    for c in all_candidates:
        by_target.setdefault(c.target, []).append(c)

    for tid, group in by_target.items():
        classified = classify(group, erased=erased_by_target.get(tid, set()),
                              priority=priority)
        auto_all.extend(classified.auto)
        review_all.extend(classified.review)

    auto_by_target: dict[str, list[LabelCandidate]] = {}
    for c in auto_all:
        auto_by_target.setdefault(c.target, []).append(c)

    total_auto_applied = 0
    for tid, cands in auto_by_target.items():
        if tid not in by_id:
            click.echo(f"   [skip auto] target {tid!r} not in registry")
            continue
        target_entry = by_id[tid]
        st = load_annotations(target_entry.json_path)

        gap_cands = [c for c in cands if c.current is None]
        rename_cands = [c for c in cands if c.current is not None]
        n_appended = _append_functions(st, gap_cands)

        if rename_cands:
            rename_items = [ReconcileItem(
                target=tid, direction=c.direction, address=c.address,
                category=c.category, current=c.current, proposed=c.proposed,
                source=c.source, evidence=c.evidence, verdict="proposed",
            ) for c in rename_cands]
            n_renamed = apply_verdicts(st, rename_items, target=tid)
        else:
            n_renamed = 0

        if n_appended + n_renamed:
            target_rom_bytes = (
                rom_bytes if tid == new_entry.id
                else target_entry.rom_path.read_bytes()
            )
            drop_imprecise_s_duplicates(st)
            drop_erased_flash_entries(st, target_rom_bytes)
            dedup_symbol_names(st)
            save_annotations(target_entry.json_path, st)
            click.echo(f"   [auto] {tid}: applied {n_appended} new function(s), {n_renamed} rename(s)")
        total_auto_applied += n_appended + n_renamed

    items = build_reconcile_items(review_all, priority)
    out_dir.mkdir(parents=True, exist_ok=True)
    reconcile_path = out_dir / f"{new_entry.id}.reconcile.toml"
    write_reconcile(reconcile_path, items)

    click.echo(
        f"\nDone. Auto-applied: {total_auto_applied} function(s). "
        f"Review items: {len(items)}. "
        f"Reconcile: {reconcile_path}"
    )
```

- [ ] **Step 2: Update `cli.py` to call `arbitrate_references` and `classify_and_apply`**

Add imports:
```python
from rom_analyzer.pipeline.arbitrate import arbitrate_references, classify_and_apply
from rom_analyzer.pipeline.types import MergeResult
```

In `analyze`, replace the inline merge/arbitrate block:
```python
matches = merge_matches([r.matches for r in results], priority)
all_propagated = [s for r in results for s in r.propagated]
propagated_all, disagreements = arbitrate_symbols(all_propagated, priority)
cross_family = [s for s in propagated_all if not s.family_match]
click.echo(...)
show_provenance = len(selected) > 1
primary_result = results[0]
ref_symbols = primary_result.ref_symbols
...
named_ref_addrs = ...
matched_count = ...
match_summary = ...
```
With:
```python
merged = arbitrate_references(results, priority)
show_provenance = len(selected) > 1
primary_result = results[0]
ref_symbols = primary_result.ref_symbols
ref_run = primary_result.ref_run
ref_symbols_by_addr = {s.address: s for s in ref_symbols}
ram_globals = [s for s in primary_result.propagated if s.category == "ram_global"]
```
And update all downstream references: `propagated_all` → `merged.propagated`, `matches` → `merged.matches`, `disagreements` → `merged.disagreements`, `cross_family` → `merged.cross_family`, `match_summary` → `merged.match_summary`.

In `enrich`, replace the large classify/apply block (from `all_candidates: list[LabelCandidate] = []` to the final `click.echo("Done...")`) with:
```python
new_store = load_annotations(new_entry.json_path)
new_fn_names: dict[int, str] = {f.entry_point: f.name for f in new_store.functions}
classify_and_apply(
    results, new_entry, new_fn_names, by_id, priority, Path(out_dir), rom_bytes
)
```

Remove now-unused imports from `cli.py`: `merge_matches`, `arbitrate_symbols`, `_erased_addrs`, `_append_functions`, the inline candidate-loop logic, and the `LabelCandidate`/`ReconcileItem`-related code that moved.

- [ ] **Step 3: Run all tests**

```bash
pytest tests/ -x -q
```
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add rom_analyzer/pipeline/arbitrate.py rom_analyzer/cli.py
git commit -m "refactor: extract arbitrate_references() and classify_and_apply() to pipeline/arbitrate.py"
```

---

### Task 7: Extract `post_match_analysis()` to `pipeline/post_match.py`

Extract the `[5.5/7]`–`[6/7]` block: MUT table, OBD, CAN slots, CRC detection, free space scan.

**Files:**
- Create: `rom_analyzer/pipeline/post_match.py`
- Modify: `rom_analyzer/cli.py`

- [ ] **Step 1: Create `rom_analyzer/pipeline/post_match.py`**

```python
"""Post-match analysis: MUT table, OBD, CAN slots, CRC detection, free space."""

from __future__ import annotations

import re as _re
from pathlib import Path

import click

from rom_analyzer.crc import Instruction, extract_crc_region
from rom_analyzer.flash_space import find_free_blocks
from rom_analyzer.ghidra import (
    fetch_callers_of, fetch_dtc_helpers_structural, fetch_instructions_at,
    fetch_r0_imm_before, fetch_function_entry, fetch_data_read_sites,
    ghidriff_program_name,
)
from rom_analyzer.ghidra.session import GhidraSession
from rom_analyzer.mode23_bindings import decode_ldi_r0_before, resolve_can_call_sites, resolve_nearest_site
from rom_analyzer.mut_table import find_mut_table_in_run, mut_table_to_propagated_symbol
from rom_analyzer.pipeline.types import AnalysisResult, ImportResult, MergeResult, RomContext
from rom_analyzer.ram_space import find_free_ram_blocks
from rom_analyzer.registry import ReferenceEntry
from rom_analyzer.emit_ld import emit_mode23_binding_line
from rom_analyzer.types import CrcRegion, PropagatedSymbol


def post_match_analysis(
    session: GhidraSession,
    ctx: RomContext,
    imported: ImportResult,
    merged: MergeResult,
    primary_entry: ReferenceEntry,
    ref_symbols: list,
    ref_run: object | None,
    enrich_project: bool,
) -> AnalysisResult:
    """Run CRC detection, free space scan, MUT table, OBD, CAN slot decode.

    Returns AnalysisResult. All optional passes (MUT/OBD/CAN) are guarded by
    the corresponding ctx.emit_* flags.
    """
    project = session.project
    new_prog_name = imported.new_prog_name
    new_run = imported.new_run
    matches = merged.matches
    propagated_all = merged.propagated
    rom_bytes = ctx.rom_bytes

    _primary_is_self_diff = ctx.is_self_diff

    # [5.5/7] MUT table
    _mut_table_ghidra_applied = False
    mut_result = None
    if not _primary_is_self_diff and new_run.data_refs:
        mut_result = find_mut_table_in_run(matches, new_run, rom_bytes)
        if mut_result is not None:
            click.echo(
                f"   MUT table: {mut_result.table_address:#x}, size={mut_result.table_size}"
            )
            if mut_result.triplet_mismatch:
                click.echo(
                    f"   warning: MUT table triplet scan disagrees; "
                    f"using data-ref result at {mut_result.table_address:#x}"
                )
            ref_table_sym = next(
                (s for s in ref_symbols if s.name == "flash_mut_variables_table"), None
            )
            ref_table_addr = ref_table_sym.address if ref_table_sym is not None else 0
            # Remove any prior entry for this name (data-ref offset may have
            # already placed flash_mut_variables_table before MUT pass ran).
            merged.propagated[:] = [p for p in merged.propagated
                                     if p.name != "flash_mut_variables_table"]
            merged.propagated.append(
                mut_table_to_propagated_symbol(mut_result, ref_table_addr)
            )
            propagated_all = merged.propagated
            if enrich_project:
                session.apply_mut_table(ctx.rom_path, mut_result)
                _mut_table_ghidra_applied = True
        else:
            click.echo("   warning: MUT table not identified via get_mut_pointer data refs")

    # [5.75/7] OBD PID + DTC analysis
    obd_result = None
    obd_pid_text = ""
    if ctx.emit_obd:
        from rom_analyzer.obd_analysis import run_obd_analysis
        click.echo("[5.75/7] OBD PID + DTC analysis")

        dtc_table_sym = next(
            (p for p in propagated_all if p.name == "flash_trouble_code_table"), None
        )
        dtc_table_addr_new = dtc_table_sym.new_address if dtc_table_sym is not None else 0x12948
        if dtc_table_sym is None:
            click.echo("   warning: flash_trouble_code_table not propagated; using reference-ROM fallback 0x12948")

        _handler_refs = [
            (1,    "sio0_obd_request_data_by_pid"),
            (2,    "obd_get_freeze_frame0"),
            (0x18, "obd_mode18_handler"),
            (0x59, "obd_mode59_handler"),
        ]
        match_by_name = {m.ref_name: m for m in matches if m.ref_name}
        handler_entries: list[tuple[int, int]] = []
        for mode, ref_name in _handler_refs:
            m = match_by_name.get(ref_name)
            if m is not None:
                handler_entries.append((mode, m.new_address))
            else:
                click.echo(f"   warning: {ref_name} not matched; mode {mode:#x} PID trace skipped")

        set_match = match_by_name.get("probably_set_dtc")
        reset_match = match_by_name.get("probably_reset_dtc")
        set_addr = set_match.new_address if set_match else None
        reset_addr = reset_match.new_address if reset_match else None

        if set_addr is None or reset_addr is None:
            click.echo("   DTC helpers not fully resolved via VTSession; trying structural scan for missing one(s)")
            scan_set, scan_reset = fetch_dtc_helpers_structural(project, new_prog_name)
            if scan_set is not None:
                n_callers = len(fetch_callers_of(project, new_prog_name, scan_set))
                if n_callers < 5:
                    click.echo(
                        f"   warning: structural set_dtc candidate "
                        f"{scan_set:#x} has only {n_callers} callers (expected ≥5)"
                    )
            if scan_reset is not None:
                n_reset_callers = len(fetch_callers_of(project, new_prog_name, scan_reset))
                if n_reset_callers < 2:
                    click.echo(
                        f"   warning: structural reset_dtc candidate "
                        f"{scan_reset:#x} has only {n_reset_callers} callers (expected ≥2)"
                    )
            set_addr = set_addr or scan_set
            reset_addr = reset_addr or scan_reset

        if set_addr is None and reset_addr is None:
            click.echo("   warning: could not identify DTC helper functions; setter attribution will be empty")

        obd_result = run_obd_analysis(
            project, new_prog_name, rom_bytes, dtc_table_addr_new,
            handler_entries, set_addr, reset_addr,
        )
        click.echo(
            f"   DTC entries: {len(obd_result.dtc_entries)}, "
            f"PID entries: {len(obd_result.pid_entries)}"
        )
        from rom_analyzer.emit_ld import emit_obd_pid_symbols
        obd_pid_text = emit_obd_pid_symbols(obd_result.pid_entries)

    # [5.8/7] CAN slot SID decode
    can_slots_result = None
    if ctx.emit_can_slots:
        from rom_analyzer.can_slots import analyze_can_slots
        click.echo("[5.8/7] CAN slot SID decode")
        prop_by_name = {p.name: p.new_address for p in propagated_all}
        check_addr = prop_by_name.get("can0_slot_check_sid")
        if check_addr is None:
            check_addr = next(
                (m.new_address for m in matches if m.ref_name == "can0_slot_check_sid"), None
            )
        if check_addr is None:
            click.echo("   warning: can0_slot_check_sid not located; CAN slot decode skipped")
        else:
            _h = _re.compile(r"^can0_slot(\d+)_(?:.+_)?(rx|tx)_update$")
            slot_handlers: dict[int, list[int | None]] = {}
            for p in propagated_all:
                mm = _h.match(p.name)
                if mm is None:
                    continue
                slot, direction = int(mm.group(1)), mm.group(2)
                rx, tx = slot_handlers.setdefault(slot, [None, None])
                if direction == "rx":
                    if rx is None or p.new_address < rx:
                        slot_handlers[slot] = [p.new_address, tx]
                else:
                    if tx is None or p.new_address < tx:
                        slot_handlers[slot] = [rx, p.new_address]
            handlers = {k: (v[0], v[1]) for k, v in slot_handlers.items()}
            can_slots_result = analyze_can_slots(rom_bytes, check_addr, handlers)
            known = sum(1 for s in can_slots_result if s.semantic)
            click.echo(f"   decoded {len(can_slots_result)} slots, {known} with known semantics")

    # [6/7] CRC detection + free space scan
    click.echo("[6/7] Detecting CRC, scanning free space")
    _crc_instrs_raw: list[dict] | None = None
    if _primary_is_self_diff:
        if new_run.rom_crc_check_step:
            _crc_instrs_raw = new_run.rom_crc_check_step["instructions"]
        else:
            click.echo("   warning: rom_crc_check_step not located in new ROM")
    else:
        match_by_name_crc = {m.ref_name: m for m in matches if m.ref_name}
        crc_match = next((m for m in matches if m.ref_name == "rom_crc_check_step"), None)
        if crc_match is not None:
            click.echo(f"   fetching rom_crc_check_step at matched address {crc_match.new_address:#x}")
            _crc_instrs_raw = fetch_instructions_at(project, new_prog_name, crc_match.new_address)
            if _crc_instrs_raw is None:
                click.echo("   warning: no instructions found at matched rom_crc_check_step address")
        else:
            click.echo("   warning: rom_crc_check_step not in VTSession/BFS matches; CRC detection skipped")

    crc: CrcRegion | None = None
    if _crc_instrs_raw is not None:
        instrs = [Instruction(i["mnemonic"], tuple(i["operands"])) for i in _crc_instrs_raw]
        try:
            crc = extract_crc_region(instrs)
        except Exception as e:
            click.echo(f"   warning: CRC extraction failed: {e}")

    new_ram_refs = set(new_run.ram_refs)
    flash_blocks = find_free_blocks(rom_bytes, crc, min_length=ctx.min_flash_block) if crc else []
    ram_blocks = find_free_ram_blocks(new_ram_refs, min_length=ctx.min_ram_block)

    # Mode23 splice-site bindings (only if emit_mode23)
    mode23_lines: list[str] = []
    if ctx.emit_mode23:
        click.echo("[7/7] Resolving mode-0x23 splice-site bindings")
        match_by_ref = {m.ref_address: m for m in matches}
        match_by_name = {m.ref_name: m for m in matches if m.ref_name}

        kline_ref_addr = next(
            (s.address for s in ref_symbols
             if s.name == "obd_rest_handler_injection_location"), None)
        txcount_ref = next(
            (s.address for s in ref_symbols if s.name == "sio0_tx_count"), None)
        if kline_ref_addr is not None and txcount_ref is not None and ref_run is not None:
            ref_prog_name = ghidriff_program_name(primary_entry.rom_path)
            ref_container = fetch_function_entry(project, ref_prog_name, kline_ref_addr)
            if _primary_is_self_diff:
                new_container = ref_container
            else:
                cm = match_by_ref.get(ref_container) if ref_container is not None else None
                new_container = cm.new_address if cm is not None else None
            prop_by_name = {p.name: p.new_address for p in propagated_all}
            txcount_new = prop_by_name.get("sio0_tx_count", txcount_ref)
            if ref_container is not None and new_container is not None:
                expected = new_container + (kline_ref_addr - ref_container)
                reads = fetch_data_read_sites(project, new_prog_name, txcount_new, new_container)
                res = resolve_nearest_site(reads, expected)
            else:
                res = resolve_nearest_site([], 0)
            mode23_lines.append(emit_mode23_binding_line("obd_rest_handler_injection_location", res))

        can_target = match_by_name.get("canrx12_15_process")
        if can_target is not None:
            callers = fetch_callers_of(project, new_prog_name, can_target.new_address)
            slot_of: dict[int, int | None] = {}
            for c in callers:
                imm = fetch_r0_imm_before(project, new_prog_name, c)
                if imm is None:
                    imm = decode_ldi_r0_before(rom_bytes, c)
                slot_of[c] = imm
            can_bindings, can_verify = resolve_can_call_sites(callers, slot_of)
            for b in can_bindings:
                mode23_lines.append(emit_mode23_binding_line(b.name, b.resolution))
            mode23_lines.append(can_verify)
        for ln in mode23_lines:
            click.echo("   " + ln.rstrip())

    return AnalysisResult(
        crc=crc,
        flash_blocks=flash_blocks,
        ram_blocks=ram_blocks,
        mut_result=mut_result,
        obd_result=obd_result,
        can_slots_result=can_slots_result,
        obd_pid_text=obd_pid_text,
        mode23_lines=mode23_lines,
    )
```

- [ ] **Step 2: Update `cli.py` to call `post_match_analysis`**

Add imports:
```python
from rom_analyzer.pipeline.post_match import post_match_analysis
from rom_analyzer.pipeline.types import AnalysisResult
```

In `analyze`, replace the `[5.5/7]` through `[6/7]` block (everything from `_mut_table_ghidra_applied = False` through `ram_blocks = find_free_ram_blocks(...)` and the mode23 resolution block) with:

```python
analysis = post_match_analysis(
    session, ctx, imported, merged,
    primary_entry=primary,
    ref_symbols=ref_symbols,
    ref_run=ref_run,
    enrich_project=enrich_project,
)
# propagated_all may have been updated by MUT table pass inside post_match_analysis
propagated_all = merged.propagated
```

- [ ] **Step 3: Run all tests**

```bash
pytest tests/ -x -q
```
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add rom_analyzer/pipeline/post_match.py rom_analyzer/cli.py
git commit -m "refactor: extract post_match_analysis() to pipeline/post_match.py"
```

---

### Task 8: Extract `write_outputs()` to `pipeline/output.py`

Extract the `[7/7]` file emission block and the `--enrich-project` apply step. After this task, `cli.py` should be ~250 lines.

**Files:**
- Create: `rom_analyzer/pipeline/output.py`
- Modify: `rom_analyzer/cli.py`

- [ ] **Step 1: Create `rom_analyzer/pipeline/output.py`**

```python
"""Emit all output files for the analyze command.

write_outputs() is the final stage: description.ld, omni stub, TOML reports,
match report, and optional Ghidra project enrichment.
"""

from __future__ import annotations

from io import StringIO

import click

from rom_analyzer.emit_ld import (
    emit_can_slots_toml, emit_crc_region_toml, emit_description_ld,
    emit_dtc_map_toml, emit_flash_free_toml, emit_omni_stub,
    emit_ram_free_toml, emit_reference_conflicts_md,
)
from rom_analyzer.ghidra.session import GhidraSession
from rom_analyzer.pipeline.types import AnalysisResult, MergeResult, ReferenceMatchResult, RomContext
from rom_analyzer.registry import ReferenceEntry
from rom_analyzer.types import DataTypeDefinition


def write_outputs(
    session: GhidraSession,
    ctx: RomContext,
    merged: MergeResult,
    analysis: AnalysisResult,
    results: list[ReferenceMatchResult],
    selected: list[ReferenceEntry],
    data_type_defs: list[DataTypeDefinition],
    show_provenance: bool,
) -> None:
    """Write all output files to ctx.out_dir. Also applies Ghidra enrichment
    when ctx.enrich_project is set."""
    out_dir = ctx.out_dir
    propagated_all = merged.propagated
    matches = merged.matches

    click.echo("[7/7] Emitting outputs")

    _desc = emit_description_ld(
        propagated_all,
        source_rom=ctx.rom_path.name,
        reference_name=("multi" if len(selected) > 1 else selected[0].id),
        variant=ctx.language_id,
        match_summary=merged.match_summary,
        show_provenance=show_provenance,
    )
    if analysis.mode23_lines:
        _desc += "\n/* mode 0x23 splice-site bindings (--emit-mode23) */\n"
        _desc += "".join(analysis.mode23_lines)
    if analysis.obd_pid_text:
        _desc += analysis.obd_pid_text
    (out_dir / "description.ld").write_text(_desc)

    primary_result = results[0]
    ram_globals = [s for s in primary_result.propagated if s.category == "ram_global"]
    (out_dir / "omni.ld.stub").write_text(emit_omni_stub(analysis.flash_blocks, ram_globals))
    (out_dir / "crc-region.toml").write_text(
        emit_crc_region_toml(analysis.crc) if analysis.crc else "# CRC region not detected\n"
    )
    (out_dir / "flash-free.toml").write_text(emit_flash_free_toml(analysis.flash_blocks))
    (out_dir / "ram-free.toml").write_text(emit_ram_free_toml(analysis.ram_blocks))

    if analysis.obd_result is not None:
        dtc_map_path = out_dir / "dtc-map.toml"
        dtc_map_path.write_text(emit_dtc_map_toml(analysis.obd_result.dtc_entries))
        click.echo(f"   wrote {dtc_map_path}")

    if analysis.can_slots_result is not None:
        can_slots_path = out_dir / "can-slots.toml"
        can_slots_path.write_text(emit_can_slots_toml(analysis.can_slots_result))
        click.echo(f"   wrote {can_slots_path}")

    (out_dir / "reference-conflicts.md").write_text(
        emit_reference_conflicts_md(merged.disagreements, merged.cross_family)
    )

    # Match report
    report = StringIO()
    report.write("# rom-analyzer match report\n\n")
    report.write(f"Source ROM: {ctx.rom_path.name}\n")
    report.write(f"Reference:  {selected[0].id}\n")
    report.write(f"Variant:    {ctx.language_id}\n\n")
    report.write(f"## Summary\n- Matched functions: {merged.match_summary}\n")
    data_labels = primary_result.data_labels
    ram_labels = primary_result.ram_labels
    sig_matches = primary_result.sig_matches
    ram_labels_p2 = primary_result.ram_labels_p2
    data_labels_p2 = primary_result.data_labels_p2
    scalar_count = sum(1 for d in data_labels if d.source == "data_refs_scalar")
    label_summary = (
        f"{len(data_labels)} ({scalar_count} via scalar refs)"
        if scalar_count else str(len(data_labels))
    )
    report.write(f"- Propagated data labels: {label_summary}\n")
    report.write(f"- Propagated RAM labels: {len(ram_labels)}\n")
    if sig_matches:
        report.write(f"- RAM-signature matches: {len(sig_matches)}\n")
        report.write(f"- Propagated RAM labels (p2): {len(ram_labels_p2)}\n")
        report.write(f"- Propagated data labels (p2): {len(data_labels_p2)}\n")
    report.write("\n")
    src_counts: dict[str, int] = {}
    for m in matches:
        src_counts[m.source] = src_counts.get(m.source, 0) + 1
    if src_counts:
        report.write("## Match sources\n")
        for src, cnt in sorted(src_counts.items()):
            report.write(f"- {src}: {cnt}\n")
        report.write("\n")
    if analysis.crc is not None:
        report.write("## CRC region\n")
        report.write(f"- Full mode:    [{analysis.crc.full_start:#x}, {analysis.crc.full_end:#x})\n")
        report.write(f"- Partial mode: [{analysis.crc.partial_start:#x}, {analysis.crc.partial_end:#x})\n")
    report.write("\n## References\n")
    for r in results:
        won = sum(1 for s in propagated_all if s.reference == r.entry.id)
        report.write(f"- {r.entry.id} (priority {r.entry.priority}): "
                     f"{len(r.matches)} matches, {won} symbols won\n")
    report.write("\n")
    (out_dir / "match-report.md").write_text(report.getvalue())

    click.echo(f"\nDone. Outputs in {out_dir}/")

    # Ghidra project enrichment (optional)
    if ctx.enrich_project:
        _mut_applied = analysis.mut_result is not None
        labels_for_apply = (
            [p for p in propagated_all if p.name != "flash_mut_variables_table"]
            if _mut_applied else propagated_all
        )
        click.echo(f"[+] Enriching Ghidra project with {len(labels_for_apply)} propagated symbols")
        n = session.apply_labels(ctx.rom_path, labels_for_apply)
        click.echo(f"    Applied {n} label(s) to {ctx.rom_path.name} Ghidra project")
        if data_type_defs:
            m = session.apply_data_types(ctx.rom_path, data_type_defs)
            click.echo(f"    Applied {m} data type definition(s)")
```

- [ ] **Step 2: Gut the `analyze` command body down to the orchestration spine**

Replace everything after `results = [...]` through the `project.close()` finally block with:

```python
merged = arbitrate_references(results, priority)
show_provenance = len(selected) > 1
primary_result = results[0]
ref_symbols = primary_result.ref_symbols
ref_run = primary_result.ref_run

analysis = post_match_analysis(
    session, ctx, imported, merged,
    primary_entry=primary,
    ref_symbols=ref_symbols,
    ref_run=ref_run,
    enrich_project=enrich_project,
)
propagated_all = merged.propagated

_primary_ref_store = load_annotations(primary.json_path)
data_type_defs = [
    DataTypeDefinition(s.address, s.data_type, 0)
    for s in _primary_ref_store.symbols if s.data_type
]

write_outputs(
    session, ctx, merged, analysis, results, selected,
    data_type_defs=data_type_defs,
    show_provenance=show_provenance,
)
```

Add import: `from rom_analyzer.pipeline.output import write_outputs`

- [ ] **Step 3: Verify `cli.py` line count**

```bash
wc -l rom_analyzer/cli.py
```
Expected: ≤ 320 lines (the threshold may be slightly over 250 due to option declarations, but should be significantly reduced from 1,125).

- [ ] **Step 4: Run all tests**

```bash
pytest tests/ -x -q
```
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add rom_analyzer/pipeline/output.py rom_analyzer/cli.py
git commit -m "refactor: extract write_outputs() to pipeline/output.py; cli.py now ~300 lines"
```

---

### Task 9: Rename root `scripts/` files

Mechanical renames only. No logic changes. Root `scripts/` gets consistent prefix naming.

**Files:** Only renames within `scripts/`

- [ ] **Step 1: Rename agent_enrich scripts**

```bash
git mv scripts/agent_enrich_init.py scripts/enrich_init.py
git mv scripts/agent_enrich_init_vars.py scripts/enrich_init_vars.py
git mv scripts/agent_enrich_decompile.py scripts/enrich_decompile.py
git mv scripts/agent_enrich_apply.py scripts/enrich_apply.py
```

- [ ] **Step 2: Rename dma and check scripts**

```bash
git mv scripts/dma_activation_analysis.py scripts/dma_activation.py
git mv scripts/check_reference_name_uniqueness.py scripts/check_reference_names.py
```

- [ ] **Step 3: Update any hardcoded script references**

Search for references to old names in shell scripts and README:

```bash
grep -r "agent_enrich_\|dma_activation_analysis\|check_reference_name_uniqueness" \
    scripts/ README.md .pre-commit-config.yaml 2>/dev/null
```

Update any occurrences found to use the new names.

- [ ] **Step 4: Commit**

```bash
git add scripts/
git commit -m "refactor: rename scripts/ for consistent prefix naming (enrich_*, dma_activation, check_reference_names)"
```

---

### Task 10: Empty and remove `rom_analyzer/scripts/`

Move all files from `rom_analyzer/scripts/` to root `scripts/` and remove the now-empty subpackage.

**Files:**
- Move: `rom_analyzer/scripts/build_reference_from_txt.py` → `scripts/build_reference_from_txt.py`
- Move: `rom_analyzer/scripts/export_annotations.py` → `scripts/export_annotations.py`
- Move: `rom_analyzer/scripts/import_annotations.py` → `scripts/import_annotations.py`
- Move: `rom_analyzer/scripts/dump_references.py` → `scripts/dump_references.py`
- Move: `rom_analyzer/scripts/m32r_analysis.py` → `scripts/m32r_analysis.py`
- Delete: `rom_analyzer/scripts/__init__.py`, `rom_analyzer/scripts/` directory

- [ ] **Step 1: Move build scripts to root `scripts/`**

```bash
git mv rom_analyzer/scripts/build_reference_from_txt.py scripts/build_reference_from_txt.py
git mv rom_analyzer/scripts/export_annotations.py scripts/export_annotations.py
git mv rom_analyzer/scripts/import_annotations.py scripts/import_annotations.py
git mv rom_analyzer/scripts/dump_references.py scripts/dump_references.py
git mv rom_analyzer/scripts/m32r_analysis.py scripts/m32r_analysis.py
git rm rom_analyzer/scripts/__init__.py
```

- [ ] **Step 2: Fix internal imports in moved scripts**

`scripts/import_annotations.py` imports `from rom_analyzer.ghidra_overlay import apply_annotations`. Since `ghidra_overlay.py` is now a shim that re-exports from `rom_analyzer.ghidra.overlay`, this import continues to work without change.

Verify there are no other broken imports in the moved scripts:
```bash
grep "from rom_analyzer" scripts/build_reference_from_txt.py \
    scripts/export_annotations.py scripts/import_annotations.py \
    scripts/dump_references.py
```
All `from rom_analyzer.*` imports are correct since the package is still installed.

- [ ] **Step 3: Run all tests**

```bash
pytest tests/ -x -q
```
Expected: all tests pass. Confirm no test still imports from `rom_analyzer.scripts`:

```bash
grep -r "from rom_analyzer.scripts" tests/ rom_analyzer/
```
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add scripts/ && git rm -r rom_analyzer/scripts/
git commit -m "refactor: move rom_analyzer/scripts/ contents to scripts/; remove empty subpackage"
```

---

## Self-Review

**Spec coverage check:**

| Spec requirement | Task |
|---|---|
| `ghidra.py` splits into `session/fetch/domain/overlay` | Task 2 |
| `ghidra/__init__.py` re-exports full public surface | Task 2, Step 5 |
| `GhidraSession` class with `open`, `close`, `__enter__`/`__exit__`, `import_rom`, `prog_name_for`, `apply_labels`, `apply_data_types`, `apply_mut_table` | Task 3 |
| `pipeline/types.py` with all 5 dataclasses | Task 4 |
| `import_stage()` and `match_reference()` in `pipeline/reference.py` | Task 5 |
| `arbitrate_references()` and `classify_and_apply()` in `pipeline/arbitrate.py` | Task 6 |
| `post_match_analysis()` in `pipeline/post_match.py` | Task 7 |
| `write_outputs()` in `pipeline/output.py` | Task 8 |
| `cleanup.py` with 3 shared functions | Task 1 |
| Root `scripts/` renaming | Task 9 |
| `rom_analyzer/scripts/` removal | Task 10 |
| `ghidra_overlay.py` kept as backward-compat shim | Task 2, Step 6 |
| `test_dedup_names.py` updated import path | Task 1, Step 4 |
| Tests pass after every step | Every task, "Run tests" step |

**All spec requirements have a corresponding task.**

**Type consistency check:**
- `ReferenceMatchResult` is defined in Task 4 (`pipeline/types.py`) and used in Tasks 5, 6, 7, 8 — consistent.
- `MergeResult` defined in Task 4, returned by `arbitrate_references` in Task 6, consumed in Tasks 7 and 8 — consistent.
- `AnalysisResult` defined in Task 4, returned by `post_match_analysis` in Task 7, consumed in Task 8 — consistent.
- `GhidraSession` defined in Task 3; `session.apply_labels(rom_path, symbols)` signature used in Tasks 5, 7, 8 — consistent.
- `import_stage` signature `(session, ctx, primary_entry) -> ImportResult` defined in Task 5; called in `cli.py` in Task 5 — consistent.
