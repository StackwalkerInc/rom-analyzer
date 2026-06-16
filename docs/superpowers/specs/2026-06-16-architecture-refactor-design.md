# rom-analyzer Architecture Refactor

**Date:** 2026-06-16
**Status:** Approved for implementation

## Problem

After 3.5 weeks and 259 commits of fast-paced feature additions, three structural problems have accumulated:

1. **`cli.py` (1,125 lines) does everything** — Ghidra session management, multi-reference orchestration, match deduplication, mode23 splice resolution, OBD/CAN slot logic, and output emission are all inline in two giant Click command functions. Adding a new analysis pass requires reading the full file to find the right insertion point.

2. **`ghidra.py` (935 lines) mixes two concerns** — the generic Ghidra API wrapper (`import_and_dump`, `apply_labels`, `fetch_*`) lives alongside domain-specific analyses (`fetch_pid_dispatch_entries`, `fetch_dtc_helpers_structural`, `fetch_dtc_call_sites`). There is no clear boundary between "Ghidra plumbing" and "M32R analysis using Ghidra".

3. **Two `scripts/` directories with different conventions** — `rom_analyzer/scripts/` contains package-importable build utilities; root `scripts/` contains standalone agent_enrich tools with inconsistent naming (`agent_enrich_init.py`, `dma_activation_analysis.py`). The relationship between them is unclear.

## Goals

- `cli.py` becomes a ~250-line thin orchestrator: parse args, construct inputs, call stages.
- Each analysis phase has a named home with a clear typed input/output contract.
- `ghidra.py` splits into generic API vs domain analysis.
- All standalone scripts live in root `scripts/` with consistent naming; `rom_analyzer/scripts/` becomes empty and is removed.
- Public CLI interface (`rom-analyzer analyze`, `rom-analyzer enrich`, `rom-analyzer apply-enrichment`) is unchanged.
- All existing test imports continue to work without modification (via re-exports).

## Non-goals

- No changes to analysis logic, matching algorithms, or output formats.
- No changes to the `enrich` workflow logic (classify/apply/reconcile).
- No new features.

---

## Module Layout

### `rom_analyzer/ghidra/` (split from `ghidra.py` + `ghidra_overlay.py`)

```
rom_analyzer/ghidra/
  __init__.py     # re-exports everything that was in rom_analyzer.ghidra
                  # so existing imports break nothing
  session.py      # GhidraSession class, import_and_dump, setup_environment,
                  # HeadlessRun, ghidriff_program_name
  fetch.py        # all fetch_* functions: fetch_instructions_at,
                  # fetch_function_entry, fetch_function_name,
                  # fetch_r0_imm_before, fetch_callers_of,
                  # fetch_callees_of, fetch_data_read_sites
  domain.py       # domain analyses that happen to use Ghidra:
                  # fetch_pid_dispatch_entries, fetch_dtc_helpers_structural,
                  # fetch_dtc_call_sites
  overlay.py      # moved from ghidra_overlay.py; apply_annotations,
                  # _parse_type_str
```

`ghidra/__init__.py` re-exports the full public surface so that `from rom_analyzer.ghidra import apply_labels, fetch_callers_of, ...` continues to work in all tests and modules without any migration pass.

### `rom_analyzer/pipeline/` (extracted from `cli.py`)

```
rom_analyzer/pipeline/
  __init__.py
  types.py        # stage result dataclasses (see below)
  reference.py    # match_reference() — the per-reference callgraph+VT+propagation pass
                  # (was analyze_against_reference in cli.py)
  arbitrate.py    # arbitrate_references() — merge + arbitrate across all references
                  # _classify_and_apply() — enrich command's apply block
  post_match.py   # post_match_analysis() — CRC, free space, MUT table, OBD, CAN slots
  output.py       # write_outputs() — all file emission (description.ld, omni stub,
                  # match report, DTC map, CAN slots, reference conflicts)
```

Only `cli.py` imports from `pipeline/`. No other module in `rom_analyzer/` imports from it.

`import_stage(session, ctx, primary_entry)` — the primary `ReferenceEntry` is passed so the stage can load the primary reference's symbols to extract `crc_step_address` before importing the target ROM. It returns `ImportResult` with the new ROM's `HeadlessRun` and program name.

### `rom_analyzer/cleanup.py` (new — extracted from `build_reference_from_txt.py`)

The three functions currently imported by `cli.py` from `rom_analyzer.scripts.build_reference_from_txt` — `drop_imprecise_s_duplicates`, `drop_erased_flash_entries`, `dedup_symbol_names` — operate on `AnnotationStore` and belong near that type. They move to a new `rom_analyzer/cleanup.py`. The import in `cli.py` is updated; `build_reference_from_txt.py` imports from `cleanup.py` instead.

### Unchanged modules

No API changes to: `annotations_io.py`, `callgraph.py`, `can_slots.py`, `crc.py`, `data_refs.py`, `diff.py`, `emit_ld.py`, `enrich.py`, `flash_space.py`, `merge.py`, `mode23_bindings.py`, `mut_table.py`, `obd_analysis.py`, `obd_std_pids.py`, `propagate.py`, `ram_signature.py`, `ram_space.py`, `registry.py`, `types.py`.

### `rom_analyzer/scripts/` — emptied and removed

After `build_reference_from_txt.py` moves to root `scripts/` and `cleanup.py` absorbs the three shared functions, `rom_analyzer/scripts/` contains only `export_annotations.py`, `import_annotations.py`, `dump_references.py`, and `m32r_analysis.py` — all of which move to root `scripts/` as standalone tools. The directory is deleted.

### Root `scripts/` — renamed and consolidated

```
scripts/
  # Agent enrichment workflow (was agent_enrich_*.py)
  enrich_init.py
  enrich_init_vars.py
  enrich_decompile.py
  enrich_apply.py

  # DMA analysis
  dma_activation.py          (was dma_activation_analysis.py)
  dma_decode_funcs.py
  dma_obd_decode.py

  # Reference build and management (moved from rom_analyzer/scripts/)
  build_reference_from_txt.py
  export_annotations.py
  import_annotations.py
  dump_references.py

  # One-offs
  check_reference_names.py   (was check_reference_name_uniqueness.py)
  m32r_analysis.py

  # Shell wrappers (unchanged)
  run-audm-colt-local.sh
  run-e2e.sh
  run-outlander-local.sh
```

---

## GhidraSession

Lives in `ghidra/session.py`. Owns the Ghidra JVM lifecycle and project handle.

```python
@dataclass
class GhidraSession:
    project: object                  # pyghidra Project (opaque)
    project_name: str
    inline_source_annotations: bool = False

    @classmethod
    def open(cls, project_dir: Path, project_name: str, ghidra_home: Path,
             *, clean: bool = False,
             inline_source_annotations: bool = False) -> "GhidraSession":
        """setup_environment + pyghidra.start() + open_project.
        clean=True removes the nested project dir first (replaces --clean-project logic)."""

    def close(self) -> None:
        """project.close()."""

    def __enter__(self) -> "GhidraSession": ...
    def __exit__(self, *_) -> None: self.close()

    def import_rom(self, rom_path: Path, language_id: str,
                   *, crc_step_address: int | None = None,
                   ref_symbols: list[ReferenceSymbol] | None = None,
                   annotations_path: Path | None = None,
                   collect_data_refs: bool = False) -> HeadlessRun:
        """Import ROM if not already in project; return HeadlessRun.
        Replaces bare import_and_dump() calls."""

    def prog_name_for(self, rom_path: Path) -> str:
        """Return the Ghidra program name for a given ROM path (sha1-based)."""

    def apply_labels(self, rom_path: Path,
                     symbols: list[PropagatedSymbol]) -> int: ...

    def apply_data_types(self, rom_path: Path,
                         data_defs: list[DataTypeDefinition]) -> int: ...

    def apply_mut_table(self, rom_path: Path,
                        result: MutTableResult) -> None: ...
```

Key decisions:
- Callers pass `rom_path`; the session derives `prog_name` internally. Eliminates four scattered `ghidriff_program_name()` calls in `cli.py`.
- Context manager replaces `try/finally project.close()` in both `analyze` and `enrich`.
- `GhidraSession.open()` absorbs the `--clean-project` mkdir/rmtree logic currently inline in `analyze`.

`apply_labels`, `apply_data_types`, `apply_mut_table` are thin delegators to the functions in `ghidra/session.py`, passing `self.project` and `self.prog_name_for(rom_path)` internally.

---

## Stage Result Types (`pipeline/types.py`)

```python
@dataclass
class RomContext:
    """Immutable inputs from CLI args. Shared across all stages."""
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
    new_run: HeadlessRun
    new_prog_name: str

@dataclass
class ReferenceMatchResult:
    """Output of match_reference() for one reference ROM."""
    entry: ReferenceEntry
    matches: list[MatchedFunction]
    propagated: list[PropagatedSymbol]
    ref_run: HeadlessRun | None
    ref_symbols: list[ReferenceSymbol]
    data_labels: list[PropagatedSymbol]      # detail for match-report
    ram_labels: list[PropagatedSymbol]
    sig_matches: list[MatchedFunction]
    ram_labels_p2: list[PropagatedSymbol]
    data_labels_p2: list[PropagatedSymbol]

@dataclass
class MergeResult:
    """Output of arbitrate_references() across all ReferenceMatchResults."""
    matches: list[MatchedFunction]
    propagated: list[PropagatedSymbol]
    disagreements: list[PropagatedSymbol]
    cross_family: list[PropagatedSymbol]
    priority: dict[str, int]
    match_summary: str           # "123/456 (27.0%)" — preformatted for the report

@dataclass
class AnalysisResult:
    """Output of post_match_analysis()."""
    crc: CrcRegion | None
    flash_blocks: list[FlashFreeBlock]
    ram_blocks: list[RamFreeBlock]
    mut_result: MutTableResult | None
    obd_result: OBDAnalysis | None
    can_slots_result: list[CanSlot] | None
    obd_pid_text: str
    mode23_lines: list[str]
```

`RomContext` replaces the ~15 keyword arguments currently threaded through `analyze_against_reference`. The four result types are the only hand-offs between stages.

---

## cli.py After Refactor (~250 lines)

```python
@click.command("analyze")
@click.argument(...)
@click.option(...)    # identical public interface
def analyze(rom_path, variant, ..., emit_mode23, emit_obd, emit_can_slots, ...):
    language_id = VARIANT_TO_LANGUAGE[variant]
    selected, priority = _load_references(registry_path, reference_ids,
                                          exclude_ids, variant, reference, reference_rom)
    primary = selected[0]
    ctx = RomContext(
        rom_path=rom_path, rom_bytes=rom_path.read_bytes(),
        language_id=language_id, out_dir=out_dir,
        target_family=primary.family,
        is_self_diff=(rom_path.resolve() == primary.rom_path.resolve()),
        emit_mode23=emit_mode23, emit_obd=emit_obd, emit_can_slots=emit_can_slots,
        enrich_project=enrich_project,
        min_flash_block=min_flash_block, min_ram_block=min_ram_block,
    )
    with GhidraSession.open(project_dir / project_name, project_name, ghidra_home,
                            clean=clean_project,
                            inline_source_annotations=inline_source_annotations) as session:
        imported = import_stage(session, ctx, primary)
        ref_results = [match_reference(session, ctx, imported, e) for e in selected]
        merged = arbitrate_references(ref_results, priority)
        analysis = post_match_analysis(session, ctx, imported, merged)
        write_outputs(ctx, merged, analysis, ref_results, selected)


@cli.command("enrich")
@click.argument("new_id")
@click.option(...)
def enrich(new_id, ...):
    new_entry, others, by_id, priority = _load_enrich_targets(new_id, registry_path)
    ctx = RomContext(...)
    with GhidraSession.open(...) as session:
        imported = import_stage(session, ctx, new_entry)
        ref_results = [match_reference(session, ctx, imported, ref)
                       for ref in others
                       if ref.variant == new_entry.variant]
        classify_and_apply(ref_results, new_entry, by_id, priority, out_dir)
```

`cli.py` keeps: Click option declarations, `VARIANT_TO_LANGUAGE`, `_REFERENCE_DIR`, two small private helpers (`_load_references`, `_load_enrich_targets`), the `cli` group, and `apply_enrichment` (already thin, unchanged).

---

## scripts/ Consolidation Detail

The three functions shared between `build_reference_from_txt.py` and `cli.py` move to `rom_analyzer/cleanup.py`:

```python
# rom_analyzer/cleanup.py
def drop_imprecise_s_duplicates(store: AnnotationStore) -> None: ...
def drop_erased_flash_entries(store: AnnotationStore, rom_bytes: bytes) -> None: ...
def dedup_symbol_names(store: AnnotationStore) -> None: ...
```

`build_reference_from_txt.py` and `cli.py` both import from `rom_analyzer.cleanup`. This is the only import path change visible outside `ghidra/` and `pipeline/`.

The `agent_enrich_state/` runtime directory stays at the repo root — the renamed scripts (`enrich_*.py`) write to the same path.

---

## Testing Strategy

- All existing unit tests pass without modification because `ghidra/__init__.py` re-exports the full old surface.
- `test_ghidra_overlay.py` continues to import from `rom_analyzer.ghidra` (re-exported from `overlay.py`).
- New unit tests are added for `GhidraSession.open` (mocked pyghidra) and each stage function in `pipeline/` using the existing fixture infrastructure.
- E2E tests are unchanged — the public CLI interface is identical.

---

## Implementation Order

1. Create `rom_analyzer/cleanup.py` — move the three shared functions; update imports in `cli.py` and `build_reference_from_txt.py`. Tests pass.
2. Create `rom_analyzer/ghidra/` — split `ghidra.py` into `session.py`, `fetch.py`, `domain.py`; move `ghidra_overlay.py` to `overlay.py`; write `__init__.py` re-export. Tests pass.
3. Introduce `GhidraSession` in `ghidra/session.py`; update `cli.py` to use it (still one big function). Tests pass.
4. Create `rom_analyzer/pipeline/types.py` — define all stage result dataclasses.
5. Extract `match_reference()` to `pipeline/reference.py`; update `cli.py` to call it. Tests pass.
6. Extract `arbitrate_references()` and `_classify_and_apply()` to `pipeline/arbitrate.py`. Tests pass.
7. Extract `post_match_analysis()` to `pipeline/post_match.py`. Tests pass.
8. Extract `write_outputs()` to `pipeline/output.py`. Tests pass. `cli.py` is now ~250 lines.
9. Move root `scripts/agent_enrich_*.py` to `scripts/enrich_*.py`; rename `dma_activation_analysis.py`; update shell wrappers and README.
10. Move `rom_analyzer/scripts/` contents to root `scripts/`; delete `rom_analyzer/scripts/`.
