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
