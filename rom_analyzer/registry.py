"""Load and select reference entries from reference/registry.toml.

The registry is the single source of truth for which annotated references
exist. Each entry pairs an annotation JSON (under reference/) with a ROM bin
(under roms/, gitignored) plus metadata used for selection and arbitration.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ReferenceEntry:
    id: str
    json_path: Path
    rom_path: Path
    family: str
    variant: str
    priority: int
    features: list[str]
    notes: str


def load_registry(path: Path) -> list[ReferenceEntry]:
    """Parse registry.toml. `json` resolves relative to the registry's own
    directory (reference/); `rom` resolves relative to <repo>/roms/.

    Raises FileNotFoundError if a referenced annotation JSON is absent — a
    registered reference with no annotations is always a configuration error.
    A missing ROM bin is NOT an error here (CI has no bins); callers filter
    those out via partition_available().
    """
    path = Path(path)
    reference_dir = path.parent
    roms_dir = reference_dir.parent / "roms"
    data = tomllib.loads(path.read_text())

    entries: list[ReferenceEntry] = []
    for raw in data.get("reference", []):
        json_path = reference_dir / raw["json"]
        if not json_path.exists():
            raise FileNotFoundError(
                f"registry entry {raw['id']!r}: annotation JSON not found: {json_path}"
            )
        entries.append(ReferenceEntry(
            id=raw["id"],
            json_path=json_path,
            rom_path=roms_dir / raw["rom"],
            family=raw["family"],
            variant=raw["variant"],
            priority=int(raw.get("priority", 0)),
            features=list(raw.get("features", [])),
            notes=raw.get("notes", ""),
        ))
    return entries


def select_references(
    entries: list[ReferenceEntry],
    *,
    variant: str,
    include_ids: list[str],
    exclude_ids: list[str],
) -> list[ReferenceEntry]:
    """Filter to references compatible with `variant`, honouring explicit
    include/exclude id lists, sorted by priority (descending) so the primary
    reference is first."""
    kept = [e for e in entries if e.variant == variant]
    if include_ids:
        want = set(include_ids)
        kept = [e for e in kept if e.id in want]
    if exclude_ids:
        drop = set(exclude_ids)
        kept = [e for e in kept if e.id not in drop]
    kept.sort(key=lambda e: e.priority, reverse=True)
    return kept


def partition_available(
    entries: list[ReferenceEntry],
) -> tuple[list[ReferenceEntry], list[ReferenceEntry]]:
    """Split entries into (rom_exists, rom_missing). Matching needs ROM bytes,
    so missing-bin entries are skipped (with a warning) by the caller."""
    available = [e for e in entries if e.rom_path.exists()]
    missing = [e for e in entries if not e.rom_path.exists()]
    return available, missing
