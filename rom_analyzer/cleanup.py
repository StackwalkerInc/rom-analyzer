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
