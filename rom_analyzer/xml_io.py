"""Parse Ghidra XML exports into ReferenceSymbol lists.

Categorization is by address range:
    addr < 0x80000  → "function" if listed under <FUNCTIONS>, else "data"
    addr >= 0x800000 → "ram_global" (everything at 0x80xxxx including MMIO)
"""

from pathlib import Path

from lxml import etree

from rom_analyzer.types import ReferenceSymbol, SymbolCategory


def load_reference_symbols(xml_path: Path) -> list[ReferenceSymbol]:
    tree = etree.parse(str(xml_path))
    root = tree.getroot()

    function_entries: set[int] = set()
    for f in root.iterfind(".//FUNCTION"):
        ep = f.get("ENTRY_POINT")
        if ep:
            function_entries.add(int(ep, 16))

    results: list[ReferenceSymbol] = []
    for sym in root.iterfind(".//SYMBOL"):
        source = sym.get("SOURCE_TYPE", "")
        if source == "IMPORTED":
            continue  # interrupt vectors etc.
        name = sym.get("NAME", "")
        addr_str = sym.get("ADDRESS", "")
        if not name or not addr_str:
            continue
        addr = int(addr_str, 16)
        cat = _categorize(addr, function_entries)
        results.append(ReferenceSymbol(name, addr, cat))

    return results


def _categorize(addr: int, function_entries: set[int]) -> SymbolCategory:
    if addr in function_entries:
        return "function"
    if addr >= 0x800000:
        return "ram_global"
    return "data"
