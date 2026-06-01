"""Parse Ghidra XML exports into ReferenceSymbol lists.

Categorization is by address range:
    addr < 0x80000  → "function" if listed under <FUNCTIONS>, else "data"
    addr >= 0x800000 → "ram_global" (everything at 0x80xxxx including MMIO)
"""

from pathlib import Path

from lxml import etree

from rom_analyzer.types import DataTypeDefinition, ReferenceSymbol, SymbolCategory


def load_reference_symbols(
    xml_path: Path,
    flash_txt: Path | None = None,
    map_txt: Path | None = None,
) -> list[ReferenceSymbol]:
    tree = etree.parse(str(xml_path))
    root = tree.getroot()

    function_entries: set[int] = set()
    for f in root.iterfind(".//FUNCTION"):
        ep = f.get("ENTRY_POINT")
        if ep:
            function_entries.add(int(ep, 16))

    results: list[ReferenceSymbol] = []
    seen_addresses: set[int] = set()

    # Parse XML first — these entries "win" on address conflict
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
        seen_addresses.add(addr)

    # Merge flash_txt entries if provided
    if flash_txt is not None:
        from rom_analyzer.parsers import parse_colt_flash

        for entry in parse_colt_flash(flash_txt):
            if entry.address not in seen_addresses:
                cat: SymbolCategory = "function" if entry.is_function else "data"
                results.append(ReferenceSymbol(entry.name, entry.address, cat))
                seen_addresses.add(entry.address)

    # Merge map_txt entries if provided
    if map_txt is not None:
        from rom_analyzer.parsers import parse_colt_map

        for entry in parse_colt_map(map_txt):
            if entry.address not in seen_addresses:
                results.append(
                    ReferenceSymbol(entry.name, entry.address, "ram_global")
                )
                seen_addresses.add(entry.address)

    return results


def _categorize(addr: int, function_entries: set[int]) -> SymbolCategory:
    if addr in function_entries:
        return "function"
    if addr >= 0x800000:
        return "ram_global"
    return "data"


def load_data_type_definitions(xml_path: Path) -> list[DataTypeDefinition]:
    """Parse <DEFINED_DATA> elements from a Ghidra XML export."""
    tree = etree.parse(str(xml_path))
    root = tree.getroot()
    results: list[DataTypeDefinition] = []
    for elem in root.iter("DEFINED_DATA"):
        addr_str = elem.get("ADDRESS")
        datatype = elem.get("DATATYPE")
        size_str = elem.get("SIZE")
        if addr_str is None or datatype is None:
            continue
        try:
            address = int(addr_str, 16)
        except ValueError:
            continue
        try:
            size = int(size_str, 0) if size_str is not None else 0
        except ValueError:
            size = 0
        results.append(DataTypeDefinition(address=address, datatype=datatype, size=size))
    return results
