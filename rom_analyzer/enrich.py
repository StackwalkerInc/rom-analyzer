"""Reference XML enrichment with type annotations from colt_flash.txt."""

from dataclasses import dataclass
from pathlib import Path

import click
from lxml import etree

from rom_analyzer.parsers import (
    FlashEntry,
    Param,
    ParsedSignature,
    parse_colt_flash,
    parse_colt_map,
    parse_function_signature,
)

_REFERENCE_DIR = Path(__file__).parent.parent / "reference"


@dataclass(frozen=True)
class GhidraType:
    datatype: str
    namespace: str   # "/stdint.h" or "" — omit DATATYPE_NAMESPACE attr when empty
    size_bytes: int  # 0 = unknown / void


_PRIMITIVE_TYPES: dict[str, GhidraType] = {
    "void":     GhidraType("void",     "",          0),
    "int":      GhidraType("int",      "",          4),
    "char":     GhidraType("char",     "",          1),
    "uint8_t":  GhidraType("uint8_t",  "/stdint.h", 1),
    "uint16_t": GhidraType("uint16_t", "/stdint.h", 2),
    "uint32_t": GhidraType("uint32_t", "/stdint.h", 4),
    "uint64_t": GhidraType("uint64_t", "/stdint.h", 8),
    "int8_t":   GhidraType("int8_t",   "/stdint.h", 1),
    "int16_t":  GhidraType("int16_t",  "/stdint.h", 2),
    "int32_t":  GhidraType("int32_t",  "/stdint.h", 4),
    "int64_t":  GhidraType("int64_t",  "/stdint.h", 8),
}

M32R_ARG_REGS = ["R0", "R1", "R2", "R3"]


def map_c_type(type_str: str) -> GhidraType:
    """Map a C type string to Ghidra XML datatype attributes (best-effort)."""
    stripped = type_str.strip()
    if stripped in _PRIMITIVE_TYPES:
        return _PRIMITIVE_TYPES[stripped]
    if "*" in stripped:
        return GhidraType(stripped, "", 4)  # M32R pointers are 32-bit
    return GhidraType(stripped, "", 0)


def assign_arg_registers(params: list[Param]) -> list[tuple[Param, str | None]]:
    """Assign M32R calling-convention registers to a parameter list.

    Returns (param, register_name) pairs. register_name is None for stack-spilled
    args (beyond R3). 64-bit arguments consume two consecutive register slots.
    """
    result: list[tuple[Param, str | None]] = []
    reg_idx = 0
    for param in params:
        if param.type_str.strip() == "void":
            break
        if reg_idx < 4:
            result.append((param, M32R_ARG_REGS[reg_idx]))
            size = map_c_type(param.type_str).size_bytes
            reg_idx += 2 if size == 8 else 1
        else:
            result.append((param, None))
    return result


def _apply_type_info(
    fn_elem: etree._Element,
    name: str,
    raw_declaration: str,
    sig: ParsedSignature | None,
) -> None:
    fn_elem.set("NAME", name)
    for tag in ("RETURN_TYPE", "TYPEINFO_CMT", "REGISTER_VAR"):
        for child in fn_elem.findall(tag):
            fn_elem.remove(child)
    if sig is None:
        return
    # Insert RETURN_TYPE before the first ADDRESS_RANGE (index 0 if none present)
    first_ar_idx = next(
        (i for i, c in enumerate(fn_elem) if c.tag == "ADDRESS_RANGE"), 0
    )
    rt_type = map_c_type(sig.return_type)
    rt_elem = etree.Element("RETURN_TYPE")
    rt_elem.set("DATATYPE", rt_type.datatype)
    if rt_type.namespace:
        rt_elem.set("DATATYPE_NAMESPACE", rt_type.namespace)
    if rt_type.size_bytes > 0:
        rt_elem.set("SIZE", hex(rt_type.size_bytes))
    fn_elem.insert(first_ar_idx, rt_elem)
    # Insert TYPEINFO_CMT before STACK_FRAME (append if no STACK_FRAME)
    sf_idx = next(
        (i for i, c in enumerate(fn_elem) if c.tag == "STACK_FRAME"), len(fn_elem)
    )
    ti_elem = etree.Element("TYPEINFO_CMT")
    ti_elem.text = raw_declaration.rstrip(";").strip()
    fn_elem.insert(sf_idx, ti_elem)
    # Append REGISTER_VAR elements after all other children
    for param, reg in assign_arg_registers(sig.params):
        if reg is None:
            continue
        rv_elem = etree.Element("REGISTER_VAR")
        rv_elem.set("NAME", param.name)
        rv_elem.set("REGISTER", reg)
        pt = map_c_type(param.type_str)
        rv_elem.set("DATATYPE", pt.datatype)
        if pt.namespace:
            rv_elem.set("DATATYPE_NAMESPACE", pt.namespace)
        fn_elem.append(rv_elem)


def _make_function_element(entry: FlashEntry, sig: ParsedSignature | None) -> etree._Element:
    fn_elem = etree.Element("FUNCTION")
    fn_elem.set("ENTRY_POINT", f"{entry.address:08x}")
    fn_elem.set("NAME", entry.name)
    fn_elem.set("LIBRARY_FUNCTION", "n")
    if sig is not None:
        rt_type = map_c_type(sig.return_type)
        rt_elem = etree.Element("RETURN_TYPE")
        rt_elem.set("DATATYPE", rt_type.datatype)
        if rt_type.namespace:
            rt_elem.set("DATATYPE_NAMESPACE", rt_type.namespace)
        if rt_type.size_bytes > 0:
            rt_elem.set("SIZE", hex(rt_type.size_bytes))
        fn_elem.append(rt_elem)
    ar_elem = etree.Element("ADDRESS_RANGE")
    ar_elem.set("START", f"{entry.address:08x}")
    ar_elem.set("END", f"{entry.address + entry.size - 1:08x}")
    fn_elem.append(ar_elem)
    if sig is not None:
        ti_elem = etree.Element("TYPEINFO_CMT")
        ti_elem.text = entry.raw_declaration.rstrip(";").strip()
        fn_elem.append(ti_elem)
    sf_elem = etree.Element("STACK_FRAME")
    sf_elem.set("LOCAL_VAR_SIZE", "0x0")
    sf_elem.set("PARAM_OFFSET", "0x0")
    sf_elem.set("RETURN_ADDR_SIZE", "0x0")
    fn_elem.append(sf_elem)
    if sig is not None:
        for param, reg in assign_arg_registers(sig.params):
            if reg is None:
                continue
            rv_elem = etree.Element("REGISTER_VAR")
            rv_elem.set("NAME", param.name)
            rv_elem.set("REGISTER", reg)
            pt = map_c_type(param.type_str)
            rv_elem.set("DATATYPE", pt.datatype)
            if pt.namespace:
                rv_elem.set("DATATYPE_NAMESPACE", pt.namespace)
            fn_elem.append(rv_elem)
    return fn_elem


def _upsert_symbol(
    sym_table: etree._Element,
    sym_by_addr: dict[int, etree._Element],
    address: int,
    name: str,
    sym_type: str,
) -> None:
    if address in sym_by_addr:
        existing = sym_by_addr[address]
        if existing.get("SOURCE_TYPE") != "IMPORTED":
            existing.set("NAME", name)
            existing.set("TYPE", sym_type)
    else:
        new_sym = etree.Element("SYMBOL")
        new_sym.set("ADDRESS", f"{address:08x}")
        new_sym.set("NAME", name)
        new_sym.set("NAMESPACE", "")
        new_sym.set("TYPE", sym_type)
        new_sym.set("SOURCE_TYPE", "USER_DEFINED")
        new_sym.set("PRIMARY", "y")
        sym_table.append(new_sym)
        sym_by_addr[address] = new_sym


def enrich_reference_xml(
    xml_path: Path,
    flash_txt: Path,
    map_txt: Path | None = None,
) -> None:
    """Enrich a Ghidra XML export in-place with type annotations from colt_flash.txt."""
    parser = etree.XMLParser(load_dtd=True, no_network=True)
    tree = etree.parse(str(xml_path), parser)
    root = tree.getroot()

    xml_fn_by_addr: dict[int, etree._Element] = {}
    for fn in root.iterfind(".//FUNCTION"):
        ep = fn.get("ENTRY_POINT")
        if ep:
            xml_fn_by_addr[int(ep, 16)] = fn

    xml_sym_table = root.find(".//SYMBOL_TABLE")
    xml_sym_by_addr: dict[int, etree._Element] = {}
    if xml_sym_table is not None:
        for sym in xml_sym_table.findall("SYMBOL"):
            addr_str = sym.get("ADDRESS")
            if addr_str:
                xml_sym_by_addr[int(addr_str, 16)] = sym

    flash_all = list(parse_colt_flash(flash_txt))
    flash_fns = [e for e in flash_all if e.is_function]
    flash_data = [e for e in flash_all if not e.is_function]
    flash_fn_by_addr = {e.address: e for e in flash_fns}

    flash_sigs: dict[int, ParsedSignature] = {}
    for entry in flash_fns:
        sig = parse_function_signature(entry.raw_declaration)
        if sig is not None:
            flash_sigs[entry.address] = sig

    map_entries = list(parse_colt_map(map_txt)) if map_txt is not None else []

    for addr, fn_elem in xml_fn_by_addr.items():
        if addr not in flash_fn_by_addr:
            continue
        entry = flash_fn_by_addr[addr]
        _apply_type_info(fn_elem, entry.name, entry.raw_declaration, flash_sigs.get(addr))

    functions_elem = root.find(".//FUNCTIONS")
    if functions_elem is not None:
        for entry in flash_fns:
            if entry.address not in xml_fn_by_addr:
                functions_elem.append(
                    _make_function_element(entry, flash_sigs.get(entry.address))
                )

    if xml_sym_table is not None:
        for entry in flash_fns:
            _upsert_symbol(xml_sym_table, xml_sym_by_addr, entry.address, entry.name, "global")
        for entry in flash_data:
            _upsert_symbol(xml_sym_table, xml_sym_by_addr, entry.address, entry.name, "global")
        for entry in map_entries:
            _upsert_symbol(xml_sym_table, xml_sym_by_addr, entry.address, entry.name, "global")

    tree.write(str(xml_path), xml_declaration=True, pretty_print=True)


@click.command()
@click.option("--xml", "xml_path", type=click.Path(path_type=Path),
              default=_REFERENCE_DIR / "33520003.xml", show_default=True)
@click.option("--flash", "flash_txt",
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              default=_REFERENCE_DIR / "colt_flash.txt", show_default=True)
@click.option("--map", "map_txt",
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              default=_REFERENCE_DIR / "colt_map.txt", show_default=True)
def cli(xml_path: Path, flash_txt: Path, map_txt: Path) -> None:
    """Enrich reference/33520003.xml in-place with type annotations from colt_flash.txt."""
    enrich_reference_xml(xml_path, flash_txt, map_txt)
    click.echo(f"Enriched {xml_path}")
