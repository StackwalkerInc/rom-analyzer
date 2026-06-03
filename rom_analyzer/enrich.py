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


def enrich_reference_xml(
    xml_path: Path,
    flash_txt: Path,
    map_txt: Path | None = None,
) -> None:
    raise NotImplementedError  # implemented in Task 5


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
