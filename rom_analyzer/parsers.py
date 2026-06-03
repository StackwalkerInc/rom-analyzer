"""Parsers for colt_flash.txt and colt_map.txt symbol tables."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class FlashEntry:
    """A parsed entry from colt_flash.txt."""
    address: int
    size: int
    name: str
    is_function: bool
    raw_declaration: str


@dataclass(frozen=True)
class MapEntry:
    """A parsed entry from colt_map.txt."""
    address: int
    size: int
    fp_offset: int
    name: str
    is_function: bool
    raw_declaration: str


@dataclass(frozen=True)
class Param:
    type_str: str  # raw C type: "uint16_t", "uint8_t *", "struct foo *"
    name: str


@dataclass(frozen=True)
class ParsedSignature:
    return_type: str      # raw return type: "uint16_t", "void", "uint8_t *"
    name: str
    params: list[Param]   # [] for void / no-arg functions


def parse_colt_flash(path: Path) -> Iterable[FlashEntry]:
    """
    Parse colt_flash.txt symbol table.

    Format: address (hex) | size (hex or decimal) | declaration (with optional // comments)

    Yields:
        FlashEntry for each valid (non-comment, non-empty) line.
    """
    with open(path, "r") as f:
        for line in f:
            line = line.rstrip("\n\r")

            # Skip empty lines
            if not line.strip():
                continue

            # Skip comment-only lines
            if line.lstrip().startswith("#") or line.lstrip().startswith("/*"):
                continue

            # Must start with 0x
            if not line.lstrip().startswith("0x"):
                continue

            # Parse: ^(0x[hex]+)\s+(0x[hex]+|\d+)\s+(.+)$
            match = re.match(r"^(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+|\d+)\s+(.+)$", line)
            if not match:
                continue

            address_str, size_str, declaration = match.groups()
            address = int(address_str, 16)
            size = int(size_str, 16) if size_str.startswith("0x") else int(size_str)

            # Strip inline // comments
            if "//" in declaration:
                declaration = declaration.split("//")[0]
            declaration = declaration.strip()

            name_match = re.search(r"([a-zA-Z_][\w.]*)\s*(?:\[|\(|;|=)", declaration)
            if not name_match:
                continue

            name = name_match.group(1)

            is_function = bool(re.match(r"^[a-zA-Z_][\w\s\*]*?\s+\*?\s*([a-zA-Z_]\w*)\s*\(", declaration))

            yield FlashEntry(
                address=address,
                size=size,
                name=name,
                is_function=is_function,
                raw_declaration=declaration,
            )


def parse_colt_map(path: Path) -> Iterable[MapEntry]:
    """
    Parse colt_map.txt symbol table.

    Format: address (hex) | size (hex or decimal) | fp_offset (fp±N) | declaration (with optional // comments)

    Yields:
        MapEntry for each valid (non-comment, non-empty) line.
    """
    with open(path, "r") as f:
        for line in f:
            line = line.rstrip("\n\r")

            # Skip empty lines
            if not line.strip():
                continue

            # Skip comment-only lines
            if line.lstrip().startswith("#") or line.lstrip().startswith("/*"):
                continue

            # Must start with 0x
            if not line.lstrip().startswith("0x"):
                continue

            # Parse: ^(0x[hex]+)\s+(0x[hex]+|\d+)\s+(fp[+-]?\d+)\s+(.+)$
            match = re.match(r"^(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+|\d+)\s+(fp[+-]?\d+)\s+(.+)$", line)
            if not match:
                continue

            address_str, size_str, fp_offset_str, declaration = match.groups()
            address = int(address_str, 16)
            size = int(size_str, 16) if size_str.startswith("0x") else int(size_str)

            fp_match = re.match(r"fp([+-]?\d+)", fp_offset_str)
            fp_offset = int(fp_match.group(1))

            # Strip inline // comments
            if "//" in declaration:
                declaration = declaration.split("//")[0]
            declaration = declaration.strip()

            name_match = re.search(r"([a-zA-Z_][\w.]*)\s*(?:\[|\(|;|=)", declaration)
            if not name_match:
                continue

            name = name_match.group(1)

            is_function = bool(re.match(r"^[a-zA-Z_][\w\s\*]*?\s+\*?\s*([a-zA-Z_]\w*)\s*\(", declaration))

            yield MapEntry(
                address=address,
                size=size,
                fp_offset=fp_offset,
                name=name,
                is_function=is_function,
                raw_declaration=declaration,
            )


def parse_function_signature(decl: str) -> ParsedSignature | None:
    """Parse a C function declaration into return type, name, and parameter list.

    Input must have // comments already stripped (raw_declaration from FlashEntry).
    Returns None for data declarations (array, variable, struct initializer).
    """
    decl = decl.rstrip(";").strip()

    paren_open = decl.find("(")
    if paren_open == -1:
        return None

    before_paren = decl[:paren_open].strip()

    paren_close = decl.rfind(")")
    if paren_close <= paren_open:
        return None

    params_str = decl[paren_open + 1 : paren_close].strip()

    # Last token (optionally prefixed with *) is the function name.
    # Examples: "uint16_t ps16_divu32_16" → name="ps16_divu32_16", return="uint16_t"
    #           "uint8_t *get_mut_pointer" → name="get_mut_pointer", return="uint8_t *"
    name_match = re.search(r"(\*\s*)?([a-zA-Z_]\w*)\s*$", before_paren)
    if not name_match:
        return None

    name = name_match.group(2)
    has_ptr_prefix = bool(name_match.group(1))
    base_return = before_paren[: name_match.start()].strip()
    return_type = (base_return + " *").strip() if has_ptr_prefix else base_return

    if not return_type:
        return None

    if not params_str or params_str == "void":
        params: list[Param] = []
    else:
        params = []
        for chunk in _split_params(params_str):
            chunk = chunk.strip()
            if not chunk:
                continue
            if chunk == "...":
                break  # stop at varargs; named params before ... still get REGISTER_VAR
            param = _parse_param(chunk)
            if param is not None:
                params.append(param)

    return ParsedSignature(return_type=return_type, name=name, params=params)


def _split_params(params_str: str) -> list[str]:
    """Split a parameter list on top-level commas (not inside nested parens)."""
    result: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in params_str:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            result.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        result.append("".join(current))
    return result


def _parse_param(chunk: str) -> Param | None:
    """Parse one parameter chunk (e.g. 'uint16_t *result') into Param."""
    chunk = chunk.strip()
    if not chunk:
        return None
    name_match = re.search(r"(\*\s*)?([a-zA-Z_]\w*)\s*$", chunk)
    if not name_match:
        return None
    param_name = name_match.group(2)
    has_ptr = bool(name_match.group(1))
    base_type = chunk[: name_match.start()].strip()
    param_type = (base_type + " *").strip() if has_ptr else base_type
    if not param_type:
        return None
    return Param(type_str=param_type, name=param_name)
