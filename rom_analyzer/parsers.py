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
