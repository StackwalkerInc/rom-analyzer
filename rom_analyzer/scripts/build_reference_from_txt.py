"""Build a rom-analyzer reference annotation JSON from mmc-research text tables.

mmc-research ships, per ROM, two hand-curated symbol tables:

  colt_flash.txt  flash area (addr < 0x80000): data objects and functions,
                  one per line as "ADDR  SIZE  <C-declaration>  [notes]".
  colt_map.txt    RAM area (addr >= 0x800000): fp-relative globals, as
                  "ADDR  SIZE  fp-OFFSET  <C-declaration>  [notes]".

This script parses both into the same `AnnotationStore` schema that
`reference/<id>.json` uses (via annotations_io.save_annotations, so the output
is guaranteed schema-compatible with the rest of rom-analyzer).

Parsing rules:
  - A flash declaration with a top-level "(...)" is a FUNCTION (entry_point =
    address); otherwise it is a DATA object. RAM declarations are RAM globals.
  - Function declarations yield return_type (None when omitted) and positional
    params (storage R0..R3 then "stack"); param names come from the source when
    present, else p0, p1, ...
  - Data/RAM declarations yield a data_type built as "<base> [*]...[N]..."
    (e.g. "uint8_t[16]", "void *[476]"); name-only entries get data_type=None.
  - Lines that are section markers (/*...*/), headers, blank, "-"/"?" only, or
    address-only (no name) are skipped.

Usage:
  python -m rom_analyzer.scripts.build_reference_from_txt \
      --flash colt_flash.txt --map colt_map.txt \
      --rom 47110032.bin --rom-id 47110032 \
      --out reference/47110032.json
"""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

from rom_analyzer.annotations_io import (
    AnnotationFunction,
    AnnotationParam,
    AnnotationStore,
    AnnotationSymbol,
    save_annotations,
)

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]+$")
_FP_RE = re.compile(r"^fp[+-]\d+$")
_IDENT_RE = re.compile(r"^[A-Za-z_]\w*$")
_ARG_REGS = ("R0", "R1", "R2", "R3")


def _strip_comment(text: str) -> str:
    """Drop a trailing // comment, '?' uncertainty markers, and whitespace."""
    i = text.find("//")
    if i != -1:
        text = text[:i]
    return text.strip().strip("?").strip()


def _strip_initializer(decl: str) -> str:
    """Drop a ' = ...' initializer (keeps the declarator)."""
    i = decl.find(" = ")
    if i != -1:
        decl = decl[:i]
    return decl.strip()


def _split_declarator(token: str) -> tuple[int, list[int], str]:
    """Split a single declarator token into (pointer_count, array_dims, name).

    Examples: "*flash[476]" -> (1, [476], "flash"); "tbl[17][16]" -> (0,[17,16],"tbl").
    """
    nptr = 0
    while token.startswith("*"):
        nptr += 1
        token = token[1:]
    dims: list[int] = []
    for m in re.finditer(r"\[(\d+)\]", token):
        dims.append(int(m.group(1)))
    # Strip every "[...]" (numeric dims captured above; "[?]"/unknown dropped).
    name = re.sub(r"\[[^\]]*\]", "", token).strip()
    return nptr, dims, name


def _format_type(base_tokens: list[str], nptr: int, dims: list[int]) -> str | None:
    """Render a data_type string like 'void *[476]' or 'uint8_t[16]'."""
    base = " ".join(t for t in base_tokens if t not in ("struct", "union", "enum"))
    if not base:
        return None
    out = base
    if nptr:
        out += " " + "*" * nptr
    for d in dims:
        out += f"[{d}]"
    return out


def _parse_data_decl(decl: str) -> tuple[str, str | None] | None:
    """Parse a data/RAM C declaration -> (name, data_type) or None if no name."""
    decl = _strip_initializer(_strip_comment(decl)).rstrip(";").strip()
    if not decl or decl in ("-", "?"):
        return None

    # Anonymous struct/union with a brace body: name follows the closing brace.
    if "{" in decl:
        tail = decl[decl.rfind("}") + 1:].strip() if "}" in decl else ""
        if not tail:
            return None
        _, dims, name = _split_declarator(tail.split()[-1])
        return (name, None) if _IDENT_RE.match(name) else None

    tokens = decl.split()
    if len(tokens) == 1:
        # Name only, no type.
        _, _, name = _split_declarator(tokens[0])
        return (name, None) if _IDENT_RE.match(name) else None

    nptr, dims, name = _split_declarator(tokens[-1])
    if not _IDENT_RE.match(name):
        return None
    data_type = _format_type(tokens[:-1], nptr, dims)
    return name, data_type


def _split_args(arg_str: str) -> list[str]:
    """Split a parameter list on top-level commas (no nesting expected here)."""
    arg_str = arg_str.strip()
    if not arg_str or arg_str == "void":
        return []
    return [a.strip() for a in arg_str.split(",") if a.strip()]


def _parse_arg(arg: str, index: int) -> AnnotationParam:
    """Parse one parameter declaration into an AnnotationParam."""
    storage = _ARG_REGS[index] if index < len(_ARG_REGS) else "stack"
    tokens = arg.split()
    if len(tokens) == 1:
        # Type only, no parameter name.
        nptr, _, _ = _split_declarator(tokens[0])
        base = re.sub(r"\*", "", tokens[0]).strip()
        ptype = base + (" " + "*" * nptr if nptr else "")
        return AnnotationParam(name=f"p{index}", storage=storage, type=ptype)
    nptr, _, name = _split_declarator(tokens[-1])
    base_tokens = [t for t in tokens[:-1] if t not in ("struct", "union", "enum")]
    ptype = " ".join(base_tokens)
    if nptr:
        ptype += " " + "*" * nptr
    if not name:
        name = f"p{index}"
    return AnnotationParam(name=name, storage=storage, type=ptype)


def _parse_function_decl(decl: str) -> tuple[str, str | None, list[AnnotationParam]] | None:
    """Parse 'ret name(args)' -> (name, return_type, params) or None."""
    decl = _strip_initializer(_strip_comment(decl)).rstrip(";").strip()
    open_i = decl.find("(")
    close_i = decl.rfind(")")
    if open_i == -1 or close_i == -1 or close_i < open_i:
        return None
    head = decl[:open_i].strip()
    args = decl[open_i + 1:close_i]
    if not head:
        return None
    head_tokens = head.split()
    nptr, _, name = _split_declarator(head_tokens[-1])
    if not _IDENT_RE.match(name):
        return None
    ret_tokens = [t for t in head_tokens[:-1] if t not in ("struct", "union", "enum")]
    return_type = " ".join(ret_tokens) if ret_tokens else None
    if return_type and nptr:
        return_type += " " + "*" * nptr
    elif nptr and not return_type:
        return_type = "*" * nptr  # unusual; keep the stars rather than lose them
    params = [_parse_arg(a, i) for i, a in enumerate(_split_args(args))]
    return name, return_type, params


def _is_function(decl: str) -> bool:
    """A flash declaration is a function iff it ends in a (...) call signature."""
    d = _strip_initializer(_strip_comment(decl)).rstrip(";").strip()
    return d.endswith(")") and "(" in d


def parse_colt_flash(path: Path) -> tuple[list[AnnotationSymbol], list[AnnotationFunction]]:
    """Parse colt_flash.txt into (data symbols, functions)."""
    symbols: list[AnnotationSymbol] = []
    functions: list[AnnotationFunction] = []
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip() or line.lstrip().startswith("/*"):
            continue
        fields = line.split("\t")
        if not _ADDR_RE.match(fields[0].strip()):
            continue
        addr = int(fields[0].strip(), 16)
        # The declaration is the first non-empty field after addr+size that is
        # not a bare '-'/size; take field index 2 (Name column) when present.
        decl = fields[2].strip() if len(fields) > 2 else ""
        if not decl or decl in ("-", "?") or decl.startswith("**"):
            continue
        if _is_function(decl):
            parsed = _parse_function_decl(decl)
            if parsed is None:
                continue
            name, return_type, params = parsed
            functions.append(AnnotationFunction(
                name=name, entry_point=addr, confidence="high",
                source="colt_flash", return_type=return_type, params=params,
            ))
        else:
            parsed_d = _parse_data_decl(decl)
            if parsed_d is None:
                continue
            name, data_type = parsed_d
            symbols.append(AnnotationSymbol(
                name=name, address=addr, category="data",
                data_type=data_type, confidence="high", source="colt_flash",
            ))
    return symbols, functions


def parse_colt_map(path: Path) -> list[AnnotationSymbol]:
    """Parse colt_map.txt RAM globals into AnnotationSymbols."""
    symbols: list[AnnotationSymbol] = []
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = [f.strip() for f in line.split("\t")]
        if not _ADDR_RE.match(fields[0]):
            continue
        addr = int(fields[0], 16)
        # The declaration is the field after the fp-OFFSET (RAddress) column.
        decl = ""
        for i, f in enumerate(fields):
            if _FP_RE.match(f) and i + 1 < len(fields):
                decl = fields[i + 1].strip()
                break
        if not decl or decl in ("-", "?"):
            continue
        parsed = _parse_data_decl(decl)
        if parsed is None:
            continue
        name, data_type = parsed
        symbols.append(AnnotationSymbol(
            name=name, address=addr, category="ram_global",
            data_type=data_type, confidence="high", source="colt_map",
        ))
    return symbols


def build_store(flash_path: Path, map_path: Path, rom_id: str,
                rom_sha256: str) -> AnnotationStore:
    data_syms, functions = parse_colt_flash(flash_path)
    ram_syms = parse_colt_map(map_path) if map_path else []
    return AnnotationStore(
        schema_version=1,
        rom_id=rom_id,
        rom_sha256=rom_sha256,
        symbols=data_syms + ram_syms,
        functions=functions,
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--flash", required=True, type=Path, help="colt_flash.txt path")
    ap.add_argument("--map", type=Path, default=None, help="colt_map.txt path (RAM)")
    ap.add_argument("--rom", type=Path, default=None,
                    help="ROM bin to hash for rom_sha256 (recommended)")
    ap.add_argument("--rom-id", required=True, help="ROM id, e.g. 47110032")
    ap.add_argument("--out", required=True, type=Path, help="output JSON path")
    args = ap.parse_args()

    rom_sha256 = ""
    if args.rom:
        rom_sha256 = hashlib.sha256(args.rom.read_bytes()).hexdigest()

    store = build_store(args.flash, args.map, args.rom_id, rom_sha256)
    save_annotations(args.out, store)

    n_data = sum(1 for s in store.symbols if s.category == "data")
    n_ram = sum(1 for s in store.symbols if s.category == "ram_global")
    print(f"Wrote {args.out}: {len(store.functions)} functions, "
          f"{n_data} data, {n_ram} ram_global (sha256={rom_sha256[:12]}...)")


if __name__ == "__main__":
    main()
