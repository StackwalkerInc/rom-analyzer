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
_LD_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*(0x[0-9a-fA-F]+)\s*;")
_S_COMMENT_RE = re.compile(r"^\s*/\*(.+?)\*/\s*$")
_S_ADDR_RE = re.compile(r"^\s*([0-9a-fA-F]+):\s")
_ARG_REGS = ("R0", "R1", "R2", "R3")

# Higher rank wins when the same address is described by multiple sources.
# colt_flash/colt_map are curated tables; the .S decl comments are next; a
# bare description.ld assignment (no type) is the weakest.
_SOURCE_RANK = {"colt_flash": 3, "colt_map": 3, "colt_s": 2, "description_ld": 1}


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
        # The declaration is the next non-empty field after the fp-OFFSET
        # (RAddress) column. Some tables pad with an extra tab (fp-NNNN\t\tdecl),
        # so skip empty fields rather than blindly taking fields[i+1].
        decl = ""
        for i, f in enumerate(fields):
            if _FP_RE.match(f):
                for nxt in fields[i + 1:]:
                    if nxt:
                        decl = nxt
                        break
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


def parse_description_ld(path: Path) -> list[AnnotationSymbol]:
    """Parse a description.ld of 'name = 0xADDR;' assignments into symbols.

    Used for ROMs (e.g. CVT decodes) whose flash labels live in a linker
    fragment rather than a colt_flash table. No type info is available, so
    data_type is None. Address decides category against the flash/RAM boundary
    at 0x800000 (RAM start): < 0x800000 -> flash data (ROM images run up to
    0xC0000 on the larger parts), >= 0x800000 -> ram_global. Linker constructs
    (SECTIONS, etc.) don't match the assignment pattern and are ignored.
    """
    symbols: list[AnnotationSymbol] = []
    for line in path.read_text(errors="replace").splitlines():
        m = _LD_ASSIGN_RE.match(line)
        if not m:
            continue
        name, addr_s = m.group(1), m.group(2)
        addr = int(addr_s, 16)
        category = "data" if addr < 0x800000 else "ram_global"
        symbols.append(AnnotationSymbol(
            name=name, address=addr, category=category,
            data_type=None, confidence="high", source="description_ld",
        ))
    return symbols


def parse_annotated_s(path: Path) -> tuple[list[AnnotationSymbol], list[AnnotationFunction]]:
    """Parse an annotated objdump .S where each object is named by an own-line
    /* C-declaration */ comment immediately preceding its address line.

    Example:
        /*void rom_crc_check_step()*/
            5e224:  ...                 <- entry point
    For many ROMs (notably CVT decodes with no colt_flash table) the .S is the
    only source of function names. Declarations use the same grammar as
    colt_flash, so the same parsers apply. RAM globals never appear here (the
    disassembly is flash); addresses are raw flash offsets.
    """
    symbols: list[AnnotationSymbol] = []
    functions: list[AnnotationFunction] = []
    pending: str | None = None
    for line in path.read_text(errors="replace").splitlines():
        cm = _S_COMMENT_RE.match(line)
        if cm:
            pending = cm.group(1).strip()
            continue
        am = _S_ADDR_RE.match(line)
        if am and pending is not None:
            addr = int(am.group(1), 16)
            # Drop trailing " - note" annotations and a '^' "see-above" marker.
            decl = pending.split(" - ")[0].strip().rstrip("^").strip()
            if decl:
                if _is_function(decl):
                    parsed = _parse_function_decl(decl)
                    if parsed is not None:
                        name, return_type, params = parsed
                        functions.append(AnnotationFunction(
                            name=name, entry_point=addr, confidence="high",
                            source="colt_s", return_type=return_type, params=params,
                        ))
                else:
                    parsed_d = _parse_data_decl(decl)
                    if parsed_d is not None:
                        name, data_type = parsed_d
                        category = "data" if addr < 0x800000 else "ram_global"
                        symbols.append(AnnotationSymbol(
                            name=name, address=addr, category=category,
                            data_type=data_type, confidence="high", source="colt_s",
                        ))
        # Any non-comment line ends the one-line association window.
        pending = None
    return symbols, functions


def _dedup_symbols(symbols: list[AnnotationSymbol]) -> list[AnnotationSymbol]:
    """Keep one symbol per (address, category): higher source rank wins; a typed
    entry beats an untyped one of equal rank."""
    def better(new: AnnotationSymbol, old: AnnotationSymbol) -> bool:
        rn, ro = _SOURCE_RANK.get(new.source, 0), _SOURCE_RANK.get(old.source, 0)
        if rn != ro:
            return rn > ro
        return old.data_type is None and new.data_type is not None

    by_key: dict[tuple[int, str], AnnotationSymbol] = {}
    for s in symbols:
        key = (s.address, s.category)
        if key not in by_key or better(s, by_key[key]):
            by_key[key] = s
    return list(by_key.values())


def _dedup_functions(functions: list[AnnotationFunction]) -> list[AnnotationFunction]:
    """Keep one function per entry_point: higher source rank wins; a function
    carrying params beats one without at equal rank."""
    def better(new: AnnotationFunction, old: AnnotationFunction) -> bool:
        rn, ro = _SOURCE_RANK.get(new.source, 0), _SOURCE_RANK.get(old.source, 0)
        if rn != ro:
            return rn > ro
        return not old.params and bool(new.params)

    by_addr: dict[int, AnnotationFunction] = {}
    for f in functions:
        if f.entry_point not in by_addr or better(f, by_addr[f.entry_point]):
            by_addr[f.entry_point] = f
    return list(by_addr.values())


_SLOPPY_SOURCES = {"colt_s", "z27ag_s"}


def drop_imprecise_s_duplicates(store: AnnotationStore, tol: int = 4) -> int:
    """Remove .S-derived entries that merely duplicate a precise-source label.

    Objdump shows data at disassembly-line boundaries, so a /*name*/ comment for
    an object at a non-line-aligned address (e.g. flash_..._ac_off at 0x2d72)
    attaches to the next line (0x2d74), producing a spurious second entry a few
    bytes off the colt_flash/colt_map/xml address. When a .S (colt_s/z27ag_s)
    entry shares a name with a precise-source entry within `tol` bytes, drop the
    .S one — the precise source owns both the name and the exact address.
    Genuine same-name objects far apart (mirrored code, name reuse) are left for
    dedup_symbol_names to disambiguate. Returns the number removed.
    """
    from collections import defaultdict
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

    A function in erased flash is a typo: it matches no code block (e.g. a
    colt_flash can0_slot11_rx_update mistyped as 0x49ef0, which is 0xFF padding,
    vs the real 0x48ef0). Only functions are checked — data labels are NOT, since
    a real table can legitimately live in an erased/blank area (e.g.
    flash_specific_area_init_data). Returns the function names removed.
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

    Linker fragments share one symbol namespace, so two objects with the same
    name (at different addresses — e.g. a function mirrored across code regions,
    or a label repeated in colt_flash/.S) would emit a duplicate `name = addr;`
    and break the link. The lowest-address object keeps the canonical name;
    later collisions are suffixed with their address (name_<hexaddr>). Returns
    the number of objects renamed.
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


def build_store(flash_path: Path | None, map_path: Path | None,
                description_ld_path: Path | None, asm_path: Path | None,
                rom_id: str, rom_sha256: str,
                rom_bytes: bytes | None = None) -> AnnotationStore:
    symbols: list[AnnotationSymbol] = []
    functions: list[AnnotationFunction] = []
    if flash_path:
        data_syms, fns = parse_colt_flash(flash_path)
        symbols += data_syms
        functions += fns
    if map_path:
        symbols += parse_colt_map(map_path)
    if description_ld_path:
        symbols += parse_description_ld(description_ld_path)
    if asm_path:
        s_syms, s_fns = parse_annotated_s(asm_path)
        symbols += s_syms
        functions += s_fns

    store = AnnotationStore(
        schema_version=1,
        rom_id=rom_id,
        rom_sha256=rom_sha256,
        symbols=_dedup_symbols(symbols),
        functions=_dedup_functions(functions),
    )
    drop_imprecise_s_duplicates(store)
    if rom_bytes is not None:
        drop_erased_flash_entries(store, rom_bytes)
    dedup_symbol_names(store)
    return store


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--flash", type=Path, default=None, help="colt_flash.txt path")
    ap.add_argument("--map", type=Path, default=None,
                    help="colt_map.txt / singa_map.txt path (RAM globals)")
    ap.add_argument("--description-ld", type=Path, default=None,
                    help="description.ld of 'name = 0xADDR;' flash labels (CVT decodes)")
    ap.add_argument("--asm", type=Path, default=None,
                    help="annotated objdump .S (function/data names as /*decl*/ "
                         "comments preceding their address line)")
    ap.add_argument("--rom", type=Path, default=None,
                    help="ROM bin to hash for rom_sha256 (recommended)")
    ap.add_argument("--rom-id", required=True, help="ROM id, e.g. 47110032")
    ap.add_argument("--out", required=True, type=Path, help="output JSON path")
    args = ap.parse_args()

    if not (args.flash or args.map or args.description_ld or args.asm):
        ap.error("provide at least one of --flash / --map / --description-ld / --asm")

    rom_bytes = args.rom.read_bytes() if args.rom else None
    rom_sha256 = hashlib.sha256(rom_bytes).hexdigest() if rom_bytes else ""

    store = build_store(args.flash, args.map, args.description_ld, args.asm,
                        args.rom_id, rom_sha256, rom_bytes=rom_bytes)
    save_annotations(args.out, store)

    n_data = sum(1 for s in store.symbols if s.category == "data")
    n_ram = sum(1 for s in store.symbols if s.category == "ram_global")
    print(f"Wrote {args.out}: {len(store.functions)} functions, "
          f"{n_data} data, {n_ram} ram_global (sha256={rom_sha256[:12]}...)")


if __name__ == "__main__":
    main()
