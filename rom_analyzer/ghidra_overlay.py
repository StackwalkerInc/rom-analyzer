"""Shared Ghidra overlay logic for applying AnnotationStore to a Ghidra program.

All Ghidra Java imports are deferred to function bodies so this module is
importable in non-Ghidra environments (unit tests, CI).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rom_analyzer.annotations_io import AnnotationFunction, AnnotationStore


# ---------------------------------------------------------------------------
# Type-string parser — pure Python, unit-testable without Ghidra
# ---------------------------------------------------------------------------

@dataclass
class _ParsedType:
    base: str
    pointer_depth: int = 0
    array_dims: list[int] = dc_field(default_factory=list)
    is_struct: bool = False


_SCALAR_ALIASES: dict[str, tuple[str, int]] = {
    # (canonical_base, extra_pointer_depth)
    "g8_t":      ("uint8_t", 0),
    "int8_t":    ("uint8_t", 0),
    "pointer":   ("void",    1),   # bare "pointer" keyword → void *
}

_KNOWN_SCALARS = frozenset({
    "void", "int", "unsigned", "uint8_t", "uint16_t", "uint32_t",
})


def _parse_type_str(type_str: str) -> _ParsedType | None:
    """Parse a C type string into a _ParsedType descriptor.

    Handles: const stripping, pointer depth (one or two levels), 1D/2D arrays,
    struct prefix, known scalar aliases, and the special keywords 'pointer' and
    'undefined *'.  Returns None only for empty / whitespace-only input.
    Unknown base names are passed through so _resolve_type can attempt a struct
    lookup and return None if absent.
    """
    s = type_str.strip()
    if not s:
        return None

    # Special keyword: bare "pointer" → void *
    if s == "pointer":
        return _ParsedType("void", pointer_depth=1)

    # Strip leading const
    if s.startswith("const "):
        s = s[6:].strip()

    # Strip trailing array dimensions (right to left: outermost first)
    array_dims: list[int] = []
    while True:
        m = re.search(r'\[(\d+)\]$', s)
        if m:
            array_dims.insert(0, int(m.group(1)))
            s = s[: m.start()].strip()
        else:
            break

    # Count trailing pointer stars (after array dims are stripped)
    pointer_depth = 0
    while s.endswith(" *"):
        s = s[:-2].strip()
        pointer_depth += 1

    # "undefined *" becomes void * — pointer_depth already captured the star(s)
    if s == "undefined":
        return _ParsedType("void", pointer_depth=pointer_depth,
                           array_dims=array_dims)

    # Strip struct prefix
    is_struct = False
    if s.startswith("struct "):
        s = s[7:].strip()
        is_struct = True

    # Apply scalar aliases
    if not is_struct and s in _SCALAR_ALIASES:
        canonical, extra_depth = _SCALAR_ALIASES[s]
        return _ParsedType(canonical, pointer_depth=pointer_depth + extra_depth,
                           array_dims=array_dims)

    return _ParsedType(s, pointer_depth=pointer_depth,
                       array_dims=array_dims, is_struct=is_struct)


# ---------------------------------------------------------------------------
# Ghidra type resolver
# ---------------------------------------------------------------------------

def _resolve_type(type_str: str, program) -> object | None:
    """Map a type string to a Ghidra DataType. Returns None if unresolvable."""
    from ghidra.program.model.data import (  # type: ignore[import]
        ArrayDataType, ByteDataType, DWordDataType, IntegerDataType,
        PointerDataType, UnsignedIntegerDataType, VoidDataType, WordDataType,
    )

    parsed = _parse_type_str(type_str)
    if parsed is None:
        return None

    _scalar_map = {
        "void":     VoidDataType.dataType,
        "int":      IntegerDataType.dataType,
        "unsigned": UnsignedIntegerDataType.dataType,
        "uint8_t":  ByteDataType.dataType,
        "uint16_t": WordDataType.dataType,
        "uint32_t": DWordDataType.dataType,
    }

    if parsed.base in _scalar_map:
        dt = _scalar_map[parsed.base]
    else:
        # Struct or unknown bare name — try DataTypeManager lookup
        dtm = program.getDataTypeManager()
        dt = dtm.getDataType("/" + parsed.base)
        if dt is None:
            return None

    # Apply pointer wrapping (innermost first)
    for _ in range(parsed.pointer_depth):
        dt = PointerDataType(dt, 4)

    # Apply array wrapping (innermost dimension last in array_dims list)
    for dim in reversed(parsed.array_dims):
        elem_size = dt.getLength()
        dt = ArrayDataType(dt, dim, elem_size)

    return dt


# ---------------------------------------------------------------------------
# Struct type registration
# ---------------------------------------------------------------------------

def _create_struct_types(program, store: "AnnotationStore") -> None:
    """Register struct_definitions from the store in the program's DataTypeManager.

    Skips any struct whose name already exists in the type manager (preserves
    richer user-defined versions).
    """
    from ghidra.program.model.data import (  # type: ignore[import]
        DataTypeConflictHandler, StructureDataType,
    )

    dtm = program.getDataTypeManager()
    for sd in store.struct_definitions:
        if dtm.getDataType("/" + sd.name) is not None:
            continue
        struct = StructureDataType(sd.name, sd.size)
        for m in sd.members:
            dt = _resolve_type(m.type, program)
            if dt is not None:
                try:
                    struct.replaceAtOffset(m.offset, dt, dt.getLength(), m.name, "")
                except Exception:
                    pass
        dtm.addDataType(struct, DataTypeConflictHandler.KEEP_HANDLER)


# ---------------------------------------------------------------------------
# Register storage helper
# ---------------------------------------------------------------------------

def _register_storage(program, reg_name: str, stack_offset: int = 0,
                      dt_size: int = 4) -> object | None:
    """Map a register name or "stack" to a Ghidra VariableStorage.

    For stack parameters pass the current stack_offset (starts at 0 for the
    first stack arg) and the actual data-type size in bytes.
    """
    from ghidra.program.model.listing import VariableStorage  # type: ignore[import]

    if reg_name == "stack":
        try:
            return VariableStorage(program, stack_offset, dt_size)
        except Exception as e:
            print(f"    [warn] stack VariableStorage(offset={stack_offset}, size={dt_size}): {e}")
            return None
    reg = program.getLanguage().getRegister(reg_name)
    if reg is None:
        print(f"    [warn] register not found: {reg_name}")
        return None
    try:
        # VariableStorage(ProgramArchitecture, Register[]) — Program implements ProgramArchitecture
        return VariableStorage(program, [reg])
    except Exception as e:
        print(f"    [warn] register VariableStorage({reg_name}): {e}")
        return None


# ---------------------------------------------------------------------------
# Function signature application
# ---------------------------------------------------------------------------

def _apply_function_signature(
    program, func_obj, fn: "AnnotationFunction"
) -> None:
    """Set return type and parameters on an existing Ghidra Function object."""
    from ghidra.program.model.listing import Function, ParameterImpl  # type: ignore[import]
    from ghidra.program.model.symbol import SourceType  # type: ignore[import]

    if fn.return_type:
        dt = _resolve_type(fn.return_type, program)
        if dt is not None:
            try:
                func_obj.setReturnType(dt, SourceType.IMPORTED)
            except Exception as e:
                print(f"    [warn] setReturnType for {fn.name}: {e}")

    if not fn.params:
        return

    params = []
    stack_offset = 0
    for p in fn.params:
        dt = _resolve_type(p.type, program)
        if dt is None:
            continue
        dt_size = dt.getLength()
        storage = _register_storage(program, p.storage, stack_offset, dt_size)
        if p.storage == "stack":
            # M32R ABI pads each stack arg to a 4-byte slot
            stack_offset += max(4, (dt_size + 3) & ~3)
        try:
            if storage is not None:
                params.append(ParameterImpl(p.name, dt, storage, program))
            else:
                params.append(ParameterImpl(p.name, dt, program))
        except Exception as e:
            print(f"    [warn] ParameterImpl({p.name}, {p.type}, {p.storage}): {e}")

    if params:
        try:
            from java.util import ArrayList  # type: ignore[import]
            java_params = ArrayList()
            for p in params:
                java_params.add(p)
            func_obj.replaceParameters(
                java_params,
                Function.FunctionUpdateType.CUSTOM_STORAGE,
                True,
                SourceType.IMPORTED,
            )
        except Exception as e:
            print(f"    [warn] replaceParameters for {fn.name}: {e}")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def apply_annotations(program, store: "AnnotationStore") -> None:
    """Apply a full AnnotationStore to an open Ghidra program.

    Must be called inside an active Ghidra transaction.
    Applies in order: struct type definitions, symbol labels + data types,
    function labels + signatures, comments.
    """
    from ghidra.program.model.data import DataUtilities  # type: ignore[import]
    from ghidra.program.model.listing import CodeUnit  # type: ignore[import]
    from ghidra.program.model.symbol import SourceType  # type: ignore[import]
    from ghidra.program.flatapi import FlatProgramAPI  # type: ignore[import]

    flat = FlatProgramAPI(program)
    listing = program.getListing()
    func_mgr = program.getFunctionManager()

    _create_struct_types(program, store)

    for s in store.symbols:
        addr = flat.toAddr(s.address)
        if addr is None:
            continue
        try:
            flat.createLabel(addr, s.name, True, SourceType.IMPORTED)
        except Exception:
            pass
        if s.data_type is not None:
            dt = _resolve_type(s.data_type, program)
            if dt is not None:
                try:
                    DataUtilities.createData(
                        program, addr, dt, -1,
                        DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
                    )
                except Exception:
                    pass

    for f in store.functions:
        addr = flat.toAddr(f.entry_point)
        if addr is None:
            continue
        try:
            flat.createLabel(addr, f.name, True, SourceType.IMPORTED)
        except Exception:
            pass
        func_obj = func_mgr.getFunctionAt(addr)
        if func_obj is None:
            try:
                func_obj = flat.createFunction(addr, f.name)
            except Exception:
                pass
        if func_obj is not None:
            _apply_function_signature(program, func_obj, f)

    _COMMENT_TYPE_MAP = {
        "end-of-line": CodeUnit.EOL_COMMENT,
        "pre":         CodeUnit.PRE_COMMENT,
        "post":        CodeUnit.POST_COMMENT,
        "plate":       CodeUnit.PLATE_COMMENT,
        "repeatable":  CodeUnit.REPEATABLE_COMMENT,
    }
    for c in store.comments:
        addr = flat.toAddr(c.address)
        if addr is None:
            continue
        ghidra_type = _COMMENT_TYPE_MAP.get(c.type)
        if ghidra_type is None:
            continue
        try:
            listing.setComment(addr, ghidra_type, c.text)
        except Exception:
            pass
