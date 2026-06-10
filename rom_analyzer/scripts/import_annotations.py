# @category ROM-Analyzer
# @menupath ROM-Analyzer.Import annotations.json
#
# Ghidra script: apply an annotations.json file to the currently open program.
# Run via Script Manager (interactive) or:
#   analyzeHeadless ... -scriptPath rom_analyzer/scripts -postScript import_annotations.py \
#       <annotations_path>

import json
import os
import re
import sys

# Make rom_analyzer importable from Script Manager
_pkg_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

# ---------------------------------------------------------------------------
# Ghidra Java imports — only available inside a Ghidra process
# ---------------------------------------------------------------------------
from ghidra.program.model.data import (  # type: ignore[import]
    ArrayDataType, ByteDataType, DataUtilities, DWordDataType,
    PointerDataType, StructureDataType, WordDataType,
)
from ghidra.program.model.listing import CodeUnit  # type: ignore[import]
from ghidra.program.model.symbol import SourceType  # type: ignore[import]
from ghidra.program.flatapi import FlatProgramAPI  # type: ignore[import]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_COMMENT_TYPE_MAP = {
    "end-of-line": CodeUnit.EOL_COMMENT,
    "pre": CodeUnit.PRE_COMMENT,
    "post": CodeUnit.POST_COMMENT,
    "plate": CodeUnit.PLATE_COMMENT,
    "repeatable": CodeUnit.REPEATABLE_COMMENT,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_datatype(type_str):
    s = type_str.strip()
    m = re.fullmatch(r'(byte|uint8_t)\[(\d+)\]', s)
    if m:
        return ArrayDataType(ByteDataType(), int(m.group(2)), 1)
    m = re.fullmatch(r'(uint16_t|word)\[(\d+)\]', s)
    if m:
        return ArrayDataType(WordDataType(), int(m.group(2)), 2)
    m = re.fullmatch(r'(uint32_t|dword)\[(\d+)\]', s)
    if m:
        return ArrayDataType(DWordDataType(), int(m.group(2)), 4)
    scalar = {
        'byte': ByteDataType(), 'uint8_t': ByteDataType(),
        'uint16_t': WordDataType(), 'word': WordDataType(),
        'uint32_t': DWordDataType(), 'dword': DWordDataType(),
        'pointer': PointerDataType(), 'pointer32': PointerDataType(),
        'undefined *': PointerDataType(),
    }
    return scalar.get(s)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # --- Script args ---
    script_args = getScriptArgs()  # type: ignore[name-defined]

    if len(script_args) >= 1:
        annotations_path = script_args[0]
    else:
        f = askFile("Select annotations.json", "Select")  # type: ignore[name-defined]
        annotations_path = str(f)

    # --- Load JSON ---
    with open(annotations_path, "r") as fh:
        data = json.load(fh)

    program = currentProgram  # type: ignore[name-defined]
    flat = FlatProgramAPI(program)
    dtm = program.getDataTypeManager()
    listing = program.getListing()

    count = 0

    tx_id = program.startTransaction("Import annotations")
    try:
        # --- Register struct definitions ---
        for sd in data.get("struct_definitions", []):
            struct = StructureDataType(sd["name"], sd.get("size", 0))
            for m in sd.get("members", []):
                member_dt = _resolve_datatype(m["type"])
                if member_dt is not None:
                    try:
                        struct.replaceAtOffset(
                            m["offset"], member_dt, member_dt.getLength(), m["name"], ""
                        )
                    except Exception:
                        pass
            try:
                dtm.addDataType(struct, None)
                count += 1
            except Exception:
                pass

        # --- Apply symbols ---
        for sym in data.get("symbols", []):
            try:
                addr = flat.toAddr(int(sym["address"], 16))
                if addr is None:
                    continue
                try:
                    flat.createLabel(addr, sym["name"], True, SourceType.USER_DEFINED)
                    count += 1
                except Exception:
                    pass
                dt_str = sym.get("data_type")
                if dt_str:
                    dt = _resolve_datatype(dt_str)
                    if dt is not None:
                        try:
                            DataUtilities.createData(
                                program, addr, dt, -1,
                                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
                            )
                        except Exception:
                            pass
            except Exception:
                pass

        # --- Apply functions ---
        # return_type and params are stored but not applied — function signatures
        # require ParameterImpl + Function.updateFunction(), deferred.
        for fn in data.get("functions", []):
            try:
                addr = flat.toAddr(int(fn["entry_point"], 16))
                if addr is None:
                    continue
                try:
                    flat.createLabel(addr, fn["name"], True, SourceType.USER_DEFINED)
                    count += 1
                except Exception:
                    pass
                try:
                    flat.createFunction(addr, fn["name"])
                except Exception:
                    pass
            except Exception:
                pass

        # --- Apply comments ---
        for cmt in data.get("comments", []):
            try:
                addr = flat.toAddr(int(cmt["address"], 16))
                if addr is None:
                    continue
                ghidra_type = _COMMENT_TYPE_MAP.get(cmt.get("type", ""))
                if ghidra_type is None:
                    continue
                try:
                    listing.setComment(addr, ghidra_type, cmt["text"])
                    count += 1
                except Exception:
                    pass
            except Exception:
                pass

    finally:
        program.endTransaction(tx_id, True)

    print("Applied %d annotations from %s" % (count, annotations_path))


# Ghidra scripts run at top level (not under __main__)
main()
