# @category ROM-Analyzer
# @menupath ROM-Analyzer.Export annotations.json
#
# Ghidra script: export user-defined symbols, functions, and comments to annotations.json.
# Run via Script Manager (interactive) or:
#   analyzeHeadless ... -scriptPath rom_analyzer/scripts -postScript export_annotations.py \
#       <annotations_path> [session_label] [user]

import json
import os
import sys
from datetime import datetime, timezone

# Make rom_analyzer importable from Script Manager
_pkg_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

# ---------------------------------------------------------------------------
# Ghidra Java imports — only available inside a Ghidra process
# ---------------------------------------------------------------------------
from ghidra.program.model.listing import CodeUnit  # type: ignore[import]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_SKIP_SOURCES = {"DEFAULT", "IMPORTED", "ANALYSIS"}

_COMMENT_TYPES = {
    CodeUnit.EOL_COMMENT: "end-of-line",
    CodeUnit.PRE_COMMENT: "pre",
    CodeUnit.POST_COMMENT: "post",
    CodeUnit.PLATE_COMMENT: "plate",
    CodeUnit.REPEATABLE_COMMENT: "repeatable",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hex_addr(addr):
    return "0x%x" % addr.getOffset()


def _provenance(user, session, ts):
    return {
        "confidence": "verified",
        "source": "ghidra",
        "verified_by": user,
        "session": session,
        "timestamp": ts,
    }


def _load_existing(path):
    """Load existing annotations.json, returning (data_dict | None)."""
    try:
        with open(path, "r") as fh:
            return json.load(fh)
    except (IOError, OSError, ValueError):
        return None


def _write_atomic(path, data):
    """Write data dict to path atomically via a .tmp file."""
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Symbol / function extraction
# ---------------------------------------------------------------------------

def _extract_params(func):
    """Return a list of param dicts (empty list if none)."""
    params = []
    for p in func.getParameters():
        reg = p.getRegister()
        if reg is not None:
            storage = reg.getName()
        else:
            try:
                storage = "stack+%d" % p.getStackOffset()
            except Exception:
                storage = "stack"
        params.append({
            "name": p.getName(),
            "storage": storage,
            "type": str(p.getDataType().getName()),
        })
    return params


def _collect_symbols_and_functions(program):
    """
    Return (symbols_dict, functions_dict) keyed by hex-address string.
    Each value is a raw dict ready for merge/write.
    """
    symbol_table = program.getSymbolTable()
    func_mgr = program.getFunctionManager()

    symbols = {}   # key: "0xADDR"
    functions = {} # key: "0xADDR"

    for sym in symbol_table.getAllSymbols(True):
        src = str(sym.getSource())
        if src in _SKIP_SOURCES:
            continue

        addr = sym.getAddress()
        if addr is None:
            continue

        offset = addr.getOffset()
        hex_addr = "0x%x" % offset
        name = sym.getName()

        func = func_mgr.getFunctionAt(addr)
        if func is not None:
            # Build function entry (provenance filled in later during merge)
            entry = {
                "name": name,
                "entry_point": hex_addr,
            }
            ret_type = func.getReturnType().getName()
            if not (ret_type == "void" or ret_type.startswith("undefined")):
                entry["return_type"] = ret_type
            params = _extract_params(func)
            if params:
                entry["params"] = params
            functions[hex_addr] = entry
        else:
            category = "ram_global" if offset >= 0x800000 else "data"
            symbols[hex_addr] = {
                "name": name,
                "address": hex_addr,
                "category": category,
            }

    return symbols, functions


# ---------------------------------------------------------------------------
# Comment extraction
# ---------------------------------------------------------------------------

def _collect_comments(program):
    """
    Return dict keyed by (hex_addr, type_str) → {"address":…, "type":…, "text":…}.
    Uses getCommentAddressIterator so only addresses with comments are visited.
    """
    listing = program.getListing()
    comments = {}

    addr_set = program.getMemory().getLoadedAndInitializedAddressSet()
    for addr in listing.getCommentAddressIterator(addr_set, True):
        for type_int, type_str in _COMMENT_TYPES.items():
            text = listing.getComment(addr, type_int)
            if text:
                key = ("0x%x" % addr.getOffset(), type_str)
                comments[key] = {
                    "address": "0x%x" % addr.getOffset(),
                    "type": type_str,
                    "text": text,
                }

    return comments


# ---------------------------------------------------------------------------
# Merge helpers
# ---------------------------------------------------------------------------

def _merge_entry(key_label, new_entry, existing_by_key, prov, interactive):
    """
    Merge one new entry into existing_by_key (mutated in place).
    key_label: a string identifying the entry (for askYesNo).
    new_entry: dict with content fields (no provenance yet).
    Returns the final entry dict.
    """
    existing = existing_by_key.get(key_label)

    if existing is None:
        # New entry — add with verified provenance
        result = dict(new_entry)
        result.update(prov)
        existing_by_key[key_label] = result
        return result, "added"

    if existing.get("confidence") != "verified":
        # Overwrite non-verified entry
        result = dict(new_entry)
        result.update(prov)
        existing_by_key[key_label] = result
        return result, "overwritten"

    # Both are verified — compare value fields (excluding provenance keys)
    _prov_keys = {"confidence", "source", "verified_by", "session", "timestamp"}
    old_vals = {k: v for k, v in existing.items() if k not in _prov_keys}
    new_vals = {k: v for k, v in new_entry.items() if k not in _prov_keys}

    if old_vals == new_vals:
        # Unchanged — preserve as-is (no provenance bump)
        return existing, "unchanged"

    # Conflict: ask user
    if interactive:
        try:
            title = "annotations.json conflict"
            message = (
                "Entry '%s' already verified with different value.\n"
                "Old: %s\nNew: %s\nReplace?" % (key_label, json.dumps(old_vals), json.dumps(new_vals))
            )
            replace = askYesNo(title, message)  # type: ignore[name-defined]
        except Exception:
            replace = False
    else:
        # Headless: keep existing to be safe
        replace = False

    if replace:
        result = dict(new_entry)
        result.update(prov)
        existing_by_key[key_label] = result
        return result, "replaced"
    else:
        return existing, "kept"


def _merge_comment(key, new_comment, existing_comments, prov):
    """Merge one comment entry. key is (hex_addr, type_str)."""
    existing = existing_comments.get(key)

    if existing is None:
        result = dict(new_comment)
        result.update({
            "verified_by": prov["verified_by"],
            "session": prov["session"],
            "timestamp": prov["timestamp"],
        })
        existing_comments[key] = result
        return result, "added"

    if existing.get("text") == new_comment["text"]:
        # Unchanged — preserve as-is (no provenance bump)
        return existing, "unchanged"

    # Text changed — always overwrite (spec: "new or changed text overwrites")
    result = dict(new_comment)
    result.update({
        "verified_by": prov["verified_by"],
        "session": prov["session"],
        "timestamp": prov["timestamp"],
    })
    existing_comments[key] = result
    return result, "replaced"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # --- Script args ---
    script_args = getScriptArgs()  # type: ignore[name-defined]

    if len(script_args) >= 1:
        annotations_path = script_args[0]
    else:
        # Interactive: ask for file
        f = askFile("Select annotations.json", "Select")  # type: ignore[name-defined]
        annotations_path = str(f)

    program = getCurrentProgram()  # type: ignore[name-defined]
    rom_id = program.getName().split("-")[0]

    _now = datetime.now(timezone.utc)
    ts = _now.strftime("%Y-%m-%dT%H:%M:%SZ")
    compact = _now.strftime("%Y%m%dT%H%M%SZ")

    if len(script_args) >= 2:
        session = script_args[1]
    else:
        session = "%s-manual-%s" % (rom_id, compact)

    if len(script_args) >= 3:
        user = script_args[2]
    else:
        try:
            from java.lang import System  # type: ignore[import]
            user = System.getProperty("user.name") or "unknown"
        except Exception:
            user = "unknown"

    prov = _provenance(user, session, ts)
    interactive = len(script_args) == 0  # only interactive when no args

    # --- Collect from Ghidra ---
    print("[export_annotations] collecting symbols and functions...")
    new_symbols, new_functions = _collect_symbols_and_functions(program)

    print("[export_annotations] collecting comments...")
    new_comments = _collect_comments(program)

    # --- Load existing ---
    existing_data = _load_existing(annotations_path)
    if existing_data is None:
        existing_data = {
            "schema_version": 1,
            "rom_id": rom_id,
            "rom_sha256": "",
            "symbols": [],
            "functions": [],
            "struct_definitions": [],
            "comments": [],
        }

    # Build keyed dicts from existing data
    ex_symbols = {e["address"]: e for e in existing_data.get("symbols", [])}
    ex_functions = {e["entry_point"]: e for e in existing_data.get("functions", [])}
    ex_comments = {(e["address"], e["type"]): e for e in existing_data.get("comments", [])}

    # --- Merge symbols ---
    n_sym_added = n_sym_overwritten = n_sym_replaced = n_sym_unchanged = 0
    for hex_addr, entry in new_symbols.items():
        _, status = _merge_entry(hex_addr, entry, ex_symbols, prov, interactive)
        if status == "added":
            n_sym_added += 1
        elif status == "overwritten":
            n_sym_overwritten += 1
        elif status == "replaced":
            n_sym_replaced += 1
        else:
            n_sym_unchanged += 1

    # --- Merge functions ---
    n_fn_added = n_fn_overwritten = n_fn_replaced = n_fn_unchanged = 0
    for hex_addr, entry in new_functions.items():
        _, status = _merge_entry(hex_addr, entry, ex_functions, prov, interactive)
        if status == "added":
            n_fn_added += 1
        elif status == "overwritten":
            n_fn_overwritten += 1
        elif status == "replaced":
            n_fn_replaced += 1
        else:
            n_fn_unchanged += 1

    # --- Merge comments ---
    n_cmt_added = n_cmt_replaced = n_cmt_unchanged = 0
    for key, entry in new_comments.items():
        _, status = _merge_comment(key, entry, ex_comments, prov)
        if status == "added":
            n_cmt_added += 1
        elif status in ("replaced", "overwritten"):
            n_cmt_replaced += 1
        else:
            n_cmt_unchanged += 1

    # --- Rebuild output ---
    def _sort_key_hex(d, field):
        try:
            return int(d[field], 16)
        except (KeyError, ValueError):
            return 0

    out_symbols = sorted(ex_symbols.values(), key=lambda d: _sort_key_hex(d, "address"))
    out_functions = sorted(ex_functions.values(), key=lambda d: _sort_key_hex(d, "entry_point"))
    out_comments = sorted(ex_comments.values(), key=lambda d: _sort_key_hex(d, "address"))

    output = {
        "schema_version": existing_data.get("schema_version", 1),
        "rom_id": existing_data.get("rom_id", rom_id),
        "rom_sha256": existing_data.get("rom_sha256", ""),
        "symbols": out_symbols,
        "functions": out_functions,
        "struct_definitions": existing_data.get("struct_definitions", []),
        "comments": out_comments,
    }

    _write_atomic(annotations_path, output)

    total_sym = len(out_symbols)
    total_fn = len(out_functions)
    total_cmt = len(out_comments)
    print(
        "Exported %d symbols, %d functions, %d comments to %s"
        % (total_sym, total_fn, total_cmt, annotations_path)
    )
    print(
        "  symbols:   +%d new, %d overwritten, %d replaced, %d unchanged"
        % (n_sym_added, n_sym_overwritten, n_sym_replaced, n_sym_unchanged)
    )
    print(
        "  functions: +%d new, %d overwritten, %d replaced, %d unchanged"
        % (n_fn_added, n_fn_overwritten, n_fn_replaced, n_fn_unchanged)
    )
    print(
        "  comments:  +%d new, %d replaced, %d unchanged"
        % (n_cmt_added, n_cmt_replaced, n_cmt_unchanged)
    )


# Ghidra scripts run at top level (not under __main__)
main()
