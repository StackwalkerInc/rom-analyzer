# @category ROM-Analyzer
# @menupath ROM-Analyzer.Import annotations.json
#
# Ghidra script: apply an annotations.json file to the currently open program.
# Run via Script Manager (interactive) or:
#   analyzeHeadless ... -scriptPath rom_analyzer/scripts -postScript import_annotations.py \
#       <annotations_path>

import os
import sys
from pathlib import Path

# Make rom_analyzer importable from Script Manager
_pkg_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

from rom_analyzer.annotations_io import load_annotations  # noqa: E402
from rom_analyzer.ghidra_overlay import apply_annotations  # noqa: E402


def main():
    script_args = getScriptArgs()  # type: ignore[name-defined]
    if len(script_args) >= 1:
        annotations_path = script_args[0]
    else:
        f = askFile("Select annotations.json", "Select")  # type: ignore[name-defined]
        annotations_path = str(f)

    store = load_annotations(Path(annotations_path))
    program = currentProgram  # type: ignore[name-defined]

    tx_id = program.startTransaction("Import annotations")
    try:
        apply_annotations(program, store)
    finally:
        program.endTransaction(tx_id, True)

    print("Applied annotations from %s (%d symbols, %d functions, %d comments)" % (
        annotations_path, len(store.symbols), len(store.functions), len(store.comments),
    ))


main()
