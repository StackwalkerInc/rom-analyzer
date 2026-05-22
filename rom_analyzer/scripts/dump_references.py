# rom_analyzer/scripts/dump_references.py
# Ghidra Jython 2.7 script. Run via `analyzeHeadless ... -postScript dump_references.py <output.json>`.
# This script uses Ghidra's headless analyzer API; the surrounding `ghidra.py` wraps it.

import json
import os
import sys


def _hex(addr):
    return "0x%x" % addr.getOffset()


def main(output_path):
    program = getCurrentProgram()  # type: ignore[name-defined] — provided by Ghidra
    listing = program.getListing()
    symbol_table = program.getSymbolTable()
    func_mgr = program.getFunctionManager()

    # Function entries
    functions = []
    for f in func_mgr.getFunctions(True):
        functions.append({
            "name": f.getName(),
            "entry": _hex(f.getEntryPoint()),
        })

    # All symbols (user + auto)
    symbols = []
    for s in symbol_table.getAllSymbols(True):
        addr = s.getAddress()
        if addr is None:
            continue
        symbols.append({
            "name": s.getName(),
            "address": _hex(addr),
            "source": str(s.getSource()),
            "type": str(s.getSymbolType()),
        })

    # RAM references (target address >= 0x804000)
    ram_refs = set()
    ref_mgr = program.getReferenceManager()
    for ref in ref_mgr.getReferenceIterator(program.getMinAddress()):
        target = ref.getToAddress()
        offset = target.getOffset()
        if 0x804000 <= offset < 0x820000:
            ram_refs.add(offset)

    # rom_crc_check_step disassembly (when symbol exists)
    crc_step = None
    for s in symbol_table.getSymbols("rom_crc_check_step"):
        f = func_mgr.getFunctionContaining(s.getAddress())
        if f is None:
            continue
        body = f.getBody()
        instrs = []
        for instr in listing.getInstructions(body, True):
            mnem = instr.getMnemonicString()
            operands = []
            for i in range(instr.getNumOperands()):
                operands.append(instr.getDefaultOperandRepresentation(i))
            instrs.append({"mnemonic": mnem, "operands": operands})
        crc_step = {"entry": _hex(s.getAddress()), "instructions": instrs}
        break

    payload = {
        "functions": functions,
        "symbols": symbols,
        "ram_refs": sorted(ram_refs),
        "rom_crc_check_step": crc_step,
    }
    with open(output_path, "w") as f:
        json.dump(payload, f)


if __name__ == "__main__":
    # Ghidra passes -postScript arguments via the script's argv.
    if len(getScriptArgs()) < 1:  # type: ignore[name-defined]
        print("usage: dump_references.py <output.json>")
        sys.exit(2)
    main(getScriptArgs()[0])  # type: ignore[name-defined]
