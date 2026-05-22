"""Wrapper around PyGhidra's in-process API.

We use `pyghidra.open_program` to import a binary with explicit loader/language
and walk Ghidra's Program API directly via JPype. No subprocess, no JSON I/O.
"""

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class HeadlessRun:
    functions: list[dict]
    symbols: list[dict]
    ram_refs: list[int]
    rom_crc_check_step: dict | None


_JDK_FALLBACK_PATHS = (
    "/opt/homebrew/opt/openjdk@21",   # Apple Silicon Homebrew
    "/usr/local/opt/openjdk@21",      # Intel Homebrew
)


def _resolve_java_home() -> str | None:
    """Return a JAVA_HOME value Ghidra can use, or None if none found.

    Honors $JAVA_HOME if set; otherwise probes common Homebrew install paths.
    """
    if "JAVA_HOME" in os.environ:
        return os.environ["JAVA_HOME"]
    for candidate in _JDK_FALLBACK_PATHS:
        if (Path(candidate) / "bin" / "java").exists():
            return candidate
    return None


def _hex(addr) -> str:
    return "0x%x" % addr.getOffset()


def _dump_program(program, crc_step_address: int | None = None) -> HeadlessRun:
    """Extract symbols/functions/ram-refs/crc-step from a loaded Ghidra Program.

    Runs entirely in-process via JPype. Equivalent to the prior dump_references
    Jython post-script but called directly.

    `crc_step_address` is the absolute address of `rom_crc_check_step` (known from
    the reference XML). When provided, we disassemble that function directly rather
    than searching by name (the fresh raw-binary import has no named symbols yet).
    """
    listing = program.getListing()
    symbol_table = program.getSymbolTable()
    func_mgr = program.getFunctionManager()
    addr_factory = program.getAddressFactory()

    functions: list[dict] = []
    for f in func_mgr.getFunctions(True):
        functions.append({
            "name": str(f.getName()),
            "entry": _hex(f.getEntryPoint()),
        })

    symbols: list[dict] = []
    for s in symbol_table.getAllSymbols(True):
        addr = s.getAddress()
        if addr is None:
            continue
        symbols.append({
            "name": str(s.getName()),
            "address": _hex(addr),
            "source": str(s.getSource()),
            "type": str(s.getSymbolType()),
        })

    ram_refs: set[int] = set()
    ref_mgr = program.getReferenceManager()
    for ref in ref_mgr.getReferenceIterator(program.getMinAddress()):
        target = ref.getToAddress()
        if target is None:
            continue
        offset = int(target.getOffset())
        if 0x804000 <= offset < 0x820000:
            ram_refs.add(offset)

    crc_step = None
    if crc_step_address is not None:
        addr = addr_factory.getDefaultAddressSpace().getAddress(crc_step_address)
        f = func_mgr.getFunctionContaining(addr)
        if f is None:
            # Auto-analysis may not have created a function at that address;
            # fall back to walking instructions until a natural boundary.
            instrs_iter = listing.getInstructions(addr, True)
            instrs: list[dict] = []
            count = 0
            for instr in instrs_iter:
                if count >= 200:  # safety cap
                    break
                mnem = str(instr.getMnemonicString())
                operands = [
                    str(instr.getDefaultOperandRepresentation(i))
                    for i in range(instr.getNumOperands())
                ]
                instrs.append({"mnemonic": mnem, "operands": operands})
                count += 1
            crc_step = {"entry": _hex(addr), "instructions": instrs}
        else:
            body = f.getBody()
            instrs = []
            for instr in listing.getInstructions(body, True):
                mnem = str(instr.getMnemonicString())
                operands = [
                    str(instr.getDefaultOperandRepresentation(i))
                    for i in range(instr.getNumOperands())
                ]
                instrs.append({"mnemonic": mnem, "operands": operands})
            crc_step = {"entry": _hex(f.getEntryPoint()), "instructions": instrs}

    return HeadlessRun(
        functions=functions,
        symbols=symbols,
        ram_refs=sorted(ram_refs),
        rom_crc_check_step=crc_step,
    )


def import_and_dump(
    ghidra_home: Path,
    project_dir: Path,
    project_name: str,
    input_path: Path,
    language_id: str,
    *,
    extra_args: tuple[str, ...] = (),  # accepted for back-compat; unused
    crc_step_address: int | None = None,
) -> HeadlessRun:
    """Import a raw-binary ROM via PyGhidra with explicit language, analyze, and dump.

    The XML loader path is not supported by this in-process flow; reference XMLs
    are consumed as plain text by `xml_io.load_reference_symbols`.
    """
    project_dir.mkdir(parents=True, exist_ok=True)

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(ghidra_home))
    java_home = _resolve_java_home()
    if java_home:
        os.environ.setdefault("JAVA_HOME", java_home)

    import pyghidra
    pyghidra.start()

    with pyghidra.open_program(
        binary_path=str(input_path),
        project_location=str(project_dir),
        project_name=project_name,
        language=language_id,
        loader="ghidra.app.util.opinion.BinaryLoader",
        analyze=True,
    ) as flat_api:
        program = flat_api.getCurrentProgram()
        return _dump_program(program, crc_step_address=crc_step_address)
