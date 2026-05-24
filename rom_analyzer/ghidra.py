import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from rom_analyzer.data_refs import DataRef, collect_data_refs_within
from rom_analyzer.types import PropagatedSymbol, ReferenceSymbol


@dataclass
class HeadlessRun:
    functions: list[dict]
    symbols: list[dict]
    ram_refs: list[int]
    rom_crc_check_step: dict | None
    data_refs: dict[int, list[DataRef]] = field(default_factory=dict)
    callees: dict[int, list[int]] = field(default_factory=dict)


_JDK_FALLBACK_PATHS = (
    "/opt/homebrew/opt/openjdk@21",   # Apple Silicon Homebrew
    "/usr/local/opt/openjdk@21",      # Intel Homebrew
    "/usr/lib/jvm/java-21-openjdk-amd64",   # Debian/Ubuntu
    "/usr/lib/jvm/java-21-openjdk",         # generic Linux
    "/usr/lib/jvm/java-21",                 # RHEL/Fedora
)


def _resolve_java_home() -> str | None:
    """Return a JAVA_HOME value Ghidra can use, or None if none found."""
    if "JAVA_HOME" in os.environ:
        return os.environ["JAVA_HOME"]
    for candidate in _JDK_FALLBACK_PATHS:
        if (Path(candidate) / "bin" / "java").exists():
            return candidate
    return None


def setup_environment(ghidra_home: Path) -> None:
    """Set GHIDRA_INSTALL_DIR and JAVA_HOME env vars. Call once before pyghidra.start()."""
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(ghidra_home))
    java_home = _resolve_java_home()
    if java_home:
        os.environ.setdefault("JAVA_HOME", java_home)


def _hex(addr) -> str:
    return "0x%x" % addr.getOffset()


def _ordered_callees(func, ref_mgr, func_mgr) -> list[int]:
    """Return callee entry addresses ordered by first call-site within the function body."""
    body = func.getBody()
    func_entry = int(func.getEntryPoint().getOffset())
    max_addr = body.getMaxAddress()
    seen: dict[int, int] = {}  # callee_entry → first source offset

    for ref in ref_mgr.getReferenceIterator(body.getMinAddress()):
        from_addr = ref.getFromAddress()
        if from_addr.compareTo(max_addr) > 0:
            break
        if not body.contains(from_addr):
            continue
        if not ref.getReferenceType().isCall():
            continue
        target = ref.getToAddress()
        if target is None:
            continue
        callee = func_mgr.getFunctionContaining(target)
        if callee is None:
            continue
        entry = int(callee.getEntryPoint().getOffset())
        if entry == func_entry:
            continue  # skip self-calls
        src_offset = int(from_addr.getOffset())
        if entry not in seen or src_offset < seen[entry]:
            seen[entry] = src_offset

    return [k for k, _ in sorted(seen.items(), key=lambda kv: kv[1])]


def _overlay_symbols(program, ref_symbols: list[ReferenceSymbol]) -> None:
    """Apply enriched reference symbols to an already-imported program (must be in a transaction)."""
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.flatapi import FlatProgramAPI

    flat = FlatProgramAPI(program)
    for s in ref_symbols:
        addr = flat.toAddr(s.address)
        if addr is None:
            continue
        try:
            flat.createLabel(addr, s.name, True, SourceType.USER_DEFINED)
        except Exception:
            pass
        if s.category == "function":
            try:
                flat.createFunction(addr, s.name)
            except Exception:
                pass


def _dump_program(
    program,
    crc_step_address: int | None = None,
    collect_data_refs_flag: bool = False,
) -> HeadlessRun:
    """Extract symbols/functions/ram-refs/crc-step/data-refs from a loaded Ghidra Program."""
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
            instrs_iter = listing.getInstructions(addr, True)
            instrs: list[dict] = []
            count = 0
            for instr in instrs_iter:
                if count >= 200:
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

    data_refs_map: dict[int, list[DataRef]] = {}
    callees_map: dict[int, list[int]] = {}
    for f in func_mgr.getFunctions(True):
        entry_addr = int(f.getEntryPoint().getOffset())
        if collect_data_refs_flag:
            data_refs_map[entry_addr] = collect_data_refs_within(program, f)
        callees_map[entry_addr] = _ordered_callees(f, ref_mgr, func_mgr)

    return HeadlessRun(
        functions=functions,
        symbols=symbols,
        ram_refs=sorted(ram_refs),
        rom_crc_check_step=crc_step,
        data_refs=data_refs_map,
        callees=callees_map,
    )


def ghidriff_program_name(binary_path: Path) -> str:
    sha1 = hashlib.sha1(binary_path.read_bytes()).hexdigest()
    return f"{binary_path.name}-{sha1[:6]}"


def _import_program(project, input_path: Path, prog_name: str, language_id: str) -> None:
    """Import input_path into the project under prog_name using BinaryLoader."""
    import pyghidra

    loader = (
        pyghidra.program_loader()
        .project(project)
        .source(str(input_path))
        .name(prog_name)
        .loaders("BinaryLoader")
        .language(language_id)
    )
    with loader.load() as load_results:
        load_results.save(pyghidra.task_monitor())


def import_and_dump(
    project,
    input_path: Path,
    language_id: str,
    *,
    crc_step_address: int | None = None,
    ref_symbols_for_overlay: list[ReferenceSymbol] | None = None,
    collect_data_refs_flag: bool = False,
) -> HeadlessRun:
    """Import a raw-binary ROM into the open project (if not already present), analyze, and dump.

    Programs are keyed by ghidriff_program_name() so the same ROM imported
    multiple times within a run is opened from disk rather than re-imported.
    """
    import pyghidra
    from ghidra.program.util import GhidraProgramUtilities

    prog_name = ghidriff_program_name(input_path)

    if project.getProjectData().getFile(f"/{prog_name}") is None:
        _import_program(project, input_path, prog_name, language_id)

    with pyghidra.program_context(project, f"/{prog_name}") as program:
        if GhidraProgramUtilities.shouldAskToAnalyze(program):
            pyghidra.analyze(program)
            program.save("Analyzed", pyghidra.task_monitor())

        if ref_symbols_for_overlay:
            with pyghidra.transaction(program, "Overlay symbols"):
                _overlay_symbols(program, ref_symbols_for_overlay)
            program.save("Symbol overlay", pyghidra.task_monitor())

        return _dump_program(
            program,
            crc_step_address=crc_step_address,
            collect_data_refs_flag=collect_data_refs_flag,
        )


def fetch_instructions_at(
    project,
    prog_name: str,
    address: int,
    max_instructions: int = 200,
) -> list[dict] | None:
    """Fetch instructions of the function at the given address from an existing project program.

    Returns None if no instructions are found at the address.
    """
    import pyghidra

    with pyghidra.program_context(project, f"/{prog_name}") as program:
        listing = program.getListing()
        func_mgr = program.getFunctionManager()
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address)
        f = func_mgr.getFunctionContaining(addr)

        if f is not None:
            body = f.getBody()
            instrs = []
            for instr in listing.getInstructions(body, True):
                mnem = str(instr.getMnemonicString())
                operands = [
                    str(instr.getDefaultOperandRepresentation(i))
                    for i in range(instr.getNumOperands())
                ]
                instrs.append({"mnemonic": mnem, "operands": operands})
            return instrs or None
        else:
            instrs_iter = listing.getInstructions(addr, True)
            instrs = []
            count = 0
            for instr in instrs_iter:
                if count >= max_instructions:
                    break
                mnem = str(instr.getMnemonicString())
                operands = [
                    str(instr.getDefaultOperandRepresentation(i))
                    for i in range(instr.getNumOperands())
                ]
                instrs.append({"mnemonic": mnem, "operands": operands})
                count += 1
            return instrs or None


def apply_labels(
    project,
    prog_name: str,
    symbols: list[PropagatedSymbol],
    *,
    add_bookmarks: bool = True,
    add_comments: bool = False,
) -> int:
    """Apply propagated symbols to an already-imported program.

    Returns the number of labels successfully applied.
    """
    import pyghidra
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import CodeUnit

    with pyghidra.program_context(project, f"/{prog_name}") as program:
        count = 0
        listing = program.getListing()
        bookmark_mgr = program.getBookmarkManager()
        with pyghidra.transaction(program, "Apply labels"):
            flat = FlatProgramAPI(program)
            for s in symbols:
                addr = flat.toAddr(s.new_address)
                if addr is None:
                    continue
                try:
                    flat.createLabel(addr, s.name, True, SourceType.USER_DEFINED)
                    count += 1
                except Exception:
                    pass
                if s.category == "function":
                    try:
                        flat.createFunction(addr, s.name)
                    except Exception:
                        pass
                if s.source:
                    annotation = (
                        f"rom-analyzer: source={s.source}"
                        f" score={s.score:.2f}"
                        f" confidence={s.confidence}"
                    )
                    if add_bookmarks:
                        try:
                            bookmark_mgr.setBookmark(
                                addr, "Analysis", "rom-analyzer", annotation
                            )
                        except Exception:
                            pass
                    if add_comments:
                        try:
                            existing = listing.getComment(
                                addr, CodeUnit.PRE_COMMENT
                            )
                            if existing is None:
                                listing.setComment(
                                    addr, CodeUnit.PRE_COMMENT, annotation
                                )
                            elif "rom-analyzer:" in existing:
                                lines = existing.split("\n")
                                new_lines = [
                                    annotation if "rom-analyzer:" in ln else ln
                                    for ln in lines
                                ]
                                listing.setComment(
                                    addr, CodeUnit.PRE_COMMENT,
                                    "\n".join(new_lines),
                                )
                            else:
                                listing.setComment(
                                    addr, CodeUnit.PRE_COMMENT,
                                    existing + "\n" + annotation,
                                )
                        except Exception:
                            pass
        program.save("Apply labels", pyghidra.task_monitor())
        return count
