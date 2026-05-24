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


def _overlay_symbols(flat_api, ref_symbols: list[ReferenceSymbol]) -> None:
    """Apply enriched reference symbols to an already-imported program.

    Uses flat_api.createLabel and flat_api.createFunction so VTSessionDB
    sees named functions and can produce named matches.
    """
    from ghidra.program.model.symbol import SourceType

    for s in ref_symbols:
        addr = flat_api.toAddr(s.address)
        if addr is None:
            continue
        try:
            flat_api.createLabel(addr, s.name, True, SourceType.USER_DEFINED)
        except Exception:
            pass
        if s.category == "function":
            try:
                flat_api.createFunction(addr, s.name)
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


def import_and_dump(
    ghidra_home: Path,
    project_dir: Path,
    project_name: str,
    input_path: Path,
    language_id: str,
    *,
    extra_args: tuple[str, ...] = (),  # accepted for back-compat; unused
    crc_step_address: int | None = None,
    ref_symbols_for_overlay: list[ReferenceSymbol] | None = None,
    collect_data_refs_flag: bool = False,
) -> HeadlessRun:
    """Import a raw-binary ROM via PyGhidra with explicit language, analyze, and dump.

    Programs are saved under {filename}-{sha1[:6]} so run_vt_diff can locate them
    by name in the project's DomainFolder.
    """
    project_dir.mkdir(parents=True, exist_ok=True)

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(ghidra_home))
    java_home = _resolve_java_home()
    if java_home:
        os.environ.setdefault("JAVA_HOME", java_home)

    import pyghidra
    pyghidra.start()

    prog_name = ghidriff_program_name(input_path)

    with pyghidra.open_program(
        binary_path=str(input_path),
        project_location=str(project_dir),
        project_name=project_name,
        language=language_id,
        loader="ghidra.app.util.opinion.BinaryLoader",
        analyze=True,
        program_name=prog_name,
    ) as flat_api:
        if ref_symbols_for_overlay:
            _overlay_symbols(flat_api, ref_symbols_for_overlay)
        program = flat_api.getCurrentProgram()
        return _dump_program(
            program,
            crc_step_address=crc_step_address,
            collect_data_refs_flag=collect_data_refs_flag,
        )


def fetch_instructions_at(
    ghidra_home: Path,
    project_dir: Path,
    project_name: str,
    input_path: Path,
    language_id: str,
    address: int,
    max_instructions: int = 200,
) -> list[dict] | None:
    """Fetch instructions of the function at the given address from an existing project.

    Opens with analyze=False (project must already exist from import_and_dump).
    Returns None if no instructions are found at the address.
    """
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(ghidra_home))
    java_home = _resolve_java_home()
    if java_home:
        os.environ.setdefault("JAVA_HOME", java_home)

    import pyghidra
    pyghidra.start()

    prog_name = ghidriff_program_name(input_path)

    with pyghidra.open_program(
        binary_path=str(input_path),
        project_location=str(project_dir),
        project_name=project_name,
        language=language_id,
        loader="ghidra.app.util.opinion.BinaryLoader",
        analyze=False,
        program_name=prog_name,
    ) as flat_api:
        program = flat_api.getCurrentProgram()
        listing = program.getListing()
        func_mgr = program.getFunctionManager()
        addr_factory = program.getAddressFactory()

        addr = addr_factory.getDefaultAddressSpace().getAddress(address)
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


def apply_symbols_to_project(
    ghidra_home: Path,
    project_dir: Path,
    project_name: str,
    input_path: Path,
    language_id: str,
    symbols: list[PropagatedSymbol],
) -> int:
    """Apply propagated symbols to an already-imported Ghidra program.

    Opens the existing program by program_name_for_project (analyze=False — already done)
    and applies createLabel / createFunction for each PropagatedSymbol.
    Returns the number of labels successfully applied.
    """
    # PyGhidra stores nested projects at project_dir/project_name/project_name.gpr
    if not (project_dir / project_name / f"{project_name}.gpr").exists():
        raise FileNotFoundError(
            f"Ghidra project not found at {project_dir / project_name / f'{project_name}.gpr'}; "
            "run without --enrich-project first to import the ROM"
        )

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(ghidra_home))
    java_home = _resolve_java_home()
    if java_home:
        os.environ.setdefault("JAVA_HOME", java_home)

    import pyghidra
    pyghidra.start()

    prog_name = ghidriff_program_name(input_path)

    with pyghidra.open_program(
        binary_path=str(input_path),
        project_location=str(project_dir),
        project_name=project_name,
        language=language_id,
        loader="ghidra.app.util.opinion.BinaryLoader",
        analyze=False,
        program_name=prog_name,
    ) as flat_api:
        from ghidra.program.model.symbol import SourceType

        count = 0
        for s in symbols:
            addr = flat_api.toAddr(s.new_address)
            if addr is None:
                continue
            try:
                flat_api.createLabel(addr, s.name, True, SourceType.USER_DEFINED)
                count += 1
            except Exception:
                pass
            if s.category == "function":
                try:
                    flat_api.createFunction(addr, s.name)
                except Exception:
                    pass
        return count
