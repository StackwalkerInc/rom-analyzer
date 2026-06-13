import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from typing import TYPE_CHECKING

from rom_analyzer.data_refs import DataRef, collect_data_refs_within, collect_ram_refs_within
from rom_analyzer.types import PropagatedSymbol, ReferenceSymbol

if TYPE_CHECKING:
    from rom_analyzer.annotations_io import AnnotationStore
    from rom_analyzer.mut_table import MutTableResult
    from rom_analyzer.types import DataTypeDefinition


@dataclass
class HeadlessRun:
    functions: list[dict]
    symbols: list[dict]
    ram_refs: list[int]
    rom_crc_check_step: dict | None
    data_refs: dict[int, list[DataRef]] = field(default_factory=dict)
    callees: dict[int, list[int]] = field(default_factory=dict)
    ram_data_refs: dict[int, list[DataRef]] = field(default_factory=dict)


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


def _overlay_from_annotations(program, store: "AnnotationStore") -> None:
    """Apply an AnnotationStore to an already-imported program (must be in a transaction)."""
    from rom_analyzer.ghidra_overlay import apply_annotations
    apply_annotations(program, store)


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
    ram_data_refs_map: dict[int, list[DataRef]] = {}
    callees_map: dict[int, list[int]] = {}
    for f in func_mgr.getFunctions(True):
        entry_addr = int(f.getEntryPoint().getOffset())
        if collect_data_refs_flag:
            data_refs_map[entry_addr] = collect_data_refs_within(program, f)
            ram_data_refs_map[entry_addr] = collect_ram_refs_within(program, f)
        callees_map[entry_addr] = _ordered_callees(f, ref_mgr, func_mgr)

    return HeadlessRun(
        functions=functions,
        symbols=symbols,
        ram_refs=sorted(ram_refs),
        rom_crc_check_step=crc_step,
        data_refs=data_refs_map,
        callees=callees_map,
        ram_data_refs=ram_data_refs_map,
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
    annotations_path: Path | None = None,
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

        if annotations_path is not None:
            from rom_analyzer.annotations_io import load_annotations
            store = load_annotations(annotations_path)
            with pyghidra.transaction(program, "Overlay annotations"):
                _overlay_from_annotations(program, store)
            program.save("Annotation overlay", pyghidra.task_monitor())
        elif ref_symbols_for_overlay:  # annotations_path takes priority when both are given
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


def fetch_function_entry(
    project,
    prog_name: str,
    address: int,
) -> int | None:
    """Return the entry-point address of the function containing `address`.

    Returns None if no function contains it.
    """
    import pyghidra

    with pyghidra.program_context(project, f"/{prog_name}") as program:
        func_mgr = program.getFunctionManager()
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address)
        f = func_mgr.getFunctionContaining(addr)
        if f is None:
            return None
        return int(f.getEntryPoint().getOffset()) & 0xFFFFFFFF


def fetch_r0_imm_before(
    project,
    prog_name: str,
    call_site: int,
    max_back: int = 6,
) -> int | None:
    """Return the immediate of the nearest `ldi r0,#imm` preceding `call_site`.

    Walks backward through the disassembly listing up to `max_back` instructions.
    Returns None if no `ldi r0` is found (caller falls back to a raw-byte decode).
    """
    import pyghidra

    with pyghidra.program_context(project, f"/{prog_name}") as program:
        listing = program.getListing()
        af = program.getAddressFactory().getDefaultAddressSpace()
        addr = af.getAddress(call_site)
        cur = listing.getInstructionBefore(addr)
        steps = 0
        while cur is not None and steps < max_back:
            mnem = str(cur.getMnemonicString())
            if (
                mnem == "ldi"
                and cur.getNumOperands() >= 2
                and str(cur.getDefaultOperandRepresentation(0)) == "r0"
            ):
                scalar = cur.getScalar(1)
                if scalar is not None:
                    return int(scalar.getValue()) & 0xFF
            cur = listing.getInstructionBefore(cur.getMinAddress())
            steps += 1
        return None


def fetch_callers_of(
    project,
    prog_name: str,
    target_address: int,
) -> list[int]:
    """Return the addresses of call instructions that call target_address.

    Uses the reference manager's references-to the target, filtered to CALL
    references. Addresses masked to uint32, sorted, de-duplicated.
    """
    import pyghidra

    with pyghidra.program_context(project, f"/{prog_name}") as program:
        ref_mgr = program.getReferenceManager()
        target = program.getAddressFactory().getDefaultAddressSpace().getAddress(target_address)
        out: set[int] = set()
        for ref in ref_mgr.getReferencesTo(target):
            if ref.getReferenceType().isCall():
                out.add(ref.getFromAddress().getOffset() & 0xFFFFFFFF)
        return sorted(out)


def fetch_data_read_sites(
    project,
    prog_name: str,
    target_address: int,
    container_entry: int,
) -> list[int]:
    """Return addresses of instructions inside the function at container_entry
    that READ target_address.

    Uses references-to the target, filtered to those whose from-address lies in
    the containing function's body and whose reference type is a data read.
    Addresses masked to uint32, sorted, de-duplicated. Empty if the container
    function is not found.
    """
    import pyghidra

    with pyghidra.program_context(project, f"/{prog_name}") as program:
        func_mgr = program.getFunctionManager()
        af = program.getAddressFactory().getDefaultAddressSpace()
        container = func_mgr.getFunctionContaining(af.getAddress(container_entry))
        if container is None:
            return []
        body = container.getBody()
        ref_mgr = program.getReferenceManager()
        target = af.getAddress(target_address)
        out: set[int] = set()
        for ref in ref_mgr.getReferencesTo(target):
            from_addr = ref.getFromAddress()
            if body.contains(from_addr) and ref.getReferenceType().isRead():
                out.add(from_addr.getOffset() & 0xFFFFFFFF)
        return sorted(out)


def fetch_pid_dispatch_entries(
    project,
    prog_name: str,
    handler_entries: list[tuple[int, int]],
) -> list[dict]:
    """Trace OBD mode dispatcher functions to find (mode, pid) → RAM address mappings.

    handler_entries: list of (mode_byte, function_entry_address).
    Returns list of dicts with keys: mode, pid, ram_addr, ram_size, confidence.
    """
    import pyghidra

    _RAM_LO = 0x800000
    _LOAD_MNEMS = frozenset({"ld", "ldh", "lduh", "ldb", "ldub"})
    _BRANCH_MNEMS = frozenset({"beq", "bne", "bc", "bnc", "blt", "bge", "bltu", "bgeu"})
    _CMP_MNEMS = frozenset({"cmp", "cmpi", "cmpu", "cmpui"})

    results: list[dict] = []

    with pyghidra.program_context(project, f"/{prog_name}") as program:
        listing = program.getListing()
        func_mgr = program.getFunctionManager()
        ref_mgr = program.getReferenceManager()
        af = program.getAddressFactory().getDefaultAddressSpace()

        for mode, entry_addr in handler_entries:
            addr_obj = af.getAddress(entry_addr)
            func = func_mgr.getFunctionContaining(addr_obj)
            if func is None:
                continue

            # Dispatch pass: find cmpi/cmp #imm + conditional branch → (pid, target)
            pid_targets: list[tuple[int, int]] = []
            instrs = list(listing.getInstructions(func.getBody(), True))
            for i, instr in enumerate(instrs):
                mnem = str(instr.getMnemonicString()).lower()
                if mnem not in _CMP_MNEMS:
                    continue
                # Extract the immediate operand from any position
                pid_val = None
                for op_idx in range(instr.getNumOperands()):
                    scalar = instr.getScalar(op_idx)
                    if scalar is not None:
                        pid_val = int(scalar.getValue()) & 0xFF
                        break
                if pid_val is None:
                    continue
                # Next instruction should be a conditional branch
                if i + 1 >= len(instrs):
                    continue
                next_instr = instrs[i + 1]
                if str(next_instr.getMnemonicString()).lower() not in _BRANCH_MNEMS:
                    continue
                for ref in ref_mgr.getReferencesFrom(next_instr.getMinAddress()):
                    if ref.getReferenceType().isFlow():
                        target = int(ref.getToAddress().getOffset()) & 0xFFFFFFFF
                        pid_targets.append((pid_val, target))

            # Load pass: walk ≤20 instructions from each pid handler for RAM reads
            for pid_val, target_addr in pid_targets:
                target_obj = af.getAddress(target_addr)
                count = 0
                for instr in listing.getInstructions(target_obj, True):
                    if count >= 20:
                        break
                    mnem = str(instr.getMnemonicString()).lower()
                    if mnem in _LOAD_MNEMS:
                        for ref in ref_mgr.getReferencesFrom(instr.getMinAddress()):
                            if ref.getReferenceType().isRead():
                                ram_addr = int(ref.getToAddress().getOffset()) & 0xFFFFFFFF
                                if ram_addr >= _RAM_LO:
                                    size = (
                                        1 if "b" in mnem else
                                        2 if "h" in mnem else
                                        4
                                    )
                                    results.append({
                                        "mode": mode,
                                        "pid": pid_val,
                                        "ram_addr": ram_addr,
                                        "ram_size": size,
                                        "confidence": "high" if count < 5 else "medium",
                                    })
                                    break
                    count += 1

    return results


def fetch_dtc_helpers_structural(
    project,
    prog_name: str,
) -> tuple[int | None, int | None]:
    """Scan all short functions for probably_set_dtc / probably_reset_dtc signatures.

    Setter signature:   slli + ≥3 (or + sth) pairs.
    Resetter signature: slli + (not + and + sth) triple.

    Returns (set_addr, reset_addr). Either may be None if not found.
    Used as Layer 2 fallback when VTSession does not match the functions.
    """
    import pyghidra

    set_addr: int | None = None
    reset_addr: int | None = None
    set_score = 0
    reset_score = 0

    with pyghidra.program_context(project, f"/{prog_name}") as program:
        listing = program.getListing()
        func_mgr = program.getFunctionManager()

        for func in func_mgr.getFunctions(True):
            body = func.getBody()
            instrs = list(listing.getInstructions(body, True))
            if len(instrs) > 40:
                continue

            mnems = [str(i.getMnemonicString()).lower() for i in instrs]
            if "slli" not in mnems:
                continue

            # Count or+sth pairs (setter pattern)
            or_sth = sum(
                1 for j in range(len(mnems) - 1)
                if mnems[j] == "or" and mnems[j + 1] == "sth"
            )

            # Count not+and+sth triples (resetter pattern)
            not_and_sth = sum(
                1 for j in range(len(mnems) - 2)
                if mnems[j] == "not" and mnems[j + 1] == "and" and mnems[j + 2] == "sth"
            )

            entry = int(func.getEntryPoint().getOffset()) & 0xFFFFFFFF

            if or_sth >= 3 and or_sth > set_score:
                set_score = or_sth
                set_addr = entry

            if not_and_sth >= 1 and not_and_sth > reset_score:
                reset_score = not_and_sth
                reset_addr = entry

    return set_addr, reset_addr


def fetch_dtc_call_sites(
    project,
    prog_name: str,
    set_addr: int | None,
    reset_addr: int | None,
    max_back: int = 8,
) -> list[dict]:
    """Enumerate every call to probably_set_dtc and probably_reset_dtc.

    For each call site walks back ≤max_back instructions looking for
    `ldi r0, #mask` (DTC bit mask) and `ldi r1, #idx` (DTC word index).
    Follows one `mv` register hop for each if needed.

    Returns list of dicts: call_site, caller_addr, caller_name, mask, idx, is_set.
    mask and idx are None if not found in the look-back window.
    """
    import pyghidra

    results: list[dict] = []

    with pyghidra.program_context(project, f"/{prog_name}") as program:
        listing = program.getListing()
        ref_mgr = program.getReferenceManager()
        func_mgr = program.getFunctionManager()
        af = program.getAddressFactory().getDefaultAddressSpace()

        for is_set, target_addr in [(True, set_addr), (False, reset_addr)]:
            if target_addr is None:
                continue
            target = af.getAddress(target_addr)

            for ref in ref_mgr.getReferencesTo(target):
                if not ref.getReferenceType().isCall():
                    continue
                call_site = int(ref.getFromAddress().getOffset()) & 0xFFFFFFFF
                call_addr = af.getAddress(call_site)

                # Walk back looking for ldi r0 (mask) and ldi r1 (idx)
                mask: int | None = None
                idx: int | None = None
                r0_src = "r0"
                r1_src = "r1"

                cur = listing.getInstructionBefore(call_addr)
                steps = 0
                while cur is not None and steps < max_back and (mask is None or idx is None):
                    mnem = str(cur.getMnemonicString()).lower()
                    num_ops = cur.getNumOperands()
                    ops = [
                        str(cur.getDefaultOperandRepresentation(i))
                        for i in range(num_ops)
                    ]

                    if mnem == "ldi" and len(ops) >= 2:
                        if ops[0] == r0_src and mask is None:
                            sc = cur.getScalar(1)
                            if sc is not None:
                                mask = int(sc.getValue()) & 0xFFFF
                        elif ops[0] == r1_src and idx is None:
                            sc = cur.getScalar(1)
                            if sc is not None:
                                idx = int(sc.getValue()) & 0xFFFF
                    elif mnem == "mv" and len(ops) >= 2:
                        if ops[0] == r0_src:
                            r0_src = ops[1]
                        elif ops[0] == r1_src:
                            r1_src = ops[1]

                    cur = listing.getInstructionBefore(cur.getMinAddress())
                    steps += 1

                # Identify the containing function
                caller_fn = func_mgr.getFunctionContaining(call_addr)
                if caller_fn is not None:
                    caller_addr = int(caller_fn.getEntryPoint().getOffset()) & 0xFFFFFFFF
                    caller_name = str(caller_fn.getName())
                else:
                    caller_addr = call_site
                    caller_name = None

                results.append({
                    "call_site": call_site,
                    "caller_addr": caller_addr,
                    "caller_name": caller_name,
                    "mask": mask,
                    "idx": idx,
                    "is_set": is_set,
                })

    return results


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


def apply_mut_table_in_ghidra(
    project,
    prog_name: str,
    result: "MutTableResult",
) -> None:
    """Apply void*[N] datatype and flash_mut_variables_table label in the Ghidra project.

    Also applies WordDataType and flash_mut_variables_table_size label at size_address.
    Follows the same open-program-context pattern as apply_labels.
    """
    import pyghidra
    from ghidra.program.model.data import ArrayDataType, PointerDataType, WordDataType
    from ghidra.program.model.data import DataUtilities
    from ghidra.program.model.symbol import SourceType

    with pyghidra.program_context(project, f"/{prog_name}") as program:
        addr_space = program.getAddressFactory().getDefaultAddressSpace()
        with pyghidra.transaction(program, "Label MUT table"):
            # Apply void*[N] to the table base address
            table_addr = addr_space.getAddress(result.table_address)
            arr_dt = ArrayDataType(PointerDataType(), result.table_size, 4)
            DataUtilities.createData(
                program, table_addr, arr_dt, -1,
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
            )
            program.getSymbolTable().createLabel(
                table_addr, "flash_mut_variables_table", SourceType.USER_DEFINED
            )
            # Apply WordDataType (uint16_t) to the size scalar
            size_addr = addr_space.getAddress(result.size_address)
            DataUtilities.createData(
                program, size_addr, WordDataType(), -1,
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
            )
            program.getSymbolTable().createLabel(
                size_addr, "flash_mut_variables_table_size", SourceType.USER_DEFINED
            )
        program.save("MUT table labels", pyghidra.task_monitor())


def _resolve_datatype(type_str: str):
    """Map an XML DATATYPE string to a Ghidra DataType, or None if unrecognised."""
    from ghidra.program.model.data import (
        ArrayDataType, ByteDataType, DWordDataType,
        PointerDataType, WordDataType,
    )
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


def apply_data_types(
    project,
    prog_name: str,
    data_defs: "list[DataTypeDefinition]",
) -> int:
    """Apply DEFINED_DATA type definitions to an already-imported program.

    Returns the number of definitions successfully applied.
    """
    import pyghidra
    from ghidra.program.model.data import DataUtilities

    with pyghidra.program_context(project, f"/{prog_name}") as program:
        addr_space = program.getAddressFactory().getDefaultAddressSpace()
        count = 0
        with pyghidra.transaction(program, "Apply data types"):
            for d in data_defs:
                dt = _resolve_datatype(d.datatype)
                if dt is None:
                    print(f"   warning: unrecognised datatype '{d.datatype}' at {d.address:#x} — skipped")
                    continue
                addr = addr_space.getAddress(d.address)
                if addr is None:
                    continue
                try:
                    DataUtilities.createData(
                        program, addr, dt, -1,
                        DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA,
                    )
                    count += 1
                except Exception as e:
                    print(f"   warning: could not apply {d.datatype} at {d.address:#x}: {e}")
        program.save("Apply data types", pyghidra.task_monitor())
    return count


def decompile_function(project, prog_name: str, address: int) -> str:
    """Return the decompiled C source for the function at *address*.

    Raises ValueError if no function exists at the given address.
    """
    import pyghidra
    from ghidra.app.decompiler import DecompInterface

    with pyghidra.program_context(project, f"/{prog_name}") as program:
        addr_space = program.getAddressFactory().getDefaultAddressSpace()
        addr = addr_space.getAddress(address)
        func = program.getFunctionManager().getFunctionAt(addr)
        if func is None:
            raise ValueError(f"No function at {address:#x} in {prog_name}")
        decomp = DecompInterface()
        decomp.openProgram(program)
        result = decomp.decompileFunction(func, 30, pyghidra.task_monitor())
        decomp.dispose()
        if result is None or not result.decompileCompleted():
            raise ValueError(f"Decompilation failed for function at {address:#x}")
        return result.getDecompiledFunction().getC()
