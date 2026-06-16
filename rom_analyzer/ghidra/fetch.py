"""Read-only Ghidra queries — fetch_* functions that open a program_context
and return Python-native data without modifying the project."""


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


def fetch_callees_of(
    project,
    prog_name: str,
    function_address: int,
) -> list[int]:
    """Return entry-point addresses of functions called by the function at function_address.

    Uses the function body's outgoing CALL references. Addresses masked to uint32,
    sorted, de-duplicated. Returns [] if no function exists at function_address.
    """
    import pyghidra

    with pyghidra.program_context(project, f"/{prog_name}") as program:
        func_mgr = program.getFunctionManager()
        af = program.getAddressFactory().getDefaultAddressSpace()
        addr = af.getAddress(function_address)
        func = func_mgr.getFunctionAt(addr)
        if func is None:
            return []
        body = func.getBody()
        ref_mgr = program.getReferenceManager()
        out: set[int] = set()
        for body_addr in body.getAddresses(True):
            for ref in ref_mgr.getReferencesFrom(body_addr):
                if ref.getReferenceType().isCall():
                    target = ref.getToAddress()
                    target_func = func_mgr.getFunctionAt(target)
                    if target_func is not None:
                        out.add(int(target_func.getEntryPoint().getOffset()) & 0xFFFFFFFF)
        return sorted(out)


def fetch_function_name(
    project,
    prog_name: str,
    entry_point: int,
) -> str | None:
    """Return the Ghidra name of the function at entry_point, or None if absent."""
    import pyghidra

    with pyghidra.program_context(project, f"/{prog_name}") as program:
        func_mgr = program.getFunctionManager()
        af = program.getAddressFactory().getDefaultAddressSpace()
        addr = af.getAddress(entry_point)
        func = func_mgr.getFunctionAt(addr)
        if func is None:
            return None
        return str(func.getName())


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
