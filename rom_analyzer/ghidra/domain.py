"""Domain-specific Ghidra analyses for M32R ECU ROMs.

These functions use the Ghidra API to implement ECU-specific logic
(OBD PID dispatch, DTC helpers, DTC call sites). They are separated
from fetch.py because they embed opcode-pattern knowledge, not just
data retrieval.
"""


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
