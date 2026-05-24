from dataclasses import dataclass
from enum import Enum

from rom_analyzer.propagate import tier_for_score
from rom_analyzer.types import ConfidenceTier, MatchedFunction, PropagatedSymbol, ReferenceSymbol


class DataRefType(Enum):
    READ = "read"      # genuine memory read: LDUH @fp(sym), LD @Rsrc, etc.
    SCALAR = "scalar"  # Ghidra scalar/computed ref: LDI Rd, #imm treated as addr


@dataclass(frozen=True)
class DataRef:
    instruction_offset: int
    referenced_address: int
    label: str | None = None
    ref_type: DataRefType = DataRefType.READ


def propagate_data_labels(
    ref_refs_by_func: dict[int, list[DataRef]],
    new_refs_by_func: dict[int, list[DataRef]],
    matches: list[MatchedFunction],
    ref_symbols_by_addr: dict[int, ReferenceSymbol],
    window_bytes: int = 8,
) -> list[PropagatedSymbol]:
    proposals: dict[str, list[tuple[int, ConfidenceTier]]] = {}

    for m in matches:
        tier = tier_for_score(m.similarity)
        if tier == "low":
            continue
        ref_refs = ref_refs_by_func.get(m.ref_address, [])
        new_refs = new_refs_by_func.get(m.new_address, [])
        if not ref_refs or not new_refs:
            continue

        new_by_offset: dict[int, DataRef] = {r.instruction_offset: r for r in new_refs}

        for ref_r in ref_refs:
            if ref_r.label is None:
                continue
            if ref_r.referenced_address >= 0x80000:
                continue
            sym = ref_symbols_by_addr.get(ref_r.referenced_address)
            if sym is None:
                continue

            match = new_by_offset.get(ref_r.instruction_offset)
            if match is None:
                for delta in range(1, window_bytes + 1):
                    match = new_by_offset.get(ref_r.instruction_offset + delta)
                    if match:
                        break
                    match = new_by_offset.get(ref_r.instruction_offset - delta)
                    if match:
                        break
            if match is None:
                continue
            # Skip scalar/computed references in the new ROM.  Ghidra marks
            # LDI Rd, #imm instructions with a scalar reference to the immediate
            # value when it falls in the ROM address space — even though the
            # instruction loads a constant, not a flash-table pointer.  Propagating
            # a label here makes Ghidra display the symbol name on the LDI operand,
            # which is misleading (the operand is a value, not an address dereference).
            if match.ref_type == DataRefType.SCALAR:
                continue

            proposals.setdefault(sym.name, []).append((match.referenced_address, tier))

    results: list[PropagatedSymbol] = []
    for name, addr_tiers in proposals.items():
        new_addrs = {a for a, _ in addr_tiers}
        final_tier: ConfidenceTier = "low" if len(new_addrs) > 1 else addr_tiers[0][1]
        new_addr = addr_tiers[0][0]
        ref_sym = next(s for s in ref_symbols_by_addr.values() if s.name == name)
        results.append(PropagatedSymbol(
            name=name,
            ref_address=ref_sym.address,
            new_address=new_addr,
            category="data",
            confidence=final_tier,
        ))

    return results


def collect_data_refs_within(program, function) -> list[DataRef]:
    """Collect flash data refs (addr < 0x80000) for all instructions in a Ghidra function."""
    listing = program.getListing()
    sym_table = program.getSymbolTable()
    ref_mgr = program.getReferenceManager()
    entry = function.getEntryPoint()
    entry_offset = int(entry.getOffset())

    results: list[DataRef] = []
    body = function.getBody()
    for instr in listing.getInstructions(body, True):
        instr_addr = instr.getAddress()
        instr_offset = int(instr_addr.getOffset()) - entry_offset
        for ref in ref_mgr.getReferencesFrom(instr_addr):
            # Collect both genuine data reads (LDUH @fp(sym)) and scalar/computed
            # references that Ghidra auto-generates for LDI Rd, #imm when the
            # immediate falls within a valid ROM address range.  Call and flow
            # references (BL, BRA) are excluded: they are not data references.
            rt = ref.getReferenceType()
            if not rt.isData():
                continue
            # Tag refs so propagate_data_labels can reject scalar matches.
            ref_type = DataRefType.READ if rt.isRead() else DataRefType.SCALAR
            target = ref.getToAddress()
            if target is None:
                continue
            # Mask to uint32: Java getOffset() returns a signed long, so addresses
            # like 0xFFFFFFFB come back as -5 in Python and slip past range guards.
            target_offset = int(target.getOffset()) & 0xFFFFFFFF
            if target_offset >= 0x80000:
                continue
            syms = list(sym_table.getSymbols(target))
            label = str(syms[0].getName()) if syms else None
            results.append(DataRef(
                instruction_offset=instr_offset,
                referenced_address=target_offset,
                label=label,
                ref_type=ref_type,
            ))
    return results
