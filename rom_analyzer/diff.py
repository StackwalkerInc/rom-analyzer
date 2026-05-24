"""Cross-ROM function matching via Ghidra VTSessionDB.

Both programs must have been imported into the Ghidra project by
import_and_dump before calling run_vt_diff. This function opens them by
name from the project, creates an in-memory VTSession, runs four standard
VT correlators in priority order, and returns matched pairs.

The VTSession is in-memory only (VTSessionDB constructor uses DBHandle with
no backing file) and is released when run_vt_diff returns.
"""

from rom_analyzer.types import MatchedFunction


def run_vt_diff(
    project,
    ref_name: str,
    new_name: str,
) -> list[MatchedFunction]:
    """Diff two pre-imported programs via Ghidra VTSessionDB.

    Both ROMs must have been imported into the project via import_and_dump
    first. Programs are located by their ghidriff_program_name() key.
    """
    import pyghidra
    from ghidra.feature.vt.api.db import VTSessionDB
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    session_name = f"{ref_name}-vs-{new_name}"

    ref_prog, ref_consumer = pyghidra.consume_program(project, f"/{ref_name}")
    try:
        new_prog, new_consumer = pyghidra.consume_program(project, f"/{new_name}")
        try:
            from java.lang import Object  # type: ignore
            session_consumer = Object()
            session = VTSessionDB(session_name, ref_prog, new_prog, session_consumer)
            try:
                _run_vt_correlators(session, monitor)
                return _matches_from_vtsession(session)
            finally:
                session.release(session_consumer)
        finally:
            new_prog.release(new_consumer)
    finally:
        ref_prog.release(ref_consumer)


def _run_vt_correlators(session, monitor) -> None:
    """Run four standard VT correlator factories against the session.

    Uses ExactMatchBytesProgramCorrelatorFactory,
    ExactMatchInstructionsProgramCorrelatorFactory, and
    ExactMatchMnemonicsProgramCorrelatorFactory (the exact-match trio).
    FunctionReferenceProgramCorrelatorFactory is included as a fourth pass
    to catch functions matched only by call-graph structure.

    createCorrelator signature (from javap):
        createCorrelator(Program src, AddressSetView srcSet,
                         Program dst, AddressSetView dstSet, VTOptions)
    correlate signature:
        correlate(VTSession, TaskMonitor)
    """
    from ghidra.feature.vt.api.correlator.program import (
        ExactMatchBytesProgramCorrelatorFactory,
        ExactMatchInstructionsProgramCorrelatorFactory,
        ExactMatchMnemonicsProgramCorrelatorFactory,
        FunctionReferenceProgramCorrelatorFactory,
    )

    src_prog = session.getSourceProgram()
    dst_prog = session.getDestinationProgram()
    src_set = src_prog.getMemory()
    dst_set = dst_prog.getMemory()

    factories = [
        ExactMatchBytesProgramCorrelatorFactory(),
        ExactMatchInstructionsProgramCorrelatorFactory(),
        ExactMatchMnemonicsProgramCorrelatorFactory(),
        FunctionReferenceProgramCorrelatorFactory(),
    ]
    tx_id = session.startTransaction("VT correlate")
    ok = False
    try:
        session.setEventsEnabled(False)
        for factory in factories:
            options = factory.createDefaultOptions()
            correlator = factory.createCorrelator(src_prog, src_set, dst_prog, dst_set, options)
            correlator.correlate(session, monitor)
        ok = True
    finally:
        session.setEventsEnabled(True)
        session.endTransaction(tx_id, ok)


def _matches_from_vtsession(session) -> list[MatchedFunction]:
    """Extract MatchedFunction list from all VTMatchSets in the session.

    When multiple correlators match the same ref address, keeps the entry
    with the highest similarity score.
    """
    best: dict[int, MatchedFunction] = {}

    for match_set in session.getMatchSets():
        for match in match_set.getMatches():
            assoc = match.getAssociation()
            ref_addr = assoc.getSourceAddress().getOffset()
            new_addr = assoc.getDestinationAddress().getOffset()
            score = float(match.getSimilarityScore().getScore())
            name = _func_name_at(session.getSourceProgram(), assoc.getSourceAddress())
            existing = best.get(ref_addr)
            if existing is None or score > existing.similarity:
                best[ref_addr] = MatchedFunction(
                    ref_name=name,
                    ref_address=ref_addr,
                    new_address=new_addr,
                    similarity=score,
                    source="vt_diff",
                )

    return list(best.values())


def _func_name_at(program, addr) -> str:
    """Return the function name at addr in program, or '' if no function there."""
    func = program.getFunctionManager().getFunctionAt(addr)
    return func.getName() if func is not None else ""
