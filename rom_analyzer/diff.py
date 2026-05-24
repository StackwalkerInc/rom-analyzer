"""Cross-ROM function matching via Ghidra VTSessionDB.

Both programs must have been imported into the Ghidra project by
import_and_dump before calling run_vt_diff. This function opens them by
name from the project's DomainFolder, creates an ephemeral VTSession, runs
four standard VT correlators in priority order, and returns matched pairs.

The VTSession file is written into the project folder as a secondary artifact;
it is deleted and recreated on each run so callers always get a fresh diff.
"""

from pathlib import Path

from rom_analyzer.ghidra import _resolve_java_home, ghidriff_program_name
from rom_analyzer.types import MatchedFunction


def run_vt_diff(
    ghidra_home: Path,
    project_dir: Path,
    project_name: str,
    reference_path: Path,
    new_path: Path,
    language_id: str = "m32r:2:fp8000",
) -> list[MatchedFunction]:
    """Diff two pre-imported programs via Ghidra VTSessionDB.

    Both ROMs must have been imported into the project via import_and_dump
    first. Programs are located by ghidriff_program_name() key in the project.
    """
    import os

    import pyghidra
    from ghidra.feature.vt.api.db import VTSessionDB
    from ghidra.util.task import ConsoleTaskMonitor

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(ghidra_home))
    java_home = _resolve_java_home()
    if java_home:
        os.environ.setdefault("JAVA_HOME", java_home)

    pyghidra.start()
    monitor = ConsoleTaskMonitor()
    ref_name = ghidriff_program_name(reference_path)
    new_name = ghidriff_program_name(new_path)
    session_name = f"{ref_name}-vs-{new_name}"

    with pyghidra.open_program(
        binary_path=str(reference_path),
        project_location=str(project_dir),
        project_name=project_name,
        language=language_id,
        loader="ghidra.app.util.opinion.BinaryLoader",
        analyze=False,
        program_name=ref_name,
    ) as ref_api:
        ref_prog = ref_api.getCurrentProgram()
        folder = ref_prog.getDomainFile().getParent()

        # Delete stale session from a prior run, if present.
        old = folder.getFile(session_name)
        if old is not None:
            old.delete()

        new_file = folder.getFile(new_name)
        if new_file is None:
            raise FileNotFoundError(
                f"Program '{new_name}' not found in project '{project_name}'. "
                "Import the new ROM via import_and_dump before calling run_vt_diff."
            )
        new_prog = new_file.getDomainObject(None, False, False, monitor)
        try:
            session = VTSessionDB(session_name, ref_prog, new_prog, None)
            try:
                _run_vt_correlators(session, monitor)
                return _matches_from_vtsession(session)
            finally:
                session.release(None)
        finally:
            new_prog.release(None)


def _run_vt_correlators(session, monitor) -> None:
    """Run three standard VT correlator factories against the session.

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
    for factory in factories:
        options = factory.createDefaultOptions()
        correlator = factory.createCorrelator(src_prog, src_set, dst_prog, dst_set, options)
        correlator.correlate(session, monitor)


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
