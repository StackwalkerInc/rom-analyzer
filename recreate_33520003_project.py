"""Recreate the 33520003 Ghidra project from scratch.

Deletes the existing project, imports the ROM, runs analysis, and applies
annotations from reference/33520003.json as IMPORTED labels.
"""

import shutil
from pathlib import Path

ROM     = Path("../externals/mmc-research/m32r/33520003_z27ag_mt_2006/Z27AG_JDM_5MT_1860B104.bin")
PROJ_DIR  = Path("../")          # parent directory where .gpr / .rep live
PROJ_NAME = "33520003-ghidra-project"
LANG_ID   = "m32r:2:fp8000"
ANNOTATIONS = Path("reference/33520003.json")

GHIDRA_HOME = Path("/opt/homebrew/opt/ghidra/libexec")

# --- Delete existing project files ---
for suffix in (".gpr", ".rep"):
    p = PROJ_DIR / (PROJ_NAME + suffix)
    if p.exists():
        print(f"Removing {p}")
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()

# --- Start PyGhidra ---
import os
os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_HOME))
os.environ.setdefault("JAVA_HOME", "/opt/homebrew/opt/openjdk@21")

import pyghidra
pyghidra.start()

# --- Create project and import ROM ---
print(f"Creating project {PROJ_DIR / PROJ_NAME}")
project = pyghidra.open_project(PROJ_DIR, PROJ_NAME, create=True)

with project:
    from rom_analyzer.ghidra import ghidriff_program_name, _import_program
    from rom_analyzer.ghidra import _overlay_from_annotations
    from rom_analyzer.annotations_io import load_annotations
    from ghidra.program.util import GhidraProgramUtilities

    prog_name = ghidriff_program_name(ROM)
    print(f"Importing {ROM} as {prog_name}")
    _import_program(project, ROM, prog_name, LANG_ID)

    with pyghidra.program_context(project, f"/{prog_name}") as program:
        print("Running analysis...")
        if GhidraProgramUtilities.shouldAskToAnalyze(program):
            pyghidra.analyze(program)
            program.save("Analyzed", pyghidra.task_monitor())

        print(f"Applying annotations from {ANNOTATIONS}")
        store = load_annotations(ANNOTATIONS)
        with pyghidra.transaction(program, "Import annotations"):
            _overlay_from_annotations(program, store)
        program.save("Annotation overlay", pyghidra.task_monitor())

    syms = len(store.symbols) + len(store.functions)
    print(f"Done. Applied {syms} labels ({len(store.comments)} comments).")
    print(f"Open with: /opt/homebrew/opt/ghidra/bin/pyghidraRun")
    print(f"Project:   {PROJ_DIR.resolve() / PROJ_NAME}")
