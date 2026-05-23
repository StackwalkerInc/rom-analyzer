"""ghidriff integration via in-process Python API.

Strategy: import_and_dump saves programs under {filename}-{sha1[:6]} in the
PyGhidra project. When run_ghidriff is called, it opens the SAME project using
ghidriff's Python API (JVM already running; ghidriff's launcher is a no-op) and
finds the pre-imported M32R programs by name. This avoids re-import and preserves
the correct language + symbol overlay applied during import.

Project path note: PyGhidra's nested_project_location=True stores the project at
  project_dir/project_name/  (i.e. ~/rom-analyzer-projects/rom-analyzer/).
We must pass THIS path as project_location to ghidriff's setup_project().
"""

import tempfile
from pathlib import Path

from rom_analyzer.ghidra import _resolve_java_home, ghidriff_program_name
from rom_analyzer.types import MatchedFunction


def _patch_launcher_for_running_jvm() -> None:
    """Reconstruct _layout on PyGhidraLauncher when the JVM is already running.

    ghidriff creates a new HeadlessLoggingPyGhidraLauncher, calls start(), but
    PyGhidraLauncher.start() returns early (no-op) when the JVM is already up,
    leaving _layout=None. This patch sets it from the live GhidraApplicationLayout
    class — exactly what start() does on first launch.
    """
    import jpype
    if not jpype.isJVMStarted():
        return

    from pyghidra.launcher import PyGhidraLauncher
    if getattr(PyGhidraLauncher, "_layout_patch_applied", False):
        return

    _orig_start = PyGhidraLauncher.start

    def _patched_start(self, **kwargs):
        _orig_start(self, **kwargs)
        if self._layout is None and jpype.isJVMStarted():
            from ghidra import GhidraApplicationLayout
            self._layout = GhidraApplicationLayout()

    PyGhidraLauncher.start = _patched_start
    PyGhidraLauncher._layout_patch_applied = True


def run_ghidriff(
    ghidra_home: Path,
    project_dir: Path,
    project_name: str,
    reference_path: Path,
    new_path: Path,
    engine: str = "VersionTrackingDiff",
) -> list[MatchedFunction]:
    """Diff two already-imported programs via ghidriff's Python API.

    Both ROMs must have been imported into the project via import_and_dump first.
    ghidriff finds them by {filename}-{sha1[:6]} key in the project.
    """
    import os
    from ghidriff import SimpleDiff, VersionTrackingDiff

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(ghidra_home))
    java_home = _resolve_java_home()
    if java_home:
        os.environ.setdefault("JAVA_HOME", java_home)

    _patch_launcher_for_running_jvm()

    DiffEngine = {"VersionTrackingDiff": VersionTrackingDiff, "SimpleDiff": SimpleDiff}[engine]

    # ghidriff.setup_project appends project_name itself (line 474 in ghidra_diff_engine.py),
    # so pass project_dir directly — the final openProject path is project_dir/project_name/
    actual_project_location = project_dir

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        symbols_path = tmp_path / "symbols"
        gzfs_path = tmp_path / "gzfs"
        symbols_path.mkdir()
        gzfs_path.mkdir()

        from argparse import Namespace
        d = DiffEngine(
            args=Namespace(),
            verbose=False,
            threaded=True,
            max_ram_percent=50.0,
            force_analysis=False,
            force_diff=True,
            verbose_analysis=False,
            no_symbols=True,
            engine_log_path=None,
            engine_log_level="WARNING",
            engine_file_log_level="WARNING",
            min_func_len=10,
            use_calling_counts=False,
            bsim=False,
            bsim_full=False,
            gdts=[],
            base_address=None,
            program_options=None,
        )

        d.setup_project(
            [reference_path, new_path],
            actual_project_location,
            project_name,
            symbols_path,
            gzfs_path,
        )
        d.analyze_project(force_analysis=False)
        pdiff = d.diff_bins(reference_path, new_path)

        # ghidriff leaves self.project open; close it so apply_symbols_to_project
        # can re-open the same project without hitting a lock error.
        if d.project is not None:
            d.project.close()
            d.project = None

    return _matches_from_payload(pdiff)


def _parse_addr(s: str) -> int:
    return int(s.strip(), 16)


def _matches_from_payload(payload: dict) -> list[MatchedFunction]:
    """Parse ghidriff's pdiff dict into MatchedFunction list.

    Primary source: pdiff["functions"]["modified"] — gives ref_name, ref_addr,
    new_addr, ratio (similarity score).

    Secondary source: pdiff["matches"]["address_matches"] — all matched pairs
    including unchanged functions (not in "modified"). Unchanged → similarity=1.0.
    """
    results: list[MatchedFunction] = []
    modified_ref_addrs: set[int] = set()

    for entry in payload.get("functions", {}).get("modified", []):
        old = entry.get("old", {})
        new = entry.get("new", {})
        ratio = float(entry.get("ratio", 0.0))
        ref_addr_str = old.get("address", "")
        new_addr_str = new.get("address", "")
        if not ref_addr_str or not new_addr_str:
            continue
        ref_addr = _parse_addr(ref_addr_str)
        new_addr = _parse_addr(new_addr_str)
        results.append(MatchedFunction(
            ref_name=str(old.get("name", "")),
            ref_address=ref_addr,
            new_address=new_addr,
            similarity=ratio,
        ))
        modified_ref_addrs.add(ref_addr)

    for ref_addr_str, new_list in payload.get("matches", {}).get("address_matches", {}).items():
        ref_addr = _parse_addr(ref_addr_str)
        if ref_addr in modified_ref_addrs:
            continue
        if not new_list:
            continue
        new_addr_str = new_list[0][0]
        results.append(MatchedFunction(
            ref_name="",  # name not available in address_matches payload
            ref_address=ref_addr,
            new_address=_parse_addr(new_addr_str),
            similarity=1.0,
        ))

    return results
