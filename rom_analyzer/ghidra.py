"""Wrapper around Ghidra's analyzeHeadless.

We never inspect Ghidra's project DB directly; we use analyzeHeadless to
import a program, run our dump_references Jython script, and consume the
resulting JSON.
"""

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class HeadlessRun:
    functions: list[dict]
    symbols: list[dict]
    ram_refs: list[int]
    rom_crc_check_step: dict | None


def _scripts_path() -> str:
    return str(Path(__file__).parent / "scripts")


def import_and_dump(
    ghidra_home: Path,
    project_dir: Path,
    project_name: str,
    input_path: Path,
    language_id: str,
    *,
    extra_args: tuple[str, ...] = (),
) -> HeadlessRun:
    """Import a binary or Ghidra XML into a Ghidra project, run dump_references,
    and return the parsed JSON.

    Project is created if absent. The input file is re-imported if not already
    present in the project (we use Ghidra's overwrite-on-re-import flag).
    """
    project_dir.mkdir(parents=True, exist_ok=True)
    analyze_headless = ghidra_home / "support" / "analyzeHeadless"
    if not analyze_headless.exists():
        raise FileNotFoundError(f"analyzeHeadless not found at {analyze_headless}")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_json = Path(tmp.name)

    cmd = [
        str(analyze_headless),
        str(project_dir),
        project_name,
        "-import", str(input_path),
        "-overwrite",
        "-processor", language_id,
        "-scriptPath", _scripts_path(),
        "-postScript", "dump_references.py", str(out_json),
    ]
    cmd.extend(extra_args)

    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"analyzeHeadless failed (exit {result.returncode}):\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )

    payload = json.loads(out_json.read_text())
    out_json.unlink(missing_ok=True)

    return HeadlessRun(
        functions=payload["functions"],
        symbols=payload["symbols"],
        ram_refs=payload["ram_refs"],
        rom_crc_check_step=payload["rom_crc_check_step"],
    )
