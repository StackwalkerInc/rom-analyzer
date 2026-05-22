"""Wrapper around ghidriff's Python API.

ghidriff is a Python tool for diffing two binaries via Ghidra. We invoke its
engine programmatically and translate its match output into our MatchedFunction
shape.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path

from rom_analyzer.ghidra import _resolve_java_home
from rom_analyzer.types import MatchedFunction


def run_ghidriff(
    ghidra_home: Path,
    reference_input: Path,
    new_input: Path,
    project_dir: Path,
    language_id: str,
) -> list[MatchedFunction]:
    """Invoke `ghidriff` CLI in JSON-output mode and return matched functions.

    We shell out to the ghidriff CLI rather than its in-process API because
    ghidriff manages Ghidra projects internally; its CLI handles the multi-step
    import/analyze/diff orchestration in one invocation.

    Output JSON shape (per current ghidriff schema): a top-level dict with a
    `matches` list of `{ref_func, new_func, similarity}` entries where each
    func entry includes `name`, `entry_point`.
    """
    project_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp_out:
        out_dir = Path(tmp_out)
        cmd = [
            "ghidriff",
            "--project-location", str(project_dir),
            "--output-path", str(out_dir),
            "--language-id", language_id,
            "--ghidra-install-dir", str(ghidra_home),
            "--json",
            str(reference_input),
            str(new_input),
        ]
        env = os.environ.copy()
        java_home = _resolve_java_home()
        if java_home:
            env["JAVA_HOME"] = java_home

        result = subprocess.run(cmd, env=env, check=False, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"ghidriff failed (exit {result.returncode}):\n"
                f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
            )

        # ghidriff writes <new>-vs-<ref>.json in output dir
        json_files = list(out_dir.glob("*.json"))
        if not json_files:
            raise RuntimeError(
                f"ghidriff produced no JSON output in {out_dir}; "
                f"STDOUT:\n{result.stdout}"
            )
        payload = json.loads(json_files[0].read_text())

    return _matches_from_payload(payload)


def _matches_from_payload(payload: dict) -> list[MatchedFunction]:
    """Translate ghidriff's JSON schema to MatchedFunction. Tolerant of
    schema-key drift across ghidriff versions: tries common alternatives.
    """
    matches_raw = (
        payload.get("matches")
        or payload.get("matched")
        or payload.get("functions", {}).get("matched", [])
    )
    out: list[MatchedFunction] = []
    for entry in matches_raw:
        ref = entry.get("ref_func") or entry.get("old_func") or entry.get("source")
        new = entry.get("new_func") or entry.get("target")
        sim = entry.get("similarity") or entry.get("score") or 0.0
        if not ref or not new:
            continue
        ref_addr = int(ref["entry_point"], 16) if isinstance(ref["entry_point"], str) else ref["entry_point"]
        new_addr = int(new["entry_point"], 16) if isinstance(new["entry_point"], str) else new["entry_point"]
        out.append(
            MatchedFunction(
                ref_name=ref["name"],
                ref_address=ref_addr,
                new_address=new_addr,
                similarity=float(sim),
            )
        )
    return out
