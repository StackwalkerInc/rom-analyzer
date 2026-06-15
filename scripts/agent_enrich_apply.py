#!/usr/bin/env python3
"""Apply agent-enrich naming results.

Reads result_*.json files from agent_enrich_state/, applies high-confidence names
to the Ghidra project and reference JSONs, routes medium/low to reconcile.toml.
Writes agent_enrich_state/applied_this_round.json with addresses confirmed this round.

Usage:
    .venv/bin/python scripts/agent_enrich_apply.py
        [--state-dir agent_enrich_state]
        [--reference-dir reference]
        [--project-dir ~/rom-analyzer-projects]
        [--project-name rom-analyzer]
        [--ghidra-home /opt/homebrew/opt/ghidra/libexec]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

GHIDRA_HOME = Path("/opt/homebrew/opt/ghidra/libexec")
PROJ_DIR = Path.home() / "rom-analyzer-projects"
PROJ_NAME = "rom-analyzer"
STATE_DIR = REPO / "agent_enrich_state"
REFERENCE_DIR = REPO / "reference"
RECONCILE_PATH = REFERENCE_DIR / "enrichment" / "corpus.reconcile.toml"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=STATE_DIR)
    parser.add_argument("--reference-dir", type=Path, default=REFERENCE_DIR)
    parser.add_argument("--project-dir", type=Path, default=PROJ_DIR)
    parser.add_argument("--project-name", default=PROJ_NAME)
    parser.add_argument("--ghidra-home", type=Path, default=GHIDRA_HOME)
    args = parser.parse_args()

    reconcile_path = args.reference_dir / "enrichment" / "corpus.reconcile.toml"

    result_files = sorted(args.state_dir.glob("result_*.json"))
    if not result_files:
        print("No result files found.")
        (args.state_dir / "applied_this_round.json").write_text(
            json.dumps({"addresses": [], "applied": 0, "review": 0}, indent=2)
        )
        return

    results = [json.loads(f.read_text()) for f in result_files]
    high = [r for r in results if r["confidence"] == "high"]
    review = [r for r in results if r["confidence"] in ("medium", "low")]

    print(f"Results: {len(high)} high, {len(review)} medium/low")

    applied_addresses: list[str] = []

    if high:
        from rom_analyzer.ghidra import setup_environment, apply_labels
        from rom_analyzer.annotations_io import load_annotations, save_annotations, AnnotationFunction
        from rom_analyzer.types import PropagatedSymbol
        from rom_analyzer.registry import load_registry

        setup_environment(args.ghidra_home)
        import pyghidra
        pyghidra.start()

        registry = load_registry(args.reference_dir / "registry.toml")
        json_paths = {e.id: e.json_path for e in registry}

        project = pyghidra.open_project(args.project_dir, args.project_name, create=False)

        with project:
            by_rom: dict[str, list[dict]] = {}
            for r in high:
                by_rom.setdefault(r["rom"], []).append(r)

            for rom_id, rom_results in by_rom.items():
                prog_name = rom_results[0]["prog_name"]
                symbols = [
                    PropagatedSymbol(
                        name=r["proposed_name"],
                        ref_address=int(r["address"], 16),
                        new_address=int(r["address"], 16),
                        category="function",
                        confidence="high",
                        source="llm:agent",
                        score=1.0,
                    )
                    for r in rom_results
                ]
                n = apply_labels(project, prog_name, symbols)
                print(f"  [{rom_id}] Applied {n} Ghidra labels")

                json_path = json_paths.get(rom_id)
                if json_path and json_path.exists():
                    store = load_annotations(json_path)
                    fn_by_ep = {f.entry_point: f for f in store.functions}
                    added = 0
                    updated = 0
                    for r in rom_results:
                        ep = int(r["address"], 16)
                        if ep in fn_by_ep:
                            fn_by_ep[ep].name = r["proposed_name"]
                            fn_by_ep[ep].source = "llm:agent"
                            fn_by_ep[ep].confidence = "high"
                            updated += 1
                        else:
                            store.functions.append(AnnotationFunction(
                                name=r["proposed_name"],
                                entry_point=ep,
                                confidence="high",
                                source="llm:agent",
                            ))
                            added += 1
                        applied_addresses.append(r["address"])
                    save_annotations(json_path, store)
                    print(f"  [{rom_id}] JSON: {updated} updated, {added} added")

    if review:
        from rom_analyzer.enrich import ReconcileItem, write_reconcile, read_reconcile

        existing_items: list[ReconcileItem] = []
        if reconcile_path.exists():
            existing_items = read_reconcile(reconcile_path)

        new_items = [
            ReconcileItem(
                target=r["rom"],
                direction="forward",
                address=int(r["address"], 16),
                category="function",
                current=r.get("current_name"),
                proposed=r["proposed_name"],
                source="llm:agent",
                evidence=r.get("reasoning", ""),
                verdict="proposed",
            )
            for r in review
        ]
        write_reconcile(reconcile_path, existing_items + new_items)
        print(f"  Appended {len(new_items)} items to {reconcile_path}")

    (args.state_dir / "applied_this_round.json").write_text(
        json.dumps({
            "addresses": applied_addresses,
            "applied": len(applied_addresses),
            "review": len(review),
        }, indent=2)
    )
    print(f"Done. {len(applied_addresses)} names applied, {len(review)} queued for review.")


if __name__ == "__main__":
    main()
