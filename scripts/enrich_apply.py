#!/usr/bin/env python3
"""Apply agent-enrich naming results (functions and variables).

Reads result_*.json files from agent_enrich_state/, applies high-confidence names
to the Ghidra project and reference JSONs, routes medium/low to reconcile.toml.
Writes agent_enrich_state/applied_this_round.json with addresses confirmed this round.

Usage:
    .venv/bin/python scripts/enrich_apply.py
        [--state-dir agent_enrich_state]
        [--reference-dir reference]
        [--project-dir ~/rom-analyzer-projects]
        [--project-name rom-analyzer]
        [--ghidra-home /opt/homebrew/opt/ghidra/libexec]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

GHIDRA_HOME = Path(os.environ.get("GHIDRA_HOME", "/opt/homebrew/opt/ghidra/libexec"))
PROJ_DIR = Path.home() / "rom-analyzer-projects"
PROJ_NAME = "rom-analyzer"
STATE_DIR = REPO / "agent_enrich_state"
REFERENCE_DIR = REPO / "reference"


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
            json.dumps({
                "addresses": [], "applied": 0, "review": 0,
                "vars_applied": 0, "vars_review": 0, "vars_addresses": [],
            }, indent=2)
        )
        return

    results = [json.loads(f.read_text()) for f in result_files]

    fn_high = [r for r in results if r.get("item_type", "function") == "function"
               and r["confidence"] == "high"]
    fn_review = [r for r in results if r.get("item_type", "function") == "function"
                 and r["confidence"] in ("medium", "low")]
    var_high = [r for r in results if r.get("item_type") == "variable"
                and r["confidence"] == "high"]
    var_review = [r for r in results if r.get("item_type") == "variable"
                  and r["confidence"] in ("medium", "low")]

    print(f"Functions: {len(fn_high)} high, {len(fn_review)} medium/low")
    print(f"Variables: {len(var_high)} high, {len(var_review)} medium/low")

    applied_addresses: list[str] = []
    vars_addresses: list[str] = []

    needs_ghidra = fn_high or var_high
    if needs_ghidra:
        from rom_analyzer.ghidra import setup_environment, apply_labels
        from rom_analyzer.annotations_io import (
            load_annotations, save_annotations,
            AnnotationFunction, AnnotationSymbol,
        )
        from rom_analyzer.types import PropagatedSymbol
        from rom_analyzer.registry import load_registry

        setup_environment(args.ghidra_home)
        import pyghidra
        pyghidra.start()

        registry = load_registry(args.reference_dir / "registry.toml")
        json_paths = {e.id: e.json_path for e in registry}
        project = pyghidra.open_project(args.project_dir, args.project_name, create=False)

        with project:
            if fn_high:
                by_rom: dict[str, list[dict]] = {}
                for r in fn_high:
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
                    print(f"  [{rom_id}] Applied {n} function Ghidra labels")

                    json_path = json_paths.get(rom_id)
                    if json_path and json_path.exists():
                        store = load_annotations(json_path)
                        fn_by_ep = {f.entry_point: f for f in store.functions}
                        added = updated = 0
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
                        print(f"  [{rom_id}] Functions JSON: {updated} updated, {added} added")

            if var_high:
                by_rom_v: dict[str, list[dict]] = {}
                for r in var_high:
                    by_rom_v.setdefault(r["rom"], []).append(r)

                for rom_id, rom_results in by_rom_v.items():
                    prog_name = rom_results[0].get("prog_name", "")
                    symbols = [
                        PropagatedSymbol(
                            name=r["proposed_name"],
                            ref_address=int(r["address"], 16),
                            new_address=int(r["address"], 16),
                            category=r.get("category", "ram_global"),
                            confidence="high",
                            source="llm:agent",
                            score=1.0,
                        )
                        for r in rom_results
                    ]
                    n = apply_labels(project, prog_name, symbols)
                    print(f"  [{rom_id}] Applied {n} variable Ghidra labels")

                    json_path = json_paths.get(rom_id)
                    if json_path and json_path.exists():
                        store = load_annotations(json_path)
                        sym_by_addr = {s.address: s for s in store.symbols}
                        added = updated = 0
                        for r in rom_results:
                            addr = int(r["address"], 16)
                            if addr in sym_by_addr:
                                sym_by_addr[addr].name = r["proposed_name"]
                                sym_by_addr[addr].source = "llm:agent"
                                sym_by_addr[addr].confidence = "high"
                                updated += 1
                            else:
                                store.symbols.append(AnnotationSymbol(
                                    name=r["proposed_name"],
                                    address=addr,
                                    category=r.get("category", "ram_global"),
                                    data_type=r.get("data_type"),
                                    confidence="high",
                                    source="llm:agent",
                                ))
                                added += 1
                            applied_addresses.append(r["address"])
                            vars_addresses.append(r["address"])
                        save_annotations(json_path, store)
                        print(f"  [{rom_id}] Variables JSON: {updated} updated, {added} added")

    all_review = fn_review + var_review
    if all_review:
        from rom_analyzer.enrich import ReconcileItem, write_reconcile, read_reconcile

        existing_items: list[ReconcileItem] = []
        if reconcile_path.exists():
            existing_items = read_reconcile(reconcile_path)

        new_items = [
            ReconcileItem(
                target=r["rom"],
                direction="forward",
                address=int(r["address"], 16),
                category=r.get("category", "ram_global") if r.get("item_type") == "variable"
                         else "function",
                current=r.get("current_name"),
                proposed=r["proposed_name"],
                source="llm:agent",
                evidence=r.get("reasoning", ""),
                verdict="proposed",
            )
            for r in all_review
        ]
        write_reconcile(reconcile_path, existing_items + new_items)
        print(f"  Appended {len(new_items)} items to {reconcile_path}")

    fn_applied = len(applied_addresses) - len(vars_addresses)
    (args.state_dir / "applied_this_round.json").write_text(
        json.dumps({
            "addresses": applied_addresses,
            "applied": fn_applied,
            "review": len(fn_review),
            "vars_applied": len(vars_addresses),
            "vars_review": len(var_review),
            "vars_addresses": vars_addresses,
        }, indent=2)
    )
    print(f"Done. {fn_applied} function names applied, {len(vars_addresses)} variable names applied, "
          f"{len(fn_review)} fn / {len(var_review)} var queued for review.")


if __name__ == "__main__":
    main()
