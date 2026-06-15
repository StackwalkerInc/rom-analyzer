#!/usr/bin/env bash
# scripts/run-e2e.sh — runs the E2E self-diff locally against a user-supplied ROM.
# Requires GHIDRA_HOME pointing at a Ghidra install with the StackwalkerInc/ghidra-m32r
# extension already installed, plus the ROM at roms/Z27AG_JDM_5MT_1860B104.bin.
set -euo pipefail
cd "$(dirname "$0")/.."

ROM="roms/Z27AG_JDM_5MT_1860B104.bin"
if [[ ! -f "$ROM" ]]; then
    echo "error: $ROM not found. Place your local copy there and re-run." >&2
    exit 1
fi

: "${GHIDRA_HOME:?error: GHIDRA_HOME unset; export it before running}"

pytest -m e2e -v
