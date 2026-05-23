#!/usr/bin/env bash
# scripts/run-outlander-local.sh — local fast-iteration loop for outlander ROM analysis.
#
# Bypasses Docker; uses Ghidra from Homebrew and the repo .venv directly.
# First run after a BFS/matching fix should always use --clean to discard
# stale Ghidra project state (wrong labels persist across runs otherwise).
#
# Usage:
#   ./scripts/run-outlander-local.sh           # reuse existing Ghidra project
#   ./scripts/run-outlander-local.sh --clean   # wipe project, start fresh
#
# Prerequisites:
#   brew install ghidra                          (or export GHIDRA_HOME=...)
#   ghidra-m32r extension installed in Ghidra    (see README)
#   roms/outlander-c7280011.bin                  (user-supplied; gitignored)
#   roms/Z27AG_JDM_5MT_1860B104.bin             (user-supplied; gitignored)
set -euo pipefail
cd "$(dirname "$0")/.."

GHIDRA_HOME="${GHIDRA_HOME:-/opt/homebrew/opt/ghidra/libexec}"
PROJECT_DIR="$HOME/rom-analyzer-projects"
PROJECT_NAME="outlander-c7280011"
OUT_DIR="$PROJECT_DIR/$PROJECT_NAME-out"

OUTLANDER_ROM="roms/outlander-c7280011.bin"
REFERENCE_ROM="roms/Z27AG_JDM_5MT_1860B104.bin"
REFERENCE_XML="reference/33520003.xml"
FLASH_TXT="reference/colt_flash.txt"
MAP_TXT="reference/colt_map.txt"

# ── prereq checks ─────────────────────────────────────────────────────────────

for f in "$OUTLANDER_ROM" "$REFERENCE_ROM" "$REFERENCE_XML" "$FLASH_TXT" "$MAP_TXT"; do
    [[ -f "$f" ]] || { echo "error: missing $f" >&2; exit 1; }
done

[[ -x "$GHIDRA_HOME/ghidraRun" ]] || {
    echo "error: ghidraRun not found at $GHIDRA_HOME" >&2
    echo "       Install: brew install ghidra   or   export GHIDRA_HOME=..." >&2
    exit 1
}

ROM_ANALYZER=".venv/bin/rom-analyzer"
[[ -x "$ROM_ANALYZER" ]] || {
    echo "error: $ROM_ANALYZER not found — activate the venv and run: pip install -e ." >&2
    exit 1
}

# ── flags ─────────────────────────────────────────────────────────────────────

CLEAN_FLAG=()
if [[ "${1:-}" == "--clean" ]]; then
    CLEAN_FLAG=(--clean-project)
    echo "==> --clean: wiping existing project state for $PROJECT_NAME"
fi

mkdir -p "$OUT_DIR"

# ── run ───────────────────────────────────────────────────────────────────────

echo "==> GHIDRA_HOME : $GHIDRA_HOME"
echo "==> Project     : $PROJECT_DIR/$PROJECT_NAME"
echo "==> Output      : $OUT_DIR"
echo ""

GHIDRA_HOME="$GHIDRA_HOME" \
"$ROM_ANALYZER" \
    "$OUTLANDER_ROM" \
    --variant fp8000 \
    --reference "$REFERENCE_XML" \
    --flash-txt "$FLASH_TXT" \
    --map-txt "$MAP_TXT" \
    --reference-rom "$REFERENCE_ROM" \
    --ghidra-home "$GHIDRA_HOME" \
    --project-dir "$PROJECT_DIR" \
    --project-name "$PROJECT_NAME" \
    --out "$OUT_DIR" \
    --diff-engine SimpleDiff \
    --enrich-project \
    "${CLEAN_FLAG[@]}"

echo ""
echo "==> Output files in $OUT_DIR:"
ls -lh "$OUT_DIR/"

# ── open Ghidra ───────────────────────────────────────────────────────────────

GHIDRA_PROJ="$PROJECT_DIR/$PROJECT_NAME/$PROJECT_NAME.gpr"
if [[ -f "$GHIDRA_PROJ" ]]; then
    echo ""
    echo "==> Opening $GHIDRA_PROJ"
    "$GHIDRA_HOME/ghidraRun" "$GHIDRA_PROJ" &
    disown
else
    echo "warning: project not found at $GHIDRA_PROJ — did the analysis succeed?" >&2
fi
