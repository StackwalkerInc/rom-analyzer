# rom-analyzer

M32R ROM analyzer: headless Ghidra (PyGhidra) producing linker fragments for mmc-patches.

## What it does

Given a stock M32R ECU ROM (e.g., a Z27AG variant), `rom-analyzer`:

1. Imports the ROM into a headless Ghidra project using the `m32r:BE:32:fp8000:default` SLEIGH variant (or the default `m32r` variant for Evo X-class ROMs).
2. Diffs against the reference 33520003 (Z27AG_JDM_5MT_1860B104) Ghidra XML via Ghidra VTSessionDB.
3. Propagates function labels and RAM globals to the new ROM's addresses.
4. Locates `rom_crc_check_step` and extracts the protected flash range.
5. Scans for unused flash (0xFF runs) and classifies by CRC band.
6. Identifies unreferenced RAM gaps.
7. Emits a `description.ld` linker fragment ready to drop into `mmc-patches/m32r/<romid>_<slug>/`, plus a starter `omni.ld.stub` and TOML reports.

## ROMs are never distributed

Per CLAUDE.md, stock ROMs are never committed to public repos. The `reference/` directory ships only the Ghidra XML export (metadata, not bytes). You supply your own ROM locally at `roms/Z27AG_JDM_5MT_1860B104.bin` (gitignored).

## Usage

```bash
# Local Python install (requires Ghidra 12.1 at GHIDRA_HOME + ghidra-m32r extension)
pip install -e .
export GHIDRA_HOME=/opt/homebrew/opt/ghidra/libexec
rom-analyzer ./my-rom.bin --variant fp8000 --out ./out

# Or via Docker (bundles everything)
docker run --rm -v "$PWD":/host ghcr.io/rcusstackwalker/rom-analyzer:latest \
    /host/my-rom.bin --variant fp8000 --out /host/out
```

## Outputs

- `description.ld` — function-entry symbols and RAM globals with addresses, ready for `mmc-patches`. Note: v0.1 does NOT yet propagate flash data labels (fuel-map / table addresses); that's v0.2 work.
- `omni.ld.stub` — INCLUDE skeleton + RAM globals + `???` placeholders for free-space and per-ROM patch parameters.
- `crc-region.toml` — `[full_flash]` and `[partial_flash]` start/end ranges.
- `flash-free.toml` — candidate free-flash blocks by CRC band.
- `ram-free.toml` — candidate free-RAM blocks (some flagged as `suspicious_large_gap`).
- `match-report.md` — match stats and CRC region.

## Workflow for adding a new ROM to mmc-patches

1. `rom-analyzer my-new-rom.bin --variant fp8000 --out out/`.
2. Review `match-report.md`; if the match rate is below ~90%, investigate before relying on the outputs.
3. Drop `out/description.ld` into `mmc-patches/m32r/<romid>_<slug>/description.ld`.
4. Hand-edit `out/omni.ld.stub` into the target's `omni.ld`: fill in patch-specific call-site hooks (compare against `mmc-patches/m32r/33520003_z27ag_mt_2006/omni.ld`), confirm `free_space_start`/`free_space_end` from `flash-free.toml`.
5. Add a per-ROM `Makefile` mirroring the 33520003 target.

## Architecture

- Pure-Python analyzers (`xml_io`, `propagate`, `crc`, `flash_space`, `ram_space`, `emit_ld`) under `rom_analyzer/`. Unit-tested in CI without Ghidra.
- Ghidra integration via `analyzeHeadless` subprocess (`rom_analyzer/ghidra.py`) and Jython post-script (`rom_analyzer/scripts/dump_references.py`) that dumps symbols + functions + RAM refs + `rom_crc_check_step` disassembly as JSON.
- Cross-ROM function matching via Ghidra's native `VTSessionDB` API (`rom_analyzer/diff.py`), plus callgraph-bootstrap/BFS/identity layers.
- The reference 33520003 Ghidra XML is vendored at `reference/33520003.xml`. The matching ROM is user-supplied at `roms/` (gitignored). End-to-end self-diff test asserts goldens match byte-for-byte; runs locally via `scripts/run-e2e.sh`.

## Companion repos

- [RcusStackwalker/ghidra-m32r](https://github.com/RcusStackwalker/ghidra-m32r) — Ghidra processor module with `m32r:2:fp8000` variant.
- [RcusStackwalker/mmc-patches](https://github.com/RcusStackwalker/mmc-patches) — patch repository consuming `description.ld` fragments produced here.
- [RcusStackwalker/codeinjector](https://github.com/RcusStackwalker/codeinjector) — Rust tool that turns compiled M32R ELFs into EcuFlash XML patches.

## License

MIT.
