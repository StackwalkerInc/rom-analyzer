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

## Multi-reference

rom-analyzer can diff a target ROM against multiple annotated references simultaneously,
arbitrate conflicts, and flag cross-family symbols that need hand-verification.

### registry.toml format

`reference/registry.toml` is the source of truth for available references. Each entry pairs
an annotation JSON (under `reference/`) with a ROM bin (under `roms/`, gitignored):

```toml
[[reference]]
id = "33520003"
json = "33520003.json"
rom = "Z27AG_JDM_5MT_1860B104.bin"
family = "z27ag"
variant = "fp8000"
priority = 100
features = ["obd", "mut", "crc", "mode23"]
notes = "primary Z27AG reference (Z27AG_JDM_5MT_1860B104)"
```

`variant` must match `--variant`; `priority` (higher = preferred) arbitrates when two
references disagree on a symbol address.

### Default behaviour

When `reference/registry.toml` exists, rom-analyzer automatically selects all
`variant`-compatible registered references whose ROM bin is present in `roms/` and runs the
full matching + propagation pipeline against each. Results are merged by priority before
emitting outputs.

### Flags

- `--registry PATH` — path to registry TOML (default: `reference/registry.toml`).
  If the file is absent, falls back to `--reference`/`--reference-rom` (legacy mode).
- `--reference-id ID` — restrict to this registry id (repeatable; can pass multiple times).
- `--exclude-id ID` — drop this registry id from the selected set (repeatable).
- `--fast` — accepted but not yet implemented; reserved for greedy incremental matching.

### New outputs with >1 reference

- `reference-conflicts.md` — two sections: `## Disagreements` (two references mapped the
  same symbol to different addresses, arbitrated by priority) and `## Cross-family VERIFY`
  (symbols carried from a reference whose `family` differs from the primary — safe to use
  but should be confirmed in Ghidra).
- `description.ld` gains `/* from <id> */` provenance comments after each symbol when more
  than one reference contributed. Single-reference runs are unchanged (no comments emitted).

### Authoring a reference

From an enriched Ghidra project:

1. Run rom-analyzer on the new ROM and enrich its Ghidra project with `--enrich-project`.
2. Export annotations: `python rom_analyzer/scripts/export_annotations.py`.
3. Place the output as `reference/<id>.json`.
4. Add a `[[reference]]` entry to `reference/registry.toml`.
5. Commit the JSON and updated registry (no ROM binary — gitignored).

From mmc-research text tables (`colt_flash.txt` / `colt_map.txt` / `description.ld` / `.S`),
use `build_reference_from_txt` — see [Cross-referencing references](#cross-referencing-references).

### Backward compatibility

If `registry.toml` is absent, the `--reference` (JSON path) and `--reference-rom` (bin
path) legacy flags are used exactly as before. Existing single-reference invocations are
fully unchanged.

## Cross-referencing references

References enrich each other: a function decoded in one ROM but unnamed in another can be
carried across by bytecode match, and CAN message semantics propagate by SID even when slot
indices differ between ROMs. This is how the reference corpus grows.

### Building a reference from mmc-research tables

Before you can cross-reference you need annotated references. `build_reference_from_txt`
turns mmc-research's hand-decoded symbol tables into a reference JSON:

```bash
python -m rom_analyzer.scripts.build_reference_from_txt \
  --flash colt_flash.txt \             # flash data + function declarations
  --map   colt_map.txt \               # fp-relative RAM globals (also singa_map.txt)
  --description-ld description.ld \     # 'name = 0xADDR;' flash labels (CVT decodes)
  --asm   colt_commented.S \           # /*decl*/ comments before each address line
  --rom   <rom>.bin \                  # for sha256 + erased-flash typo removal
  --rom-id <id> --out reference/<id>.json
```

At least one source is required; combine whatever the ROM directory provides. The builder:

- merges sources, preferring typed `colt_flash`/`colt_map` over untyped `.S`/`description.ld`
  labels at the same address;
- drops `.S` rounding artifacts — objdump lists data at disassembly-line boundaries, so a
  comment for a sub-aligned symbol lands a few bytes off the precise table address;
- drops **function** entries that fall in erased (`0xFF`) flash — typos that match no code
  (data labels in blank/erased areas are kept);
- makes every name unique — the lowest-address object keeps the canonical name; genuine
  duplicates (mirrored code, name reuse) get an address suffix (`name_<hexaddr>`).

Then register the result in `registry.toml` (see above).

### Reference-to-reference enrichment

To find what reference **B** can contribute to reference **A**, analyze A's own ROM using
B as the reference, then compare the result to A's existing annotations:

```bash
rom-analyzer roms/<A>.bin --variant fp8000 --reference-id <B> --out out/ab
```

`out/ab/description.ld` now holds B's labels propagated onto A's addresses. Compare them to
`reference/<A>.json` by address:

- **agreement** — same name at the same address: corroboration the match is sound.
- **new** — B names an address A didn't: an enrichment candidate.
- **conflict** — both name the address, differently: review by hand.

Apply only what is reliable, tagging the origin as `source = "xref:<B>"`:

- **Functions** are bytecode-matched and cross-family safe — apply freely.
- **RAM / data are NOT** carried by absolute address across families: a given fp-offset can
  hold a different variable in another ECU. Propagate a RAM symbol only when it is accessed
  the same way in the matched function in both ROMs (usage-equivalence), never by raw offset.
- **CAN slots** must be matched by **SID**, never by handler bytecode — every
  `can0_slotN_rx_update` shares the same code shape, so bytecode pairing produces false
  friends. Use `--emit-can-slots` (below).

After applying cross-referenced labels, the same de-duplication that runs in the builder
(`drop_imprecise_s_duplicates` → `drop_erased_flash_entries` → `dedup_symbol_names`) keeps
the reference linker-clean.

### CAN slot semantics by SID

```bash
rom-analyzer roms/<rom>.bin --variant fp8000 --reference-id <id> --emit-can-slots --out out/
```

`can-slots.toml` decodes each mailbox's 11-bit SID — `(sid0 & 0x1f) << 6 | (sid1 & 0x3f)`,
with the two flash tables located from `can0_slot_check_sid` — and assigns the known
semantic (ABS = `0x231`, EPS = `0x2f1`, ASC = `0x300`, AC = `0x443`, …). Because the SID is
stable while the slot index shifts between ROMs (ABS is slot 7 on 33520003 but slot 8 on
30200003), this reliably names the handler in any ROM as
`can0_slot{N}_{semantic}_{rx|tx}_update`.

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
- Reference annotations are vendored as JSON at `reference/<id>.json` (metadata only, no bytes); the matching ROM is user-supplied at `roms/` (gitignored). End-to-end self-diff test asserts goldens match byte-for-byte; runs locally via `scripts/run-e2e.sh`.

## Companion repos

- [RcusStackwalker/ghidra-m32r](https://github.com/RcusStackwalker/ghidra-m32r) — Ghidra processor module with `m32r:2:fp8000` variant.
- [RcusStackwalker/mmc-patches](https://github.com/RcusStackwalker/mmc-patches) — patch repository consuming `description.ld` fragments produced here.
- [RcusStackwalker/codeinjector](https://github.com/RcusStackwalker/codeinjector) — Rust tool that turns compiled M32R ELFs into EcuFlash XML patches.

## License

MIT.
