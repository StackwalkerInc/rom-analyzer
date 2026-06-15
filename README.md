# rom-analyzer

M32R ROM analyzer: headless Ghidra (PyGhidra) producing linker fragments for mmc-patches.

## What it does

Given a stock M32R ECU ROM, `rom-analyzer`:

1. Imports the ROM into a headless Ghidra project using the appropriate SLEIGH variant (`m32r:BE:32:fp8000:default` for Colt/Outlander family, `m32r:BE:32:default` for Evo X-class ROMs).
2. Diffs against one or more annotated reference ROMs via Ghidra's VTSessionDB API, propagating function labels and RAM globals to the target ROM's addresses.
3. Arbitrates conflicts when multiple references disagree, preferring higher-priority references and flagging cross-family symbols for verification.
4. Locates `rom_crc_check_step` and extracts the protected flash range.
5. Scans for unused flash (0xFF runs) and classifies by CRC band.
6. Identifies unreferenced RAM gaps.
7. Emits a `description.ld` linker fragment ready to drop into `mmc-patches/m32r/<romid>_<slug>/`, plus a starter `omni.ld.stub` and TOML reports.

## ROMs are never distributed

Stock ROMs are never committed to public repos. The `reference/` directory ships only annotation JSON files (symbol names, addresses, types — metadata only, no bytes). You supply your own ROM locally at `roms/` (gitignored).

## Usage

```bash
# Local Python install (requires Ghidra 12.1 at GHIDRA_HOME + ghidra-m32r extension)
pip install -e .
export GHIDRA_HOME=/opt/homebrew/opt/ghidra/libexec
rom-analyzer analyze ./my-rom.bin --variant fp8000 --out ./out

# Or via Docker (bundles Ghidra + ghidra-m32r)
docker run --rm -v "$PWD":/host ghcr.io/rcusstackwalker/rom-analyzer:latest \
    analyze /host/my-rom.bin --variant fp8000 --out /host/out
```

By default, `analyze` uses all registered references whose ROM bins are present in `roms/`,
merges their matches by priority, and emits consolidated outputs. To restrict to a single
reference:

```bash
rom-analyzer analyze ./my-rom.bin --variant fp8000 --reference-id 33520003 --out ./out
```

## References

References are annotation JSON files at `reference/<id>.json` paired with ROM bins at
`roms/<file>.bin` (gitignored). `reference/registry.toml` is the index:

```toml
[[reference]]
id = "33520003"
json = "33520003.json"
rom = "Z27AG_JDM_5MT_1860B104.bin"
family = "z27ag"
variant = "fp8000"
priority = 100
features = ["obd", "mut"]
notes = "primary Z27AG reference (Z27AG_JDM_5MT_1860B104)"
```

`variant` must match `--variant`; `priority` (higher = preferred) arbitrates when two
references disagree on a symbol address. All `variant`-compatible references whose ROM bin
is present in `roms/` are selected automatically.

### analyze flags

- `--registry PATH` — path to registry TOML (default: `reference/registry.toml`). If absent,
  falls back to `--reference`/`--reference-rom` (single-reference legacy mode).
- `--reference-id ID` — restrict to this registry id (repeatable).
- `--exclude-id ID` — drop this registry id from the selected set (repeatable).
- `--emit-mode23` — resolve and emit per-ROM OBD mode 0x23 splice-site bindings.
- `--emit-can-slots` — decode per-slot CAN SIDs and emit `can-slots.toml`.
- `--emit-obd` — extract OBD PID + DTC ground-truth labels and emit `dtc-map.toml`.
- `--enrich-project` — write propagated labels back into the Ghidra project for the target ROM.
- `--fast` — accepted but not yet implemented; reserved for greedy incremental matching.

### Outputs with multiple references

When more than one reference contributed, `description.ld` gains `/* from <id> */` provenance
comments and an additional `reference-conflicts.md` is emitted:

- `## Disagreements` — two references mapped the same symbol to different addresses;
  arbitrated by priority.
- `## Cross-family VERIFY` — symbols carried from a reference with a different `family`; safe
  to use but worth confirming in Ghidra.

## Authoring a reference

**From a Ghidra project:**

1. Run `rom-analyzer analyze` on the ROM with `--enrich-project` to write propagated symbols into Ghidra.
2. Export annotations: `python rom_analyzer/scripts/export_annotations.py`.
3. Place the output as `reference/<id>.json`.
4. Add a `[[reference]]` entry to `reference/registry.toml`.
5. Commit the JSON and updated registry (no ROM binary — gitignored).

**From hand-decoded symbol tables** (`colt_flash.txt` / `colt_map.txt` / `description.ld` / `.S`):

```bash
python -m rom_analyzer.scripts.build_reference_from_txt \
  --flash colt_flash.txt \
  --map   colt_map.txt \
  --description-ld description.ld \
  --asm   colt_commented.S \
  --rom   <rom>.bin \
  --rom-id <id> --out reference/<id>.json
```

At least one source is required. The builder merges sources (preferring typed
`colt_flash`/`colt_map` over untyped `.S`/`description.ld`), drops rounding artifacts and
erased-flash entries, and deduplicates names. Then add the result to `registry.toml`.

## Cross-referencing references

References enrich each other: a function decoded in one ROM but unnamed in another can be
carried across by bytecode match; CAN message semantics propagate by SID even when slot
indices differ between ROMs.

To find what reference **B** can contribute to reference **A**:

```bash
rom-analyzer analyze roms/<A>.bin --variant fp8000 --reference-id <B> --out out/ab
```

`out/ab/description.ld` holds B's labels propagated onto A's addresses. Rules for applying:

- **Functions** — bytecode-matched, cross-family safe; apply freely.
- **RAM / data** — carry only when usage-equivalent (accessed the same way in the matched
  function in both ROMs); never by raw offset alone.
- **CAN slots** — match by SID, never by bytecode; every `can0_slotN_rx_update` shares the
  same code shape. Use `--emit-can-slots` to get reliable semantic names.

### CAN slot semantics

```bash
rom-analyzer analyze roms/<rom>.bin --variant fp8000 --emit-can-slots --out out/
```

`can-slots.toml` decodes each mailbox's 11-bit SID — `(sid0 & 0x1f) << 6 | (sid1 & 0x3f)` —
and assigns the known semantic (ABS = `0x231`, EPS = `0x2f1`, ASC = `0x300`, AC = `0x443`, …).
Because the SID is stable while the slot index shifts between ROMs, this reliably names
handlers as `can0_slot{N}_{semantic}_{rx|tx}_update`.

## Reference enrichment (automated)

Cross-referencing is automated by two commands through a **propose → review → apply** cycle.
Human judgement is only needed on genuine conflicts.

```bash
# 1. Cross-match <id> against every registered reference (both directions),
#    auto-apply new functions, emit a reconcile file of conflicts + RAM/data for review
rom-analyzer enrich e5090011

# 2. Edit verdicts in reference/enrichment/e5090011.reconcile.toml

# 3. Apply verdicts to the reference JSONs and re-deduplicate
rom-analyzer apply-enrichment reference/enrichment/e5090011.reconcile.toml
```

`enrich` runs one Ghidra cross-match between `<id>`'s ROM and each same-variant reference,
yielding both directions: *forward* (reference labels onto `<id>`) and *back* (`<id>` labels
onto existing refs). It then:

- **auto-applies** new functions (bytecode-matched, cross-family safe; tagged `source=xref:<src>`);
- **drops** Ghidra auto-names (`FUN_*`, `icu_isr_*`) and functions landing in erased `0xFF` flash;
- **routes to review** genuine name conflicts and RAM/data candidates;
- re-runs cleanup (drop stray entries, de-dup names) on every touched JSON.

The reconcile file — one `[[item]]` per review entry; edit `verdict`:

```toml
[[item]]
target    = "33520003"            # reference being modified
direction = "back"                # forward (into <id>) | back (into existing ref)
address   = "0x804d5e"
category  = "ram_global"          # function | data | ram_global
current   = "fp12962_u16"         # target's existing name ("" if a gap)
proposed  = "tacho_output_state"  # candidate from the source reference
source    = "e5090011"
evidence  = "usage-equiv: written by tacho_set/reset in matched fn 0x14ed8"
verdict   = "proposed"            # proposed | keep | drop | <custom-name>
```

`verdict` is pre-filled by auto-resolution rules: registry `priority` wins; `sio0`/`sio1`
prefixes are held; descriptive names beat placeholders (`callNNNN`, `fpNNNN_*`); agreement
from ≥2 refs is never listed. Change only what you disagree with, then run `apply-enrichment`.

After `apply-enrichment` touches a reference that has an e2e golden (e.g. `33520003`),
refresh the golden: re-run `rom-analyzer analyze … --emit-mode23` and update `tests/golden/`.

## Outputs

- `description.ld` — function-entry symbols and RAM globals with addresses, ready for `mmc-patches`.
- `omni.ld.stub` — INCLUDE skeleton + RAM globals + `???` placeholders for free-space and per-ROM patch parameters.
- `crc-region.toml` — `[full_flash]` and `[partial_flash]` start/end ranges.
- `flash-free.toml` — candidate free-flash blocks by CRC band.
- `ram-free.toml` — candidate free-RAM blocks (some flagged as `suspicious_large_gap`).
- `match-report.md` — match stats and CRC region.
- `reference-conflicts.md` — disagreements and cross-family symbols (multi-reference runs only).

## Workflow for adding a new ROM to mmc-patches

1. `rom-analyzer analyze my-new-rom.bin --variant fp8000 --out out/`
2. Review `match-report.md`; below ~90% match rate, investigate before relying on the outputs.
3. Drop `out/description.ld` into `mmc-patches/m32r/<romid>_<slug>/description.ld`.
4. Hand-edit `out/omni.ld.stub` into the target's `omni.ld`: fill in patch-specific call-site
   hooks (compare against `mmc-patches/m32r/33520003_z27ag_mt_2006/omni.ld`), confirm
   `free_space_start`/`free_space_end` from `flash-free.toml`.
5. Add a per-ROM `Makefile` mirroring the 33520003 target.

## Architecture

- Pure-Python analyzers (`propagate`, `crc`, `flash_space`, `ram_space`, `emit_ld`, `merge`)
  under `rom_analyzer/`. Unit-tested in CI without Ghidra.
- Ghidra integration via PyGhidra (in-process JVM; `rom_analyzer/ghidra.py`). A Jython
  analysis script (`rom_analyzer/scripts/m32r_analysis.py`) extracts symbols, functions,
  RAM references, and `rom_crc_check_step` disassembly into a structured dict.
- Cross-ROM function matching via Ghidra's native `VTSessionDB` API (`rom_analyzer/diff.py`),
  plus callgraph-bootstrap/BFS/identity layers.
- Reference annotations stored as JSON at `reference/<id>.json` (metadata only, no bytes);
  the matching ROM is user-supplied at `roms/` (gitignored). End-to-end self-diff test asserts
  goldens match byte-for-byte; runs locally via `scripts/run-e2e.sh`.

## Companion repos

- [StackwalkerInc/ghidra-m32r](https://github.com/StackwalkerInc/ghidra-m32r) — Ghidra processor module with `m32r:2:fp8000` and `m32r:2:fpc000` variants.
- [RcusStackwalker/mmc-patches](https://github.com/RcusStackwalker/mmc-patches) — patch repository consuming `description.ld` fragments produced here.
- [RcusStackwalker/codeinjector](https://github.com/RcusStackwalker/codeinjector) — Rust tool that turns compiled M32R ELFs into EcuFlash XML patches.

## License

MIT.
