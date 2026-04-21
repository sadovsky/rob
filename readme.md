# R.O.B. — Reverse-engineering Opcode Buddy

<img src="https://upload.wikimedia.org/wikipedia/commons/6/6c/NES-ROB.jpg" alt="NES R.O.B." width="320"/>

An annotated 6502 disassembler for NES games. Point it at an iNES ROM and it
produces a single self-contained HTML page with hyperlinked cross-references,
auto-generated labels, and named NES hardware registers.

## What it does

- Parses iNES headers and extracts the 32 KB PRG ROM.
- Runs a recursive-descent disassembly starting from the NMI / RESET / IRQ
  vectors, following `JSR`, `JMP abs`, and conditional branches.
- Rescues routines reached only via dispatch tables:
  - the byte immediately after every `RTS` / `RTI` / `JMP` / `BRK` is
    tried as a candidate entry point;
  - every word-aligned 16-bit value in unmarked data whose high byte is
    in PRG range (`$80-$ff`) is tried as a candidate code pointer.
  - Tentative traces commit only if they run for ≥6 clean instructions
    ending in a terminator, and contain no `BRK` — which filters out
    data tables that happen to start with a valid opcode byte.
- Marks reachable bytes as code; everything else is emitted as batched
  `.byte` data.
- Auto-labels every jump/branch target (`L_xxxx`) and data reference
  (`D_xxxx`), and turns them into in-page anchor links.
- Resolves NES hardware registers by name (`PPUCTRL`, `OAMDMA`, `SND_CHN`, …).
- Looks up known RAM addresses from a small per-game table (e.g. 1942's
  score / lives / rolls / level bytes).
- Renders the whole listing in a SuperMarioBros-disassembly-style column
  layout (address · bytes · label · mnemonic · operand · comment).

## Scope and limits

- **Mapper 0 (NROM-256) only.** 32 KB PRG mapped at `$8000-$ffff`, no
  bank switching.
- **Indirect jumps** (`JMP (addr)`) and jump-table dispatchers whose
  tables live outside `$80-$ff` high-byte PRG pointers won't be traced.
- **No CHR decoding.** Pattern tables are ignored.
- **Undocumented 6502 opcodes** terminate the current trace and fall back
  to data.

## Usage

Requires Python 3. `disasm.py` has no dependencies. The optional
runtime probe additionally needs [`nes-py`](https://github.com/Kautenja/nes-py).

```
python3 disasm.py 1942.nes -o 1942.html
```

Open the resulting HTML file in any browser. Click a `L_xxxx` / `D_xxxx`
reference to jump to its definition.

## Verification

Two scripts sanity-check the output:

- `roundtrip.py` reparses the generated HTML and confirms that every byte
  in the listing reconstructs the original PRG exactly (no skipped, double-
  emitted, or misaddressed bytes). On 1942: 32768/32768 bytes match.
- `runtime_probe.py` boots the ROM through `nes-py`, presses Start, and
  checks that the RAM addresses we labeled (`Score_*`, `Lives_*`, `Rolls`,
  `Level`) actually hold the values Data Crystal documents once the game
  is running. For 1942 this confirms `Lives_Ones=$02`, `Rolls=$03`, etc.

## Files

- `disasm.py` — the disassembler.
- `roundtrip.py` — reassembly round-trip check.
- `runtime_probe.py` — `nes-py` live-RAM validator.
- `1942.html` — pre-rendered example output.

The 1942 ROM itself is not redistributed here — supply your own dump as
`1942.nes`.

## Adding per-game annotations

RAM labels live in the `RAM_LABELS` dict in `disasm.py`. Each entry maps an
address to a `(name, comment)` pair. The shipped table covers 1942, sourced
from [Data Crystal's RAM map](https://datacrystal.tcrf.net/wiki/1942_(NES)/RAM_map).
