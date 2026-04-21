# R.O.B. — Reverse-engineering Opcode Buddy

<img src="https://upload.wikimedia.org/wikipedia/commons/6/6c/NES-ROB.jpg" alt="NES R.O.B." width="320"/>

An annotated 6502 disassembler for NES games. Point it at an iNES ROM and it
produces a single self-contained HTML page with hyperlinked cross-references,
auto-generated labels, and named NES hardware registers.

## What it does

- Parses iNES headers and extracts the 32 KB PRG ROM.
- Runs a recursive-descent disassembly starting from the NMI / RESET / IRQ
  vectors, following `JSR`, `JMP abs`, and conditional branches.
- Marks reachable bytes as code; everything else is emitted as `.byte` data.
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
- **Static analysis only.** Indirect jumps (`JMP (addr)`) and jump tables
  are not followed — bytes only reached that way show up as `.byte` data.
- **No CHR decoding.** Pattern tables are ignored.
- **Undocumented 6502 opcodes** terminate the current trace and fall back
  to data.

## Usage

Requires Python 3. No dependencies.

```
python3 disasm.py 1942.nes -o 1942.html
python3 disasm.py smb1.nes -o SuperMarioBros.html
```

Open the resulting HTML file in any browser. Click a `L_xxxx` / `D_xxxx`
reference to jump to its definition.

## Files

- `disasm.py` — the disassembler.
- `1942.nes`, `smb1.nes` — sample ROMs.
- `1942.html`, `SuperMarioBros.html` — pre-rendered example output.

## Adding per-game annotations

RAM labels live in the `RAM_LABELS` dict in `disasm.py`. Each entry maps an
address to a `(name, comment)` pair. The shipped table covers 1942, sourced
from [Data Crystal's RAM map](https://datacrystal.tcrf.net/wiki/1942_(NES)/RAM_map).
