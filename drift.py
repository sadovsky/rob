#!/usr/bin/env python3
"""Multi-checkpoint drift analyzer for scripted scenarios.

Runs a scenario via scenarios.py, then for every RAM byte that changes
across checkpoints prints a per-checkpoint timeline + a trend tag
(UP/DOWN/SAW/FLIP) + a list of write-sites in the disassembly. This
is the "what's a steady counter vs what's input-driven" view that we
hand-rolled twice in throwaway _drift*.py scripts; consolidate it here.

Usage:
    python3 drift.py <scenario> [--genie CODE ...] [--top N]
                                [--monotonic-only] [--addr-range LO:HI]

Examples:
    python3 drift.py long_idle --genie SZXLKEVK
    python3 drift.py die_once --top 30
    python3 drift.py enemy_observe --genie SZXLKEVK --addr-range 0x48e:0x683
"""

import argparse
import os
import sys
import warnings

warnings.filterwarnings('ignore')
os.environ.setdefault('PYTHONWARNINGS', 'ignore')

import disasm
import scenarios


# Default exclusions: same as scenarios.diff (sprite OAM is too noisy).
DEFAULT_EXCLUDE = ((0x100, 0x200), (0x200, 0x300))


def trend(col):
    """Classify a per-checkpoint timeline. Returns (tag, score) where
    score is a sortable secondary (e.g. number of strict steps for
    monotone trends, swing magnitude for SAW). Returns None for FLAT."""
    if min(col) == max(col):
        return None
    diffs = [col[i+1] - col[i] for i in range(len(col)-1)]
    if all(d >= 0 for d in diffs) and any(d > 0 for d in diffs):
        return ('UP', sum(1 for d in diffs if d > 0))
    if all(d <= 0 for d in diffs) and any(d < 0 for d in diffs):
        return ('DOWN', sum(1 for d in diffs if d < 0))
    # Distinguish saw (oscillates around something) from flip (binary toggle).
    distinct = sorted(set(col))
    if len(distinct) == 2:
        return ('FLIP', sum(1 for d in diffs if d != 0))
    return ('SAW', max(col) - min(col))


def collect(snaps, exclude=DEFAULT_EXCLUDE):
    """Return {addr: timeline} for every byte that's not constant."""
    timelines = {}
    for addr in range(len(snaps[0])):
        if any(lo <= addr < hi for (lo, hi) in exclude):
            continue
        col = [int(s[addr]) for s in snaps]
        if min(col) == max(col):
            continue
        timelines[addr] = col
    return timelines


def parse_addr_range(s):
    if not s:
        return None
    lo_str, hi_str = s.split(':')
    return (int(lo_str, 0), int(hi_str, 0))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('scenario', help='scenario name (see scenarios.py --list)')
    ap.add_argument('--rom', default='1942.nes')
    ap.add_argument('--labels', default='labels.json')
    ap.add_argument('--genie', action='append', default=[],
                    help='Game Genie code to apply (repeatable)')
    ap.add_argument('--top', type=int, default=60,
                    help='print at most N rows (default 60)')
    ap.add_argument('--monotonic-only', action='store_true',
                    help='only show UP/DOWN trends')
    ap.add_argument('--addr-range', default=None,
                    help='restrict to addresses in [LO,HI), '
                         'e.g. 0x48e:0x683 for the entity SOA')
    args = ap.parse_args()

    if args.scenario not in scenarios.SCENARIOS:
        sys.exit(f'unknown scenario: {args.scenario}')
    scenario = scenarios.SCENARIOS[args.scenario]

    rom_path = scenarios.ensure_fixed_rom(args.rom, tuple(args.genie))
    if args.genie:
        print(f'applied Game Genie codes: {", ".join(args.genie)}',
              file=sys.stderr)

    snaps = scenarios.run(rom_path, scenario)
    print(f'snapshots: {len(snaps)}', file=sys.stderr)

    addr_range = parse_addr_range(args.addr_range)
    exclude = list(DEFAULT_EXCLUDE)
    timelines = collect(snaps, exclude=exclude)
    if addr_range:
        lo, hi = addr_range
        timelines = {a: t for a, t in timelines.items() if lo <= a < hi}

    rom = disasm.load_ines(args.rom)
    dis = disasm.Disassembler(rom['prg'])
    dis.disassemble()
    ram_labels = dict(disasm.RAM_LABELS)
    ram_labels.update(disasm.load_user_labels(args.labels))

    def label(addr):
        return ram_labels[addr][0] if addr in ram_labels else ''

    rows = []
    for addr, col in timelines.items():
        t = trend(col)
        if not t:
            continue
        if args.monotonic_only and t[0] not in ('UP', 'DOWN'):
            continue
        rows.append((addr, t[0], t[1], col))

    # Sort: UP/DOWN first by step-count desc, then SAW/FLIP by magnitude.
    tag_order = {'UP': 0, 'DOWN': 0, 'SAW': 1, 'FLIP': 2}
    rows.sort(key=lambda r: (tag_order[r[1]], -r[2], r[0]))

    print(f'addresses changing across {len(snaps)} checkpoints: {len(rows)}')
    print()
    print(f'{"addr":<8}{"trend":<6}{"score":<7}{"label":<22}timeline    writers')
    print('-' * 110)
    for addr, t, score, col in rows[:args.top]:
        ts = ' '.join(f'{v:02x}' for v in col)
        writers = sorted(set(dis.writes_to(addr)))
        wstr = ','.join(f'L_{p:04x}' for p in writers[:3])
        if len(writers) > 3:
            wstr += f',+{len(writers)-3}'
        print(f'${addr:04x}  {t:<6}{score:<7}{label(addr):<22}{ts}    {wstr}')


if __name__ == '__main__':
    main()
