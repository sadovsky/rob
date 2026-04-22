#!/usr/bin/env python3
"""Scripted scenario harness for label discovery.

Each scenario boots 1942 through nes-py, holds predefined button actions
for predefined frame counts, and snapshots RAM at each checkpoint. The
correlator then joins every changed RAM byte to the STA/STX/STY
instructions in the disassembly that write it, producing a tight list
the user can read and name.

Typical loop:

    python3 scenarios.py press_start
    # -> inspect the report, identify interesting RAM writes
    # -> add "$0711": ["Fire_Cooldown", "..."] to labels.json
    python3 disasm.py 1942.nes -o 1942.html
"""

import argparse
import os
import sys
import warnings
from dataclasses import dataclass, field
from typing import List, Tuple

warnings.filterwarnings('ignore')
os.environ.setdefault('PYTHONWARNINGS', 'ignore')

import disasm
import genie


# nes-py's strict iNES parser rejects headers with non-zero flags7..15.
# Retail dumps often have flags7=$08; patch a working copy to zero those
# bytes so the emulator accepts the ROM. Optional `genie_codes` list
# applies Game Genie 6/8-letter patches at the PRG bytes they target —
# this is how we hand the emulator an "infinite lives" / "9 rolls" ROM
# without writing a real Game Genie hardware emulator.
def ensure_fixed_rom(src_path, genie_codes=()):
    with open(src_path, 'rb') as f:
        data = bytearray(f.read())
    suffix = '.fixed.nes'
    needs_patch = False
    if data[7:16] != bytes(9):
        data[7:16] = bytes(9)
        needs_patch = True
    if genie_codes:
        suffix = '.fixed.' + '_'.join(c.lower() for c in genie_codes) + '.nes'
        # PRG starts at offset 16 (no trainer in mapper-0 1942) and is
        # mapped to $8000-$ffff, so the byte at PRG_offset = addr-$8000+16.
        for code in genie_codes:
            addr, value, compare = genie.decode(code)
            off = (addr - 0x8000) + 16
            if compare is not None and data[off] != compare:
                sys.exit(f'genie code {code}: byte at ${addr:04x} is '
                         f'${data[off]:02x}, expected ${compare:02x}')
            data[off] = value
        needs_patch = True
    if not needs_patch:
        return src_path
    fixed = src_path.rsplit('.', 1)[0] + suffix
    with open(fixed, 'wb') as f:
        f.write(data)
    return fixed


# Joypad bit layout per nes-py JoypadSpace._button_map:
#   A=0x01  B=0x02  SELECT=0x04  START=0x08
#   UP=0x10 DOWN=0x20 LEFT=0x40 RIGHT=0x80
A, B, SELECT, START = 0x01, 0x02, 0x04, 0x08
UP, DOWN, LEFT, RIGHT = 0x10, 0x20, 0x40, 0x80


@dataclass
class Scenario:
    name: str
    # Each step: (action_byte, frame_count). action_byte is a bitmask of
    # buttons to hold for that many frames.
    steps: List[Tuple[int, int]]
    # Step indices (0-based, into `steps`) after which RAM should be
    # snapshotted. The baseline snapshot (before any step) is always
    # captured as checkpoint 0; step-indexed checkpoints follow it.
    checkpoints: List[int] = field(default_factory=list)
    # Short description for the report header.
    description: str = ''


_boot_steps = [(0, 30), (0, 210)]

_press_start_steps = [
    (0, 240),
    (START, 6), (0, 12),
    (START, 6), (0, 12),
    (START, 6), (0, 12),
    (START, 6), (0, 12),
    (0, 240),
]

_INGAME_SETTLE = 180  # extra idle frames after press_start to reach playable state


def _ingame(action_steps):
    """Build a scenario that boots into the game, idles INGAME_SETTLE
    more frames so the player plane is actually flying (not in the
    pre-game cutscene), snapshots that baseline, then runs the action
    steps. Returns (steps, checkpoints) = (steps, [baseline, after])."""
    settle_step = (0, _INGAME_SETTLE)
    steps = list(_press_start_steps) + [settle_step] + list(action_steps)
    baseline_idx = len(_press_start_steps)  # the settle step
    final_idx = len(steps) - 1
    return steps, [baseline_idx, final_idx]


# Baseline: enter game, snapshot, idle the same total frames the action
# scenarios use. The diff isolates "what changes during gameplay even
# without input" — scrolling, enemy AI, RNG. Subtract these addresses
# from action-scenario diffs to find truly button-driven changes.
_idle_steps,       _idle_cps       = _ingame([(0, 126)])
_press_a_steps,    _press_a_cps    = _ingame([(A, 6),     (0, 120)])
_press_b_steps,    _press_b_cps    = _ingame([(B, 6),     (0, 120)])
_move_left_steps,  _move_left_cps  = _ingame([(LEFT, 60), (0, 10)])
_move_right_steps, _move_right_cps = _ingame([(RIGHT, 60),(0, 10)])
_move_up_steps,    _move_up_cps    = _ingame([(UP, 60),   (0, 10)])
_move_down_steps,  _move_down_cps  = _ingame([(DOWN, 60), (0, 10)])


# Long auto-fire run with intermediate checkpoints. The aim is to reveal
# state that drifts during a level — scroll counters, level/wave flags,
# enemy spawn cursors. We hold B for 6 frames at a time (the press
# pattern that spawned a bullet in press_b) interleaved with idle, and
# snapshot every 600 frames (~10 seconds at 60 fps).
def _build_autofire(total_chunks=8, chunk_frames=600):
    """Returns (steps, checkpoints) for an autofire run.
    Steps after press_start+settle: alternating (B, 6) (0, chunk_frames-6)
    blocks. Checkpoints: baseline (settle) + after each chunk."""
    chunks = []
    for _ in range(total_chunks):
        chunks.append((B, 6))
        chunks.append((0, chunk_frames - 6))
    settle_step = (0, _INGAME_SETTLE)
    steps = list(_press_start_steps) + [settle_step] + chunks
    baseline_idx = len(_press_start_steps)
    cps = [baseline_idx]
    cur = baseline_idx
    for _ in range(total_chunks):
        cur += 2  # one (B,6) + one (0, chunk-6)
        cps.append(cur)
    return steps, cps


_autofire_steps, _autofire_cps = _build_autofire()


# Long pure-idle in-game run with frequent checkpoints. We sit at the
# starting position and don't press anything; the goal is to isolate
# the steady scroll/level/wave counters that advance even without input.
def _build_long_idle(total_chunks=15, chunk_frames=120):
    """Steps after press_start+settle: total_chunks * chunk_frames
    of pure idle. Checkpoints after each chunk reveal monotonic
    drifters — anything that ticks here is gameplay-time-driven, not
    input-driven."""
    chunks = [(0, chunk_frames) for _ in range(total_chunks)]
    settle_step = (0, _INGAME_SETTLE)
    steps = list(_press_start_steps) + [settle_step] + chunks
    baseline_idx = len(_press_start_steps)
    cps = [baseline_idx]
    cur = baseline_idx
    for _ in range(total_chunks):
        cur += 1
        cps.append(cur)
    return steps, cps


_long_idle_steps, _long_idle_cps = _build_long_idle()

SCENARIOS = {
    'boot': Scenario(
        name='boot',
        description=('30 idle frames, then 210 more idle — baseline '
                     'reset/init churn only; diff shows what changes '
                     'during pure attract-screen waiting'),
        steps=_boot_steps,
        checkpoints=[0, len(_boot_steps) - 1],
    ),
    'press_start': Scenario(
        name='press_start',
        description=('240 idle frames, then 4× (6 frames START + 12 idle), '
                     'then 240 idle — reaches the in-game state where '
                     'Lives_Ones / Rolls / Level are initialized'),
        steps=_press_start_steps,
        checkpoints=[0, len(_press_start_steps) - 1],
    ),
    'idle': Scenario(
        name='idle',
        description=('enter game, snapshot, idle 126 frames. Baseline '
                     'gameplay churn (scrolling, enemy AI, RNG) with no '
                     'controller input. Subtract this set from any '
                     'button scenario to isolate input-driven writes'),
        steps=_idle_steps,
        checkpoints=_idle_cps,
    ),
    'press_a': Scenario(
        name='press_a',
        description=('enter game, snapshot, hold A for 6 frames + 120 '
                     'idle. Compare against idle to find what A does'),
        steps=_press_a_steps,
        checkpoints=_press_a_cps,
    ),
    'press_b': Scenario(
        name='press_b',
        description=('enter game, snapshot, hold B for 6 frames + 120 '
                     'idle. Compare against idle to find what B does'),
        steps=_press_b_steps,
        checkpoints=_press_b_cps,
    ),
    'move_left': Scenario(
        name='move_left',
        description=('enter game, snapshot, hold LEFT for 60 frames + 10 '
                     'idle. The byte that drops monotonically is the '
                     "player's logical X position"),
        steps=_move_left_steps,
        checkpoints=_move_left_cps,
    ),
    'move_right': Scenario(
        name='move_right',
        description=('enter game, snapshot, hold RIGHT for 60 frames + '
                     '10 idle. Cross-reference with move_left: the byte '
                     'that moved opposite ways in the two scenarios is X'),
        steps=_move_right_steps,
        checkpoints=_move_right_cps,
    ),
    'move_up': Scenario(
        name='move_up',
        description='enter game, snapshot, hold UP for 60 frames + 10 idle',
        steps=_move_up_steps,
        checkpoints=_move_up_cps,
    ),
    'move_down': Scenario(
        name='move_down',
        description='enter game, snapshot, hold DOWN for 60 frames + 10 idle',
        steps=_move_down_steps,
        checkpoints=_move_down_cps,
    ),
    'autofire': Scenario(
        name='autofire',
        description=('enter game, snapshot, then 8 chunks of (B for 6 '
                     'frames + 594 idle) = ~80 seconds of auto-firing. '
                     'Snapshots every chunk reveal what monotonically '
                     'drifts (scroll counters, level/wave indices) vs '
                     'what oscillates (entity slots). Pair with '
                     '--genie IESUTYZA --genie PASIOALE for max lives '
                     'and rolls so the player survives long enough.'),
        steps=_autofire_steps,
        checkpoints=_autofire_cps,
    ),
    'long_idle': Scenario(
        name='long_idle',
        description=('enter game, snapshot, then 15 chunks of 120 idle '
                     'frames each = ~30 seconds of doing absolutely '
                     'nothing. The player will eventually get killed; '
                     'pair with --genie SZXLKEVK (Infinite Lives P1) '
                     'so the snapshots stay in-game. Use to isolate '
                     'gameplay-time-driven counters (scroll position, '
                     'wave timer) from input-driven state'),
        steps=_long_idle_steps,
        checkpoints=_long_idle_cps,
    ),
}


def run(rom_path, scenario):
    """Execute scenario on nes-py. Returns list of 2-KiB RAM snapshots,
    one per checkpoint, in the order given by scenario.checkpoints."""
    from nes_py import NESEnv  # imported lazily so `--list` works without nes-py
    env = NESEnv(rom_path)
    env.reset()
    snapshots = {}

    # Prime the emulator with one no-op step so env.ram is populated.
    env.step(0)

    for i, (action, frames) in enumerate(scenario.steps):
        for _ in range(frames):
            _, _, done, _ = env.step(action)
            if done:
                env.reset()
        if i in scenario.checkpoints:
            snapshots[i] = env.ram.copy()

    env.close()
    return [snapshots[i] for i in scenario.checkpoints]


def diff(a, b, exclude=((0x200, 0x300),)):
    """Return (addr, a[addr], b[addr]) tuples for every differing byte,
    excluding ranges in `exclude` (half-open intervals). The default
    excludes sprite OAM, which churns every frame and drowns out signal."""
    out = []
    for addr in range(len(a)):
        if any(lo <= addr < hi for (lo, hi) in exclude):
            continue
        if a[addr] != b[addr]:
            out.append((addr, int(a[addr]), int(b[addr])))
    return out


def correlate(dis, changes):
    """For each changed RAM address, return the sorted list of PCs that
    store to it. Both zp and abs stores key on the same integer for
    addresses <$100, so a single lookup covers both modes."""
    return {addr: sorted(set(dis.writes_to(addr)))
            for addr, _, _ in changes}


def format_label(addr, ram_labels):
    name = ram_labels.get(addr)
    if name:
        return name[0]
    if addr in disasm.HW_REGS:
        return disasm.HW_REGS[addr]
    return ''


def report(scenario, changes, correlations, ram_labels):
    lines = []
    lines.append(f'# scenario: {scenario.name}')
    if scenario.description:
        lines.append(f'# {scenario.description}')
    lines.append(f'# {len(changes)} RAM bytes changed (sprite OAM excluded)')
    lines.append('')
    lines.append(f'{"addr":<8}{"before":<8}{"after":<8}'
                 f'{"label":<18}write-sites')
    lines.append('-' * 72)
    for addr, a, b in changes:
        pcs = correlations.get(addr, [])
        pc_str = ', '.join(f'L_{pc:04x}' for pc in sorted(set(pcs))) or '-'
        label = format_label(addr, ram_labels)
        lines.append(f'${addr:04x}   ${a:02x}     ${b:02x}     '
                     f'{label:<18}{pc_str}')
    return '\n'.join(lines)


def _scenario_changes(rom_path, scenario):
    """Run scenario; return the set of addresses that changed between
    its first and last checkpoint (sprite OAM excluded)."""
    snaps = run(rom_path, scenario)
    return {addr for addr, _, _ in diff(snaps[0], snaps[-1])}, snaps


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('scenario', nargs='?',
                    help='scenario name (see --list for options)')
    ap.add_argument('--rom', default='1942.nes',
                    help='path to ROM (default: 1942.nes)')
    ap.add_argument('--labels', default='labels.json',
                    help='path to user label overlay (default: labels.json)')
    ap.add_argument('--baseline',
                    help='subtract another scenario\'s changed addresses '
                         '(e.g. --baseline idle to filter out gameplay churn)')
    ap.add_argument('--genie', action='append', default=[],
                    help='Game Genie code to apply to the ROM before running '
                         '(repeatable). E.g. --genie IESUTYZA for 9 lives.')
    ap.add_argument('--list', action='store_true',
                    help='list available scenarios and exit')
    args = ap.parse_args()

    if args.list or not args.scenario:
        print('available scenarios:')
        for s in SCENARIOS.values():
            print(f'  {s.name:<14s} {s.description}')
        return 0 if args.list else 1

    if args.scenario not in SCENARIOS:
        sys.exit(f'unknown scenario: {args.scenario}. Try --list.')
    scenario = SCENARIOS[args.scenario]

    if not os.path.exists(args.rom):
        sys.exit(f'ROM not found: {args.rom}')
    rom_path = ensure_fixed_rom(args.rom, tuple(args.genie))
    if args.genie:
        print(f'applied Game Genie codes: {", ".join(args.genie)} '
              f'-> {rom_path}', file=sys.stderr)

    # Load disassembly once; correlator queries write_sites.
    rom = disasm.load_ines(args.rom)
    dis = disasm.Disassembler(rom['prg'])
    dis.disassemble()

    ram_labels = dict(disasm.RAM_LABELS)
    ram_labels.update(disasm.load_user_labels(args.labels))

    baseline_addrs = set()
    if args.baseline:
        if args.baseline not in SCENARIOS:
            sys.exit(f'unknown baseline scenario: {args.baseline}')
        print(f'running baseline scenario: {args.baseline}', file=sys.stderr)
        baseline_addrs, _ = _scenario_changes(rom_path,
                                              SCENARIOS[args.baseline])
        print(f'baseline noise: {len(baseline_addrs)} addresses',
              file=sys.stderr)

    print(f'running scenario: {scenario.name}', file=sys.stderr)
    snapshots = run(rom_path, scenario)
    print(f'captured {len(snapshots)} checkpoint(s)', file=sys.stderr)

    # Report diffs between consecutive checkpoints. For the common case
    # of 2 checkpoints (baseline + final) this is a single diff.
    for i in range(1, len(snapshots)):
        changes = diff(snapshots[i - 1], snapshots[i])
        if baseline_addrs:
            changes = [(a, x, y) for (a, x, y) in changes
                       if a not in baseline_addrs]
        correlations = correlate(dis, changes)
        print()
        print(f'=== checkpoint {i-1} -> {i} ===')
        if args.baseline:
            print(f'(filtered: addresses also touched by '
                  f'{args.baseline} are hidden)')
        print(report(scenario, changes, correlations, ram_labels))
    return 0


if __name__ == '__main__':
    sys.exit(main())
