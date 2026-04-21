#!/usr/bin/env python3
"""Boot 1942.nes via nes-py, run a few seconds of frames pressing START on
each frame, and snapshot RAM. Cross-check the Data Crystal RAM-map labels
(score, lives, rolls, level) against what's actually stored there.
"""

import os
import sys
import warnings

# Silence the gym 0.21 deprecation noise.
warnings.filterwarnings('ignore')
os.environ.setdefault('PYTHONWARNINGS', 'ignore')

import numpy as np
from nes_py import NESEnv

ROM = '1942.fixed.nes'  # flags7 cleared so strict iNES parsers accept it

# Joypad bit layout per nes-py JoypadSpace._button_map:
#   0x01 = A       0x02 = B       0x04 = select  0x08 = start
#   0x10 = up      0x20 = down    0x40 = left    0x80 = right
A      = 0x01
B      = 0x02
SELECT = 0x04
START  = 0x08

LABELS = {
    0x0427: 'Score_D5',
    0x0428: 'Score_D4',
    0x0429: 'Score_D3',
    0x042a: 'Score_D2',
    0x042b: 'Score_D1',
    0x042c: 'Score_D0',
    0x0431: 'Lives_Tens',
    0x0432: 'Lives_Ones',
    0x0436: 'Rolls',
    0x0438: 'Level',
}


def step(env, action, frames):
    """Hold `action` for `frames` frames; return final RAM snapshot."""
    obs, _, done, _ = env.step(0)  # ensure ram exists
    for _ in range(frames):
        obs, _, done, _ = env.step(action)
        if done:
            env.reset()
    return env.ram.copy()


def diff(a, b, low=0, high=0x800):
    return [(addr, int(a[addr]), int(b[addr]))
            for addr in range(low, high) if a[addr] != b[addr]]


def main():
    env = NESEnv(ROM)
    env.reset()

    # Boot far enough to see the title screen.
    ram_boot = step(env, 0, 240)
    print('after 240 idle frames (title screen?):')
    for addr, name in LABELS.items():
        print(f'  ${addr:04x} {name:<11} = ${ram_boot[addr]:02x}')

    # Tap START several times to navigate menu, then idle to settle into game.
    for _ in range(4):
        step(env, START, 6)
        step(env, 0, 12)
    ram_after_start = step(env, 0, 240)
    print()
    print('after several START presses + 240 idle frames:')
    for addr, name in LABELS.items():
        print(f'  ${addr:04x} {name:<11} = ${ram_after_start[addr]:02x}')

    print()
    print('all changed bytes in $0400-$04ff between boot and after-start:')
    for addr, a, b in diff(ram_boot, ram_after_start, 0x0400, 0x0500):
        name = LABELS.get(addr, '')
        print(f'  ${addr:04x}: ${a:02x} -> ${b:02x}  {name}')

    # Bigger view: every changed RAM byte (excluding the typical sprite
    # buffer at $0200-$02ff which churns every frame).
    print()
    print('top 30 changed addresses outside sprite OAM:')
    changed = diff(ram_boot, ram_after_start, 0, 0x800)
    changed = [(a, x, y) for (a, x, y) in changed if not (0x200 <= a < 0x300)]
    print(f'(total: {len(changed)} bytes changed)')
    for addr, a, b in changed[:30]:
        name = LABELS.get(addr, '')
        print(f'  ${addr:04x}: ${a:02x} -> ${b:02x}  {name}')

    env.close()


if __name__ == '__main__':
    main()
