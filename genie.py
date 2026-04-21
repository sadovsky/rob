#!/usr/bin/env python3
"""Decode NES Game Genie codes (6 or 8 letter) to (address, value[,
compare]) and locate the patched byte inside our disassembly listing.

Reference: https://tuxnes.sourceforge.net/gamegenie.html — the 6-letter
form is unconditional poke; the 8-letter form only pokes when the
original byte matches `compare`.
"""

import argparse
import re
import sys

ALPHABET = 'APZLGITYEOXUKSVN'


def _decode_letters(code):
    code = code.upper()
    if not all(c in ALPHABET for c in code):
        sys.exit(f'invalid Game Genie letters in {code!r}; '
                 f'allowed: {ALPHABET}')
    return [ALPHABET.index(c) for c in code]


def decode(code):
    """Return (address, value, compare) for a 6- or 8-letter code.
    `compare` is None for 6-letter codes."""
    n = _decode_letters(code)
    if len(n) not in (6, 8):
        sys.exit(f'Game Genie codes must be 6 or 8 letters, got {len(n)}')

    # Bit assembly per the standard NES Game Genie spec.
    addr = (
        0x8000
        | ((n[3] & 7) << 12)
        | ((n[5] & 7) << 8) | ((n[4] & 8) << 8)
        | ((n[2] & 7) << 4) | ((n[1] & 8) << 4)
        | (n[4] & 7) | (n[3] & 8)
    )
    if len(n) == 6:
        value = (
            ((n[1] & 7) << 4) | ((n[0] & 8) << 4)
            | (n[0] & 7) | (n[5] & 8)
        )
        return addr, value, None
    else:
        value = (
            ((n[1] & 7) << 4) | ((n[0] & 8) << 4)
            | (n[0] & 7) | (n[7] & 8)
        )
        compare = (
            ((n[7] & 7) << 4) | ((n[6] & 8) << 4)
            | (n[6] & 7) | (n[5] & 8)
        )
        return addr, value, compare


def lookup_in_html(addr, html_path='1942.html'):
    """Find the disassembly line for `addr` and the surrounding context."""
    pat = re.compile(rf'^{addr:04x}: ')
    surrounding = []
    with open(html_path) as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        if pat.match(line):
            lo = max(0, i - 2)
            hi = min(len(lines), i + 4)
            for j in range(lo, hi):
                marker = '  >>' if j == i else '    '
                surrounding.append(marker + lines[j].rstrip())
            return '\n'.join(surrounding)
    # Fallback: maybe the byte is mid-instruction; find the nearest line
    # whose 4-hex address is <= addr.
    line_re = re.compile(r'^([0-9a-f]{4}): ')
    best = None
    for i, line in enumerate(lines):
        m = line_re.match(line)
        if m:
            line_addr = int(m.group(1), 16)
            if line_addr <= addr:
                if best is None or line_addr > best[1]:
                    best = (i, line_addr)
            else:
                break
    if best is not None:
        i, _ = best
        lo = max(0, i - 2)
        hi = min(len(lines), i + 4)
        for j in range(lo, hi):
            marker = '  >>' if j == i else '    '
            surrounding.append(marker + lines[j].rstrip())
        return '\n'.join(surrounding) + f'\n    (addr ${addr:04x} falls inside this line)'
    return f'(no line found for ${addr:04x})'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('codes', nargs='+',
                    help='6- or 8-letter Game Genie code(s)')
    ap.add_argument('--html', default='1942.html',
                    help='disassembly HTML to look up addresses in')
    ap.add_argument('--no-context', action='store_true',
                    help='just print decoded address/value, skip disassembly lookup')
    args = ap.parse_args()

    for code in args.codes:
        addr, value, compare = decode(code)
        if compare is None:
            print(f'{code:>10s}  ${addr:04x} <- ${value:02x}  (unconditional)')
        else:
            print(f'{code:>10s}  ${addr:04x} <- ${value:02x}  '
                  f'(if original is ${compare:02x})')
        if not args.no_context:
            print(lookup_in_html(addr, args.html))
            print()


if __name__ == '__main__':
    main()
