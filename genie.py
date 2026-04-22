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


def encode(addr, value, compare=None):
    """Inverse of decode(). Returns a 6-letter code if compare is None,
    else an 8-letter code. Useful for proposing a Game Genie code that
    patches a specific ROM byte."""
    if not (0x8000 <= addr <= 0xffff):
        sys.exit(f'Game Genie addr must be in $8000..$ffff, got ${addr:04x}')
    if not (0 <= value <= 0xff):
        sys.exit(f'value must be a byte, got {value}')
    if compare is not None and not (0 <= compare <= 0xff):
        sys.exit(f'compare must be a byte, got {compare}')

    # Each n[i] holds 4 bits scattered across addr/value/compare.
    # See decode() for the forward mapping; this just inverts it.
    n = [0] * (8 if compare is not None else 6)
    n[0] = (value & 7) | ((value >> 4) & 8)        # val0..2 + val7
    n[1] = ((value >> 4) & 7) | ((addr >> 4) & 8)  # val4..6 + addr7
    n[2] = ((addr >> 4) & 7)                       # addr4..6 + format flag
    if compare is not None:
        n[2] |= 8
    n[3] = ((addr >> 12) & 7) | (addr & 8)         # addr12..14 + addr3
    n[4] = (addr & 7) | ((addr >> 8) & 8)          # addr0..2 + addr11
    n[5] = (addr >> 8) & 7                         # addr8..10 + see below
    if compare is None:
        n[5] |= (value & 8)                        # val3
    else:
        n[5] |= (compare & 8)                      # cmp3
        n[6] = (compare & 7) | ((compare >> 4) & 8)  # cmp0..2 + cmp7
        n[7] = ((compare >> 4) & 7) | (value & 8)    # cmp4..6 + val3

    return ''.join(ALPHABET[x] for x in n)


def _self_test():
    """Roundtrip every documented cheat from labels.json."""
    cases = [
        'IESUTYZA', 'IAKUUAZA', 'IASUOAZA', 'PASIOALE',
        'SZXLKEVK', 'SZKULGAX', 'OZVULSPX', 'OZOYUEPX',
        'SZESPUVK', 'AEUSGZAP', 'PAEIXKNY',
    ]
    for code in cases:
        addr, value, compare = decode(code)
        again = encode(addr, value, compare)
        assert again == code, f'{code} -> ${addr:04x},${value:02x},{compare} -> {again}'
        print(f'  {code}  ${addr:04x} <- ${value:02x}'
              f'{f" (if ${compare:02x})" if compare is not None else ""}  ok')
    print(f'roundtrip: {len(cases)}/{len(cases)} ok')


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
    ap.add_argument('codes', nargs='*',
                    help='6- or 8-letter Game Genie code(s)')
    ap.add_argument('--html', default='1942.html',
                    help='disassembly HTML to look up addresses in')
    ap.add_argument('--no-context', action='store_true',
                    help='just print decoded address/value, skip disassembly lookup')
    ap.add_argument('--encode', nargs='+', metavar='ADDR,VAL[,CMP]',
                    help='encode address,value[,compare] tuples to codes')
    ap.add_argument('--test', action='store_true',
                    help='roundtrip-test encode against documented cheats')
    args = ap.parse_args()

    if args.test:
        _self_test()
        return

    if args.encode:
        for spec in args.encode:
            parts = [int(p, 0) for p in spec.split(',')]
            if len(parts) == 2:
                addr, value = parts
                compare = None
            elif len(parts) == 3:
                addr, value, compare = parts
            else:
                sys.exit(f'bad --encode spec {spec!r} (want addr,val[,cmp])')
            code = encode(addr, value, compare)
            tail = f' (if ${compare:02x})' if compare is not None else ''
            print(f'  ${addr:04x} <- ${value:02x}{tail}  ->  {code}')
        if not args.codes:
            return

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
