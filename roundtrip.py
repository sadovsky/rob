#!/usr/bin/env python3
"""Round-trip check: parse the address+bytes column out of 1942.html and
verify that reconstructing those 32 KB byte-for-byte reproduces the original
PRG. This catches line-emission bugs (skipped bytes, double-emit, off-by-one
addresses) regardless of how the rest of the line is formatted."""

import re
import sys

PRG = open('1942.nes', 'rb').read()[16:16 + 32768]

# Each disassembly line begins with: "xxxx: bb bb bb..." (4-hex addr + colon
# + space, then space-separated 2-hex bytes; possibly trailing " ..").
LINE = re.compile(r'^([0-9a-f]{4}): ((?:[0-9a-f]{2} )+)')

reconstructed = bytearray(0x8000)
seen = bytearray(0x8000)  # 1 if this byte was emitted somewhere
errors = []

for lineno, line in enumerate(open('1942.html'), 1):
    # The "bb .." abbreviation hides bytes for big data rows. To validate
    # round-trip we want every byte present, so look for either the bytes
    # column directly, OR the operand column ".byte $aa, $bb, $cc, ..." for
    # data rows.
    m = LINE.match(line)
    if not m:
        continue
    addr = int(m.group(1), 16)
    if addr < 0x8000 or addr > 0xffff:
        continue

    # Try operand-column data form first: ".byte $hh, $hh, ..."
    op_match = re.search(r'\.byte\s+((?:\$[0-9a-f]{2}(?:,\s*)?)+)', line)
    if op_match:
        bytes_list = [int(b[1:], 16)
                      for b in re.findall(r'\$[0-9a-f]{2}', op_match.group(1))]
    elif '.word' in line:
        # Vector entries: read the bytes column directly (always 2 bytes).
        bytes_list = [int(b, 16) for b in m.group(2).split()]
    else:
        # Code instruction: the bytes column lists every byte (no "..").
        bytes_list = [int(b, 16) for b in m.group(2).split()]

    for i, b in enumerate(bytes_list):
        off = addr + i - 0x8000
        if off < 0 or off >= 0x8000:
            errors.append(f'line {lineno}: addr ${addr+i:04x} out of PRG range')
            continue
        if seen[off]:
            errors.append(f'line {lineno}: byte ${addr+i:04x} double-emitted '
                          f'(was ${reconstructed[off]:02x}, now ${b:02x})')
        seen[off] = 1
        reconstructed[off] = b

# Compare against the original PRG.
mismatches = [(off, PRG[off], reconstructed[off])
              for off in range(0x8000)
              if seen[off] and PRG[off] != reconstructed[off]]
unseen = [off for off in range(0x8000) if not seen[off]]

print(f'lines parsed: {sum(seen)} bytes covered out of 32768')
print(f'mismatches:   {len(mismatches)}')
print(f'unseen bytes: {len(unseen)}')
if mismatches:
    print('first 10 mismatches:')
    for off, want, got in mismatches[:10]:
        print(f'  ${0x8000+off:04x}: want ${want:02x}, got ${got:02x}')
if unseen:
    print('first 20 unseen offsets:')
    print('  ' + ' '.join(f'${0x8000+o:04x}' for o in unseen[:20]))
if errors:
    print(f'{len(errors)} parse errors; first 10:')
    for e in errors[:10]:
        print('  ' + e)

ok = (not mismatches) and (not unseen) and (not errors)
print()
print('ROUND-TRIP', 'PASSED' if ok else 'FAILED')
sys.exit(0 if ok else 1)
