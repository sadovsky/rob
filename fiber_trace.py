#!/usr/bin/env python3
"""Fiber reachability walker for the 1942 entity-coroutine system.

Given a fiber slot (0..15 from Fiber_EntryPointTable at $c3aa) or a raw
entry-point address, walk every code path reachable without going through
the scheduler. The walk follows JMP/JSR/Bxx but stops at RTS/RTI/BRK,
indirect JMP, JMP Main_Loop, and JSR to the kill-self/kill-other helpers.
JSRs to the yield helpers do not stop the trace (yield returns when the
fiber is later resumed) but are counted. JSRs to Coroutine_Spawn do not
follow into the spawned fiber's entry point (that is a separate subgraph)
but DO record the spawn-arg slot when the immediately-preceding insn is
`lda #imm` — the standard call idiom.

Output per fiber:
- a header (slot + entry + name if known)
- counts: yields, spawns (with slot args), kills (self/other), reachable
  instruction count
- labeled entries reached (anything in our user labels or RAM_LABELS)
- unlabeled branch targets that have multiple xrefs (good label
  candidates)
- RAM bytes the fiber reads / writes (for guessing its state)

Usage:
    python3 fiber_trace.py --slot 6
    python3 fiber_trace.py --entry 0xec45
    python3 fiber_trace.py --all
"""

import argparse
import sys

import disasm


FIBER_TABLE_ADDR = 0xc3aa
NUM_SLOTS = 16

MAIN_LOOP = 0xc2c0
SPAWN = 0xc1f5
KILL_SELF = 0xc237
KILL_OTHER = 0xc240
YIELDS = {0xc275, 0xc288, 0xc2a4, 0xc251}

# Memory-reading mnemonics (anything that loads from a memory operand).
READ_OPS = {'lda', 'ldx', 'ldy', 'adc', 'sbc', 'and', 'ora', 'eor',
            'cmp', 'cpx', 'cpy', 'bit', 'asl', 'lsr', 'rol', 'ror',
            'inc', 'dec'}
WRITE_OPS = {'sta', 'stx', 'sty'}


def fiber_entry(dis, slot):
    """Read the entry-point pointer for fiber `slot` and return PC.
    Pushed values are (entry - 1) so caller's rts lands at the actual
    entry point — undo that here."""
    base = FIBER_TABLE_ADDR + slot * 2
    lo = dis.read(base)
    hi = dis.read(base + 1)
    return ((hi << 8) | lo) + 1


def trace(dis, entry):
    visited = set()
    spawns = []
    yields = 0
    kills_self = 0
    kills_other = 0
    reads = set()
    writes = set()

    queue = [entry]
    while queue:
        pc = queue.pop(0)
        if pc in visited or not dis.in_prg(pc):
            continue

        last_imm = None  # for spawn-arg sniffing
        cur = pc
        while True:
            if cur in visited or not dis.in_prg(cur):
                break
            opcode = dis.read(cur)
            info = disasm.OPCODES.get(opcode)
            if info is None:
                break
            mnemonic, mode = info
            length = disasm.MODE_LEN[mode]
            visited.add(cur)
            next_pc = cur + length

            # Track most recent A-load for the spawn-arg idiom.
            if mnemonic == 'lda' and mode == 'imm':
                last_imm = dis.read(cur + 1)
            elif mnemonic in {'tax', 'tay', 'pha', 'php', 'sta',
                              'stx', 'sty', 'clc', 'sec', 'cld', 'sed',
                              'cli', 'sei', 'clv', 'nop', 'inx', 'iny',
                              'dex', 'dey'}:
                pass  # doesn't clobber A
            else:
                last_imm = None

            # Record memory operand reads/writes.
            target = None
            if mode in ('abs', 'abx', 'aby'):
                target = dis.read_word(cur + 1)
            elif mode in ('zp', 'zpx', 'zpy'):
                target = dis.read(cur + 1)
            if target is not None:
                if mnemonic in WRITE_OPS:
                    writes.add(target)
                elif mnemonic in READ_OPS:
                    reads.add(target)

            terminator = False

            if mode == 'rel':
                off = dis.read(cur + 1)
                if off >= 0x80:
                    off -= 0x100
                target = next_pc + off
                if dis.in_prg(target) and target not in visited:
                    queue.append(target)
            elif mnemonic == 'jmp' and mode == 'abs':
                target = dis.read_word(cur + 1)
                terminator = True
                if target == MAIN_LOOP:
                    pass
                elif target == KILL_SELF:
                    kills_self += 1
                elif target == KILL_OTHER:
                    kills_other += 1
                elif target in YIELDS:
                    yields += 1
                elif dis.in_prg(target) and target not in visited:
                    queue.append(target)
            elif mnemonic == 'jmp' and mode == 'ind':
                terminator = True
            elif mnemonic == 'jsr':
                target = dis.read_word(cur + 1)
                if target == KILL_SELF:
                    kills_self += 1
                    terminator = True
                elif target == KILL_OTHER:
                    kills_other += 1
                    terminator = True
                elif target == SPAWN:
                    spawns.append(last_imm)  # may be None if not adjacent
                elif target in YIELDS:
                    yields += 1
                elif dis.in_prg(target) and target not in visited:
                    queue.append(target)
            elif mnemonic in ('rts', 'rti', 'brk'):
                terminator = True

            if terminator:
                break
            cur = next_pc

    return {
        'visited': visited, 'spawns': spawns, 'yields': yields,
        'kills_self': kills_self, 'kills_other': kills_other,
        'reads': reads, 'writes': writes,
    }


def fmt_ram_addr(addr, ram_labels):
    if addr in ram_labels:
        return f'${addr:04x} {ram_labels[addr][0]}'
    return f'${addr:04x}'


def report(dis, ram_labels, slot, entry, r):
    name = ram_labels[entry][0] if entry in ram_labels else ''
    head = f'slot {slot}  entry ${entry:04x}'
    if name:
        head += f'  ({name})'
    print('=' * 70)
    print(head)
    print('=' * 70)
    print(f'reachable insns: {len(r["visited"])}')
    sp = ', '.join(f'#${s:02x}' if s is not None else '?' for s in r['spawns'])
    print(f'yields: {r["yields"]}  spawns: [{sp}]  '
          f'kill-self: {r["kills_self"]}  kill-other: {r["kills_other"]}')

    visited = sorted(r['visited'])
    labeled = [pc for pc in visited if pc in ram_labels]
    print()
    print(f'labeled entries reached ({len(labeled)}):')
    for pc in labeled:
        print(f'  ${pc:04x}  {ram_labels[pc][0]}')

    # Unlabeled branch targets with at least one in-fiber xref.
    cands = []
    for pc in visited:
        if pc in ram_labels:
            continue
        srcs = dis.code_xref.get(pc, set())
        in_fiber = sum(1 for s in srcs if s in r['visited'])
        if in_fiber >= 1:
            cands.append((pc, in_fiber, len(srcs)))
    print()
    print(f'unlabeled branch targets ({len(cands)}):')
    for pc, in_fiber, total in cands:
        print(f'  ${pc:04x}  in-fiber xrefs: {in_fiber}  total: {total}')

    ram_reads = sorted(a for a in r['reads'] if a < 0x800)
    ram_writes = sorted(a for a in r['writes'] if a < 0x800)
    print()
    print(f'RAM reads ({len(ram_reads)}):')
    for a in ram_reads:
        print(f'  {fmt_ram_addr(a, ram_labels)}')
    print()
    print(f'RAM writes ({len(ram_writes)}):')
    for a in ram_writes:
        print(f'  {fmt_ram_addr(a, ram_labels)}')


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--slot', type=int, help='fiber slot 0..15')
    g.add_argument('--entry', type=lambda s: int(s, 0),
                   help='entry-point addr (e.g. 0xec45)')
    g.add_argument('--all', action='store_true', help='trace every slot')
    ap.add_argument('--rom', default='1942.nes')
    ap.add_argument('--labels', default='labels.json')
    args = ap.parse_args()

    rom = disasm.load_ines(args.rom)
    dis = disasm.Disassembler(rom['prg'])
    dis.disassemble()
    ram_labels = dict(disasm.RAM_LABELS)
    ram_labels.update(disasm.load_user_labels(args.labels))

    if args.all:
        for slot in range(NUM_SLOTS):
            entry = fiber_entry(dis, slot)
            if entry == 0x0001:  # slot 0 = $0000+1, unused
                print('=' * 70)
                print(f'slot {slot}: unused (table entry = $0000)')
                print()
                continue
            report(dis, ram_labels, slot, entry, trace(dis, entry))
            print()
    elif args.slot is not None:
        entry = fiber_entry(dis, args.slot)
        report(dis, ram_labels, args.slot, entry, trace(dis, entry))
    else:
        report(dis, ram_labels, '?', args.entry, trace(dis, args.entry))


if __name__ == '__main__':
    main()
