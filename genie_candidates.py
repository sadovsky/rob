#!/usr/bin/env python3
"""Enumerate Game-Genie-patchable bytes ranked by predicted interestingness.

For each candidate the tool emits a row: (ROM addr, current → patch byte,
suggested 6-letter Game Genie code, predicted effect, nearest user label,
confidence). Confirm with `drift.py <scenario> --genie <CODE>` and label
the site if the predicted effect is real.

Categories (descending interestingness; --category to filter):

    counter_write    `dec`/`dec,X` to a labeled RAM byte → patch opcode
                     to `lda` so the counter never decrements (the
                     SZXLKEVK pattern).
    init_immediate   `lda #$NN` immediately followed by `sta <labeled>`
                     → patch the immediate byte.
    store_skip       `sta`/`stx`/`sty` to a labeled RAM byte → patch
                     opcode to `lda` to suppress the write.
    mask_test        `and`/`ora`/`eor`/`bit` followed by Bxx → patch
                     opcode to `lda` to disable the test.
    comparison       `cmp/cpx/cpy #$NN` followed by Bxx → patch the
                     immediate to flip the threshold.
    dispatch_table   bytes inside EnemyType_InitDispatch ($eff2) and
                     EnemyType_AnimTable ($fd4a) → swap a pointer byte
                     to redirect a per-type behavior.
    branch_redirect  `Bxx` rel-mode offset byte → flatten the branch
                     (offset → 0). Lowest signal; surface for review.

Usage:
    python3 genie_candidates.py
    python3 genie_candidates.py --category counter_write --top 30
    python3 genie_candidates.py --near 0xb800
"""

import argparse
import bisect
import sys

import disasm
import genie


# Opcode swaps that turn a write into an A/X/Y-load. Length-preserving.
DISABLE_WRITE = {
    0xc6: 0xa5,  # dec zp     -> lda zp
    0xd6: 0xb5,  # dec zpx    -> lda zpx
    0xce: 0xad,  # dec abs    -> lda abs
    0xde: 0xbd,  # dec abs,X  -> lda abs,X
    0x85: 0xa5,  # sta zp     -> lda zp
    0x95: 0xb5,  # sta zpx    -> lda zpx
    0x8d: 0xad,  # sta abs    -> lda abs
    0x9d: 0xbd,  # sta abs,X  -> lda abs,X
    0x99: 0xb9,  # sta abs,Y  -> lda abs,Y
    0x86: 0xa6,  # stx zp     -> ldx zp
    0x96: 0xb6,  # stx zpy    -> ldx zpy
    0x8e: 0xae,  # stx abs    -> ldx abs
    0x84: 0xa4,  # sty zp     -> ldy zp
    0x94: 0xb4,  # sty zpx    -> ldy zpx
    0x8c: 0xac,  # sty abs    -> ldy abs
}

# Opcode swaps that turn a logical/test op into an A-load (effect: the
# subsequent branch sees the operand value as-is, not the masked result).
DISABLE_TEST = {
    0x29: 0xa9,  # and imm    -> lda imm
    0x09: 0xa9,  # ora imm    -> lda imm
    0x49: 0xa9,  # eor imm    -> lda imm
    0x24: 0xa5,  # bit zp     -> lda zp
    0x2c: 0xad,  # bit abs    -> lda abs
    0x25: 0xa5,  # and zp     -> lda zp
    0x2d: 0xad,  # and abs    -> lda abs
    0x05: 0xa5,  # ora zp     -> lda zp
    0x0d: 0xad,  # ora abs    -> lda abs
}

CMP_IMM = {0xc9: 'cmp', 0xe0: 'cpx', 0xc0: 'cpy'}

# Substring hints in label names that tag an address as a counter / state
# byte the player would notice if frozen.
COUNTER_HINTS = ('lives', 'rolls', 'bullet', 'timer', 'tick', 'cooldown',
                 'count', 'health', 'hp', 'limit', 'score', 'level',
                 'frame', 'state', 'index', 'cursor', 'respawn')

DISPATCH_TABLES = (
    # (base, name, type_offset) — index i in the table corresponds to
    # Entity_TypeId == i + type_offset. AnimTable starts at type $0a.
    (0xeff2, 'EnemyType_InitDispatch', 0x00),
    (0xfd4a, 'EnemyType_AnimTable',    0x0a),
)


class Candidate:
    __slots__ = ('addr', 'current', 'patch', 'category', 'confidence', 'note')

    def __init__(self, addr, current, patch, category, confidence, note):
        self.addr = addr
        self.current = current
        self.patch = patch
        self.category = category
        self.confidence = confidence
        self.note = note


def looks_like_counter(name):
    n = name.lower()
    return any(h in n for h in COUNTER_HINTS)


def labeled_ram(target, ram_labels):
    """Name of the user label for `target` if it's a labeled RAM byte."""
    if target >= 0x2000:
        return None
    info = ram_labels.get(target)
    return info[0] if info else None


def is_branch(opcode):
    info = disasm.OPCODES.get(opcode)
    return info is not None and info[1] == 'rel'


def operand_addr(dis, addr, mode):
    if mode in ('abs', 'abx', 'aby'):
        return dis.read_word(addr + 1)
    if mode in ('zp', 'zpx', 'zpy'):
        return dis.read(addr + 1)
    return None


def enum_writes(dis, ram_labels):
    """counter_write (dec) + store_skip (sta/stx/sty).
    The labeled-RAM operand is a strong enough filter to scan every byte
    (no is_code gate) — that's how known cheats like SZXLKEVK ($b824
    `dec Lives_Ones`) surface even though the recursive-descent
    disassembler classed those bytes as data."""
    out = []
    for off in range(0x8000 - 2):
        addr = 0x8000 + off
        opcode = dis.read(addr)
        if opcode not in DISABLE_WRITE:
            continue
        mnem, mode = disasm.OPCODES[opcode]
        target = operand_addr(dis, addr, mode)
        if target is None:
            continue
        label = labeled_ram(target, ram_labels)
        if label is None:
            continue
        new_op = DISABLE_WRITE[opcode]
        is_counter = looks_like_counter(label)
        in_code = bool(dis.is_code[off])
        suffix = '' if in_code else ' [data?]'
        if mnem == 'dec':
            cat = 'counter_write'
            conf = (9 if is_counter else 7) - (0 if in_code else 1)
            note = f'dec→lda: {label} (${target:04x}) stops decrementing{suffix}'
        else:
            cat = 'store_skip'
            conf = (7 if is_counter else 5) - (0 if in_code else 1)
            note = f'{mnem}→lda: writes to {label} (${target:04x}) suppressed{suffix}'
        out.append(Candidate(addr, opcode, new_op, cat, conf, note))
    return out


def enum_init_immediates(dis, ram_labels):
    """`lda #$NN` immediately followed by sta/stx/sty to a labeled RAM byte."""
    out = []
    for off in range(0x8000 - 5):
        if not dis.is_code[off]:
            continue
        addr = 0x8000 + off
        if dis.read(addr) != 0xa9:           # lda imm
            continue
        nxt = addr + 2
        if not dis.is_code[nxt - 0x8000]:
            continue
        nopc = dis.read(nxt)
        info = disasm.OPCODES.get(nopc)
        if info is None:
            continue
        nmnem, nmode = info
        if nmnem != 'sta':
            continue                          # only A-stores match `lda #imm`
        target = operand_addr(dis, nxt, nmode)
        if target is None:
            continue
        label = labeled_ram(target, ram_labels)
        if label is None:
            continue
        cur_imm = dis.read(addr + 1)
        is_counter = looks_like_counter(label)
        # Default patch: 0xff (max counter), 0x00 (suppress). Pick the
        # one that's most likely to be a behavioral swing.
        patch = 0xff if (is_counter and cur_imm <= 0x10) else 0x00
        if patch == cur_imm:
            patch = (cur_imm ^ 0x80) & 0xff
        conf = 8 if is_counter else 6
        note = (f'lda #${cur_imm:02x} → #${patch:02x} before '
                f'sta {label} (${target:04x})')
        out.append(Candidate(addr + 1, cur_imm, patch,
                             'init_immediate', conf, note))
    return out


def enum_comparisons(dis, ram_labels):
    """cmp/cpx/cpy #imm followed (within 2 bytes) by a Bxx."""
    out = []
    for off in range(0x8000 - 4):
        if not dis.is_code[off]:
            continue
        addr = 0x8000 + off
        opcode = dis.read(addr)
        if opcode not in CMP_IMM:
            continue
        nxt = addr + 2
        if not dis.is_code[nxt - 0x8000] or not is_branch(dis.read(nxt)):
            continue
        cur_imm = dis.read(addr + 1)
        # Patch: cur ^ 0x80 maximally swings the comparison. For boundary
        # values (0x00, 0x01, 0xff) prefer the obvious flip.
        if cur_imm == 0x00:
            patch = 0xff
        elif cur_imm == 0xff:
            patch = 0x00
        else:
            patch = (cur_imm ^ 0x80) & 0xff
        out.append(Candidate(addr + 1, cur_imm, patch, 'comparison', 5,
                             f'{CMP_IMM[opcode]} #${cur_imm:02x} → '
                             f'#${patch:02x}; gates Bxx at ${nxt:04x}'))
    return out


def enum_masks(dis, ram_labels):
    """and/ora/eor/bit followed (within insn length) by a Bxx."""
    out = []
    for off in range(0x8000 - 4):
        if not dis.is_code[off]:
            continue
        addr = 0x8000 + off
        opcode = dis.read(addr)
        if opcode not in DISABLE_TEST:
            continue
        mnem, mode = disasm.OPCODES[opcode]
        length = disasm.MODE_LEN[mode]
        nxt = addr + length
        nxt_off = nxt - 0x8000
        if nxt_off >= 0x8000 or not dis.is_code[nxt_off]:
            continue
        if not is_branch(dis.read(nxt)):
            continue
        new_op = DISABLE_TEST[opcode]
        # Operand label for context.
        if mode == 'imm':
            op_lbl = f'#${dis.read(addr + 1):02x}'
        else:
            tgt = operand_addr(dis, addr, mode)
            n = labeled_ram(tgt, ram_labels) if tgt is not None else None
            op_lbl = n if n else (f'${tgt:04x}' if tgt is not None else '?')
        out.append(Candidate(addr, opcode, new_op, 'mask_test', 6,
                             f'{mnem} {op_lbl} → lda; disables test '
                             f'gating Bxx at ${nxt:04x}'))
    return out


def enum_dispatch(dis, ram_labels):
    """Each pointer byte in $eff2 / $fd4a, swapped with the first
    distinct neighbor's same-column byte. One candidate per byte."""
    out = []
    for base, name, type_off in DISPATCH_TABLES:
        ptrs = [(dis.read(base + i*2), dis.read(base + i*2 + 1))
                for i in range(16)]
        for i in range(16):
            cur_lo, cur_hi = ptrs[i]
            cur = (cur_hi << 8) | cur_lo
            alt_idx = next((j for j in range(16)
                            if (ptrs[j][1] << 8) | ptrs[j][0] != cur), None)
            if alt_idx is None:
                continue
            alt_lo, alt_hi = ptrs[alt_idx]
            new_lo_target = (cur_hi << 8) | alt_lo
            new_hi_target = (alt_hi << 8) | cur_lo
            tid = i + type_off
            out.append(Candidate(
                base + i*2, cur_lo, alt_lo, 'dispatch_table', 7,
                f'{name}[{i:2d}].lo: type ${tid:02x} → ${cur:04x} swapped '
                f'to ${new_lo_target:04x} (steal lo from idx {alt_idx})'))
            out.append(Candidate(
                base + i*2 + 1, cur_hi, alt_hi, 'dispatch_table', 7,
                f'{name}[{i:2d}].hi: type ${tid:02x} → ${cur:04x} swapped '
                f'to ${new_hi_target:04x} (steal hi from idx {alt_idx})'))
    return out


def enum_branch_redirects(dis, ram_labels):
    """Every Bxx rel-mode offset byte. Patch: offset → 0 (flatten)."""
    out = []
    for off in range(0x8000):
        if not dis.is_code[off]:
            continue
        addr = 0x8000 + off
        opcode = dis.read(addr)
        if not is_branch(opcode):
            continue
        cur = dis.read(addr + 1)
        if cur == 0:
            continue                          # already a no-op offset
        out.append(Candidate(addr + 1, cur, 0x00, 'branch_redirect', 3,
                             f'Bxx offset → 0; flattens branch at ${addr:04x}'))
    return out


def collect_all(dis, ram_labels):
    out = []
    out += enum_writes(dis, ram_labels)
    out += enum_init_immediates(dis, ram_labels)
    out += enum_comparisons(dis, ram_labels)
    out += enum_masks(dis, ram_labels)
    out += enum_dispatch(dis, ram_labels)
    out += enum_branch_redirects(dis, ram_labels)
    return out


def build_prg_label_index(ram_labels):
    return sorted(la for la in ram_labels if 0x8000 <= la <= 0xffff)


def nearest_prg_label(addr, sorted_labels, ram_labels):
    i = bisect.bisect_right(sorted_labels, addr)
    if i == 0:
        return None
    la = sorted_labels[i - 1]
    return (la, ram_labels[la][0])


CATEGORIES = ('counter_write', 'init_immediate', 'store_skip',
              'mask_test', 'comparison', 'dispatch_table', 'branch_redirect')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rom', default='1942.nes')
    ap.add_argument('--labels', default='labels.json')
    ap.add_argument('--category', choices=CATEGORIES,
                    help='restrict to one category')
    ap.add_argument('--top', type=int, default=40,
                    help='print at most N rows (default 40, 0 = all)')
    ap.add_argument('--near', type=lambda s: int(s, 0),
                    help='restrict to candidates within ±near-window of addr')
    ap.add_argument('--near-window', type=int, default=256,
                    help='half-window for --near (default 256 bytes)')
    args = ap.parse_args()

    rom = disasm.load_ines(args.rom)
    dis = disasm.Disassembler(rom['prg'])
    dis.disassemble()
    ram_labels = dict(disasm.RAM_LABELS)
    ram_labels.update(disasm.load_user_labels(args.labels))

    cands = collect_all(dis, ram_labels)
    if args.category:
        cands = [c for c in cands if c.category == args.category]
    if args.near is not None:
        lo = args.near - args.near_window
        hi = args.near + args.near_window
        cands = [c for c in cands if lo <= c.addr <= hi]

    cands.sort(key=lambda c: (-c.confidence, c.category, c.addr))

    sorted_prg_labels = build_prg_label_index(ram_labels)

    print(f'{"addr":<7}{"cur→pat":<10}{"code":<10}{"cf":<4}'
          f'{"category":<17}context')
    print('-' * 110)
    limit = len(cands) if args.top == 0 else args.top
    for c in cands[:limit]:
        code = genie.encode(c.addr, c.patch)
        ctx = c.note
        nl = nearest_prg_label(c.addr, sorted_prg_labels, ram_labels)
        if nl is not None:
            ctx += f'  [near {nl[1]}+${c.addr - nl[0]:x}]'
        print(f'${c.addr:04x}  {c.current:02x}→{c.patch:02x}    '
              f'{code:<10}{c.confidence:<4}{c.category:<17}{ctx}')

    by_cat = {}
    for c in cands:
        by_cat[c.category] = by_cat.get(c.category, 0) + 1
    print()
    print('summary:')
    for cat in CATEGORIES:
        if cat in by_cat:
            print(f'  {cat:<17} {by_cat[cat]}')
    print(f'  TOTAL             {len(cands)}')


if __name__ == '__main__':
    main()
