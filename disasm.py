#!/usr/bin/env python3
"""6502 recursive-descent disassembler for NROM-256 (mapper 0) NES ROMs.

Produces an HTML disassembly listing styled like the doppelheathen
SuperMarioBros disassembly: address column, hex bytes column, label column,
mnemonic, operand, optional comment. Cross-references between code points
become anchor links.
"""

import argparse
import html
import json
import os
import sys
from collections import defaultdict

# ---------------------------------------------------------------------------
# 6502 opcode table.
# Each entry: (mnemonic, addressing_mode).
# Addressing modes determine instruction length and operand format.
#   imp = implied, acc = accumulator, imm = immediate, zp = zero page,
#   zpx/zpy = zero page indexed, abs = absolute, abx/aby = absolute indexed,
#   ind = indirect, inx = (zp,X), iny = (zp),Y, rel = PC-relative branch.
# Undefined opcodes (NMOS 6502) are absent — they get rendered as raw bytes.
# ---------------------------------------------------------------------------
OPCODES = {
    0x00: ('brk', 'imp'), 0x01: ('ora', 'inx'), 0x05: ('ora', 'zp'),
    0x06: ('asl', 'zp'),  0x08: ('php', 'imp'), 0x09: ('ora', 'imm'),
    0x0a: ('asl', 'acc'), 0x0d: ('ora', 'abs'), 0x0e: ('asl', 'abs'),
    0x10: ('bpl', 'rel'), 0x11: ('ora', 'iny'), 0x15: ('ora', 'zpx'),
    0x16: ('asl', 'zpx'), 0x18: ('clc', 'imp'), 0x19: ('ora', 'aby'),
    0x1d: ('ora', 'abx'), 0x1e: ('asl', 'abx'),
    0x20: ('jsr', 'abs'), 0x21: ('and', 'inx'), 0x24: ('bit', 'zp'),
    0x25: ('and', 'zp'),  0x26: ('rol', 'zp'),  0x28: ('plp', 'imp'),
    0x29: ('and', 'imm'), 0x2a: ('rol', 'acc'), 0x2c: ('bit', 'abs'),
    0x2d: ('and', 'abs'), 0x2e: ('rol', 'abs'),
    0x30: ('bmi', 'rel'), 0x31: ('and', 'iny'), 0x35: ('and', 'zpx'),
    0x36: ('rol', 'zpx'), 0x38: ('sec', 'imp'), 0x39: ('and', 'aby'),
    0x3d: ('and', 'abx'), 0x3e: ('rol', 'abx'),
    0x40: ('rti', 'imp'), 0x41: ('eor', 'inx'), 0x45: ('eor', 'zp'),
    0x46: ('lsr', 'zp'),  0x48: ('pha', 'imp'), 0x49: ('eor', 'imm'),
    0x4a: ('lsr', 'acc'), 0x4c: ('jmp', 'abs'), 0x4d: ('eor', 'abs'),
    0x4e: ('lsr', 'abs'),
    0x50: ('bvc', 'rel'), 0x51: ('eor', 'iny'), 0x55: ('eor', 'zpx'),
    0x56: ('lsr', 'zpx'), 0x58: ('cli', 'imp'), 0x59: ('eor', 'aby'),
    0x5d: ('eor', 'abx'), 0x5e: ('lsr', 'abx'),
    0x60: ('rts', 'imp'), 0x61: ('adc', 'inx'), 0x65: ('adc', 'zp'),
    0x66: ('ror', 'zp'),  0x68: ('pla', 'imp'), 0x69: ('adc', 'imm'),
    0x6a: ('ror', 'acc'), 0x6c: ('jmp', 'ind'), 0x6d: ('adc', 'abs'),
    0x6e: ('ror', 'abs'),
    0x70: ('bvs', 'rel'), 0x71: ('adc', 'iny'), 0x75: ('adc', 'zpx'),
    0x76: ('ror', 'zpx'), 0x78: ('sei', 'imp'), 0x79: ('adc', 'aby'),
    0x7d: ('adc', 'abx'), 0x7e: ('ror', 'abx'),
    0x81: ('sta', 'inx'), 0x84: ('sty', 'zp'),  0x85: ('sta', 'zp'),
    0x86: ('stx', 'zp'),  0x88: ('dey', 'imp'), 0x8a: ('txa', 'imp'),
    0x8c: ('sty', 'abs'), 0x8d: ('sta', 'abs'), 0x8e: ('stx', 'abs'),
    0x90: ('bcc', 'rel'), 0x91: ('sta', 'iny'), 0x94: ('sty', 'zpx'),
    0x95: ('sta', 'zpx'), 0x96: ('stx', 'zpy'), 0x98: ('tya', 'imp'),
    0x99: ('sta', 'aby'), 0x9a: ('txs', 'imp'), 0x9d: ('sta', 'abx'),
    0xa0: ('ldy', 'imm'), 0xa1: ('lda', 'inx'), 0xa2: ('ldx', 'imm'),
    0xa4: ('ldy', 'zp'),  0xa5: ('lda', 'zp'),  0xa6: ('ldx', 'zp'),
    0xa8: ('tay', 'imp'), 0xa9: ('lda', 'imm'), 0xaa: ('tax', 'imp'),
    0xac: ('ldy', 'abs'), 0xad: ('lda', 'abs'), 0xae: ('ldx', 'abs'),
    0xb0: ('bcs', 'rel'), 0xb1: ('lda', 'iny'), 0xb4: ('ldy', 'zpx'),
    0xb5: ('lda', 'zpx'), 0xb6: ('ldx', 'zpy'), 0xb8: ('clv', 'imp'),
    0xb9: ('lda', 'aby'), 0xba: ('tsx', 'imp'), 0xbc: ('ldy', 'abx'),
    0xbd: ('lda', 'abx'), 0xbe: ('ldx', 'aby'),
    0xc0: ('cpy', 'imm'), 0xc1: ('cmp', 'inx'), 0xc4: ('cpy', 'zp'),
    0xc5: ('cmp', 'zp'),  0xc6: ('dec', 'zp'),  0xc8: ('iny', 'imp'),
    0xc9: ('cmp', 'imm'), 0xca: ('dex', 'imp'), 0xcc: ('cpy', 'abs'),
    0xcd: ('cmp', 'abs'), 0xce: ('dec', 'abs'),
    0xd0: ('bne', 'rel'), 0xd1: ('cmp', 'iny'), 0xd5: ('cmp', 'zpx'),
    0xd6: ('dec', 'zpx'), 0xd8: ('cld', 'imp'), 0xd9: ('cmp', 'aby'),
    0xdd: ('cmp', 'abx'), 0xde: ('dec', 'abx'),
    0xe0: ('cpx', 'imm'), 0xe1: ('sbc', 'inx'), 0xe4: ('cpx', 'zp'),
    0xe5: ('sbc', 'zp'),  0xe6: ('inc', 'zp'),  0xe8: ('inx', 'imp'),
    0xe9: ('sbc', 'imm'), 0xea: ('nop', 'imp'), 0xec: ('cpx', 'abs'),
    0xed: ('sbc', 'abs'), 0xee: ('inc', 'abs'),
    0xf0: ('beq', 'rel'), 0xf1: ('sbc', 'iny'), 0xf5: ('sbc', 'zpx'),
    0xf6: ('inc', 'zpx'), 0xf8: ('sed', 'imp'), 0xf9: ('sbc', 'aby'),
    0xfd: ('sbc', 'abx'), 0xfe: ('inc', 'abx'),
}

MODE_LEN = {'imp': 1, 'acc': 1, 'imm': 2, 'zp': 2, 'zpx': 2, 'zpy': 2,
            'abs': 3, 'abx': 3, 'aby': 3, 'ind': 3, 'inx': 2, 'iny': 2,
            'rel': 2}

BRANCH_OPS = {'bpl', 'bmi', 'bvc', 'bvs', 'bcc', 'bcs', 'bne', 'beq'}

# Known NES hardware register addresses + names.
HW_REGS = {
    0x2000: 'PPUCTRL',   0x2001: 'PPUMASK',   0x2002: 'PPUSTATUS',
    0x2003: 'OAMADDR',   0x2004: 'OAMDATA',   0x2005: 'PPUSCROLL',
    0x2006: 'PPUADDR',   0x2007: 'PPUDATA',
    0x4000: 'SQ1_VOL',   0x4001: 'SQ1_SWEEP', 0x4002: 'SQ1_LO',
    0x4003: 'SQ1_HI',    0x4004: 'SQ2_VOL',   0x4005: 'SQ2_SWEEP',
    0x4006: 'SQ2_LO',    0x4007: 'SQ2_HI',    0x4008: 'TRI_LINEAR',
    0x400a: 'TRI_LO',    0x400b: 'TRI_HI',    0x400c: 'NOISE_VOL',
    0x400e: 'NOISE_LO',  0x400f: 'NOISE_HI',  0x4010: 'DMC_FREQ',
    0x4011: 'DMC_RAW',   0x4012: 'DMC_START', 0x4013: 'DMC_LEN',
    0x4014: 'OAMDMA',    0x4015: 'SND_CHN',   0x4016: 'JOY1',
    0x4017: 'JOY2',
}

# RAM annotations for 1942, sourced from Data Crystal's RAM map.
# Format: addr -> (label, comment)
RAM_LABELS = {
    0x0427: ('Score_D5',   'score digit (100,000s)'),
    0x0428: ('Score_D4',   'score digit (10,000s)'),
    0x0429: ('Score_D3',   'score digit (1,000s)'),
    0x042a: ('Score_D2',   'score digit (100s)'),
    0x042b: ('Score_D1',   'score digit (10s)'),
    0x042c: ('Score_D0',   'score digit (1s)'),
    0x0431: ('Lives_Tens', 'lives tens digit'),
    0x0432: ('Lives_Ones', 'lives ones digit (starts at 02)'),
    0x0436: ('Rolls',      'special rolls remaining (starts at 03)'),
    0x0438: ('Level',      'current stage (00 = stage 1)'),
}

# Vector labels.
VECTOR_LABELS = {
    0xfffa: ('NMIVector',   'NMI vector'),
    0xfffc: ('ResetVector', 'RESET vector'),
    0xfffe: ('IRQVector',   'IRQ/BRK vector'),
}


# ---------------------------------------------------------------------------
# User-editable label overlay. Format: {"$0711": ["Fire_Cooldown", "comment"]}.
# Keys are hex strings (parsed via int(k, 16)); values are [name, comment].
# Entries merge on top of the hardcoded RAM_LABELS, so additions or
# overrides persist without touching disasm.py itself.
# ---------------------------------------------------------------------------
def load_user_labels(path='labels.json'):
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        raw = json.load(f)
    labels = {}
    for k, v in raw.items():
        key = k.lstrip('$')  # tolerate "$0711" or "0711"
        addr = int(key, 16)
        if isinstance(v, list) and len(v) >= 1:
            name = v[0]
            comment = v[1] if len(v) >= 2 else ''
        else:
            sys.exit(f'labels.json: value for {k} must be [name, comment]')
        labels[addr] = (name, comment)
    return labels


# ---------------------------------------------------------------------------
# iNES loader
# ---------------------------------------------------------------------------
def load_ines(path):
    with open(path, 'rb') as f:
        data = f.read()
    if data[:4] != b'NES\x1a':
        sys.exit('not an iNES file: bad magic')
    prg_banks = data[4]
    chr_banks = data[5]
    flags6 = data[6]
    flags7 = data[7]
    mapper = (flags6 >> 4) | (flags7 & 0xf0)
    has_trainer = bool(flags6 & 0x04)
    prg_size = prg_banks * 16384
    chr_size = chr_banks * 8192
    off = 16 + (512 if has_trainer else 0)
    prg = data[off:off + prg_size]
    chr_rom = data[off + prg_size:off + prg_size + chr_size]
    return {
        'mapper': mapper, 'prg_banks': prg_banks, 'chr_banks': chr_banks,
        'flags6': flags6, 'flags7': flags7, 'header': data[:16],
        'prg': prg, 'chr': chr_rom,
    }


# ---------------------------------------------------------------------------
# Recursive descent disassembly
# ---------------------------------------------------------------------------
class Disassembler:
    def __init__(self, prg):
        if len(prg) != 0x8000:
            sys.exit(f'expected 32 KB PRG (NROM-256), got {len(prg)}')
        self.prg = prg                          # 32 KB, mapped at $8000
        self.is_code = bytearray(0x8000)        # 1 = start of an instruction
        self.is_op_byte = bytearray(0x8000)     # 1 = part of an instruction
        self.code_xref = defaultdict(set)       # target_addr -> {source_addrs}
        self.data_xref = defaultdict(set)       # target_addr -> {source_addrs}
        self.write_sites = defaultdict(list)    # target_addr -> [pc, ...] for STA/STX/STY
        self.entry_points = set()               # explicit roots (vectors, etc.)
        self.jump_targets = set()               # branch/jmp/jsr destinations

    def writes_to(self, addr):
        """Return PCs of all STA/STX/STY instructions that write to `addr`."""
        return list(self.write_sites.get(addr, ()))

    def read(self, addr):
        return self.prg[addr - 0x8000]

    def read_word(self, addr):
        return self.read(addr) | (self.read(addr + 1) << 8)

    def in_prg(self, addr):
        return 0x8000 <= addr <= 0xffff

    def disassemble(self):
        # Standard NES vectors live at the top of PRG.
        for vec in (0xfffa, 0xfffc, 0xfffe):
            target = self.read_word(vec)
            if self.in_prg(target):
                self.entry_points.add(target)
                self.jump_targets.add(target)

        # Pass 1: trace from the official entry points.
        self._trace_worklist(list(self.entry_points), tentative=False)

        # Pass 2: rescue routines reached via dispatch. Iterate two
        # heuristics to convergence:
        #   (a) the byte after every routine terminator (RTS/RTI/JMP/BRK) is
        #       a plausible new entry point;
        #   (b) every word-aligned 16-bit value in unmarked data whose high
        #       byte falls in PRG range ($80-$ff) is a plausible code
        #       pointer (i.e. a jump-table entry).
        # Speculative traces only commit if they produce >= 6 bytes of
        # clean code ending in a terminator, so data tables that happen to
        # start with a valid opcode are rejected.
        for _ in range(16):
            before = sum(self.is_op_byte)
            candidates = self._terminator_followers() + self._jump_table_targets()
            if not candidates:
                break
            self._trace_worklist(candidates, tentative=True)
            if sum(self.is_op_byte) == before:
                break

    def _trace_worklist(self, worklist, tentative=False):
        """Trace each address in worklist forward until a terminator or until
        an invalid opcode is hit. When tentative=True, only commit the trace
        if it stayed valid for a meaningful run."""
        visited = set()
        for entry in worklist:
            if entry in visited or not self.in_prg(entry):
                continue
            if tentative and self.is_op_byte[entry - 0x8000]:
                continue  # already known to be code
            stack = [entry]
            while stack:
                pc = stack.pop()
                trace = []                      # (pc, length, mnemonic, mode)
                branch_targets = []
                jsr_targets = []
                cur = pc
                ok = True
                while True:
                    if cur in visited or not self.in_prg(cur):
                        break
                    if tentative and self.is_op_byte[cur - 0x8000]:
                        break
                    opcode = self.read(cur)
                    info = OPCODES.get(opcode)
                    if info is None:
                        ok = False if tentative and len(trace) < 6 else True
                        break
                    mnemonic, mode = info
                    length = MODE_LEN[mode]
                    if cur + length - 1 > 0xffff:
                        ok = False
                        break
                    trace.append((cur, length, mnemonic, mode))
                    visited.add(cur)
                    next_pc = cur + length
                    terminator = False

                    if mode == 'rel':
                        off = self.read(cur + 1)
                        if off >= 0x80: off -= 0x100
                        target = next_pc + off
                        if self.in_prg(target):
                            branch_targets.append((target, cur))
                    elif mnemonic == 'jmp' and mode == 'abs':
                        target = self.read_word(cur + 1)
                        if self.in_prg(target):
                            branch_targets.append((target, cur))
                        terminator = True
                    elif mnemonic == 'jmp' and mode == 'ind':
                        terminator = True
                    elif mnemonic == 'jsr':
                        target = self.read_word(cur + 1)
                        if self.in_prg(target):
                            jsr_targets.append((target, cur))
                    elif mnemonic in ('rts', 'rti', 'brk'):
                        terminator = True
                    elif mode in ('abs', 'abx', 'aby'):
                        target = self.read_word(cur + 1)
                        if self.in_prg(target):
                            self.data_xref[target].add(cur)

                    if terminator:
                        break
                    cur = next_pc

                # Tentative traces must (a) be reasonably long, (b) end in a
                # real terminator (not "fell off into invalid"), and (c) not
                # contain BRK ($00 opcode) — BRK is exceedingly rare in real
                # game code but data tables of zeros and small values often
                # disassemble cleanly into BCC/LDY/BCS/BVC sequences ending
                # at the first $00 byte. Rejecting any tentative trace that
                # contains BRK eliminates that whole class of false positive.
                contains_brk = any(self.prg[c - 0x8000] == 0x00
                                   for (c, _, _, _) in trace)
                if tentative and (not ok or len(trace) < 6 or contains_brk):
                    for (cur, _, _, _) in trace:
                        visited.discard(cur)
                    continue

                # Commit the trace. Mark the entry point as a label so it's
                # visible in the listing as a jump-table target. Also record
                # write-sites so downstream tools can ask "what code stores
                # to this RAM address?"
                if trace:
                    self.jump_targets.add(trace[0][0])
                for (cur, length, mnemonic, mode) in trace:
                    self.is_code[cur - 0x8000] = 1
                    for i in range(length):
                        self.is_op_byte[cur + i - 0x8000] = 1
                    if (mnemonic in ('sta', 'stx', 'sty')
                            and mode in ('abs', 'abx', 'aby', 'zp', 'zpx', 'zpy')):
                        if mode.startswith('zp'):
                            target = self.read(cur + 1)
                        else:
                            target = self.read_word(cur + 1)
                        self.write_sites[target].append(cur)
                for (target, src) in branch_targets:
                    self.jump_targets.add(target)
                    self.code_xref[target].add(src)
                    if target not in visited:
                        stack.append(target)
                for (target, src) in jsr_targets:
                    self.jump_targets.add(target)
                    self.code_xref[target].add(src)
                    if target not in visited:
                        stack.append(target)

    def _jump_table_targets(self):
        """Find candidate code pointers in data: scan unmarked PRG bytes for
        16-bit words whose high byte is in $80-$ff. Treat the pointed-to
        addresses as candidate code starts. Tentative tracing rejects most
        false positives."""
        targets = set()
        off = 0
        while off + 1 < 0x8000:
            if self.is_op_byte[off] or self.is_op_byte[off + 1]:
                off += 1
                continue
            hi = self.prg[off + 1]
            if 0x80 <= hi <= 0xff:
                target = self.prg[off] | (hi << 8)
                if not self.is_op_byte[target - 0x8000]:
                    targets.add(target)
            off += 2  # word-aligned scan; misaligned tables get caught next pass
        # Also scan starting at off=1 to catch odd-aligned tables.
        off = 1
        while off + 1 < 0x8000:
            if self.is_op_byte[off] or self.is_op_byte[off + 1]:
                off += 1
                continue
            hi = self.prg[off + 1]
            if 0x80 <= hi <= 0xff:
                target = self.prg[off] | (hi << 8)
                if not self.is_op_byte[target - 0x8000]:
                    targets.add(target)
            off += 2
        return list(targets)

    def _terminator_followers(self):
        """Return list of addresses that immediately follow an RTS/RTI/JMP/BRK
        and are not yet marked as code."""
        followers = []
        terminators = {0x60, 0x40, 0x4c, 0x6c, 0x00}  # rts, rti, jmp abs, jmp ind, brk
        for off in range(0x8000):
            if not self.is_code[off]:
                continue
            opcode = self.prg[off]
            if opcode in terminators:
                # Length is 1 for rts/rti/brk, 3 for jmp abs/ind.
                length = 3 if opcode in (0x4c, 0x6c) else 1
                follower_off = off + length
                if follower_off < 0x8000 and not self.is_op_byte[follower_off]:
                    followers.append(0x8000 + follower_off)
        return followers


# ---------------------------------------------------------------------------
# Operand formatting + symbol resolution
# ---------------------------------------------------------------------------
def fmt_byte(b): return f'${b:02x}'
def fmt_word(w): return f'${w:04x}'


def label_for(addr, dis, ram_labels):
    """Return (label, css_class, anchor_id_or_None) for an address operand."""
    if addr in HW_REGS:
        return (HW_REGS[addr], 'reg', None)
    if addr in ram_labels:
        return (ram_labels[addr][0], 'ram', None)
    if 0x8000 <= addr <= 0xffff and addr in dis.jump_targets:
        return (f'L_{addr:04x}', 'code', f'L_{addr:04x}')
    return (None, None, None)


def operand_html(pc, opcode, mode, mnemonic, dis, ram_labels):
    """Return (operand_text, operand_html). operand_text is plain string used
    for column padding; operand_html is what we write to the file."""
    p = dis.prg
    base = pc - 0x8000

    def lookup(addr):
        return label_for(addr, dis, ram_labels)

    if mode == 'imp':
        return ('', '')
    if mode == 'acc':
        return ('A', 'A')
    if mode == 'imm':
        b = p[base + 1]
        return (f'#{fmt_byte(b)}', html.escape(f'#{fmt_byte(b)}'))
    if mode == 'zp':
        b = p[base + 1]
        lbl, _, _ = lookup(b)
        if lbl:
            return (lbl, html.escape(lbl))
        return (fmt_byte(b), html.escape(fmt_byte(b)))
    if mode == 'zpx':
        b = p[base + 1]
        return (f'{fmt_byte(b)},X', html.escape(f'{fmt_byte(b)},X'))
    if mode == 'zpy':
        b = p[base + 1]
        return (f'{fmt_byte(b)},Y', html.escape(f'{fmt_byte(b)},Y'))
    if mode in ('abs', 'abx', 'aby'):
        w = p[base + 1] | (p[base + 2] << 8)
        lbl, _, anchor = lookup(w)
        suffix = {'abs': '', 'abx': ',X', 'aby': ',Y'}[mode]
        if lbl:
            text = lbl + suffix
            if anchor:
                disp = f'<a href="#{anchor}">{html.escape(lbl)}</a>{html.escape(suffix)}'
            else:
                disp = html.escape(lbl) + html.escape(suffix)
            return (text, disp)
        text = fmt_word(w) + suffix
        return (text, html.escape(text))
    if mode == 'ind':
        w = p[base + 1] | (p[base + 2] << 8)
        return (f'({fmt_word(w)})', html.escape(f'({fmt_word(w)})'))
    if mode == 'inx':
        b = p[base + 1]
        return (f'({fmt_byte(b)},X)', html.escape(f'({fmt_byte(b)},X)'))
    if mode == 'iny':
        b = p[base + 1]
        return (f'({fmt_byte(b)}),Y', html.escape(f'({fmt_byte(b)}),Y'))
    if mode == 'rel':
        off = p[base + 1]
        if off >= 0x80:
            off -= 0x100
        target = pc + 2 + off
        lbl, _, anchor = lookup(target)
        if lbl:
            if anchor:
                return (lbl, f'<a href="#{anchor}">{html.escape(lbl)}</a>')
            return (lbl, html.escape(lbl))
        text = fmt_word(target)
        return (text, html.escape(text))
    return ('', '')


# ---------------------------------------------------------------------------
# Line emission. Column layout matches the SMB disassembly:
#   cols 1-6   address ("XXXX: ")
#   cols 7-19  bytes (13 chars: 4 bytes × 3 chars + slack)
#   cols 20-35 label (16 chars)
#   cols 36-43 mnemonic (8 chars)
#   cols 44-67 operand (24 chars)
#   cols 68+   ;comment
# ---------------------------------------------------------------------------
ADDR_W = 6
BYTES_W = 13
LABEL_W = 16
MNEMONIC_W = 8
OPERAND_W = 24


def pad_html(visible, html_str, width):
    """Return html_str padded with trailing spaces so the visible column is
    `width` wide. Spaces past the visible width are ordinary spaces."""
    pad = max(0, width - len(visible))
    return html_str + ' ' * pad


def emit_instruction(pc, dis, ram_labels, comment=None):
    opcode = dis.read(pc)
    mnemonic, mode = OPCODES[opcode]
    length = MODE_LEN[mode]
    bytes_hex = ' '.join(f'{dis.read(pc + i):02x}' for i in range(length))

    addr_col = f'{pc:04x}: '
    bytes_col = pad_html(bytes_hex, bytes_hex, BYTES_W)

    label_text = ''
    label_html = ''
    if pc in dis.jump_targets:
        name = f'L_{pc:04x}'
        label_text = name
        label_html = f'<span id="{name}">{name}</span>'
    label_col = pad_html(label_text, label_html, LABEL_W)

    mnemonic_col = pad_html(mnemonic, mnemonic, MNEMONIC_W)

    op_text, op_html = operand_html(pc, opcode, mode, mnemonic, dis, ram_labels)
    operand_col = pad_html(op_text, op_html, OPERAND_W)

    line = addr_col + bytes_col + label_col + mnemonic_col + operand_col
    if comment:
        line += '; ' + html.escape(comment)
    return line


DATA_PER_ROW = 8


def emit_data_row(pc, run_bytes, dis):
    """Emit a row of up to DATA_PER_ROW data bytes as `.byte $xx, $xx, ...`.
    The run is broken so labels always start a new row."""
    addr_col = f'{pc:04x}: '
    hex_run = ' '.join(f'{b:02x}' for b in run_bytes[:4])
    if len(run_bytes) > 4:
        hex_run += ' ..'
    bytes_col = pad_html(hex_run, hex_run, BYTES_W)

    label_text = ''
    label_html = ''
    if pc in dis.jump_targets or pc in dis.data_xref:
        name = f'D_{pc:04x}'
        label_text = name
        label_html = f'<span id="{name}">{name}</span>'
    label_col = pad_html(label_text, label_html, LABEL_W)

    mnemonic_col = pad_html('.byte', '.byte', MNEMONIC_W)
    op_text = ', '.join(fmt_byte(b) for b in run_bytes)
    operand_col = op_text  # let it overflow the operand column for data rows
    return addr_col + bytes_col + label_col + mnemonic_col + operand_col


# ---------------------------------------------------------------------------
# Top-level: render the full listing as HTML
# ---------------------------------------------------------------------------
HTML_HEADER = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8"/>
    <title>1942 Disassembly</title>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <meta name="description" content="Machine-generated 6502 disassembly of 1942 (NES)"/>
    <style>
      body { font-family: ui-monospace, Menlo, Consolas, monospace;
             background: #fafafa; color: #222; margin: 1.5em; }
      h1 { font-family: system-ui, sans-serif; }
      pre { font-size: 13px; line-height: 1.35; white-space: pre; }
      a { color: #1a4fb0; text-decoration: none; }
      a:hover { text-decoration: underline; }
      .preamble { font-family: system-ui, sans-serif; max-width: 60em;
                  background: #fff; border: 1px solid #ddd; padding: 1em 1.5em;
                  border-radius: 6px; }
      .preamble code { background: #f0f0f0; padding: 0 .25em; border-radius: 3px; }
      span[id^="L_"] { color: #0a6e0a; font-weight: 600; }
      span[id^="D_"] { color: #8a4500; font-weight: 600; }
    </style>
</head>
<body>
"""

PREAMBLE = """<h1>1942 Disassembly (NES)</h1>
<div class="preamble">
<p><b>This is a machine-generated disassembly</b>, not a hand-curated reverse
engineering. Code reachable from the RESET / NMI / IRQ vectors is decoded as
6502 instructions; everything else is shown as raw <code>.byte</code> data.
Routines are auto-labeled <code>L_xxxx</code> at every JSR/JMP/branch target
and data references are labeled <code>D_xxxx</code>. NES hardware registers
(<code>PPUCTRL</code>, <code>OAMDMA</code>, etc.) and the small RAM map
documented at <a href="https://datacrystal.tcrf.net/wiki/1942_(NES)/RAM_map">Data
Crystal</a> (score, lives, rolls, level) are resolved by name.</p>
<p>The ROM is NROM-256 (mapper 0): 32 KB PRG mapped at <code>$8000-$ffff</code>
plus 8 KB CHR. Only the PRG is disassembled here.</p>
<p><b>Game Genie codes</b> (from <a
href="https://gamegenie.com/cheats/gamegenie/nes/1942.html">gamegenie.com</a>):
<code>IESUTYZA</code>/<code>AESUTYZE</code> set 1P starting lives to 6/9;
<code>IAKUUAZA</code>/<code>AAKUUAZE</code> set P1 continue lives in 2P;
<code>IASUOAZA</code>/<code>AASUOAZE</code> set P2 lives;
<code>PASIOALE</code> sets both players to 9 rolls. The patch sites these
target appear in the listing below as <code>STA Lives_Ones</code> /
<code>STA Rolls</code> stores after game start.</p>
</div>
<pre>
"""

HTML_FOOTER = """</pre>
</body>
</html>
"""


def render(rom, dis, out_path, user_labels=None):
    prg = rom['prg']
    ram_labels = dict(RAM_LABELS)
    if user_labels:
        ram_labels.update(user_labels)
    lines = []

    # Header banner with iNES + vector info.
    h = rom['header']
    lines.append(html.escape(
        '*' * 80))
    lines.append(html.escape(
        f'* 1942 (NES) — Capcom, December 1985'.ljust(79) + '*'))
    lines.append(html.escape(
        f'* iNES: PRG={rom["prg_banks"]}x16K  CHR={rom["chr_banks"]}x8K  '
        f'mapper={rom["mapper"]}  flags6=${h[6]:02x}  flags7=${h[7]:02x}'.ljust(79) + '*'))
    nmi = dis.read_word(0xfffa); rst = dis.read_word(0xfffc); irq = dis.read_word(0xfffe)
    lines.append(html.escape(
        f'* Vectors: NMI=${nmi:04x}  RESET=${rst:04x}  IRQ=${irq:04x}'.ljust(79) + '*'))
    lines.append(html.escape('*' * 80))
    lines.append('')

    # Hardware register equates (for reference).
    lines.append('; ----- NES hardware registers -----')
    for addr in sorted(HW_REGS):
        name = HW_REGS[addr]
        lines.append(f'{name:<12s} = ${addr:04x}')
    lines.append('')
    lines.append('; ----- 1942 RAM map (Data Crystal) -----')
    for addr in sorted(ram_labels):
        name, desc = ram_labels[addr][0], ram_labels[addr][1]
        lines.append(f'{name:<12s} = ${addr:04x}  ; {desc}')
    lines.append('')

    # Walk the PRG in address order, emitting instructions for code bytes
    # and .byte directives for everything else.
    pc = 0x8000
    while pc <= 0xffff:
        idx = pc - 0x8000

        if dis.is_code[idx]:
            opcode = dis.read(pc)
            _, mode = OPCODES[opcode]
            length = MODE_LEN[mode]
            comment = None
            if pc == dis.read_word(0xfffc): comment = 'RESET entry point'
            if pc == dis.read_word(0xfffa): comment = 'NMI entry point'
            if pc == dis.read_word(0xfffe): comment = 'IRQ/BRK entry point'
            lines.append(emit_instruction(pc, dis, ram_labels, comment))
            pc += length
            continue

        # Vectors: emit them as little-endian word data with names.
        if pc == 0xfffa:
            for v_addr, (name, desc) in VECTOR_LABELS.items():
                lo = dis.read(v_addr); hi = dis.read(v_addr + 1)
                addr_col = f'{v_addr:04x}: '
                bytes_col = pad_html(f'{lo:02x} {hi:02x}',
                                     f'{lo:02x} {hi:02x}', BYTES_W)
                label_html = f'<span id="{name}">{name}</span>'
                label_col = pad_html(name, label_html, LABEL_W)
                mnem_col = pad_html('.word', '.word', MNEMONIC_W)
                target = lo | (hi << 8)
                tlabel, _, anchor = label_for(target, dis, ram_labels)
                if tlabel and anchor:
                    op_disp = f'<a href="#{anchor}">{html.escape(tlabel)}</a>'
                    op_vis = tlabel
                else:
                    op_vis = f'${target:04x}'
                    op_disp = html.escape(op_vis)
                op_col = pad_html(op_vis, op_disp, OPERAND_W)
                lines.append(addr_col + bytes_col + label_col + mnem_col +
                             op_col + '; ' + desc)
            pc = 0x10000
            continue

        # Group consecutive data bytes into rows of up to DATA_PER_ROW.
        # Break the row early at any address that has a label (so the label
        # always lands at the start of its own row).
        run = []
        run_start = pc
        while (pc <= 0xffff
               and not dis.is_op_byte[pc - 0x8000]
               and pc != 0xfffa
               and len(run) < DATA_PER_ROW):
            if run and (pc in dis.jump_targets or pc in dis.data_xref):
                break  # label boundary — flush and start new row next iteration
            run.append(dis.read(pc))
            pc += 1
        if run:
            lines.append(emit_data_row(run_start, run, dis))

    with open(out_path, 'w') as f:
        f.write(HTML_HEADER)
        f.write(PREAMBLE)
        for line in lines:
            f.write(line)
            f.write('\n')
        f.write(HTML_FOOTER)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('rom')
    ap.add_argument('-o', '--output', required=True)
    ap.add_argument('--labels', default='labels.json',
                    help='path to user label overlay (default: labels.json)')
    args = ap.parse_args()

    rom = load_ines(args.rom)
    print(f'loaded: mapper={rom["mapper"]} prg={len(rom["prg"])} '
          f'chr={len(rom["chr"])}', file=sys.stderr)
    if rom['mapper'] != 0:
        sys.exit(f'this disassembler only supports mapper 0 (got {rom["mapper"]})')
    dis = Disassembler(rom['prg'])
    dis.disassemble()
    code_bytes = sum(dis.is_op_byte)
    print(f'code coverage: {code_bytes}/{len(rom["prg"])} bytes '
          f'({100*code_bytes/len(rom["prg"]):.1f}%)', file=sys.stderr)
    print(f'jump targets:  {len(dis.jump_targets)}', file=sys.stderr)
    user_labels = load_user_labels(args.labels)
    if user_labels:
        print(f'user labels:   {len(user_labels)} from {args.labels}',
              file=sys.stderr)
    render(rom, dis, args.output, user_labels=user_labels)
    print(f'wrote {args.output}', file=sys.stderr)


if __name__ == '__main__':
    main()
