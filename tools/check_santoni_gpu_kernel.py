#!/usr/bin/env python3
"""Check the actual CI binary before staging an opt-in GPU boot image.

This checks wiring/code generation, not GPU functionality or TrustZone policy.
"""
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
import re
import struct
import subprocess
import sys
import argparse
from santoni_gpu_cache_audit import HELPERS as CACHE_HELPERS, audit_cache
from santoni_gpu_stock_audit import HELPERS as STOCK_HELPERS, audit_stock
from santoni_gpu_pixel_audit import HELPERS as PIXEL_HELPERS, audit_pixels
from santoni_gpu_g3_audit import HELPERS as G3_HELPERS, audit_g3
from santoni_gpu_control_audit import GATE as CONTROL_GATE, audit_control
from santoni_gpu_session_audit import audit_session

ROOT = Path(__file__).resolve().parents[1]


def _symbols(text, local=False):
    symbols = {}
    for line in text.splitlines():
        match = re.fullmatch(r'\s*([0-9a-fA-F]+)\s+[A-Za-z]\s+(\S+)\s*', line)
        if match and (not local or line.split()[-2].islower()):
            symbols.setdefault(match[2], set()).add(int(match[1], 16))
    return symbols


def _number(text):
    try:
        return int(text.strip().removeprefix('#'), 0)
    except ValueError:
        return None


def _unsupported(op, operands):
    # Check decoded mnemonics, never comments, symbol names or diagnostic prose.
    # Include LSE store aliases, acquire/release and byte/halfword suffixes,
    # paired CAS, RCpc/RCpc2, and every PAC instruction/branch spelling.
    return bool(re.fullmatch(
        r'(?:cas|swp|(?:ld|st)(?:add|clr|eor|set|smax|smin|umax|umin)|'
        r'ldapr|ldapur|stlur|pac|aut|xpac|braa|brab|blraa|blrab|'
        r'retaa|retab|eretaa|eretab|ldraa|ldrab|ld64b|st64b)[a-z0-9]*|'
        r'bti|sb|ssbb|pssbb|dgh|cfinv|rmif|setf8|setf16|sdot|udot', op) or
        re.search(r'\b(?:z\d+|p\d+)\b', operands))


class _Code:
    """Bounded decoded instruction graph, including unreachable instructions.

    LLVM remains the decoder. Missing/unknown instructions, holes and unresolved
    direct branches are not evidence of inspected code and fail closed.
    """
    def __init__(self, text, symbol, address, noreturn=()):
        self.symbol, self.entry, self.ins = symbol, address, {}
        active = False
        for line in text.splitlines():
            header = re.fullmatch(r'\s*([0-9a-fA-F]+) <([^>]+)>:\s*', line)
            if header:
                active = header[2] == symbol and int(header[1], 16) == address
                continue
            if active and line.strip() == '...':
                raise ValueError(f'elided actual code: {symbol}')
            if not active or not re.match(r'\s*[0-9a-fA-F]+:', line):
                continue
            decoded = re.fullmatch(
                r'\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{8}|'
                r'(?:[0-9a-fA-F]{2}\s+){3}[0-9a-fA-F]{2})\s+'
                r'([A-Za-z][A-Za-z0-9_.]*)\s*(.*?)\s*', line)
            if not decoded or decoded[2] == 'unknown':
                raise ValueError(f'could not decode actual Cortex-A53 code: {symbol}')
            pc, op = int(decoded[1], 16), decoded[2].lower()
            body = decoded[3].split(';', 1)[0].split('<', 1)[0].strip()
            if _unsupported(op, body):
                raise ValueError(f'unsupported Cortex-A53 instruction in {symbol}: {op}')
            args = tuple(re.split(r',\s*(?![^\[]*\])', body)) if body else ()
            if op == 'udf':
                encoded = re.search(r':\s+([0-9a-fA-F]{8}|(?:[0-9a-fA-F]{2}\s+){3}[0-9a-fA-F]{2})', line)
                if (not encoded or re.sub(r'\s+', '', encoded[1]) != '00000000' or
                        len(args) != 1 or _number(args[0]) != 0):
                    raise ValueError(f'could not decode actual Cortex-A53 code: {symbol}')
            if pc != address + 4 * len(self.ins) or len(self.ins) >= 10000:
                raise ValueError(f'incomplete/oversized actual code inspection: {symbol}')
            self.ins[pc] = (op, args)
        if not self.ins:
            raise ValueError(f'could not inspect actual GPU code: {symbol}')
        # AppleClang places up to 12 bytes of zero padding after a terminating
        # branch/return to align the next function to 16 bytes. LLVM prints this
        # known zero encoding as UDF #0. Never admit a reachable/interior trap,
        # unknown opcode or arbitrary hole as padding.
        padding = []
        while self.ins and self.ins[max(self.ins)][0] == 'udf':
            padding.append(max(self.ins))
            del self.ins[max(self.ins)]
        terminates = bool(self.ins) and (self.ins[max(self.ins)][0] in ('b', 'ret') or
            self.ins[max(self.ins)][0] == 'bl' and _number(self.ins[max(self.ins)][1][-1]) in noreturn)
        if padding and (not terminates or len(padding) > 3 or (max(padding) + 4) % 16):
            raise ValueError(f'unproven zero alignment padding in {symbol}')
        if any(op == 'udf' or (op == 'b' or self.conditional(op)) and
               _number(args[-1]) in padding for op, args in self.ins.values()):
            raise ValueError(f'reachable/interior zero trap in {symbol}')
        self.padding = tuple(sorted(padding))
        # A decoded BL to a separately verified non-returning callee is a
        # terminal edge. Never infer this from LLVM's symbol annotation or
        # from an arbitrary call at the end of a truncated disassembly.
        self.noreturn = {pc for pc, (op, args) in self.ins.items()
                         if op == 'bl' and _number(args[-1]) in noreturn}
        self.succ, self.pred = {}, {pc: set() for pc in self.ins}
        for pc, (op, args) in self.ins.items():
            successors = []
            if op == 'b' or self.conditional(op):
                target = _number(args[-1])
                if target is None or (self.conditional(op) and target not in self.ins):
                    raise ValueError(f'uninspectable branch in {symbol}')
                if target in self.ins:
                    successors.append(target)
            if op not in ('ret', 'b', 'br', 'brk', 'hlt') and pc not in self.noreturn:
                if pc + 4 in self.ins:
                    successors.append(pc + 4)
            self.succ[pc] = tuple(dict.fromkeys(successors))
            for successor in successors:
                self.pred[successor].add(pc)
        self.reachable = self.walk(self.entry)
        if any(not self.succ[pc] and pc not in self.noreturn and
               self.ins[pc][0] not in ('ret', 'b', 'br', 'brk', 'hlt')
               for pc in self.reachable):
            raise ValueError(f'truncated actual code: {symbol}')

    @staticmethod
    def conditional(op):
        return op.startswith('b.') or op in ('cbz', 'cbnz', 'tbz', 'tbnz')

    def walk(self, start, exclude=()):
        seen, pending = set(), [start]
        while pending:
            pc = pending.pop()
            if pc in seen or pc in exclude:
                continue
            seen.add(pc)
            pending.extend(self.succ[pc])
        return seen

    def calls_to(self, addresses, reachable=None):
        return sorted(pc for pc in (self.reachable if reachable is None else reachable)
                if self.ins[pc][0] in ('bl', 'b') and
                _number(self.ins[pc][1][-1]) in addresses and
                (self.ins[pc][0] != 'b' or _number(self.ins[pc][1][-1]) not in self.ins))


def _mmio(code, bits, write, reachable=None):
    """Require the actual inline-asm block, with no branch into its middle."""
    operation, prefix = ('str', 'w' if bits == 32 else 'x') if write else (
        'ldr', 'w' if bits == 32 else 'x')
    reachable = code.reachable if reachable is None else set(reachable)
    blocks = []
    for pc in sorted(reachable):
        op, args = code.ins[pc]
        if op != operation or len(args) != 2:
            continue
        # Stack spills and address-table loads are not MMIO. Read callbacks
        # return their inline-asm output in register 0 in the inspected ABI.
        if write and re.match(r'\[(?:sp|x29)(?:,|\])', args[1]):
            continue
        if not write and args[0] not in ('w0', 'x0', 'wzr', 'xzr') and code.ins.get(pc + 4) != ('dmb', ('sy',)):
            continue
        expected = re.fullmatch(prefix + r'\d+', args[0]) if write else args[0] == prefix + '0'
        address = re.fullmatch(r'\[x\d+(?:, #(?:0|0x0))?\]', args[1])
        post = ('dsb', ('sy',)) if write else ('dmb', ('sy',))
        if (not expected or not address or code.ins.get(pc + 4) != post or
                code.pred[pc + 4] & reachable != {pc} or
                (write and (code.ins.get(pc - 4) != ('dmb', ('sy',)) or
                            code.pred[pc] & reachable != {pc - 4}))):
            raise ValueError(f'MMIO {bits}-bit {operation}/ordered reachable barriers invalid: {code.symbol}')
        blocks.append(hex(pc))
    if not blocks:
        raise ValueError(f'MMIO {bits}-bit {operation}/barrier block missing: {code.symbol}')
    return blocks


class _Image:
    """Read-only VA view; resolve chained pointers on an in-memory copy only."""
    def __init__(self, data):
        import mkpayload
        try:
            header = struct.unpack_from('<8I', data)
            if header[0] != 0xfeedfacf or header[1] != 0x100000c:
                raise ValueError('not an ARM64 Mach-O')
            count, size = header[4:6]
            if count > 4096 or 32 + size > len(data):
                raise ValueError('load commands out of bounds')
            off = 32
            protections = {}
            for _ in range(count):
                command, length = struct.unpack_from('<II', data, off)
                if length < 8 or off + length > 32 + size:
                    raise ValueError('load command out of bounds')
                if command == 0x19:
                    if length < 72:
                        raise ValueError('short segment command')
                    segment = struct.unpack_from('<II16s4Q4I', data, off)
                    identity = (segment[2].split(b'\0', 1)[0].decode(), *segment[3:7])
                    if identity in protections:
                        raise ValueError('ambiguous segment protections')
                    protections[identity] = segment[8]
                off += length
            if off != 32 + size:
                raise ValueError('incomplete load commands')
            self.meta = mkpayload.parse_macho(data)
            self.segs = self.meta['segs']
            for seg in self.segs:
                seg['initprot'] = protections[(seg['name'], seg['vmaddr'], seg['vmsize'],
                                              seg['fileoff'], seg['filesize'])]
                # XNU carries file-only __CTF metadata at vmsize=0. It is
                # not mapped by mkpayload and cannot supply an Ops pointer.
                if ((seg['vmsize'] and seg['filesize'] > seg['vmsize']) or
                        seg['fileoff'] + seg['filesize'] > len(data)):
                    raise ValueError('segment out of bounds')
            view = bytearray(data)
            mkpayload.apply_chained_fixups(view, self.meta)
            self.data = bytes(view)
        except (AssertionError, IndexError, KeyError, struct.error, ValueError) as error:
            raise ValueError('could not inspect Mach-O Ops pointers') from error

    def read(self, address, size):
        matches = [s for s in self.segs if s['vmsize'] and s['vmaddr'] <= address and
                   address + size <= s['vmaddr'] + min(s['vmsize'], s['filesize'])]
        if len(matches) != 1:
            return None
        off = matches[0]['fileoff'] + address - matches[0]['vmaddr']
        return int.from_bytes(self.data[off:off + size], 'little')


@dataclass(frozen=True)
class _Value:
    bits: int
    expr: object


def _cast(value, bits):
    if value is None:
        return None
    if isinstance(value.expr, int):
        return _Value(bits, value.expr & ((1 << bits) - 1))
    if value.expr[0] == 'bytes':
        if bits % 8:
            return None
        data = value.expr[1][:bits // 8]
        data += (0,) * (bits // 8 - len(data))
        if all(byte is not None for byte in data):
            return _Value(bits, int.from_bytes(bytes(data), 'little'))
        return _Value(bits, ('bytes', data)) if any(byte is not None for byte in data) else None
    if bits == value.bits or value.expr[0] in ('result', 'bool'):
        return _Value(bits, value.expr)
    if value.expr[0] == 'zext' and bits <= value.expr[1].bits:
        return _cast(value.expr[1], bits)
    return _Value(bits, ('lo' if bits < value.bits else 'zext', value))


def _binary(op, bits, a, b):
    if a is None or b is None:
        return None
    if op in ('add', 'sub') and isinstance(b.expr, int) and isinstance(a.expr, tuple) and a.expr[0] in (
            'stack', 'probe', 'ops', 'report'):
        return _Value(bits, (a.expr[0], a.expr[1] + b.expr * (1 if op == 'add' else -1)))
    if isinstance(a.expr, int) and isinstance(b.expr, int):
        x, y = a.expr, b.expr
        if op in ('lsl', 'lsr') and not 0 <= y < bits:
            return None
        value = {'add': lambda: x + y, 'sub': lambda: x - y,
                 'and': lambda: x & y, 'orr': lambda: x | y,
                 'eor': lambda: x ^ y, 'bic': lambda: x & ~y,
                 'lsl': lambda: x << y, 'lsr': lambda: x >> y}[op]()
        return _cast(_Value(bits, value), bits)
    if op in ('and', 'orr', 'eor', 'add'):
        a, b = sorted((a, b), key=repr)
    return _Value(bits, (op, a, b))


def _eq(a, b):
    return ('eq', *sorted((a, b), key=repr))


def _contains(value, token):
    if value == token:
        return True
    if isinstance(value, _Value):
        return _contains(value.expr, token)
    return isinstance(value, tuple) and any(_contains(part, token) for part in value)


class _State:
    def __init__(self, regs=None, memory=None, flags=None, facts=None):
        self.regs, self.memory = regs or {}, memory or {}
        self.flags, self.facts = flags, facts or {}

    def copy(self):
        return _State(dict(self.regs), dict(self.memory), self.flags, dict(self.facts))

    @staticmethod
    def reg(name):
        if name in ('sp', 'wsp'):
            return 'sp', 64 if name == 'sp' else 32
        match = re.fullmatch(r'([wxqvdsbh])(\d+|zr)', name)
        if not match:
            return None, 0
        kind, number = match.groups()
        return ('x' if kind in 'wx' else 'q') + number, {
            'x': 64, 'w': 32, 'q': 128, 'v': 128, 'd': 64, 's': 32, 'h': 16, 'b': 8}[kind]

    def get(self, name):
        reg, bits = self.reg(name)
        if reg in ('xzr', 'qzr'):
            return _Value(bits, 0)
        return self.resolve(_cast(self.regs.get(reg), bits))

    def put(self, name, value):
        reg, bits = self.reg(name)
        if reg and reg not in ('xzr', 'qzr'):
            if value is None:
                self.regs.pop(reg, None)
            else:
                self.regs[reg] = _cast(value, bits)

    def resolve(self, value):
        if value is None or isinstance(value.expr, int):
            return value
        op, *parts = value.expr
        if op == 'bool':
            truth = self.truth(parts[0])
            return value if truth is None else _Value(value.bits, int(truth))
        if op in ('lo', 'zext'):
            inner = self.resolve(parts[0])
            return _cast(inner, value.bits)
        if op in ('add', 'sub', 'and', 'orr', 'eor', 'bic', 'lsl', 'lsr'):
            return _binary(op, value.bits, *(self.resolve(p) for p in parts))
        return value

    def truth(self, pred):
        if pred in self.facts:
            return self.facts[pred]
        if pred is None:
            return None
        if pred[0] == 'not':
            answer = self.truth(pred[1])
            return None if answer is None else not answer
        if pred[0] == 'and':
            answers = [self.truth(part) for part in pred[1:]]
            return False if False in answers else True if all(value is True for value in answers) else None
        if pred[0] == 'eq':
            a, b = (self.resolve(v) for v in pred[1:])
            if a is not None and b is not None and isinstance(a.expr, int) and isinstance(b.expr, int):
                return a.expr == b.expr
            # These tags denote valid allocated probe/stack objects, not
            # arbitrary incoming arguments. A null branch cannot describe
            # the same invocation as a checked concrete object contract.
            for pointer, zero in ((a, b), (b, a)):
                if (pointer is not None and pointer.bits == 64 and zero == _Value(64, 0) and
                        isinstance(pointer.expr, tuple) and pointer.expr[0] in
                        ('stack', 'probe', 'ops', 'report')):
                    return False
            return None
        _, cond, flags = pred
        if flags is None:
            return None
        if flags[0] == 'ccmp':
            _, previous, a, b, nzcv, guard = flags
            before = self.copy()
            before.flags = previous
            selected = before.truth(before.condition(guard))
            if selected is None:
                return None
            flags = ('cmp', a, b) if selected else ('nzcv', nzcv)
        if flags[0] == 'nzcv':
            n, z, c, v = (bool(flags[1] & bit) for bit in (8, 4, 2, 1))
        else:
            a, b = (self.resolve(value) for value in flags[1:])
            if a is None or b is None or not isinstance(a.expr, int) or not isinstance(b.expr, int):
                return None
            x, y, sign = a.expr, b.expr, 1 << (a.bits - 1)
            if flags[0] == 'cmn':
                total = x + y
                diff = total & ((sign << 1) - 1)
                n, z, c, v = (bool(diff & sign), diff == 0, total >= sign << 1,
                              bool(~(x ^ y) & (x ^ diff) & sign))
            else:
                diff = (x - y) & ((sign << 1) - 1)
                n, z, c, v = bool(diff & sign), diff == 0, x >= y, bool((x ^ y) & (x ^ diff) & sign)
        return {'eq': z, 'ne': not z, 'hs': c, 'cs': c, 'lo': not c, 'cc': not c,
                'hi': c and not z, 'ls': not c or z, 'mi': n, 'pl': not n,
                'vs': v, 'vc': not v, 'ge': n == v, 'lt': n != v,
                'gt': not z and n == v, 'le': z or n != v, 'al': True}.get(cond)

    def condition(self, cond):
        if cond in ('eq', 'ne') and self.flags and self.flags[0] == 'cmn':
            a, b = self.flags[1:]
            bits = a.bits if a is not None else 64
            eq = _eq(_binary('add', bits, a, b), _Value(bits, 0))
            return eq if cond == 'eq' else ('not', eq)
        if cond in ('eq', 'ne') and self.flags and self.flags[0] == 'cmp':
            eq = _eq(*self.flags[1:])
            return eq if cond == 'eq' else ('not', eq)
        if (cond in ('eq', 'ne') and self.flags and self.flags[0] == 'ccmp' and
                self.flags[-1] == 'eq' and not (self.flags[-2] & 4)):
            # CCMP on EQ with fallback Z=0 is exactly the conjunction of
            # previous equality and this full-width comparison. Preserve both.
            before = self.copy()
            before.flags = self.flags[1]
            eq = ('and', *sorted((before.condition('eq'), _eq(self.flags[2], self.flags[3])), key=repr))
            return eq if cond == 'eq' else ('not', eq)
        return ('cond', cond, self.flags)

    def operand(self, text):
        number = _number(text)
        return _Value(64, number) if number is not None else self.get(text)

    def address(self, text):
        match = re.fullmatch(r'\[(sp|x\d+)(?:,\s*(#[+-]?(?:0x[0-9a-f]+|\d+)))?\](!?)', text)
        if not match:
            indexed = re.fullmatch(r'\[(x\d+),\s*([wx]\d+)(?:,\s*(uxtw|lsl)(?: #(\d+))?)?\]', text)
            if indexed:
                base, index, kind, shift = indexed.groups()
                if (index.startswith('w') and kind != 'uxtw' or
                        index.startswith('x') and kind not in (None, 'lsl')):
                    return None, None
                offset = _cast(self.get(index), 64)
                offset = _binary('lsl', 64, offset, _Value(64, int(shift or 0)))
                return _binary('add', 64, self.get(base), offset), None
            return None, None
        value = _binary('add', 64, self.get(match[1]), _Value(64, _number(match[2]) if match[2] else 0))
        return value, match[1] if match[3] else None

    def load(self, address, size, image):
        if address is None:
            return None
        if address.expr == ('probe', 0) and size == 8:
            return _Value(64, ('ops', 0))
        if address.expr == ('probe', 8) and size == 8:
            return _Value(64, ('report', 0))
        if isinstance(address.expr, tuple) and address.expr[0] == 'ops' and size == 8:
            slot = address.expr[1]
            if slot == 0:
                return _Value(64, ('ctx', 0))
            if slot in range(8, 104, 8):
                return _Value(64, ('callback', slot))
        for (base, length), value in self.memory.items():
            delta = self.distance(address.expr, base)
            if delta is not None and 0 <= delta and delta + size <= length:
                value = self.resolve(value)
                if value is not None and isinstance(value.expr, int):
                    return _cast(_Value(size * 8, value.expr >> (8 * delta)), size * 8)
                if delta == 0:
                    return _cast(value, size * 8)
        # Scalar frame fields can be copied by paired vector loads. Assemble
        # only a fully covered constant byte range; any hole/opaque byte stays
        # unknown, including bytes invalidated by a mutating SCM callback.
        if 0 < size <= 4096:
            covered = {}
            for (base, length), value in self.memory.items():
                delta = self.distance(base, address.expr)
                value = self.resolve(value)
                if (delta is None or value is None or not isinstance(value.expr, int) or
                        delta >= size or delta + length <= 0):
                    continue
                for index in range(max(0, delta), min(size, delta + length)):
                    covered[index] = (value.expr >> (8 * (index - delta))) & 0xff
            if len(covered) == size:
                return _Value(size * 8, int.from_bytes(bytes(covered[i] for i in range(size)), 'little'))
        if isinstance(address.expr, int):
            value = image.read(address.expr, size)
            return _Value(size * 8, value) if value is not None else None
        return None

    @staticmethod
    def distance(a, b):
        if isinstance(a, int) and isinstance(b, int):
            return a - b
        if isinstance(a, tuple) and isinstance(b, tuple) and a[0] == b[0] and a[0] in (
                'stack', 'probe', 'ops', 'report'):
            return a[1] - b[1]
        return None

    def load_copy(self, address, size, image):
        """Snapshot partially known vector-copy bytes; unknown neighbors stay unknown.

        Normal scalar loads still require complete coverage. LLVM may use an
        unaligned D-register load to copy two adjacent boot-option scalars;
        the known scalar must survive without inventing the unknown one.
        """
        value = self.load(address, size, image)
        if value is not None or size not in (8, 16):
            return value
        data = []
        for index in range(size):
            at = _binary('add', 64, address, _Value(64, index))
            byte = self.load(at, 1, image)
            data.append(byte.expr if byte is not None and isinstance(byte.expr, int) else None)
        return _cast(_Value(size * 8, ('bytes', tuple(data))), size * 8)

    def store(self, address, size, value):
        if address is None:
            return
        if value is not None and isinstance(value.expr, tuple) and value.expr[0] == 'bytes':
            # Invalidate the WHOLE destination first, including unknown bytes;
            # never preserve an old zero initializer underneath an opaque lane.
            self.store(address, size, None)
            for index, byte in enumerate(value.expr[1][:size]):
                if byte is not None:
                    at = _binary('add', 64, address, _Value(64, index))
                    self.store(at, 1, _Value(8, byte))
            return
        preserved = {}
        for base, length in list(self.memory):
            delta = self.distance(address.expr, base)
            if delta is not None and delta < length and delta + size > 0:
                previous = self.resolve(self.memory[base, length])
                # A readiness-byte update must not forget adjacent constant
                # owned/commands_started flags packed into the same zero store.
                # Preserve only exact integer fragments, never guessed values.
                if previous is not None and isinstance(previous.expr, int):
                    prefix = max(0, delta)
                    if prefix:
                        preserved[base, prefix] = _cast(previous, prefix * 8)
                    suffix_start = max(0, delta + size)
                    if suffix_start < length:
                        suffix = _binary('add', 64, _Value(64, base), _Value(64, suffix_start))
                        preserved[suffix.expr, length - suffix_start] = _Value(
                            (length - suffix_start) * 8, previous.expr >> (suffix_start * 8))
                del self.memory[base, length]
        self.memory.update(preserved)
        if value is not None:
            self.memory[address.expr, size] = _cast(value, size * 8)

    def merge(self, other):
        result = self.copy()
        for attr in ('regs', 'memory', 'facts'):
            values, incoming = getattr(result, attr), getattr(other, attr)
            for key in list(values):
                if incoming.get(key) != values[key]:
                    del values[key]
        if result.flags != other.flags:
            result.flags = None
        changed = (result.regs, result.memory, result.flags, result.facts) != (
            self.regs, self.memory, self.flags, self.facts)
        return result, changed


def _initial(symbol):
    state = _State({'sp': _Value(64, ('stack', 0)),
                    **{f'x{i}': _Value(64, ('arg', i)) for i in range(8)}})
    if symbol in ('_sgpu_probe', '_sgpu_bootstrap'):
        state.put('x0', _Value(64, ('ops', 0)))
        state.put('x4', _Value(64, ('report', 0)))
        if symbol == '_sgpu_bootstrap':
            state.put('x5', _Value(64, ('probe', 0)))
    elif symbol in ('_checked_write32', '_checked_write64', '_branch_state', '_sgpu_failure',
                     '_sgpu_power', '_sgpu_restore_power', '_sgpu_smmu_start', '_sgpu_smmu_restore', '_sgpu_a505_init',
                     '_sgpu_a505_halt', '_sgpu_a505_resume', '_sgpu_a505_sp_release', '_marker_test',
                     '_sgpu_stock_transition', '_sgpu_stock_check32', '_sgpu_stock_pixels_test',
                     '_render_test', '_consume', '_sgpu_pixel_fence', '_sgpu_g3_prepare', '_sgpu_g3_test', '_sgpu_g3_wait'):
        state.put('x0', _Value(64, ('probe', 0)))
    for i in ((1, 2, 3, 4) if symbol == '_checked_write32' else
              (1, 2) if symbol in ('_checked_write64', '_branch_state') else
              (1, 2) if symbol == '_sgpu_pas_allocate' else
              (1,) if symbol == '_sgpu_a505_halt' else
              (1, 2) if symbol == '_sgpu_stock_transition' else
              (1, 2, 3) if symbol == '_sgpu_stock_check32' else
              (1,) if symbol in ('_sgpu_stock_pixels_test','_consume') else (2,) if symbol == '_clean' else ()):
        state.put(f'w{i}', _Value(32, ('arg', i)))
    return state


class _Flow:
    """Small forward def-use analysis, not an AArch64/hardware emulator.

    Only constants, affine stack addresses, Ops-slot provenance, scalar spills,
    vector constant-table copies and equality/boolean dependencies are tracked.
    Opaque operations lose their destination value. Joins retain only facts
    common to every predecessor; fixed-point work and function size are bounded.
    """
    def __init__(self, code, image, names, start=None, initial=None, overrides=None,
                 stops=(), effects=None):
        self.code, self.image, self.names = code, image, names
        self.overrides = overrides or {}
        self.effects = effects or {}
        self.before = {}
        initial = initial or _initial(code.symbol)
        if start is None:
            initial = _scm_enter(initial, code.symbol, names)
        start = code.entry if start is None else start
        pending = [(start, initial)]
        work = 0
        while pending:
            pc, state = pending.pop()
            work += 1
            if work > 100000:
                raise ValueError(f'bounded code analysis did not converge: {code.symbol}')
            if pc in self.before:
                state, changed = self.before[pc].merge(state)
                if not changed:
                    continue
            self.before[pc] = state
            if pc in stops:
                continue
            after = self.step(pc, state.copy())
            successors = code.succ[pc]
            if code.conditional(code.ins[pc][0]):
                truth = state.truth(self.predicate(pc, state))
                if truth is not None:
                    successors = (_number(code.ins[pc][1][-1]) if truth else pc + 4,)
            pending.extend((successor, after.copy()) for successor in successors)

    def predicate(self, pc, state):
        op, args = self.code.ins[pc]
        if op.startswith('b.'):
            return state.condition(op[2:])
        value = state.get(args[0])
        if op in ('tbz', 'tbnz'):
            bit = _number(args[1])
            if bit is None or not 0 <= bit < (value.bits if value else 64):
                raise ValueError(f'uninspectable bit branch: {self.code.symbol}')
            value = _binary('and', value.bits if value else 64, value, _Value(value.bits if value else 64, 1 << bit))
        eq = _eq(value, _Value(value.bits if value else 64, 0))
        return eq if op in ('cbz', 'tbz') else ('not', eq)

    def call(self, pc, state):
        op, args = self.code.ins[pc]
        if op in ('blr', 'br'):
            target = state.get(args[0])
            if target is None or not (isinstance(target.expr, int) or target.expr[0] == 'callback'):
                raise ValueError(f'unresolved indirect call/branch in {self.code.symbol}')
            return target.expr
        return _number(args[-1])

    def step(self, pc, state):
        op, args = self.code.ins[pc]
        if op in ('bl', 'blr', 'br') or (op == 'b' and _number(args[-1]) not in self.code.ins):
            target = self.call(pc, state)
            incoming = state.copy()
            scm_incoming = incoming
            for symbol in ('_sgpu_scm_readonly_transport', '_sgpu_scm_query', '_sgpu_scm_probe'):
                if target in self.names.get(symbol, ()):
                    scm_incoming = _scm_arguments(incoming, symbol, self.names)
                    break
            if isinstance(target, int) and target in self.names.get('_bzero', ()):
                length, address = state.get('x1'), state.get('x0')
                if (length is not None and isinstance(length.expr, int) and 0 < length.expr <= 4096 and
                        address is not None and isinstance(address.expr, tuple) and
                        address.expr[0] in ('stack', 'probe')):
                    # LLVM outlines the aggregate probe zero initializer. Only
                    # this known, bounded local range is zeroed, not other state.
                    state.store(address, length.expr, _Value(length.expr * 8, 0))
            if isinstance(target, int) and target in self.names.get('_memcpy', ()):
                length, destination, source = state.get('x2'), state.get('x0'), state.get('x1')
                if length is not None and isinstance(length.expr, int) and 0 < length.expr <= 4096:
                    for offset in range(0, length.expr, 8):
                        size = min(8, length.expr - offset)
                        value = incoming.load(_binary('add', 64, source, _Value(64, offset)), size, self.image)
                        state.store(_binary('add', 64, destination, _Value(64, offset)), size, value)
            if (isinstance(target, int) and target in self.names.get('_PE_parse_boot_argn', ()) and
                    state.get('x2') == _Value(64, 4)):
                # A parsed boot option may replace its local zero initializer.
                # Forget only the known output scalar, never adjacent Ops/spills.
                state.store(state.get('x1'), 4, None)
            if isinstance(target, int) and any(target in self.names.get(name, ()) for name in (
                    '_sgpu_smmu_start', '_sgpu_smmu_restore')):
                # A private callee receives smmu_saved*. Its initialized-zero
                # matching/changed bytes are not still zero after that call.
                # Forget the 64-byte saved-state object, not nearby Ops,
                # firmware or scalar spill slots used by the wiring proof.
                state.store(state.get('x1'), 64, None)
            if isinstance(target, int) and target in self.names.get('_sgpu_a505_resume', ()):
                # _a505_resume_wiring verifies readiness equals this checked
                # boolean return. Do not leave its pre-call false initializer,
                # or treat failed resume as an unknown success during cleanup.
                result = self.overrides.get(pc, _Value(32, ('result', pc)))
                ready = _Value(32, ('bool', ('not', _eq(result, _Value(32, 0)))))
                state.store(_binary('add', 64, state.get('x0'), _Value(64, 739)), 1, ready)
                # Verified below as the pre-write partial-resume marker. A
                # failed cold resume must not take the old untouched teardown.
                state.store(_binary('add', 64, state.get('x0'), _Value(64, 740)), 1, _Value(8, 1))
            if isinstance(target, int) and target in self.names.get('_sgpu_stock_transition', ()):
                report = state.load(_binary('add', 64, state.get('x0'), _Value(64, 8)), 8, self.image)
                state.store(_binary('add', 64, report, _Value(64, 160)), 12, None)
            if isinstance(target, int) and target in self.names.get('_sgpu_stock_pixels_test', ()):
                report = state.load(_binary('add', 64, state.get('x0'), _Value(64, 8)), 8, self.image)
                state.store(report, 192 if '_sgpu_g3_test' in self.names else 176, None)
            if isinstance(target, int):
                for symbol, size in (('_sgpu_pas_allocate', 24),
                                     ('_sgpu_pas_release', 24),
                                     ('_sgpu_pas_cached_prepare', 32),
                                     ('_sgpu_pas_cached_release', 32)):
                    if target in self.names.get(symbol, ()):
                        # Ownership/cache helpers can replace fields in the
                        # passed object. Never carry stale initialized state
                        # across their calls as proof of a safe release.
                        state.store(state.get('x0'), size, None)
                # SCM callbacks mutate returned frames/reports. Initial zeros
                # cannot remain evidence of a transport or service result.
                if target in self.names.get('_sgpu_smc_frame', ()):
                    state.store(state.get('x2'), 64, None)
                elif target in self.names.get('_sgpu_scm_readonly_transport', ()):
                    state.store(scm_incoming.get('x6'), 96, None)
                    state.store(_binary('add', 64, scm_incoming.get('x5'), _Value(64, 8)), 8, None)
                elif target in self.names.get('_sgpu_scm_query', ()):
                    state.store(scm_incoming.get('x7'), 96, None)
                    state.store(_binary('add', 64, scm_incoming.get('x6'), _Value(64, 8)), 8, None)
                elif target in self.names.get('_sgpu_scm_probe', ()):
                    state.store(scm_incoming.get('x4'), 496, None)
                elif target in self.names.get('_sgpu_scm_failure', ()):
                    state.store(_binary('add', 64, state.get('x0'), _Value(64, 4)), 4, None)
                    state.store(_binary('add', 64, state.get('x0'), _Value(64, 400)), 96, None)
            for reg in [*(f'x{i}' for i in range(19)), *(f'q{i}' for i in (*range(8), *range(16, 32)))]:
                state.regs.pop(reg, None)
            state.flags = None
            if isinstance(target, tuple):
                slot = target[1]
                if slot in (16, 24, 48):
                    state.put('w0' if slot == 16 else 'x0', _Value(
                        32 if slot == 16 else 64, ('now' if slot == 48 else 'read', pc)))
            elif any(target in self.names.get(name, ()) for name in (
                    '_sgpu_probe', '_sgpu_bootstrap', '_sgpu_power', '_sgpu_restore_power', '_sgpu_smmu_start',
                     '_sgpu_smmu_restore', '_sgpu_a505_resume', '_sgpu_a505_halt', '_sgpu_a505_sp_release',
                     '_checked_write32', '_checked_write64', '_branch_state',
                     '_sgpu_pas_allocate', '_sgpu_zap_layout', '_sgpu_zap_prepare',
                     '_sgpu_smc_frame', '_sgpu_scm_readonly_transport', '_sgpu_scm_query',
                     '_sgpu_scm_probe', '_sgpu_scm_capability_probe')):
                state.put('w0', self.overrides.get(pc, _Value(32, ('result', pc))))
            elif any(target in self.names.get(name, ()) for name in (
                    '_sgpu_pas_cache_preflight', '_sgpu_pas_cached_prepare', '_sgpu_pas_cached_release',
                    '_sgpu_pas_cached_views', '_sgpu_pas_cache_view', '_pmap_santoni_pas_cache_control',
                    '_sgpu_pas_release')):
                state.put('w0', self.overrides.get(pc, _Value(32, ('result', pc))))
            elif any(target in self.names.get(name, ()) for name in STOCK_HELPERS):
                state.put('w0', self.overrides.get(pc, _Value(32, ('result', pc))))
            elif any(target in self.names.get(name, ()) for name in (*PIXEL_HELPERS, *G3_HELPERS,
                    '_render_test', '_consume', '_sgpu_memory_validate', '_poll', '_sgpu_blit_commands')):
                state.put('w0', self.overrides.get(pc, _Value(32, ('result', pc))))
            elif target in self.names.get('_now_us', ()):
                state.put('x0', self.overrides.get(pc, _Value(64, ('now', pc))))
            if pc in self.effects:
                self.effects[pc](state, scm_incoming)
        elif op == 'smc':
            for i in range(18):
                state.regs.pop(f'x{i}', None)
            state.flags = None
        elif op in ('adr', 'adrp'):
            state.put(args[0], state.operand(args[1]))
        elif op == 'mov' or op.startswith('movi.'):
            state.put(args[0], state.operand(args[1]))
        elif op == 'movk':
            old, value = state.get(args[0]), _number(args[1])
            shift = _number(args[2].removeprefix('lsl ')) if len(args) > 2 else 0
            state.put(args[0], _Value(old.bits, (old.expr & ~(0xffff << shift)) | (value << shift))
                      if old and isinstance(old.expr, int) and value is not None and shift is not None else None)
        elif op in ('sxtw', 'sxth', 'sxtb', 'uxtw', 'uxth', 'uxtb'):
            size = {'w': 32, 'h': 16, 'b': 8}[op[-1]]
            value, bits = state.get(args[1]), self.code_width(args[0])
            if value is not None and isinstance(value.expr, int):
                value = value.expr & ((1 << size) - 1)
                if op.startswith('s') and value & (1 << (size - 1)):
                    value -= 1 << size
                state.put(args[0], _cast(_Value(bits, value), bits))
            else:
                state.put(args[0], None)
        elif op in ('ubfx', 'ubfiz'):
            value, shift, width = state.get(args[1]), _number(args[2]), _number(args[3])
            bits = self.code_width(args[0])
            if value is not None and shift is not None and width is not None and 0 < width <= bits:
                value = _binary('lsr' if op == 'ubfx' else 'and', bits, _cast(value, bits),
                                _Value(bits, shift if op == 'ubfx' else (1 << width) - 1))
                value = _binary('and' if op == 'ubfx' else 'lsl', bits, value,
                                _Value(bits, (1 << width) - 1 if op == 'ubfx' else shift))
                state.put(args[0], value)
            else:
                state.put(args[0], None)
        elif op in ('cmp', 'tst', 'cmn'):
            a, b = state.get(args[0]), state.operand(args[1])
            b = _cast(b, a.bits) if a else b
            if len(args) > 2:
                shift = re.fullmatch(r'lsl #(\d+)', args[2])
                b = _binary('lsl', a.bits if a else 64, b,
                            _Value(64, int(shift[1]))) if shift else None
            if op == 'tst':
                a, b = _binary('and', a.bits if a else 64, a, b), _Value(a.bits if a else 64, 0)
            state.flags = ('cmn' if op == 'cmn' else 'cmp', a, b)
        elif op in ('ccmp', 'ccmn'):
            truth = state.truth(state.condition(args[-1]))
            if truth is True:
                a, b = state.get(args[0]), state.operand(args[1])
                state.flags = ('cmp', a, _cast(b, a.bits) if a else b)
            elif truth is False:
                state.flags = ('nzcv', _number(args[2]))
            else:
                a, b = state.get(args[0]), state.operand(args[1])
                state.flags = ('ccmp', state.flags, a, _cast(b, a.bits) if a else b,
                               _number(args[2]), args[-1])
        elif op in ('cset', 'csetm'):
            value = _Value(32, ('bool', state.condition(args[1])))
            if op == 'csetm':
                value = _binary('sub', self.code_width(args[0]), _Value(self.code_width(args[0]), 0), value)
            state.put(args[0], state.resolve(value))
        elif op in ('csel', 'csinc', 'csinv', 'csneg'):
            truth = state.truth(state.condition(args[-1]))
            value = state.get(args[1] if truth else args[2]) if truth is not None else None
            if truth is False and op != 'csel':
                bits = self.code_width(args[0])
                value = _binary({'csinc': 'add', 'csinv': 'eor', 'csneg': 'sub'}[op], bits,
                                _Value(bits, 0) if op == 'csneg' else value,
                                value if op == 'csneg' else _Value(bits, 1 if op == 'csinc' else (1 << bits) - 1))
            state.put(args[0], value)
        elif op.rstrip('s') in ('add', 'sub', 'and', 'orr', 'eor', 'bic', 'lsl', 'lsr'):
            operation = op[:-1] if op in ('adds', 'subs', 'ands', 'bics') else op
            bits, a, b = self.code_width(args[0]), state.get(args[1]), state.operand(args[2])
            if len(args) > 3:
                shift = re.fullmatch(r'lsl #(\d+)', args[3])
                extend = re.fullmatch(r'uxtw(?: #(\d+))?', args[3])
                if extend and args[2].startswith('w') and bits == 64:
                    b = _binary('lsl', 64, _cast(b, 64), _Value(64, int(extend[1] or 0)))
                else:
                    b = _binary('lsl', bits, b, _Value(bits, int(shift[1]))) if shift else None
            b = _cast(b, bits)
            value = _binary(operation, bits, a, b)
            state.put(args[0], value)
            if op in ('adds', 'subs', 'ands', 'bics'):
                state.flags = ('cmp', a, b) if op == 'subs' else ('cmp', value, _Value(bits, 0))
        elif op.startswith(('ldr', 'ldur', 'str', 'stur')) or op in ('ldp', 'stp'):
            pair, load = op in ('ldp', 'stp'), op.startswith('ld')
            index = 2 if pair else 1
            address, pre = state.address(args[index])
            size = 1 if op.endswith('b') else 2 if op.endswith('h') else self.code_width(args[0]) // 8
            for i, reg in enumerate(args[:index]):
                at = _binary('add', 64, address, _Value(64, i * size))
                if load:
                    value = state.load_copy(at, size, self.image) if reg.startswith(('q', 'd', 'v')) else state.load(at, size, self.image)
                    state.put(reg, value)
                else:
                    state.store(at, size, state.get(reg))
            if pre:
                state.put(pre, address)
            elif len(args) > index + 1 and re.fullmatch(r'\[(?:sp|x\d+)\]', args[index]):
                base = args[index][1:-1]
                state.put(base, _binary('add', 64, state.get(base), state.operand(args[index + 1])))
        elif op not in ('ret', 'b', 'nop', 'dmb', 'dsb', 'isb', 'dc', 'yield', 'brk', 'hlt') and not self.code.conditional(op):
            if args:
                state.put(args[0], None)
            if op.endswith('s'):
                state.flags = None
        return state

    @staticmethod
    def code_width(reg):
        return _State.reg(reg)[1] or 64

    def returns(self, value):
        exits = [pc for pc in self.before if self.code.ins[pc][0] == 'ret']
        return bool(exits) and all(self.before[pc].get('w0') == _Value(32, value) for pc in exits)


_CALLBACKS = {8: '_io_map', 16: '_sgpu_io_read32', 24: '_sgpu_io_read64',
              32: '_sgpu_io_write32', 40: '_sgpu_io_write64', 48: '_now_us',
              56: '_sgpu_kernel_wait_us', 64: '_allocate', 72: '_release',
              80: '_clean', 88: '_sgpu_cache_invalidate', 96: '_trace'}


def _gpu_entries(names):
    """Both explicit worker branches must preserve opt-ins and refusal edges."""
    return ('_sgpu_probe',) + (('_sgpu_session_start',) if '_sgpu_session_start' in names else ())


def _ops_wiring(code, image, names, local_names):
    flow = _Flow(code, image, names)
    targets = _gpu_entries(names)
    entry_sites = {target: code.calls_to(names[target], flow.before) for target in targets}
    for target, calls in entry_sites.items():
        if not calls:
            raise ValueError('GPU worker never calls ' + target.removeprefix('_'))
    sites = sorted({pc for calls in entry_sites.values() for pc in calls})
    callbacks = {}
    for pc in sites:
        state, ops = flow.before[pc], flow.before[pc].get('x0')
        if state.load(ops, 8, image) != _Value(64, 0):
            raise ValueError('could not inspect worker Ops table/context passed to GPU entry')
        for slot, name in _CALLBACKS.items():
            pointer = state.load(_binary('add', 64, ops, _Value(64, slot)), 8, image)
            if pointer is None or pointer.expr not in local_names.get(name, ()):
                raise ValueError(f'worker Ops table callback linkage invalid: {name}')
            if name in callbacks and callbacks[name] != pointer.expr:
                raise ValueError('inconsistent worker Ops tables')
            callbacks[name] = pointer.expr
    evidence = {'probe_calls': [hex(pc) for pc in entry_sites['_sgpu_probe']],
                'Ops_callbacks': {name: hex(address) for name, address in callbacks.items()}}
    if '_sgpu_session_start' in entry_sites:
        evidence['session_start_calls'] = [hex(pc) for pc in entry_sites['_sgpu_session_start']]
    return callbacks, evidence


def _helper_readback(code, image, names, bits):
    flow = _Flow(code, image, names)
    sp_release = code.symbol == '_sgpu_a505_sp_release'
    a505 = code.symbol == '_sgpu_a505_halt' or sp_release
    slots = (16, 32, 16) if bits == 32 else (24, 40, 24)
    events = sorted((pc, flow.call(pc, state)) for pc, state in flow.before.items()
                    if code.ins[pc][0] in ('blr', 'br'))
    if a505:
        traces = [(pc, target) for pc, target in events if target == ('callback', 96)]
        events = [(pc, target) for pc, target in events if target != ('callback', 96)]
    if [target for _, target in events] != [('callback', slot) for slot in slots]:
        raise ValueError(f'{code.symbol}: checked read/write/read Ops callbacks missing')
    block, offset_arg, value_arg = _Value(32, ('arg', 1)), 2, 4 if bits == 32 else 3
    if bits == 64:
        first = flow.before[events[0][0]]
        if first.get('w1') == _Value(32, 5):
            block = _Value(32, 5)  # Every source checked_write64 call is SMMU-only.
            if first.get('w2') == _Value(32, ('arg', 1)):
                # LLVM may drop the constant block argument from this private
                # noinline function: ABI becomes (probe, offset, uint64 value).
                initial = _initial(code.symbol)
                initial.put('w1', _Value(32, ('arg', 1)))
                initial.put('x2', _Value(64, ('arg', 2)))
                flow = _Flow(code, image, names, initial=initial)
                offset_arg, value_arg = 1, 2
    expected = _Value(bits, ('arg', value_arg))
    if a505:
        block = _Value(32, 4)
        old = _Value(32, ('read', events[0][0]))
        expected = _binary('and' if sp_release else 'orr', 32, old,
                           _Value(32, 0xffffff00 if sp_release else 3))
        if len(traces) != 1 or traces[0][0] in code.walk(code.entry, exclude=(events[-1][0],)):
            raise ValueError('A505 halt phase trace must follow the ordered read/write/read')
        traced = flow.before[traces[0][0]]
        if (traced.get('x0') != _Value(64, ('ctx', 0)) or
                traced.get('w2') != (old if sp_release else _Value(32, ('arg', 1))) or
                traced.get('w3') != (expected if sp_release else old) or
                traced.get('w4') != _Value(32, ('read', events[-1][0]))):
            raise ValueError('A505 halt phase/old/readback trace provenance differs')
    for i, (pc, _) in enumerate(events):
        state = flow.before[pc]
        if (state.get('x0') != _Value(64, ('ctx', 0)) or
                state.get('w1') != block or
                state.get('w2') != (_Value(32, 0x19c if sp_release else 0x20c8) if a505 else
                                   _Value(32, ('arg', offset_arg))) or
                (i == 1 and state.get('w3' if bits == 32 else 'x3') != expected)):
            raise ValueError(f'{code.symbol}: checked callback context/register/value differs')
        if i and pc in code.walk(code.entry, exclude=(events[i - 1][0],)):
            raise ValueError(f'{code.symbol}: read/write/read is not ordered on every path')
    got = _Value(bits, ('read', events[-1][0]))
    if sp_release:
        difference = _binary('eor', 32, got, expected)
        low = _binary('and', 32, got, _Value(32, 0xff))
        low_zero = _eq(low, _Value(32, 0))
        full_echo = _eq(got, expected)
        comparisons = (full_echo, _eq(difference, _Value(32, 0)),
                       _eq(_binary('orr', 32, difference, low), _Value(32, 0)),
                       ('and', *sorted((low_zero, full_echo), key=repr)))
    elif a505:
        comparisons = (_eq(_binary('and', 32, got, _Value(32, 3)), _Value(32, 3)),)
    elif bits == 32:
        mask = _Value(32, ('arg', 3))
        comparisons = (_eq(_binary('and', 32, got, mask), _binary('and', 32, expected, mask)),
                       _eq(_binary('and', 32, _binary('eor', 32, got, expected), mask), _Value(32, 0)))
    else:
        comparisons = (_eq(got, expected), _eq(_binary('eor', 64, got, expected), _Value(64, 0)))
    for pc, state in flow.before.items():
        if not code.conditional(code.ins[pc][0]):
            continue
        pred = flow.predicate(pc, state)
        eq = pred[1] if pred and pred[0] == 'not' else pred
        if eq not in comparisons:
            continue
        if pc in code.walk(code.entry, exclude=(events[-1][0],)):
            continue
        # A mismatch must record the failure and return false. A match must
        # return true without calling the failure recorder. cset/boolean spills
        # are resolved using the same equality fact as the controlling branch.
        results = []
        for matches in (False, True):
            branch_state = state.copy()
            branch_state.facts[eq] = matches
            if sp_release and matches:
                # Full echo of old & ~0xff mathematically requires low-byte0.
                # This derived fact only assists an additional explicit check;
                # it never substitutes a low-byte check for full preservation.
                branch_state.facts[_eq(_binary('and', 32, got, _Value(32, 0xff)), _Value(32, 0))] = True
            taken = branch_state.truth(pred)
            successor = _number(code.ins[pc][1][-1]) if taken else pc + 4
            suffix = _Flow(code, image, names, successor, branch_state)
            failures = code.calls_to(names['_sgpu_failure'], suffix.before)
            results.append(suffix.returns(int(matches)) and
                           (not failures if matches else bool(failures) and all(
                               suffix.before[p].get('w1') == _Value(32, 2) for p in failures)))
        returns = [p for p in flow.before if code.ins[p][0] == 'ret']
        bypass = [p for p in returns if p in code.walk(code.entry, exclude=(pc,))]
        pre_write_guards = []
        if bypass and code.symbol == '_checked_write32':
            # 0203 adds a refusal BEFORE the store when the last TRUST read
            # changed. Its false/SG_FAIL_GUARD return intentionally bypasses
            # the post-store echo. Never admit a post-write exit this way.
            prefix = _Flow(code, image, names, stops=(pc,))
            pre_write_guards = [q for q in code.calls_to(names['_sgpu_failure'], prefix.before)
                                if prefix.before[q].get('w1') == _Value(32, 4)]
            safe = (prefix.returns(0) and pre_write_guards and
                    not any(q in code.walk(events[1][0], exclude=(pc,)) for q in bypass) and
                    not any(q in code.walk(code.entry, exclude=(pc, *pre_write_guards)) for q in bypass))
            if safe:
                bypass = []
        if all(results) and not bypass:
            return {'callbacks': [hex(p) for p, _ in events], 'readback_branch': hex(pc),
                    'pre_write_guard_failure_calls': [hex(q) for q in pre_write_guards],
                    'block': block.expr, 'offset_argument': offset_arg, 'value_argument': value_arg}
    raise ValueError(f'{code.symbol}: checked full-width/masked readback comparison and failure exits missing')


def _a505_resume_wiring(codes, image, names):
    resume = codes['_sgpu_a505_resume']
    flow = _Flow(resume, image, names)
    calls = sorted(resume.calls_to(names['_checked_write32'], flow.before))
    expected = ((4, 0x19c, 0xffffffff, 0x55), (4, 0x14cc, 0xffffffff, 0x182))
    if len(calls) != 2 or any(tuple(flow.before[pc].get(f'w{i}') for i in range(1, 5)) !=
                             tuple(_Value(32, value) for value in args) for pc, args in zip(calls, expected)):
        raise ValueError('A505 SP halt/top-level HWCG/ISDB checked completion wiring differs')
    policy = [pc for pc, state in flow.before.items() if resume.ins[pc][0] in ('blr', 'br') and
              flow.call(pc, state) == ('callback', 32) and
              tuple(state.get(f'w{i}') for i in (1, 2, 3)) ==
              tuple(_Value(32, value) for value in (4, 0x19c, 0xaaa8aa00))]
    release_calls = resume.calls_to(names['_sgpu_a505_sp_release'], flow.before)
    if (len(policy) != 1 or len(release_calls) != 1 or
            calls[1] in resume.walk(resume.entry, exclude=policy) or
            release_calls[0] in resume.walk(resume.entry, exclude=(calls[1],))):
        raise ValueError('A505 vendor TOP policy -> ISDB -> full RMW release ordering is missing')
    flags = {}
    touched = []
    for pc, state in flow.before.items():
        op, args = resume.ins[pc]
        if op not in ('strb', 'sturb', 'strh', 'sturh', 'str', 'stur'):
            continue
        addr, _ = state.address(args[1])
        width = 1 if op.endswith('b') else 2 if op.endswith('h') else _State.reg(args[0])[1] // 8
        for offset in (739, 740):
            delta = state.distance(('probe', offset), addr.expr) if addr is not None else None
            if delta is None or not 0 <= delta < width:
                continue
            value = state.get(args[0])
            # LLVM may combine adjacent {resumed=false,touched=true} into
            # STRH #0x100. Inspect the exact bytes, not a mnemonic assumption.
            byte = (value.expr >> (delta * 8)) & 0xff if value is not None and isinstance(value.expr, int) else None
            if offset == 740:
                if byte != 1:
                    raise ValueError('partial-resume marker must become true before hardware writes')
                touched.append(pc)
            elif byte in (0, 1):
                flags.setdefault(byte, []).append(pc)
            else:
                raise ValueError('A505 resume readiness has an uninspectable extra store')
    if (set(flags) != {0, 1} or any(len(sites) != 1 for sites in flags.values()) or
            any(pc in resume.walk(resume.entry, exclude=flags[0]) for pc in calls) or
            flags[1][0] in resume.walk(resume.entry, exclude=release_calls)):
        raise ValueError('A505 resume readiness flag is not cleared/set around checked completion')
    if len(touched) != 1 or calls[0] in resume.walk(resume.entry, exclude=touched):
        raise ValueError('A505 partial-resume marker is not set before initial clock write')
    ready_suffix = _Flow(resume, image, names, flags[1][0], flow.before[flags[1][0]].copy())
    if not ready_suffix.returns(1):
        raise ValueError('A505 completed readiness must return true')
    probe = codes.get('_sgpu_bootstrap', codes['_sgpu_probe'])
    pflow = _Flow(probe, image, names)
    resumes = probe.calls_to(names['_sgpu_a505_resume'], pflow.before)
    halts = set(probe.calls_to(names['_sgpu_a505_halt'], pflow.before))
    sites = {pflow.before[pc].get('w1'): pc for pc in halts}
    if len(resumes) != 3 or set(sites) != {_Value(32, i) for i in range(1, 5)} or len(halts) != 4:
        raise ValueError('A505 cold/post-reset/recovery resume or four distinct halt phases are missing')
    if sites[_Value(32, 1)] in probe.walk(probe.entry, exclude=resumes):
        raise ValueError('A505 cold halt can bypass manual resume')
    resets = []
    for pc, state in pflow.before.items():
        if probe.ins[pc][0] in ('blr', 'br') and pflow.call(pc, state) == ('callback', 32):
            if tuple(state.get(f'w{i}') for i in (1, 2, 3)) == tuple(_Value(32, v) for v in (4, 0x10c, 0)):
                resets.append(pc)
    if len(resets) != 2 or any(halts & probe.walk(pc + 4, exclude=resumes) for pc in resets):
        raise ValueError('A505 initial/recovery reset can reach CP without a new resume')
    config = probe.calls_to(names['_sgpu_a505_init'], pflow.before)
    if not config:
        raise ValueError('execution wiring missing: sgpu_probe -> sgpu_a505_init')
    release = []
    for code in codes.values():
        if code.symbol not in ('_sgpu_probe', '_sgpu_bootstrap', '_marker_test'):
            continue
        cflow = _Flow(code, image, names)
        for pc in code.calls_to(names['_checked_write32'], cflow.before):
            state = cflow.before[pc]
            if state.get('w1') == _Value(32, 4) and state.get('w2') == _Value(32, 0x20c8):
                if state.get('w3') != _Value(32, 3) or state.get('w4') != _Value(32, 0):
                    raise ValueError('A505 CP release must check both low stop bits against zero')
                release.append(pc)
    if len(release) != 1:
        raise ValueError('A505 paired-stop release check is missing')
    return {'clock_completion_calls': list(map(hex, calls)), 'TOP_policy_write': list(map(hex, policy)),
            'SP_RMW_release_call': list(map(hex, release_calls)), 'resumes': list(map(hex, sorted(resumes))),
            'halt_phases': {value.expr: hex(pc) for value, pc in sites.items()},
            'reset_deassertions': list(map(hex, resets)), 'release': list(map(hex, release))}


def _branch_poll(code, image, names):
    flow = _Flow(code, image, names)
    events = {slot: [] for slot in (16, 48, 56)}
    for pc, state in flow.before.items():
        if code.ins[pc][0] not in ('blr', 'br'):
            continue
        target = flow.call(pc, state)
        if target not in [('callback', slot) for slot in events] or state.get('x0') != _Value(64, ('ctx', 0)):
            raise ValueError('branch_state polling Ops callbacks invalid')
        slot = target[1]
        if slot == 16 and (state.get('w1') != _Value(32, 0) or state.get('w2') != _Value(32, ('arg', 1))):
            raise ValueError('branch_state must read the requested clock register')
        if slot == 56 and state.get('w1') != _Value(32, 100):
            raise ValueError('branch_state bounded poll wait missing')
        events[slot].append(pc)
    failures = code.calls_to(names['_sgpu_failure'], flow.before)
    loop = next((r for r in events[16] if any(
        t in code.walk(r) and w in code.walk(t) and r in code.walk(w)
        for t in events[48] for w in events[56])), None)
    if loop is None or not failures:
        raise ValueError('branch_state must poll READ/time/wait and record timeout failure')
    read_checked, expiry_checked = False, False
    for pc, state in flow.before.items():
        op, args = code.ins[pc]
        if not code.conditional(op):
            continue
        pred = flow.predicate(pc, state)
        if _contains(pred, ('read', loop)):
            read_checked = True
        if _expiry_limit(state.flags, op, events[48]) == 10000:
            expired = _number(args[-1]) if op in ('b.hs', 'b.cs', 'b.hi') else pc + 4
            suffix = _Flow(code, image, names, expired, state.copy())
            sites = code.calls_to(names['_sgpu_failure'], suffix.before)
            expiry_checked = suffix.returns(0) and bool(sites) and all(
                suffix.before[p].get('w1') == _Value(32, 3) for p in sites)
    if not read_checked or not expiry_checked:
        raise ValueError('branch_state read/time comparisons and checked timeout exits missing')
    return {str(slot): [hex(pc) for pc in sorted(sites)] for slot, sites in events.items()}


def _expiry_limit(flags, op, clocks):
    """Exact unsigned elapsed-time bounds, including LLVM's power-of-two fold.

    (elapsed >> 4) > 624 is precisely elapsed >= 10000, not a relaxed budget.
    Require current-minus-start 64-bit clock provenance before accepting it.
    """
    if not flags or flags[0] != 'cmp' or op not in ('b.hs', 'b.cs', 'b.hi', 'b.lo', 'b.cc', 'b.ls'):
        return None
    elapsed, bound = flags[1:]
    if elapsed is None or bound is None or elapsed.bits != 64 or not isinstance(bound.expr, int):
        return None
    shift = 0
    if isinstance(elapsed.expr, tuple) and elapsed.expr[0] == 'lsr':
        elapsed, amount = elapsed.expr[1:]
        if not isinstance(amount.expr, int) or not 0 <= amount.expr < 64:
            return None
        shift = amount.expr
    expr = elapsed.expr
    if not isinstance(expr, tuple) or expr[0] != 'sub' or elapsed.bits != 64:
        return None
    current, start = expr[1:]
    if (current.expr not in [('now', pc) for pc in clocks] or
            start.expr != ('now', min(clocks)) or current.expr == start.expr):
        return None
    threshold = bound.expr + (1 if op in ('b.hi', 'b.ls') else 0)
    return threshold << shift


def _controlled_calls(code, image, names, callee, false_return=True, forbidden=(), containment=False):
    flow = _Flow(code, image, names)
    sites = sorted(code.calls_to(names[callee], flow.before))
    if not sites:
        raise ValueError(f'execution wiring missing: {code.symbol} -> {callee}')
    all_success = None
    if containment:
        overrides = {pc: _Value(32, 1) for name in ('_checked_write32', '_checked_write64')
                     for pc in code.calls_to(names[name], flow.before)}
        all_success = _Flow(code, image, names, overrides=overrides).before
    for pc in sites:
        if code.ins[pc][0] != 'bl':
            raise ValueError(f'could not inspect checked call return: {code.symbol} -> {callee}')
        state = flow.step(pc, flow.before[pc].copy())
        suffix = _Flow(code, image, names, pc + 4, state)
        controlled = any(code.conditional(code.ins[p][0]) and
                         _result_checked(suffix.predicate(p, before), pc)
                         for p, before in suffix.before.items())
        if not controlled and containment and pc not in all_success and suffix.returns(0):
            continue  # Only the source's already-failed, false-return containment writes.
        if not controlled:
            raise ValueError(f'unchecked helper result: {code.symbol} -> {callee}')
        state.put('w0', _Value(32, 0))
        state.facts[_eq(_Value(32, ('result', pc)), _Value(32, 0))] = True
        failure = _Flow(code, image, names, pc + 4, state)
        if ((false_return and not failure.returns(0)) or any(
                code.calls_to(names[name], failure.before) for name in forbidden)):
            raise ValueError(f'failed helper permits unsafe continuation: {code.symbol} -> {callee}')
    return [{'caller': code.symbol, 'callee': callee, 'site': hex(pc)} for pc in sites]


def _result_checked(pred, pc):
    if pred and pred[0] == 'not':
        pred = pred[1]
    if pred and pred[0] == 'and':
        return any(_result_checked(part, pc) for part in pred[1:])
    if not pred or pred[0] != 'eq':
        return False
    for value, constant in (pred[1:], pred[1:][::-1]):
        if (value is None or constant is None or constant.expr not in (0, 1) or
                not _contains(value, ('result', pc))):
            continue
        expr = value.expr
        while isinstance(expr, tuple) and expr[0] in ('lo', 'zext'):
            expr = expr[1].expr
        if expr == ('result', pc) or expr[0] == 'bool':
            return True
        if expr[0] == 'and' and any(v.expr == 1 for v in expr[1:]):
            return True
    return False


def _firmware_absence(data, bundle):
    from santoni_gpu_boot import firmware_blob
    try:
        blob, records = firmware_blob(bundle)
        _, _, _, a, b, _, _ = struct.unpack_from('<8s6I', blob)
        originals = (blob[32:32 + a], blob[32 + a:32 + a + b])
        if len(blob) != 32 + a + b or len(records) != 2 or min(a, b) < 16:
            raise ValueError('incomplete corpus')
    except (OSError, KeyError, TypeError, struct.error, ValueError) as error:
        raise ValueError('validated private firmware corpus required for the no-embedding gate') from error
    for raw in originals:
        if raw in data or raw[4:] in data:
            raise ValueError('private device firmware original or executable payload was embedded in the kernel binary')
    # Only digests/sizes leave the private reference validator, never raw bytes.
    return [{key: item[key] for key in ('file', 'file_sha256', 'payload_sha256', 'payload_bytes')}
            for item in records]


_SCM_CALLBACKS = {8: '_sgpu_smc_frame', 16: '_now_us',
                  24: '_sgpu_kernel_wait_us', 32: '_trace'}
_SCM_HELPERS = ('_sgpu_scm_capability_probe', '_sgpu_scm_probe',
                '_sgpu_scm_query', '_sgpu_scm_readonly_transport',
                '_sgpu_scm_failure', '_sgpu_smc_frame')


class _SCMNames(dict):
    """One candidate private ABI, accepted only after all wiring checks pass."""
    def __init__(self, names, compact=False):
        super().__init__(names)
        # AppleClang can delete constant parameters from private noinline
        # functions. Entries map source argument number to machine register;
        # None means the caller's already-checked constant was propagated.
        self.scm_abi = {
            '_sgpu_scm_probe': (0, None, 1, 2, 3),
            '_sgpu_scm_query': (0, None, None, None, 1, 2, 3, 4),
            '_sgpu_scm_readonly_transport': (0, None, None, None, 1, 2, 3),
        } if compact else {}


def _scm_enter(state, symbol, names):
    mapping = getattr(names, 'scm_abi', {}).get(symbol)
    if mapping is None:
        return state
    mapped = state.copy()
    for i in range(8):
        mapped.put(f'x{i}', None)
    for source, register in enumerate(mapping):
        if register is not None:
            mapped.put(f'x{register}', state.get(f'x{source}'))
    return mapped


def _scm_arguments(state, symbol, names):
    mapping = getattr(names, 'scm_abi', {}).get(symbol)
    if mapping is None:
        return state
    canonical = state.copy()
    for source, register in enumerate(mapping):
        canonical.put(f'x{source}', state.get(f'x{register}') if register is not None
                      else _Value(64, {1: 3, 2: 1, 3: 1}[source]))
    return canonical


def _scm_dynamic_gates(symbol, names, values):
    mapping = getattr(names, 'scm_abi', {}).get(symbol)
    # Omitted parameters have no independent machine ABI input. Their exact
    # constants are instead proved at the guarded entry and every caller edge.
    return mapping is None or all(mapping[i] is not None or value == expected
                                  for i, (value, expected) in enumerate(zip(values, (3, 1, 1)), 1))


def _scm_at(base, offset):
    return _binary('add', 64, base, _Value(64, offset))


def _scm_sites(flow, symbols):
    targets = {address for name in symbols for address in flow.names.get(name, ())}
    return sorted(pc for pc in flow.before if
                  (flow.code.ins[pc][0] in ('bl', 'blr', 'br') or
                   flow.code.ins[pc][0] == 'b' and
                   _number(flow.code.ins[pc][1][-1]) not in flow.code.ins) and
                  flow.call(pc, flow.before[pc]) in targets)


def _scm_initial(symbol, names):
    state, ops = _initial(symbol), _Value(64, ('probe', 0x1000))
    state.put('x0', ops)
    state.store(ops, 8, _Value(64, 0))
    for offset, name in _SCM_CALLBACKS.items():
        if len(names.get(name, ())) != 1:
            raise ValueError('SCM callback identity is ambiguous or missing')
        state.store(_scm_at(ops, offset), 8, _Value(64, next(iter(names[name]))))
    return state


def _scm_words(state, base, image):
    return [state.load(_scm_at(base, i * 8), 8, image) for i in range(8)]


def _scm_frame_wiring(code, image, names):
    sites = [pc for pc in code.reachable if code.ins[pc][0] == 'smc']
    if len(sites) != 1:
        raise ValueError('SCM frame callback needs exactly one reachable SMC')
    pc = sites[0]
    if (code.ins[pc][1] != ('#0',) or
            code.ins.get(pc - 4) != ('dmb', ('sy',)) or
            code.ins.get(pc + 4) != ('dsb', ('sy',)) or
            code.pred[pc] != {pc - 4} or code.pred[pc + 4] != {pc}):
        raise ValueError('SCM SMC/barrier block is reordered or has an interior entry')
    base = _Value(64, ('probe', 0x6000))
    # Complementary sentinels exercise every input/return bit. A forced OR/AND
    # cannot pass merely because that bit happened to match one sample frame.
    for wide, complement in ((0, 0), (0, 0xffffffffffffffff),
                             (1, 0), (1, 0xffffffffffffffff)):
        incoming = [(0x1122334455660000 + i) ^ complement for i in range(8)]
        returned = [(0x8877665544332200 + i) ^ complement for i in range(8)]
        state = _initial(code.symbol)
        state.put('x0', _Value(64, 0))
        state.put('w1', _Value(32, wide))
        state.put('x2', base)
        for i, value in enumerate(incoming):
            state.store(_scm_at(base, 8 * i), 8, _Value(64, value))
        flow = _Flow(code, image, names, initial=state, stops=(pc,))
        before = flow.before.get(pc)
        if before is None or any(before.get(f'x{i}') != _Value(
                64, incoming[i] if wide else incoming[i] & 0xffffffff) for i in range(7)):
            raise ValueError('SCM actual x0..x6 input loads or SMC32 truncation differ')
        if before.get('x7') != _Value(64, 0):
            raise ValueError('SCM x7 input is not explicitly zero')
        after = flow.step(pc, before.copy())
        for i, value in enumerate(returned):
            after.put(f'x{i}', _Value(64, value))
        suffix = _Flow(code, image, names, pc + 4, after)
        exits = [at for at in suffix.before if code.ins[at][0] == 'ret']
        expected = [_Value(64, value if wide or i == 7 else value & 0xffffffff)
                    for i, value in enumerate(returned)]
        if (not exits or not suffix.returns(1) or
                any(_scm_words(suffix.before[at], base, image) != expected for at in exits)):
            raise ValueError('SCM returned x0..x7 stores or SMC32 truncation differ')
    return {'SMC_instruction': hex(pc), 'ordered_system_barriers': True,
            'input_x0_through_x6_and_zero_x7': True,
            'returned_x0_through_x7_preserved': True, 'SMC32_truncation_checked': True}


def _scm_transport_wiring(code, image, names):
    request_base, budget_base, result_base = (
        _Value(64, ('probe', offset)) for offset in (0x2000, 0x3000, 0x4000))
    stamp = 0x12345678
    allowed = ((0xc2000601, 0x82000601), (0x82000601, 0x82000601),
               (0x42000601, 0x02000207), (0x02000601, 0x02000207),
               (0x42000207, 13), (0x02000207, 13))

    def initial(frame, mode=3, zap=1, enabled=1, calls=0, busy=0):
        state = _scm_initial(code.symbol, names)
        for reg, value in (('w1', mode), ('w2', zap), ('w3', enabled)):
            state.put(reg, _Value(32, value))
        for reg, base in (('x4', request_base), ('x5', budget_base), ('x6', result_base)):
            state.put(reg, base)
        for i, value in enumerate(frame):
            state.store(_scm_at(request_base, i * 8), 8, _Value(64, value))
        state.store(budget_base, 8, _Value(64, stamp))
        state.store(_scm_at(budget_base, 8), 4, _Value(32, calls))
        state.store(_scm_at(budget_base, 12), 4, _Value(32, busy))
        return state

    frame = [allowed[0][0], 1, allowed[0][1], 0, 0, 0, 0, 0]
    discovery = _Flow(code, image, names, initial=initial(frame))
    smcs = _scm_sites(discovery, ('_sgpu_smc_frame',))
    clocks = _scm_sites(discovery, ('_now_us',))
    if len(smcs) != 1 or not clocks:
        raise ValueError('SCM transport has no inspected frame/clock callback path')

    def flow(state, elapsed=100, start=None):
        return _Flow(code, image, names, start=start, initial=state, stops=smcs,
                     overrides={at: _Value(64, stamp + elapsed) for at in clocks})

    def first(state, expected):
        walked = flow(state)
        sites = _scm_sites(walked, ('_sgpu_smc_frame',))
        if len(sites) != 1:
            raise ValueError('SCM scalar whitelist rejects a required capability query')
        pc = sites[0]
        before = walked.before[pc]
        if (before.get('x0') != _Value(64, 0) or
                before.get('w1') != _Value(32, bool(expected[0] & 0x40000000)) or
                _scm_words(before, before.get('x2'), image) != [_Value(64, v) for v in expected]):
            raise ValueError('SCM transport passes a different scalar frame/context/convention')
        if before.load(budget_base, 8, image) != _Value(64, stamp):
            raise ValueError('SCM transport reset the shared time budget')
        return walked, pc, before

    for function, argument in allowed:
        request = [function, 1, argument, 0, 0, 0, 0, 0]
        _, _, before = first(initial(request, calls=7, busy=3), request)
        if (before.load(_scm_at(budget_base, 8), 4, image) != _Value(32, 8) or
                before.load(_scm_at(budget_base, 12), 4, image) != _Value(32, 3)):
            raise ValueError('SCM transport reset or failed to consume the shared counters')
    rejected = []
    for function in (0, 0x02000201, 0x42000201, 0x02000202, 0x42000205, 0x02000206,
                     0x82000207, 0x100000000 + frame[0]):
        rejected.append([function, *frame[1:]])
    for slot in range(1, 8):
        for value in (2, 0x100000000):
            changed = list(frame); changed[slot] = value
            rejected.append(changed)
    for request in rejected:
        walked = flow(initial(request))
        if _scm_sites(walked, ('_sgpu_smc_frame',)) or not walked.returns(0):
            raise ValueError('SCM binary whitelist admits a non-scalar/forbidden request')
    for mode, zap, enabled in ((0, 1, 1), (1, 1, 1), (2, 1, 1), (4, 1, 1),
                               (3, 0, 1), (3, 2, 1), (3, 1, 0), (3, 1, 2)):
        if not _scm_dynamic_gates(code.symbol, names, (mode, zap, enabled)):
            continue
        walked = flow(initial(frame, mode, zap, enabled))
        if _scm_sites(walked, ('_sgpu_smc_frame',)) or not walked.returns(0):
            raise ValueError('SCM transport does not independently enforce all three opt-ins')
    for calls, elapsed, error in ((64, 100, 3), (0, 1000000, 4)):
        walked = flow(initial(frame, calls=calls), elapsed)
        exits = [at for at in walked.before if code.ins[at][0] == 'ret']
        if (_scm_sites(walked, ('_sgpu_smc_frame',)) or not walked.returns(0) or
                any(walked.before[at].load(result_base, 4, image) != _Value(32, error) for at in exits)):
            raise ValueError('SCM actual 64-call/one-second boundary is not enforced')
    for function, argument in (allowed[0], allowed[1]):
        request = [function, 1, argument, 0, 0, 0, 0, 0]
        for status in (1, -12):
            walked, pc, before = first(initial(request), request)
            returned = [status & 0xffffffff, 0x31, 0x42, 0x53, 0x64, 0x75, 0x86, 0x97]
            after = walked.step(pc, before.copy())
            for i, value in enumerate(returned):
                after.store(_scm_at(before.get('x2'), i * 8), 8, _Value(64, value))
            after.put('w0', _Value(32, 1))  # wrapper transport completed, not a0 service status
            suffix = flow(after, start=pc + 4)
            sites = _scm_sites(suffix, ('_sgpu_smc_frame',))
            if len(sites) != 1:
                raise ValueError('SCM returned-frame resume/busy restart path is missing')
            next_state = suffix.before[sites[0]]
            expected = returned if status == 1 else request
            if (_scm_words(next_state, next_state.get('x2'), image) != [_Value(64, v) for v in expected] or
                    next_state.get('w1') != _Value(32, bool(function & 0x40000000)) or
                    next_state.load(budget_base, 8, image) != _Value(64, stamp) or
                    next_state.load(_scm_at(budget_base, 8), 4, image) != _Value(32, 2) or
                    next_state.load(_scm_at(budget_base, 12), 4, image) != _Value(32, int(status == -12))):
                raise ValueError('SCM interrupts lose returned session or busy retries lose the original frame')
            waits = _scm_sites(suffix, ('_sgpu_kernel_wait_us',))
            if (status == 1 and waits) or (status == -12 and
                    (len(waits) != 1 or suffix.before[waits[0]].get('w1') != _Value(32, 30000))):
                raise ValueError('SCM busy wait is missing, changed, or used for interruption')
    for status, service in ((0, 0), (0, 1), (-2, 1)):
        walked, pc, before = first(initial(frame), frame)
        after = walked.step(pc, before.copy())
        for i, value in enumerate((status & 0xffffffff, service, 0, 0, 0, 0, 0, 0)):
            after.store(_scm_at(before.get('x2'), i * 8), 8, _Value(64, value))
        after.put('w0', _Value(32, 1))
        suffix = flow(after, start=pc + 4)
        exits = [at for at in suffix.before if code.ins[at][0] == 'ret']
        if (_scm_sites(suffix, ('_sgpu_smc_frame',)) or not suffix.returns(int(status == 0)) or
                any(suffix.before[at].load(result_base, 4, image) != _Value(32, 6 if status else 0)
                    for at in exits)):
            raise ValueError('SCM transport confuses a0 completion with a1 capability/service status')
    walked, pc, before = first(initial(frame, busy=20), frame)
    after = walked.step(pc, before.copy())
    after.store(before.get('x2'), 8, _Value(64, 0xfffffff4))
    after.put('w0', _Value(32, 1))
    suffix = flow(after, start=pc + 4)
    exits = [at for at in suffix.before if code.ins[at][0] == 'ret']
    if (_scm_sites(suffix, ('_sgpu_smc_frame', '_sgpu_kernel_wait_us')) or
            not suffix.returns(0) or any(suffix.before[at].load(result_base, 4, image) !=
                                       _Value(32, 5) for at in exits)):
        raise ValueError('SCM shared 20-busy-retry limit is not enforced')
    return {'scalar_request_whitelist_checked': True,
            'opt_ins_checked_at_guarded_entry_and_all_caller_edges': True,
            'independent_transport_opt_ins': not bool(getattr(names, 'scm_abi', {})),
            'shared_calls_time_and_busy_budget_checked': True,
            'interrupted_returned_session_and_busy_original_frame_checked': True,
            'transport_callback': hex(smcs[0]),
            'scope': 'decoded ABI, whitelist, boundary and resume wiring; host tests cover full policy'}


def _scm_query_wiring(code, image, names):
    budget, result = _Value(64, ('probe', 0x3000)), _Value(64, ('probe', 0x4000))
    sites = set()
    for function, argument in ((0xc2000601, 0x82000601), (0x82000601, 0x82000601),
                               (0x42000601, 0x02000207), (0x02000601, 0x02000207),
                               (0x42000207, 13), (0x02000207, 13)):
        state = _scm_initial(code.symbol, names)
        for i, value in enumerate((3, 1, 1, function, argument), 1):
            state.put(f'w{i}', _Value(32, value))
        state.put('x6', budget); state.put('x7', result)
        flow = _Flow(code, image, names, initial=state)
        calls = _scm_sites(flow, ('_sgpu_scm_readonly_transport',))
        if len(calls) != 1:
            raise ValueError('SCM query has no unique inspected transport call')
        pc = calls[0]
        before = _scm_arguments(flow.before[pc], '_sgpu_scm_readonly_transport', names)
        request = before.get('x4')
        if (request is None or not isinstance(request.expr, tuple) or request.expr[0] != 'stack' or
                _scm_words(before, request, image) != [_Value(64, v) for v in
                    (function, 1, argument, 0, 0, 0, 0, 0)] or
                before.get('x5') != budget or before.get('x6') != result or
                any(before.get(f'w{i}') != _Value(32, value) for i, value in enumerate((3, 1, 1), 1))):
            raise ValueError('SCM query does not build the exact scalar request and pass shared budget/result')
        for passed in (0, 1):
            after = flow.step(pc, flow.before[pc].copy()); after.put('w0', _Value(32, passed))
            suffix = _Flow(code, image, names, pc + 4, after)
            if not suffix.returns(passed):
                raise ValueError('SCM query ignores or changes the transport boolean result')
        sites.add(pc)
    return [hex(pc) for pc in sorted(sites)]


def _scm_failure_wiring(code, image, names):
    report, result = _Value(64, ('probe', 0x5000)), _Value(64, ('probe', 0x7000))
    original = int.from_bytes(bytes(range(96)), 'little')
    for prior, source_error in ((prior, error) for prior in (0, 1, 4) for error in (0, 6)):
        state = _initial(code.symbol)
        state.put('x0', report); state.put('w1', _Value(32, 3))
        state.put('x2', result); state.put('w3', _Value(32, 8))
        state.store(_scm_at(report, 4), 4, _Value(32, prior))
        state.store(_scm_at(report, 400), 96, _Value(768, original))
        state.store(result, 96, _Value(768, source_error))
        flow = _Flow(code, image, names, initial=state)
        exits = [pc for pc in flow.before if code.ins[pc][0] == 'ret']
        if not exits:
            raise ValueError('SCM first-failure helper has no inspected return')
        for pc in exits:
            before = flow.before[pc]
            if before.load(_scm_at(report, 4), 4, image) != _Value(32, prior or 3):
                raise ValueError('SCM first failure phase is overwritten or never recorded')
            if prior:
                if before.load(_scm_at(report, 400), 96, image) != _Value(768, original):
                    raise ValueError('SCM first failure raw evidence is mutable')
            elif before.load(_scm_at(report, 400), 96, image) != _Value(768, source_error or 8):
                raise ValueError('SCM failure result copy or separate error classification differs')
    return True


def _scm_probe_wiring(code, image, names):
    report = _Value(64, ('probe', 0x5000))

    def initial(mode=3, zap=1, enabled=1):
        state = _scm_initial(code.symbol, names)
        for i, value in enumerate((mode, zap, enabled), 1):
            state.put(f'w{i}', _Value(32, value))
        state.put('x4', report)
        return state

    discovery = _Flow(code, image, names, initial=initial())
    queries = _scm_sites(discovery, ('_sgpu_scm_query',))
    if len(queries) != 4:
        raise ValueError('SCM convention/availability/support query boundaries are missing')
    for args in ((0, 1, 1), (1, 1, 1), (2, 1, 1), (4, 1, 1),
                 (3, 0, 1), (3, 2, 1), (3, 1, 0), (3, 1, 2)):
        if not _scm_dynamic_gates(code.symbol, names, args):
            continue
        flow = _Flow(code, image, names, initial=initial(*args))
        if _scm_sites(flow, ('_sgpu_scm_query',)) or not flow.returns(0):
            raise ValueError('SCM probe bypasses its independent mode/zap/SCM gate')

    def scenario(wide, failed=0, remote=-2, negative64=False, fallback_status=-1):
        order = [16, 208, 304] if wide else [16, 112, 208, 304]
        if failed:
            order = order[:order.index(failed) + 1]
        seen, shared = [], []

        def query_effect(state, incoming):
            result, budget = incoming.get('x7'), incoming.get('x6')
            offset = _State.distance(result.expr, report.expr) if result is not None else None
            if offset not in (16, 112, 208, 304) or len(seen) >= len(order) or offset != order[len(seen)]:
                raise ValueError('SCM probe issues a query after unsupported/uncertain completion')
            mask = 0x40000000 if wide else 0
            function, argument = {16: (0xc2000601, 0x82000601),
                                  112: (0x82000601, 0x82000601),
                                  208: (0x02000601 | mask, 0x02000207),
                                  304: (0x02000207 | mask, 13)}[offset]
            if (incoming.get('w4') != _Value(32, function) or incoming.get('w5') != _Value(32, argument) or
                    any(incoming.get(f'w{i}') != _Value(32, value) for i, value in enumerate((3, 1, 1), 1))):
                raise ValueError('SCM probe scalar function/argument/convention wiring differs')
            start = incoming.load(budget, 8, image)
            if not shared:
                if (budget is None or not isinstance(budget.expr, tuple) or budget.expr[0] != 'stack' or
                        start is None or not isinstance(start.expr, tuple) or start.expr[0] != 'now'):
                    raise ValueError('SCM shared budget does not start from the inspected clock callback')
                shared.append((budget, start))
            if ((budget, start) != shared[0] or
                    incoming.load(_scm_at(budget, 8), 4, image) != _Value(32, len(seen)) or
                    incoming.load(_scm_at(budget, 12), 4, image) != _Value(32, len(seen))):
                raise ValueError('SCM probe recreates or resets a per-query time/call/busy budget')
            count = len(seen) + 1
            seen.append(offset)
            state.store(_scm_at(budget, 8), 4, _Value(32, count))
            state.store(_scm_at(budget, 12), 4, _Value(32, count))
            fallback = not wide and offset == 16
            status = remote if offset == failed else 0 if negative64 else fallback_status if fallback else 0
            error = 6 if status else 0
            service = 0 if fallback or offset == failed and remote == 0 else 1
            state.store(result, 96, _Value(768, 0))
            state.store(result, 4, _Value(32, error))
            state.store(_scm_at(result, 24), 8, _Value(64, status & 0xffffffff))
            state.store(_scm_at(result, 32), 8, _Value(64, service))
            state.put('w0', _Value(32, int(status == 0)))

        flow = _Flow(code, image, names, initial=initial(),
                     effects={pc: query_effect for pc in queries})
        if seen != order or not flow.returns(0 if failed else 1):
            raise ValueError('SCM probe loses its capability result or follows a failed query')
        failures = _scm_sites(flow, ('_sgpu_scm_failure',))
        if failed:
            phase = {16: 1, 112: 2, 208: 3, 304: 4}[failed]
            if (len(failures) != 1 or flow.before[failures[0]].get('w1') != _Value(32, phase) or
                    flow.before[failures[0]].get('x0') != report or
                    flow.before[failures[0]].get('x2') != _scm_at(report, failed) or
                    flow.before[failures[0]].get('w3') != _Value(32, 7 if phase <= 2 else 8)):
                raise ValueError('SCM probe records a different first-failure phase/result')
        elif failures:
            raise ValueError('SCM positive capability route records an unrelated failure')
        else:
            exits = [pc for pc in flow.before if code.ins[pc][0] == 'ret']
            if any(flow.before[pc].load(report, 4, image) != _Value(32, 2 if wide else 1) or
                   flow.before[pc].load(_scm_at(report, 9), 1, image) != _Value(8, 1) for pc in exits):
                raise ValueError('SCM accepted convention/support fields are disconnected')

    scenario(True)
    scenario(False)
    scenario(False, fallback_status=-4)
    scenario(False, negative64=True)
    scenario(True, failed=16)
    scenario(False, failed=112)
    scenario(True, failed=208)
    scenario(True, failed=304)
    scenario(True, failed=208, remote=0)
    scenario(True, failed=304, remote=0)
    return {'query_sites': [hex(pc) for pc in queries], 'SMC64_and_documented_SMC32_routes': True,
            'availability_before_PAS_ID13_support': True, 'same_budget_on_every_query': True,
            'terminal_error_paths_stop_before_followup_query': True}


def _scm_smc_scope(codes):
    for name, code in codes.items():
        if name != '_sgpu_smc_frame' and any(op == 'smc' for op, _ in code.ins.values()):
            raise ValueError('SMC exists outside the inspected SCM frame callback')


def _scm_capability_wiring_profile(codes, image, names, local_names):
    symbol = '_sgpu_scm_capability_probe'
    _scm_smc_scope(codes)
    if symbol not in codes:
        if '_sgpu_smc_frame' in codes:
            raise ValueError('SCM frame callback is present without its guarded entry')
        return None
    if any(name not in codes for name in _SCM_HELPERS):
        raise ValueError('SCM capability helper boundaries are missing')
    entry = codes[symbol]
    callees = {
        symbol: ('_PE_parse_boot_argn', '_printf', '_sgpu_scm_probe'),
        '_sgpu_scm_probe': ('_sgpu_scm_query', '_sgpu_scm_failure', '_now_us', '_trace'),
        '_sgpu_scm_query': ('_sgpu_scm_readonly_transport', '_trace'),
        '_sgpu_scm_readonly_transport': ('_sgpu_smc_frame', '_now_us', '_sgpu_kernel_wait_us'),
        '_sgpu_scm_failure': (),
        '_sgpu_smc_frame': (),
    }
    for name in _SCM_HELPERS:
        allowed = (*callees[name], *(() if name == '_sgpu_smc_frame' else ('_memcpy', '_bzero')))
        targets = {address for callee in allowed for address in names.get(callee, ())}
        targets.update(_number(codes[name].ins[pc][1][-1]) for pc in codes[name].noreturn)
        for pc in codes[name].reachable:
            op, args = codes[name].ins[pc]
            if ((op == 'bl' or op == 'b' and _number(args[-1]) not in codes[name].ins) and
                    _number(args[-1]) not in targets):
                raise ValueError('unreviewed direct callee in scalar-only SCM capability layer')
        flow = _Flow(codes[name], image, names,
                     initial=_scm_initial(name, names) if name in
                     ('_sgpu_scm_query', '_sgpu_scm_probe', '_sgpu_scm_readonly_transport') else None)
        for pc in flow.before:
            op, args = codes[name].ins[pc]
            if (op in ('bl', 'blr', 'br') or op == 'b' and _number(args[-1]) not in codes[name].ins):
                if flow.call(pc, flow.before[pc]) not in targets:
                    raise ValueError('unreviewed callee in scalar-only SCM capability layer')
    parse = names.get('_PE_parse_boot_argn', ())
    for mode in (0, 1, 2, 4, 0xffffffff):
        state = _initial(symbol); state.put('w0', _Value(32, mode))
        flow = _Flow(entry, image, names, initial=state)
        if entry.calls_to(parse, flow.before) or _scm_sites(flow, ('_sgpu_scm_probe',)) or not flow.returns(0):
            raise ValueError('SCM entry permits a non-mode3 diagnostic')
    state = _initial(symbol); state.put('w0', _Value(32, 3))
    flow = _Flow(entry, image, names, initial=state)
    parses = sorted(entry.calls_to(parse, flow.before))
    if len(parses) != 2:
        raise ValueError('SCM entry needs separate explicit zap and SCM boot-argument parses')
    destinations = []
    for pc, literal in zip(parses, (b'santonigpu_zap\0', b'santonigpu_scm\0')):
        before = flow.before[pc]
        option, destination = before.get('x0'), before.get('x1')
        if (option is None or not isinstance(option.expr, int) or
                image.read(option.expr, len(literal)) != int.from_bytes(literal, 'little') or
                before.get('x2') != _Value(64, 4) or destination is None or
                not isinstance(destination.expr, tuple) or destination.expr[0] != 'stack'):
            raise ValueError('SCM entry parses a different argument, width or nonlocal output')
        destinations.append(destination)
    distance = _State.distance(destinations[0].expr, destinations[1].expr)
    if distance is None or abs(distance) < 4:
        raise ValueError('SCM entry aliases its independent opt-in scalars')
    callbacks = {}
    for zap in (0, 1, 2, 0xffffffff):
        for enabled in (0, 1, 2, 0xffffffff):
            after = flow.step(parses[0], flow.before[parses[0]].copy())
            after.store(destinations[0], 4, _Value(32, zap))
            middle = _Flow(entry, image, names, parses[0] + 4, after)
            if parses[1] not in middle.before:
                raise ValueError('SCM entry loses the independent SCM parse')
            after = middle.step(parses[1], middle.before[parses[1]].copy())
            after.store(destinations[1], 4, _Value(32, enabled))
            suffix = _Flow(entry, image, names, parses[1] + 4, after)
            calls = _scm_sites(suffix, ('_sgpu_scm_probe',))
            if zap != 1 or enabled != 1:
                if calls or not suffix.returns(0):
                    raise ValueError('SCM entry does not require exactly zap=1 and SCM=1')
                continue
            if len(calls) != 1:
                raise ValueError('SCM opted-in entry does not reach the inspected probe')
            pc = calls[0]
            before = _scm_arguments(suffix.before[pc], '_sgpu_scm_probe', names)
            if any(before.get(f'w{i}') != _Value(32, value) for i, value in enumerate((3, 1, 1), 1)):
                raise ValueError('SCM entry changes the mode or opt-ins passed to its probe')
            ops = before.get('x0')
            if before.load(ops, 8, image) != _Value(64, 0):
                raise ValueError('SCM actual Ops context is not the inspected adapter context')
            report = before.get('x4')
            if report is None or not isinstance(report.expr, tuple) or report.expr[0] != 'stack':
                raise ValueError('SCM entry does not pass a local report object')
            for base, size in ((ops, 40), *((destination, 4) for destination in destinations)):
                distance = _State.distance(report.expr, base.expr) if base is not None else None
                if distance is None or -496 < distance < size:
                    raise ValueError('SCM report aliases its Ops table or independent opt-ins')
            for offset, name in _SCM_CALLBACKS.items():
                pointer = before.load(_scm_at(ops, offset), 8, image)
                if pointer is None or pointer.expr not in local_names.get(name, ()):
                    raise ValueError('SCM actual Ops table points at a different callback')
                callbacks[name] = hex(pointer.expr)
            for passed in (0, 1):
                final = suffix.step(pc, suffix.before[pc].copy()); final.put('w0', _Value(32, passed))
                handled = _Flow(entry, image, names, pc + 4, final)
                if not handled.returns(1):
                    raise ValueError('SCM entry continues GPU work after success or failure')
    worker = codes['_sgpu_kernel_thread']
    running = _Flow(worker, image, names)
    calls = _scm_sites(running, (symbol,))
    if len(calls) != 1:
        raise ValueError('GPU worker does not reach SCM capability diagnostic exactly once')
    pc = calls[0]
    for handled in (0, 1):
        after = running.step(pc, running.before[pc].copy()); after.put('w0', _Value(32, handled))
        suffix = _Flow(worker, image, names, pc + 4, after)
        forbidden = _scm_sites(suffix, ('_sgpu_zap_allocation_preflight', *_gpu_entries(names)))
        if handled:
            terminates = _scm_sites(suffix, ('_thread_terminate_self',))
            if forbidden or len(terminates) != 1:
                raise ValueError('SCM handled result does not terminate before allocation/GPU MMIO')
            pending, seen = [pc + 4], set()
            while pending:
                at = pending.pop()
                if at in seen or at in terminates or at not in suffix.before:
                    continue
                seen.add(at)
                if not worker.succ[at]:
                    raise ValueError('SCM worker can exit without the inspected thread termination')
                pending.extend(worker.succ[at])
        elif not _scm_sites(suffix, _gpu_entries(names)):
            raise ValueError('SCM disabled result disconnects the existing GPU worker')
    return {'Ops_callbacks': callbacks, 'explicit_mode3_zap1_SCM1': True,
            'worker_terminates_after_both_handled_results': True,
            'frame': _scm_frame_wiring(codes['_sgpu_smc_frame'], image, names),
            'transport': _scm_transport_wiring(codes['_sgpu_scm_readonly_transport'], image, names),
            'scalar_query_sites': _scm_query_wiring(codes['_sgpu_scm_query'], image, names),
            'first_failure_immutable': _scm_failure_wiring(codes['_sgpu_scm_failure'], image, names),
            'negotiation': _scm_probe_wiring(codes['_sgpu_scm_probe'], image, names),
            'PAS_authentication_or_pixels_verified': False}


def _scm_capability_wiring(codes, image, names, local_names):
    # Constants deleted by IPO are acceptable only behind the verified
    # mode3/zap1/scm1 entry. No other decoded GPU routine may enter a layer.
    parents = dict(zip(_SCM_HELPERS, (
        '_sgpu_kernel_thread', '_sgpu_scm_capability_probe', '_sgpu_scm_probe',
        '_sgpu_scm_query', '_sgpu_scm_probe', '_sgpu_scm_readonly_transport')))
    for caller, code in codes.items():
        for pc in code.reachable:
            op, args = code.ins[pc]
            if op not in ('bl', 'b') or op == 'b' and _number(args[-1]) in code.ins:
                continue
            for callee, parent in parents.items():
                if _number(args[-1]) in names.get(callee, ()) and caller != parent:
                    raise ValueError('unreviewed caller bypasses the guarded SCM layer')
    errors = []
    for compact in (False, True):
        try:
            result = _scm_capability_wiring_profile(codes, image, _SCMNames(names, compact), local_names)
            if result:
                result['private_ABI'] = 'constant_parameters_removed' if compact else 'source_parameters'
            return result
        except ValueError as error:
            errors.append(str(error))
    raise ValueError('SCM wiring rejected both inspected private ABIs: ' + '; '.join(errors))


def _pas_preflight_wiring(codes, image, names):
    """Audit allocation-only ABI/opt-in wiring, not TZ acceptance or a VM model."""
    symbol = '_sgpu_zap_allocation_preflight'
    if symbol not in codes:
        return None  # historical kernels remain valid for ordinary GPU modes
    helpers = (symbol, '_sgpu_zap_prepare', '_sgpu_zap_layout',
               '_sgpu_pas_allocate', '_sgpu_pas_release')
    if any(name not in codes for name in helpers):
        raise ValueError('PAS preflight helper boundaries are missing')
    allowed = {*helpers, '_sgpu_zap_u16', '_sgpu_zap_u32', '_memcmp', '_bcmp', '_memcpy',
               '_bzero', '_printf', '_PE_parse_boot_argn', '_SecureDTLookupEntry',
               '_SecureDTGetProperty', '_kmem_alloc_contig_guard', '_kmem_free_guard',
               '_kmem_free', '_pmap_find_phys'}
    allowed_addresses = {address for name in allowed for address in names.get(name, ())}
    for name in helpers:
        code = codes[name]
        if any(op == 'smc' for op, _ in code.ins.values()):
            raise ValueError('allocation-only PAS preflight contains an SMC')
        for pc in code.reachable:
            op, args = code.ins[pc]
            if op in ('blr', 'br') or (op in ('bl', 'b') and
                    _number(args[-1]) not in code.ins and _number(args[-1]) not in allowed_addresses):
                raise ValueError('unreviewed callee in allocation-only PAS preflight')
    worker = codes['_sgpu_kernel_thread']
    if len(worker.calls_to(names[symbol])) != 1:
        raise ValueError('worker does not reach the audited PAS preflight exactly once')
    checked = _controlled_calls(codes['_sgpu_zap_prepare'], image, names, '_sgpu_zap_layout',
                                forbidden=('_sgpu_pas_allocate', '_sgpu_pas_release'))
    checked += _controlled_calls(codes['_sgpu_zap_prepare'], image, names, '_sgpu_pas_allocate')
    if len(codes['_sgpu_zap_prepare'].calls_to(names['_sgpu_pas_allocate'])) != 2:
        raise ValueError('PAS prepare must allocate separate owned metadata and image spans')
    checked += _controlled_calls(codes[symbol], image, names, '_sgpu_zap_prepare',
                                 false_return=False, forbidden=('_sgpu_pas_release',))
    preflight = codes[symbol]
    parse = names.get('_PE_parse_boot_argn', ())
    prepare = names['_sgpu_zap_prepare']
    for mode in (0, 1, 2, 4, 0xffffffff):
        initial = _initial(symbol)
        initial.put('w0', _Value(32, mode))
        flow = _Flow(preflight, image, names, initial=initial)
        if preflight.calls_to(parse, flow.before) or preflight.calls_to(prepare, flow.before):
            raise ValueError('PAS preflight mode gate permits a non-render mode')
    initial = _initial(symbol)
    initial.put('w0', _Value(32, 3))
    flow = _Flow(preflight, image, names, initial=initial)
    parses = preflight.calls_to(parse, flow.before)
    if len(parses) != 1:
        raise ValueError('PAS preflight needs one explicit zap boot-argument parse')
    pc = parses[0]
    before = flow.before[pc]
    option = before.get('x0')
    literal = b'santonigpu_zap\0'
    if (option is None or not isinstance(option.expr, int) or
            image.read(option.expr, len(literal)) != int.from_bytes(literal, 'little')):
        raise ValueError('PAS preflight parses a different boot option')
    if before.get('x2') != _Value(64, 4):
        raise ValueError('PAS preflight boot option is not a 32-bit value')
    destination = before.get('x1')
    if destination is None or not isinstance(destination.expr, tuple) or destination.expr[0] != 'stack':
        raise ValueError('PAS preflight option output is not a local scalar')
    for enabled in (0, 1, 2, 0xffffffff):
        state = flow.step(pc, before.copy())
        state.store(destination, 4, _Value(32, enabled))
        suffix = _Flow(preflight, image, names, pc + 4, state)
        sites = preflight.calls_to(prepare, suffix.before)
        if (enabled == 1 and len(sites) != 1) or (enabled != 1 and sites):
            raise ValueError('PAS preflight does not require exactly zap=1')
    allocator = codes['_sgpu_pas_allocate']
    allocated = _Flow(allocator, image, names)
    sites = allocator.calls_to(names.get('_kmem_alloc_contig_guard', ()), allocated.before)
    if len(sites) != 1:
        raise ValueError('PAS allocation is not wired to the contiguous guarded VM allocator')
    args = allocated.before[sites[0]]
    # XNU 8796: KMA_DATA=0x8000, KMA_ZERO=0x40; x2 VA byte mask,
    # x3 physical maximum page number, x4 physical alignment page mask.
    if any(args.get(reg) != _Value(64, value) for reg, value in (
            ('x2', 4095), ('x3', 0xfffff), ('x5', 0x8040))):
        raise ValueError('PAS contiguous allocation mask/maximum/zeroed flags differ')
    alignment = _binary('lsr', 32, _Value(32, ('arg', 2)), _Value(32, 12))
    expected_mask = _cast(_binary('sub', 32, alignment, _Value(32, 1)), 64)
    if args.get('x4') != expected_mask:
        raise ValueError('PAS physical alignment mask is not page-number-based')
    if not allocator.calls_to(names.get('_pmap_find_phys', ()), allocated.before):
        raise ValueError('PAS allocation has no physical mapping validation')
    release = codes['_sgpu_pas_release']
    frees = names.get('_kmem_free_guard', set()) | names.get('_kmem_free', set())
    for exposed in (0, 1):
        initial = _initial(release.symbol)
        base = _Value(64, ('probe', 0))
        initial.put('x0', base)
        initial.store(base, 8, _Value(64, 0x100000))
        initial.store(_Value(64, ('probe', 16)), 4, _Value(32, 8192))
        initial.store(_Value(64, ('probe', 20)), 1, _Value(8, exposed))
        flow = _Flow(release, image, names, initial=initial)
        calls = release.calls_to(frees, flow.before)
        if (exposed and calls) or (not exposed and len(calls) != 1):
            raise ValueError('PAS release lacks the exposed-memory quarantine guard')
    return {'mode3_only': True, 'explicit_zap_one_required': True,
            'contiguous_VM_call': hex(sites[0]), 'zeroed_data_flags': '0x8040',
            'VA_alignment_mask': 4095, 'maximum_pnum': 0xfffff,
            'mapping_validation_linked': True, 'exposed_release_blocked': True,
            'checked_prepare_edges': checked,
            'no_SMC_or_unreviewed_callees': True,
            'scope': 'binary ABI/opt-in/exposure wiring; full-span correctness is host-tested, not hardware proof'}


def _stack_failure_terminal(names):
    """Verify the compiler's stack-failure stub reaches XNU's noreturn panic.

    XNU libkern/stack_protector.c defines __stack_chk_fail with a panic call;
    osfmk/kern/debug.h declares panic noreturn. Decode the actual stub too:
    every reachable exit must be the numeric panic target, with no other call.
    """
    if '___stack_chk_fail' not in names:
        return set(), None, None
    if len(names['___stack_chk_fail']) != 1 or len(names.get('_panic', ())) != 1:
        raise ValueError('ambiguous stack-failure/panic identity')
    address = next(iter(names['___stack_chk_fail']))
    return {address}, next(iter(names['_panic'])), address


SCALAR_USER_HELPERS = ('_sgpu_user_options', '_sgpu_user_test_options',
    '_sgpu_user_open', '_sgpu_user_close', '_sgpu_user_ioctl', '_sgpu_user_publish',
    '_sgpu_user_preflight', '_sgpu_user_preflight_time', '_sgpu_client_open',
    '_sgpu_client_close', '_sgpu_client_call', '_sgpu_client_packet_valid')
SCALAR_USER_STORAGE = ('_sgpu_user_client', '_sgpu_user_major',
                       '_sgpu_user_published', '_sgpu_user_cdevsw')


def _scalar_user_helpers(names):
    """Close the new namespace, including methods reached only via cdevsw data.

    Loading these boundaries screens their ISA; it does not certify ownership,
    packet copies, preflight scheduling or mode1 exclusion. Dedicated decoded
    proofs remain required before the packager can authorize either new role.
    """
    found={name for name in names if name.startswith(('_sgpu_user_', '_sgpu_client_'))}
    if not found:return ()
    required={*SCALAR_USER_HELPERS,*SCALAR_USER_STORAGE}
    if found!=required or any(len(names[name])!=1 for name in required):
        raise ValueError('scalar user audit missing, ambiguous or unreviewed boundaries')
    if len({next(iter(names[name])) for name in required})!=len(required):
        raise ValueError('scalar user function/storage identities alias')
    return SCALAR_USER_HELPERS


def audit(commit, mode1_control=False):
    import os
    # Explicit per-command private corpus override; never restore/overwrite a
    # deleted historical intake directory or fetch firmware during the audit.
    private_bundle = os.environ.get('SANTONI_GPU_AUDIT_BUNDLE')
    ucode_bundle = Path(private_bundle) if private_bundle else ROOT / 'out/santoni-gpu-msm49-fw-working'
    zap_bundle = Path(private_bundle) if private_bundle else ROOT / 'out/santoni-gpu-pas-fw-working'
    if type(mode1_control) is not bool:
        raise ValueError('control audit requires an explicit boolean role')
    if not re.fullmatch(r'[0-9a-f]{40}', commit):
        raise ValueError('exact CI commit SHA required')
    folder = ROOT / f'out/ci-{commit[:7]}'
    run = json.loads((folder / 'run.json').read_text())
    if (run.get('headSha'), run.get('status'), run.get('conclusion')) != (
            commit, 'completed', 'success') or not run.get('repository_private'):
        raise ValueError('successful exact CI and restored private visibility required')
    kernel = folder / 'kernel/kernel.development.santoni'
    data = kernel.read_bytes()
    sums = {name.lstrip('*'): digest for digest, name in
            (line.split(None, 1) for line in (folder / 'kernel/SHA256SUMS').read_text().splitlines())}
    digest = hashlib.sha256(data).hexdigest()
    if sums.get(kernel.name) != digest:
        raise ValueError('CI kernel checksum mismatch')
    image = _Image(data)
    nm = subprocess.check_output(['llvm-nm', '--defined-only', str(kernel)], text=True)
    inventory = folder / 'kernel.symbols.txt'
    if inventory.exists():
        if inventory.read_text() != nm:
            raise ValueError('existing symbol inventory differs; preserve it before auditing')
    else:
        with inventory.open('x') as stream: stream.write(nm)
    names, local_names = _symbols(nm), _symbols(nm, local=True)
    required = ('_santoni_gpu_start', '_sgpu_probe', '_sgpu_tables_build',
                '_sgpu_firmware_validate', '_sgpu_blit_commands', '_sgpu_kernel_thread',
                '_sgpu_io_write32', '_sgpu_io_write64', '_sgpu_cache_invalidate',
                 '_sgpu_io_read32', '_sgpu_io_read64', '_sgpu_kernel_wait_us',
                 '_sgpu_failure', '_sgpu_failure_summary', '_sgpu_power',
                 '_checked_write32', '_checked_write64', '_branch_state',
                  '_sgpu_restore_power', '_sgpu_smmu_start', '_sgpu_smmu_restore', '_sgpu_a505_init',
                  '_sgpu_a505_resume', '_sgpu_a505_halt', '_sgpu_a505_sp_release',
                 '_kernel_thread_start', '_CleanPoC_DcacheRegion_Force')
    for symbol in required:
        if symbol not in names:
            raise ValueError(f'GPU source was not linked: {symbol}')
    assemblies, codes = {}, {}
    noreturn, panic_address, stack_address = _stack_failure_terminal(names)
    if noreturn:
        text = subprocess.check_output(['llvm-objdump', '--disassemble', '--disassemble-zeroes',
            '--disassemble-symbols=___stack_chk_fail', str(kernel)], text=True)
        stub = _Code(text, '___stack_chk_fail', stack_address, noreturn=(panic_address,))
        exits = [pc for pc in stub.reachable if not stub.succ[pc]]
        calls = [pc for pc in stub.reachable if stub.ins[pc][0] in ('bl', 'blr', 'br', 'b')]
        if not exits or set(exits) != stub.noreturn or set(calls) != stub.noreturn:
            raise ValueError('stack-failure stub is not an inspected noreturn panic call')
        codes['___stack_chk_fail'], assemblies['___stack_chk_fail'] = stub, text

    kernel_noreturn = {}
    if any(symbol in names for symbol in CACHE_HELPERS):
        # Existing XNU interfaces, not new GPU helpers: kern/debug.h declares
        # panic __abortlike; kern/assert.h declares Assert __abortlike when
        # CONFIG_NONFATAL_ASSERTS is off (the Santoni DEVELOPMENT contract).
        # Treat these external ABIs like the existing allocator/lock APIs.
        # This does NOT relax _Code's instruction, hole or zero-padding checks.
        for symbol in ('_panic', '_Assert'):
            if symbol in names:
                if len(names[symbol]) != 1:
                    raise ValueError('ambiguous kernel noreturn ABI: ' + symbol)
                address = next(iter(names[symbol]))
                kernel_noreturn[symbol] = address
                noreturn.add(address)

    def load(symbol, address=None):
        text = subprocess.check_output(['llvm-objdump', '--disassemble', '--disassemble-zeroes',
                                        f'--disassemble-symbols={symbol}', str(kernel)], text=True)
        if address is None:
            if len(names.get(symbol, ())) != 1:
                raise ValueError(f'could not inspect actual GPU code: {symbol}')
            address = next(iter(names[symbol]))
        codes[symbol] = _Code(text, symbol, address, noreturn=noreturn)
        assemblies[symbol] = text

    for symbol in (*required, '_IOKitBSDInit'):
        load(symbol)
    if '_sgpu_bootstrap' in names:
        load('_sgpu_bootstrap')
        for symbol in ('_sgpu_session_options', '_sgpu_session_start', '_sgpu_session_loop',
                       '_sgpu_session_producer', '_sgpu_session_queue_init', '_sgpu_session_enqueue',
                       '_sgpu_session_take', '_sgpu_session_commit', '_sgpu_session_finish',
                       '_sgpu_session_close', '_sgpu_session_fault_pending', '_sgpu_session_get',
                       '_sgpu_session_prepare', '_sgpu_session_execute', '_sgpu_session_stop',
                       '_sgpu_session_failure_result'):
            load(symbol)
    user_helpers = _scalar_user_helpers(names)
    for symbol in user_helpers:
        load(symbol)  # open/close are indirect cdevsw methods, not ordinary callees
    from santoni_gpu_launcher_audit import load_launcher, default_off, PUBLIC, CALLBACKS, CHANGED
    launcher_cold = {}
    if PUBLIC[0] in names:
        # Xcode outlines some existing mockfs/init panic branches. Prove each
        # concrete cold callee is acyclic and ends only at an admitted noreturn
        # ABI before treating its callers' BL as a terminal. Never ignore a
        # decoder truncation or infer termination from the '.cold' spelling.
        for parent in (*PUBLIC, *CALLBACKS, *CHANGED, '_load_init_program_at_path'):
            outlined = [n for n in names if n.startswith(parent + '.cold.')]
            if len(outlined) > 8 or any(not re.fullmatch(re.escape(parent) + r'\.cold\.[1-8]', n) for n in outlined):
                raise ValueError('unreviewed launcher cold boundary')
            for symbol in outlined:
                load(symbol)
                code = codes[symbol]
                exits = [pc for pc in code.reachable if not code.succ[pc]]
                if not exits or any(code.ins[pc][0] not in ('bl', 'b') or
                        _number(code.ins[pc][1][-1]) not in noreturn for pc in exits):
                    raise ValueError('launcher cold boundary can return or escape its panic ABI')
                degrees = {pc: len(code.pred[pc] & code.reachable) for pc in code.reachable}
                pending = [pc for pc, degree in degrees.items() if not degree]
                visited = set()
                while pending:
                    pc = pending.pop(); visited.add(pc)
                    for after in code.succ[pc]:
                        degrees[after] -= 1
                        if not degrees[after]: pending.append(after)
                if visited != code.reachable:
                    raise ValueError('launcher cold terminal proof reaches a loop')
                noreturn.add(code.entry)
                launcher_cold[symbol] = {'entry': hex(code.entry), 'terminal_calls': [hex(pc) for pc in exits],
                                         'acyclic_instruction_count': len(visited)}
    launcher_metadata = {}
    launcher_present = load_launcher(load, codes, names, image=image, data_evidence=launcher_metadata)
    launcher_mount_provider = None
    launcher_dispatch = None
    if launcher_present:
        from santoni_gpu_mockfs_vfs_audit import audit as audit_mockfs_vfs
        from santoni_gpu_audit_compat import shared_ast
        provider_identity = {'commit': commit, 'ci_run': run['databaseId'], 'kernel_sha256': digest,
            'provider_sha256': hashlib.sha256((ROOT / 'tools/santoni_gpu_mockfs_vfs_audit.py').read_bytes()).hexdigest(),
            'machine_sha256': hashlib.sha256((ROOT / 'tools/santoni_gpu_binary_model.py').read_bytes()).hexdigest(),
            'shared_decoder_ast_sha256': hashlib.sha256(shared_ast(Path(__file__).read_bytes()).encode()).hexdigest()}
        provider_key = hashlib.sha256(json.dumps(provider_identity, sort_keys=True).encode()).hexdigest()
        provider_component = folder / ('launcher-mount-provider-' + provider_key[:16] + '.json')
        if provider_component.is_file():
            saved = json.loads(provider_component.read_text())
            result = saved.get('result', {})
            if (saved.get('identity') != provider_identity or result.get('success') is not True or
                    result.get('enabled_LP64_mount_dispatch_checked') is not True or
                    result.get('kernel_sha256') != digest or
                    result.get('registration', {}).get('vfs_flags') != '0x104' or
                    [case.get('case') for case in result.get('cases', [])] != [
                        'linked64', 'linked32', 'ready64', 'callee-error', 'wrong-bit',
                        'missing-callback', 'dead-mount']):
                raise ValueError('completed launcher mount provider component differs')
            launcher_mount_provider = result
        else:
            # These VFS roots are outside the GPU loader's code map. The provider
            # decodes them and binds every instruction word to this checked image.
            launcher_mount_provider = audit_mockfs_vfs(folder, image, names, sys.modules[__name__])
            provider_component.write_text(json.dumps({'identity': provider_identity,
                'result': launcher_mount_provider}, indent=2) + '\n')
        from santoni_gpu_trace_dispatch_audit import (decode as decode_trace_dispatch,
            audit as audit_trace_dispatch, validate as validate_trace_dispatch, ROOTS as DISPATCH_ROOTS)
        from santoni_gpu_launcher_audit import trace_bindings
        dispatch_identity = {'commit': commit, 'ci_run': run['databaseId'], 'kernel_sha256': digest}
        dispatch_tool = hashlib.sha256((ROOT / 'tools/santoni_gpu_trace_dispatch_audit.py').read_bytes()).hexdigest()
        dispatch_key = hashlib.sha256(json.dumps({**dispatch_identity, 'tool': dispatch_tool,
            'machine': provider_identity['machine_sha256'],
            'decoder': provider_identity['shared_decoder_ast_sha256']}, sort_keys=True).encode()).hexdigest()
        dispatch_file = folder / ('trace-common-dispatch-' + dispatch_key[:16] + '.json')
        if dispatch_file.exists():
            launcher_dispatch = validate_trace_dispatch(json.loads(dispatch_file.read_text()),
                dispatch_identity, trace_bindings(image, names))
        else:
            dispatch_codes = decode_trace_dispatch(folder, image, names, sys.modules[__name__])
            launcher_dispatch = {**audit_trace_dispatch(dispatch_codes, image, names, sys.modules[__name__]),
                **dispatch_identity, 'tool_sha256': dispatch_tool}
            validate_trace_dispatch(launcher_dispatch, dispatch_identity, trace_bindings(image, names))
            with dispatch_file.open('x') as stream:
                stream.write(json.dumps(launcher_dispatch, indent=2) + '\n')
    if '_sgpu_zap_allocation_preflight' in names:
        for symbol in ('_sgpu_zap_allocation_preflight', '_sgpu_zap_prepare', '_sgpu_zap_layout',
                       '_sgpu_pas_allocate', '_sgpu_pas_release'):
            load(symbol)
    if any(symbol in names for symbol in _SCM_HELPERS):
        if any(symbol not in names for symbol in _SCM_HELPERS):
            raise ValueError('SCM capability helper boundaries are missing')
        for symbol in _SCM_HELPERS:
            load(symbol)
    if any(symbol in names for symbol in CACHE_HELPERS):
        if any(symbol not in names for symbol in CACHE_HELPERS):
            raise ValueError('PAS cache helper boundaries are missing')
        for symbol in CACHE_HELPERS:
            load(symbol)
    if any(symbol in names for symbol in STOCK_HELPERS):
        if any(symbol not in names for symbol in STOCK_HELPERS):
            raise ValueError('stock A505 transition helper boundaries missing')
        for symbol in STOCK_HELPERS:
            load(symbol)
    if any(symbol in names for symbol in PIXEL_HELPERS):
        if any(symbol not in names for symbol in (*PIXEL_HELPERS, '_render_test', '_consume')):
            raise ValueError('pixel diagnostic helper boundaries missing')
        for symbol in (*PIXEL_HELPERS, '_render_test', '_consume'):
            load(symbol)
    if any(symbol in names for symbol in G3_HELPERS):
        if any(symbol not in names for symbol in G3_HELPERS):raise ValueError('G3 helper boundaries missing')
        for symbol in G3_HELPERS:load(symbol)
    from santoni_gpu_render_audit import helpers as render_helpers, prepared_only, inspection_budget
    for symbol in render_helpers(names):
        load(symbol)
    from santoni_gpu_ui_audit import helpers as ui_helpers, caller_boundary as ui_boundary
    for symbol in ui_helpers(names):
        load(symbol)
    from santoni_gpu_graphics_audit import helpers as graphics_helpers, caller_boundary as graphics_boundary
    for symbol in graphics_helpers(names):
        load(symbol)
    dyld_startup = None
    if '_santoni_gpu_graphics_dyld_flags' in names:
        from santoni_gpu_dyld_startup_audit import audit_startup, inspection_helpers as startup_helpers, BOOT as DYLD_BOOT, BSD as DYLD_BSD
        # LLVM outlines XNU's fatal checks. Prove each terminal body before
        # using its no-return edge in the bootstrap/initial-user order graph.
        # Never exempt unknown/interior instructions or infer termination merely
        # from a cold name, final call, counter or source-only declaration.
        cold_proofs=[]
        startup=startup_helpers(names)
        for symbol in startup[2:]:
            load(symbol);code=codes[symbol]
            exits=[pc for pc in code.reachable if not code.succ[pc]]
            terminal=bool(exits) and all(pc in code.noreturn or code.ins[pc][0]=='b' and
                _number(code.ins[pc][1][-1]) in noreturn for pc in exits)
            cold_proofs.append({'symbol':symbol,'proven_noreturn':terminal,'terminal_PCs':[hex(pc) for pc in exits]})
            if terminal:noreturn.add(next(iter(names[symbol])))
        load(DYLD_BOOT);load(DYLD_BSD)
        dyld_startup=audit_startup(codes,names)
        dyld_startup['cold_terminal_proofs']=cold_proofs
    _scm_smc_scope(codes)
    callbacks, wiring = _ops_wiring(codes['_sgpu_kernel_thread'], image, names, local_names)
    if render_helpers(names):
        wiring['prepared_render_API'] = prepared_only(codes, names)
    if launcher_cold:
        wiring['EL0_launcher_cold_terminal_proofs'] = launcher_cold
    if launcher_present:
        wiring['EL0_launcher_allocation_data'] = launcher_metadata
    for symbol, address in callbacks.items():
        load(symbol, address)
    # Outlined GPU-local callees must not escape the changed-code ISA screen.
    wrappers = {'_poll', '_change', '_update_rcg', '_read32', '_write32', '_write64',
                '_wait_us', '_consume', '_marker_test', '_render_test', '_faults',
                '_has_fault', '_map_pages', '_packet4', '_little32', '_version',
                '_pmap_santoni_pas_aperture_pte', '_address',
                '_session_time', '_session_fail', '_session_poll', '_session_check',
                '_session_readiness', '_session_queue_settle', '_session_cancel_queued'}
    by_address = {}
    for name, addresses in names.items():
        for address in addresses:
            by_address.setdefault(address, []).append(name)
    while True:
        extra = {name: address for code in codes.values() for pc in code.reachable
                 if code.ins[pc][0] in ('bl', 'b')
                 for address in [_number(code.ins[pc][1][-1])]
                 for name in by_address.get(address, ()) if name not in codes and
                 (name.startswith('_sgpu_') or name in wrappers or
                  launcher_present and name.startswith('_launch_'))}
        if not extra:
            break
        # 0206 adds sixteen public/adapter boundaries and seven local helpers.
        # Keep the old bound for old kernels and a finite expanded inspection
        # budget for the explicitly loaded new bootstrap/session roots.
        if len(codes) + len(extra) > inspection_budget(names, launcher_present, '_sgpu_bootstrap' in codes):
            raise ValueError('GPU-local code inspection exceeded its bound')
        for symbol, address in extra.items():
            load(symbol, address)
    _scm_smc_scope(codes)
    launcher_default = None
    if ui_helpers(names):
        wiring['UI_presentation_boundary'] = ui_boundary(codes, names)
    if graphics_helpers(names):
        wiring['graphics_client_boundary'] = graphics_boundary(codes,names)
    from santoni_gpu_renderer_audit import RENDERER as RENDERER_TASK, audit_renderer_task
    renderer_identity = None
    if RENDERER_TASK in codes:
        renderer_identity = audit_renderer_task(codes,image,names,sys.modules[__name__])
        wiring['graphics_renderer_identity_helper'] = renderer_identity
    dyld_contracts = None
    if '_santoni_gpu_graphics_dyld_flags' in codes:
        from santoni_gpu_dyld_audit import audit_flags, audit_callback, audit_registration, audit_trace, TRACE_BEGIN, TRACE_EVENT
        if renderer_identity is None:
            raise ValueError('renderer dyld contracts require the executable identity proof')
        dyld_contracts = {'success': True,
            'flags': audit_flags(codes,image,names,sys.modules[__name__]),
            'callback': audit_callback(codes,image,names,sys.modules[__name__]),
            'registration': audit_registration(codes,image,names,sys.modules[__name__]),
            'bounded_startup_trace': audit_trace(codes,image,names,sys.modules[__name__]) if TRACE_BEGIN in codes else None,
            'boot_registration_invocation_checked': dyld_startup is not None,
            'startup': dyld_startup,
            'runtime_dyld_verified': False, 'hardware_verified': False}
        wiring['graphics_renderer_dyld_contracts'] = dyld_contracts
    if launcher_present:
        from santoni_gpu_audit_compat import shared_ast
        graph = {n: {'ins': c.ins, 'succ': c.succ, 'noreturn': sorted(c.noreturn), 'padding': c.padding}
                 for n, c in codes.items() if n.startswith(('_santoni_gpu_user_launch_', '_sgpu_launch_', '_launch_')) or
                 n == '_load_init_program'}
        identity = {'kernel_sha256': digest,
            'launcher_auditor_sha256': hashlib.sha256((ROOT / 'tools/santoni_gpu_launcher_audit.py').read_bytes()).hexdigest(),
            'machine_sha256': hashlib.sha256((ROOT / 'tools/santoni_gpu_binary_model.py').read_bytes()).hexdigest(),
            'shared_decoder_ast_sha256': hashlib.sha256(shared_ast(Path(__file__).read_bytes()).encode()).hexdigest(),
            'decoded_graph_sha256': hashlib.sha256(json.dumps(graph, sort_keys=True).encode()).hexdigest()}
        key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
        component = folder / ('launcher-default-component-' + key[:16] + '.json')
        if component.is_file():
            saved = json.loads(component.read_text())
            if saved.get('identity') != identity or saved.get('result', {}).get('success') is not True:
                raise ValueError('completed launcher default component differs')
            launcher_default = saved['result']
            wiring['EL0_launcher_default_component_consumed'] = str(component)
        else:
            launcher_default = default_off(codes, image, names, sys.modules[__name__])
            component.write_text(json.dumps({'identity': identity, 'result': launcher_default}, indent=2) + '\n')
    if launcher_default:
        wiring['EL0_launcher_default_off'] = launcher_default
    if launcher_mount_provider:
        wiring['EL0_launcher_mount_provider'] = launcher_mount_provider
    if launcher_dispatch:
        wiring['EL0_launcher_trace_dispatch'] = launcher_dispatch
    startup = _Flow(codes['_IOKitBSDInit'], image, names)
    if not codes['_IOKitBSDInit'].calls_to(names['_santoni_gpu_start'], startup.before):
        raise ValueError('BSD startup never launches the optional GPU worker')
    launch = _Flow(codes['_santoni_gpu_start'], image, names)
    launches = codes['_santoni_gpu_start'].calls_to(names['_kernel_thread_start'], launch.before)
    if not launches or any(launch.before[pc].get('x0') != _Value(
            64, codes['_sgpu_kernel_thread'].entry) for pc in launches):
        raise ValueError('startup does not pass the inspected GPU worker to kernel_thread_start')
    clean = _Flow(codes['_clean'], image, names)
    clean_sites = codes['_clean'].calls_to(names['_CleanPoC_DcacheRegion_Force'], clean.before)
    if not clean_sites or any(clean.before[pc].get('x0') != _Value(64, ('arg', 1)) or
                              clean.before[pc].get('x1') != _cast(_Value(32, ('arg', 2)), 64)
                              for pc in clean_sites):
        raise ValueError('Ops cache-clean callback never calls CleanPoC_DcacheRegion_Force')
    wiring['cache_clean_calls'] = [hex(pc) for pc in clean_sites]
    worker = _Flow(codes['_sgpu_kernel_thread'], image, names)
    if len(codes['_sgpu_kernel_thread'].calls_to(names['_sgpu_failure_summary'], worker.before)) != 2:
        raise ValueError('worker must print separate first-failure and rollback records')
    if not any(codes['_sgpu_failure'].ins[pc][0] in ('str', 'stp') and not re.search(
            r'\[(?:sp|x29)(?:,|\])', codes['_sgpu_failure'].ins[pc][1][-1])
            for pc in codes['_sgpu_failure'].reachable):
        raise ValueError('first-failure record stores are missing from the actual binary')
    wiring['checked_write32'] = _helper_readback(codes['_checked_write32'], image, names, 32)
    wiring['checked_write64'] = _helper_readback(codes['_checked_write64'], image, names, 64)
    wiring['A505_paired_stop'] = _helper_readback(codes['_sgpu_a505_halt'], image, names, 32)
    wiring['A505_SP_full_RMW_release'] = _helper_readback(codes['_sgpu_a505_sp_release'], image, names, 32)
    wiring['branch_state_poll'] = _branch_poll(codes['_branch_state'], image, names)
    edges = []
    for caller in ('_sgpu_power', '_sgpu_restore_power'):
        edges += _controlled_calls(codes[caller], image, names, '_branch_state')
    for caller in ('_sgpu_smmu_start', '_sgpu_smmu_restore'):
        for helper in ('_checked_write32', '_checked_write64'):
            edges += _controlled_calls(codes[caller], image, names, helper,
                                        containment=caller == '_sgpu_smmu_restore')
    edges += _controlled_calls(codes['_sgpu_a505_resume'], image, names, '_checked_write32')
    edges += _controlled_calls(codes['_sgpu_a505_resume'], image, names, '_sgpu_a505_sp_release')
    wiring['A505_resume_boundaries'] = _a505_resume_wiring(codes, image, names)
    probe = codes.get('_sgpu_bootstrap', codes['_sgpu_probe'])
    for callee, forbidden in (
             ('_sgpu_power', ('_sgpu_smmu_start', '_sgpu_a505_init', '_sgpu_a505_resume', '_sgpu_a505_halt')),
             ('_sgpu_smmu_start', ('_sgpu_a505_init',)),
             ('_sgpu_a505_resume', ('_sgpu_smmu_start', '_sgpu_a505_init', '_sgpu_a505_halt', '_sgpu_restore_power')),
             ('_sgpu_smmu_restore', ('_sgpu_restore_power',)), ('_sgpu_restore_power', ())):
        edges += _controlled_calls(probe, image, names, callee, forbidden=forbidden)
    edges += _controlled_calls(probe, image, names, '_checked_write32', false_return=False)
    edges += _controlled_calls(probe, image, names, '_sgpu_a505_halt', false_return=False)
    wiring['checked_call_edges'] = edges
    wiring['nonexecuted_zero_alignment_padding'] = {
        name: [hex(pc) for pc in code.padding] for name, code in codes.items() if code.padding}
    wiring['verified_noreturn_stack_failure_calls'] = {
        name: [hex(pc) for pc in code.noreturn
               if _number(code.ins[pc][1][-1]) in names.get('___stack_chk_fail', ())]
        for name, code in codes.items() if any(_number(code.ins[pc][1][-1]) in
            names.get('___stack_chk_fail', ()) for pc in code.noreturn)}
    pas = _pas_preflight_wiring(codes, image, names)
    cache = None
    if CACHE_HELPERS[0] in codes:
        bootstrap = subprocess.check_output(['llvm-objdump', '--disassemble', '--disassemble-zeroes',
            '--disassemble-symbols=_arm_vm_init', str(kernel)], text=True)
        terminals = set(noreturn)
        cold_evidence = {}
        outlined = {address: name for name in names if re.fullmatch(r'_OUTLINED_FUNCTION_\d+', name)
                    for address in names[name]}

        def terminal_wrapper(symbol, address, ancestors=()):
            if address in ancestors or len(ancestors) >= 8:
                raise ValueError('cyclic/oversized bootstrap terminal-wrapper chain')
            text = subprocess.check_output(['llvm-objdump', '--disassemble', '--disassemble-zeroes',
                '--disassemble-symbols=' + symbol, str(kernel)], text=True)
            # Outlined targets are provisional until recursively verified below;
            # no name or LLVM annotation alone earns terminal status.
            cold = _Code(text, symbol, address, noreturn=noreturn | outlined.keys())
            calls = [pc for pc in cold.reachable if cold.ins[pc][0] in ('bl', 'br', 'blr') or
                     cold.ins[pc][0] == 'b' and _number(cold.ins[pc][1][-1]) not in cold.ins]
            exits = [pc for pc in cold.reachable if not cold.succ[pc]]
            if not exits or set(exits) != set(calls):
                raise ValueError('bootstrap wrapper has a returning/nonterminal path: ' + symbol)
            for pc in calls:
                target = _number(cold.ins[pc][1][-1])
                if cold.ins[pc][0] not in ('bl', 'b'):
                    raise ValueError('indirect bootstrap terminal target')
                if target in outlined:
                    terminal_wrapper(outlined[target], target, (*ancestors, address))
                elif target not in noreturn:
                    raise ValueError('bootstrap wrapper calls an unreviewed target')
            cold_evidence[symbol + '@' + hex(address)] = hex(address)
            assemblies[symbol + '@' + hex(address)] = text

        for symbol in sorted(name for name in names if re.fullmatch(r'_arm_vm_(?:init|physmap_slide)\.cold\.\d+', name)):
            if len(names[symbol]) != 1:
                raise ValueError('ambiguous bootstrap cold helper')
            address = next(iter(names[symbol]))
            terminal_wrapper(symbol, address)
            terminals.add(address)
        slide = subprocess.check_output(['llvm-objdump', '--disassemble', '--disassemble-zeroes',
            '--disassemble-symbols=_arm_vm_physmap_slide', str(kernel)], text=True)
        cache = audit_cache(codes, image, names, sys.modules[__name__], bootstrap, terminals, slide)
        cache['kernel_external_noreturn_ABIs'] = {name: hex(address) for name, address in kernel_noreturn.items()}
        cache['verified_bootstrap_terminal_wrappers'] = cold_evidence
        assemblies['_arm_vm_init'] = bootstrap
        assemblies['_arm_vm_physmap_slide'] = slide
        wiring['PAS_cache_preflight'] = cache
        for literal in (b'santonigpu_cache\0', b'PAS CACHE RESULT', b'NO SCM, NO GPU CONTINUATION'):
            if literal not in data:
                raise ValueError('PAS cache opt-in/result diagnostics missing')
    scm = _scm_capability_wiring(codes, image, names, local_names)
    stock = audit_stock(codes, image, names, sys.modules[__name__])
    if stock:
        wiring['stock_A505_transition'] = stock
    pixels = audit_pixels(codes, image, names, sys.modules[__name__])
    if pixels:
        wiring['stock_A505_pixels'] = pixels
    g3 = audit_g3(codes, image, names, sys.modules[__name__])
    if g3:
        wiring['G3_kernel_IB'] = g3
    if scm:
        for literal in (b'santonigpu_scm\0', b'SCM capability-only opt-in; REAL SMC',
                        b'SCM LAST FRAME', b'SCM PROBE RESULT', b'NO PAS LOAD'):
            if literal not in data:
                raise ValueError('SCM opt-in/raw-frame/result diagnostic contract is missing')
        wiring['SCM_capability_probe'] = scm
    if pas:
        for literal in (b'santonigpu_zap\0', b'santoni-gpu-zap-mdt\0', b'santoni-gpu-zap-b02\0',
                        b'zap allocation-only preflight', b'NO PAS/SMC'):
            if literal not in data:
                raise ValueError('PAS preflight argument/property/diagnostic contract is missing')
        from santoni_gpu_boot import zap_preflight_inputs
        inputs, zap_reference = zap_preflight_inputs(zap_bundle)
        if any(blob in data for blob in inputs.values()):
            raise ValueError('private zap firmware is embedded in the CI kernel')
        pas['private_firmware_reference'] = zap_reference
        wiring['PAS_allocation_preflight'] = pas
    mmio = {}
    for bits in (32, 64):
        for role in ('write', 'read'):
            symbol = f'_sgpu_io_{role}{bits}'
            mmio[symbol] = _mmio(codes[symbol], bits, role == 'write',
                                 _Flow(codes[symbol], image, names).before)
    if not any(codes['_sgpu_cache_invalidate'].ins[pc][0] == 'dc' and
               codes['_sgpu_cache_invalidate'].ins[pc][1][0] == 'ivac'
               for pc in codes['_sgpu_cache_invalidate'].reachable):
        raise ValueError('GPU-result invalidation was elided by coherent-IO assumptions')
    if not any(codes['_sgpu_kernel_wait_us'].ins[pc][0] == 'mrs' and
               codes['_sgpu_kernel_wait_us'].ins[pc][1][-1].lower() == 'cntvct_el0'
               for pc in codes['_sgpu_kernel_wait_us'].reachable):
        raise ValueError('hardware delay loop no longer reads the architectural counter')
    for literal in (b'santonigpu\0', b'santoni-gpu-firmware\0', b'SANTONI GPU: RESULT',
                    b'SANTONI GPU: request', b'SANTONI GPU: worker entered',
                    b'SANTONI GPU: worker awake', b'SANTONI GPU: worker queued',
                    b'FIRST_FAIL\0', b'ROLLBACK_FAIL\0', b'FAIL offset/mask/want',
                    b'FAIL old/written/got', b'FAIL elapsed/budget/saved', b'trust_read=%u',
                    b'power_pending=%u', b'quiescent=%u', b'smmu_restored=%u', b'ROLLBACK_MORE',
                    b'A505 CP halt site/old/got', b'A505 SP release old/written/got',
                    b'partial A50x resume; power held until reboot'):
        if literal not in data:
            raise ValueError('GPU boot-argument/firmware/result contract is missing')
    firmware = _firmware_absence(data, ucode_bundle)
    # A session certificate is emitted only after the complete decoded audit
    # returns. The isolated mode1 role deliberately does not run/certify it.
    control = session = None
    if mode1_control:
        control = audit_control(codes, image, names, sys.modules[__name__], launcher=launcher_default)
        wiring['mode1_control'] = control
    else:
        session = audit_session(codes, image, names, sys.modules[__name__], launcher=launcher_default)
        if session is not None:
            wiring['G3_persistent_session'] = session
    report = {'commit': commit, 'ci_run': run['databaseId'], 'kernel_sha256': digest,
              'audit_scope': 'mode1-control' if mode1_control else 'full',
              'permitted_modes': [1] if mode1_control else [0, 1, 2, 3],
              CONTROL_GATE: control is not None,
              'persistent_session_present': '_sgpu_bootstrap' in codes,
              'G3_persistent_session_wiring_checked': session is not None,
              'scalar_user_client_present': bool(user_helpers),
              'EL0_launcher_present': launcher_present,
              'EL0_launcher_changed_code_A53_checked': launcher_present,
              'EL0_launcher_mount_registry_checked': bool(launcher_mount_provider and launcher_mount_provider['enabled_LP64_mount_dispatch_checked']),
              'mode1_control_EL0_launcher_unreachable_checked': bool(control and launcher_default),
              'EL0_launcher_wiring_checked': False,
              'EL0_launcher_trace_dispatch_checked': bool(launcher_dispatch),
              # Host contracts/ISA screening cannot authorize linked user roles.
              # Retain the explicit negative gates until their new exact-kernel
              # ownership/preflight/control instruction proofs are completed.
              'G3_scalar_user_client_wiring_checked': False,
              'G3_scalar_user_preflight_wiring_checked': False,
              'mode1_control_scalar_user_unreachable_checked': bool(
                  control and user_helpers and control.get('scalar_user_unreachable_checked') is True),
              'GPU_driver_linked_and_BSD_startup_hook_present': True,
              'checked_changed_code_is_Cortex_A53_compatible': True,
              'MMIO_stores_use_real_registers_and_barriers': True,
              'explicit_result_cache_invalidation_present': True,
              'request_and_pre_delay_worker_diagnostics_present': True,
              'first_failure_and_rollback_diagnostics_present': True,
              'power_clock_path_is_separately_auditable': True,
              'checked_translation_and_clock_halt_helpers_linked': True,
              'target_clock_setup_and_restore_wiring_checked': True,
              'a505_paired_stop_and_resume_wiring_checked': True,
              'a505_vendor_SP_RMW_release_and_partial_failure_hold_checked': True,
              'firmware_is_not_embedded_in_CI_kernel': True,
              'PAS_allocation_preflight_wiring_checked': bool(pas),
              'SCM_capability_probe_wiring_checked': bool(scm),
              'PAS_cache_preflight_wiring_checked': bool(cache),
              'stock_transition_present': STOCK_HELPERS[0] in codes,
              'stock_A505_transition_wiring_checked': bool(stock),
              'stock_pixels_present': PIXEL_HELPERS[0] in codes,
              'stock_A505_pixel_wiring_checked': bool(pixels),
              'g3_present': G3_HELPERS[0] in codes,
              'G3_kernel_IB_wiring_checked': bool(g3),
              'hardware_verified': False, 'review': 'source/host and binary self-audit, not hardware proof',
              'UI_presentation_present': bool(ui_helpers(names)),
              'UI_presentation_changed_code_A53_checked': bool(ui_helpers(names)),
              'graphics_client_present': bool(graphics_helpers(names)),
              'graphics_client_changed_code_A53_checked': bool(graphics_helpers(names)),
              'graphics_renderer_identity_helper_checked': renderer_identity is not None,
              # Executable identity is only one prerequisite. Connection-role,
              # status/mapping/submit/GLES-bit instruction proofs remain separate.
              'graphics_renderer_client_wiring_checked': False,
              # Startup invocation and runtime selection remain separate from
              # the scalar/data contracts checked below.
              'graphics_renderer_dyld_policy_wiring_checked': dyld_contracts is not None and dyld_startup is not None,
              'graphics_renderer_dyld_scalar_contracts_checked': dyld_contracts is not None,
              'graphics_renderer_dyld_registration_operands_checked': dyld_contracts is not None,
              'MMIO_block_addresses': mmio, 'validated_private_firmware_references': firmware,
              'wiring_evidence': wiring,
              'inspection_scope': 'decoded GPU routines/callees, reachable ABI wiring, checked readback/timeout branches; not hardware functionality',
              'inspected_functions': sorted(set(codes) | (set(DISPATCH_ROOTS) if launcher_dispatch else set()))}
    for symbol, text in assemblies.items():
        (folder / (symbol.removeprefix('_') + '.asm')).write_text(text)
    (folder / 'gpu-binary-audit.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('commit')
    parser.add_argument('--mode1-control', action='store_true',
                        help='certify only mode1 with all experimental options absent; session remains blocked')
    args = parser.parse_args()
    print(json.dumps(audit(args.commit, mode1_control=args.mode1_control), indent=2))
