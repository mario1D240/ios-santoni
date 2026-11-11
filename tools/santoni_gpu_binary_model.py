"""Bounded concrete replay of LLVM-decoded A53 integer/NEON instructions.

This never executes native kernel code or accesses hardware. Only explicitly
mapped model objects are writable; external calls require supplied contracts.
Unknown branch/address/operation, out-of-object access and instruction-budget
exhaustion reject. The normal decoder/ISA/caller audits remain prerequisites.
"""
import re


class Memory:
    def __init__(self, image):
        self.image, self.regions, self.write_hook = image, [], None
        self.readonly = []

    def map(self, address, size, fill=0, known=True):
        if size <= 0 or any(address < a + len(data) and a < address + size for a, data, _ in self.regions):
            raise ValueError('overlapping/empty binary-model region')
        self.regions.append((address, bytearray([fill]) * size, bytearray([int(known)]) * size))

    def locate(self, address, size):
        for base, data, known in self.regions:
            if base <= address and address + size <= base + len(data):
                return data, known, address - base
        return None

    def bytes(self, address, size, partial=False):
        if size < 0 or size > 131072:
            raise ValueError('binary-model memory extent exceeds bound')
        region = self.locate(address, size)
        if region:
            data, known, offset = region
            result = tuple(data[i] if known[i] else None for i in range(offset, offset + size))
            if partial: return result
            if None in result: raise ValueError('unknown bytes used as concrete input')
            return bytes(result)
        if any(s.get('initprot', 0) & 2 and s['vmaddr'] <= address < s['vmaddr'] + s['vmsize']
               for s in getattr(self.image, 'segs', ())):
            raise ValueError('unmodeled mutable kernel storage read')
        value = self.image.read(address, size)
        if value is None:
            raise ValueError(f'unmapped binary-model read at {address:#x}+{size}')
        data = value.to_bytes(size, 'little')
        return tuple(data) if partial else data

    def write(self, address, data):
        if any(address < end and start < address + len(data) for start, end in self.readonly):
            raise ValueError('binary-model write to immutable kernel state')
        region = self.locate(address, len(data))
        if region is None:
            raise ValueError(f'binary-model write outside owned objects: {address:#x}+{len(data)}')
        if self.write_hook: self.write_hook(address, len(data))
        target, known, offset = region
        for i, byte in enumerate(data):
            target[offset + i] = byte or 0
            known[offset + i] = int(byte is not None)

    def get(self, address, size=4):
        return int.from_bytes(self.bytes(address, size), 'little')

    def put(self, address, value, size=4):
        self.write(address, (value & ((1 << (size * 8)) - 1)).to_bytes(size, 'little'))


def state_type(e):
    class State(e._State):
        def __init__(self, memory, regs=None, flags=None):
            super().__init__(regs=regs, flags=flags)
            self.backing = memory

        def copy(self):
            return State(self.backing, dict(self.regs), self.flags)

        def store(self, address, size, value):
            if address is None or not isinstance(address.expr, int):
                raise ValueError('unknown concrete store address')
            if value is None:
                data = (None,) * size
            elif isinstance(value.expr, int):
                data = (value.expr & ((1 << (size * 8)) - 1)).to_bytes(size, 'little')
            elif value.expr[0] == 'bytes':
                data = value.expr[1][:size]
            else:
                raise ValueError('symbolic value stored in concrete replay')
            self.backing.write(address.expr, data)

        def load(self, address, size, image):
            if address is None or not isinstance(address.expr, int):
                raise ValueError('unknown concrete load address')
            data = self.backing.bytes(address.expr, size, partial=True)
            if None not in data: return e._Value(size * 8, int.from_bytes(bytes(data), 'little'))
            return e._Value(size * 8, ('bytes', data))

        load_copy = load
    return State


def integer(state, reg):
    value = state.get(reg)
    if value is None or not isinstance(value.expr, int):
        raise ValueError('unknown concrete register: ' + reg)
    return value.expr


def vector_step(op, args, state, memory, e):
    if op == 'rev64.2s':
        if len(args) != 2 or not all(re.fullmatch(r'v\d+', reg) for reg in args):
            raise ValueError('unreviewed REV64 vector geometry')
        value = integer(state, args[1]) & ((1 << 64) - 1)
        state.put(args[0], e._Value(64, ((value & 0xffffffff) << 32) | (value >> 32)))
        return True
    shape = re.fullmatch(r'(movi|dup|shl|cmeq|cmlt|mvn|eor|and|orr|bit|xtn|umaxv)\.(\d+)([bhsd])', op)
    if shape:
        kind, count, suffix = shape.groups()
        count, bits = int(count), {'b': 8, 'h': 16, 's': 32, 'd': 64}[suffix]
        width = count * bits
        if width not in (64, 128): raise ValueError('unreviewed concrete vector geometry')
        mask, full = (1 << bits) - 1, (1 << width) - 1
        if kind == 'movi':
            value = e._number(args[1])
            if value is None or len(args) != 2: raise ValueError('unreviewed MOVI immediate')
            result = sum((value & mask) << (i * bits) for i in range(count))
        else:
            a = integer(state, args[1])
            if kind == 'dup': result = sum((a & mask) << (i * bits) for i in range(count))
            elif kind == 'mvn': result = ~a
            elif kind == 'shl':
                shift = e._number(args[2])
                if shift is None or not 0 <= shift < bits: raise ValueError('unreviewed vector shift')
                result = sum((((a >> (i * bits)) & mask) << shift & mask) << (i * bits) for i in range(count))
            elif kind == 'xtn':
                if width != 64: raise ValueError('unreviewed narrowing geometry')
                result = sum(((a >> (i * bits * 2)) & mask) << (i * bits) for i in range(count))
            elif kind == 'umaxv': result = max((a >> (i * bits)) & mask for i in range(count))
            elif kind == 'cmlt':
                if args[2] != '#0': raise ValueError('unreviewed signed vector comparison')
                result = sum((mask if a & (1 << (i * bits + bits - 1)) else 0) << (i * bits) for i in range(count))
            else:
                b = integer(state, args[2])
                if kind == 'cmeq':
                    result = sum((mask if (a >> (i * bits)) & mask == (b >> (i * bits)) & mask else 0)
                                 << (i * bits) for i in range(count))
                elif kind == 'eor': result = a ^ b
                elif kind == 'and': result = a & b
                elif kind == 'orr': result = a | b
                else: result = (integer(state, args[0]) & ~b) | (a & b)
        state.put(args[0], e._Value(width, result & full))
        return True
    if op == 'fmov':
        if len(args) != 2 or (args[0][0], args[1][0]) not in (('w', 's'), ('s', 'w'), ('x', 'd'), ('d', 'x')):
            raise ValueError('unreviewed floating-point operation')
        state.put(args[0], state.get(args[1]))
        return True
    if op in ('ld1.s', 'mov.d'):
        if op == 'ld1.s':
            dest = re.fullmatch(r'\{\s*v(\d+)\s*\}\[(\d+)\]', args[0])
            bits = 32
            address, pre = state.address(args[1])
            if pre or len(args) != 2 or address is None: raise ValueError('unreviewed lane load')
            value = memory.get(address.expr, 4)
        else:
            dest = re.fullmatch(r'v(\d+)\[(\d+)\]', args[0])
            source = re.fullmatch(r'v(\d+)\[(\d+)\]', args[1])
            bits = 64
            if source is None or int(source[2]) > 1: raise ValueError('unreviewed lane source')
            value = integer(state, 'q' + source[1]) >> (int(source[2]) * bits)
        if dest is None or int(dest[2]) >= 128 // bits: raise ValueError('unreviewed lane destination')
        register, shift = 'q' + dest[1], int(dest[2]) * bits
        mask = ((1 << bits) - 1) << shift
        state.put(register, e._Value(128, (integer(state, register) & ~mask) | ((value << shift) & mask)))
        return True
    return False


class Machine:
    STACK = 0x50000000
    STACK_SIZE = 0x20000
    RETURN = 0x12345678

    def __init__(self, codes, image, names, e, memory=None, stack_base=None):
        self.codes, self.image, self.names, self.e = codes, image, names, e
        self.memory = memory or Memory(image)
        if stack_base is not None: self.STACK = stack_base
        self.memory.map(self.STACK, self.STACK_SIZE, known=False)
        if '___stack_chk_guard' in names:
            guard = next(iter(names['___stack_chk_guard']))
            if self.memory.locate(guard, 8) is None:
                self.memory.map(guard, 8)
                self.memory.put(guard, 0xa505ab1c00133755, 8)  # modeled kernel canary, never device data
                self.memory.readonly.append((guard, guard + 8))
        self.State = state_type(e)
        self.by_entry = {code.entry: code for code in codes.values()}
        self.by_pc = {pc: code for code in codes.values() for pc in code.ins}
        self.by_address = {a: n for n, addresses in names.items() for a in addresses}
        self.external = None
        self.syscall = None
        self.observe = None
        self.visited, self.calls = set(), []
        self.pc = None

    def run(self, symbol, arguments=(), budget=2000000):
        e = self.e
        state = self.State(self.memory, {'sp': e._Value(64, self.STACK + self.STACK_SIZE),
                                         'x30': e._Value(64, self.RETURN)})
        for i, value in enumerate(arguments): state.put('x' + str(i), e._Value(64, value))
        code = self.codes[symbol]
        engines = {}
        pc, stack = code.entry, []
        for _ in range(budget):
            self.pc = pc
            if pc not in self.by_pc: raise ValueError(f'binary replay escaped decoded code: {pc:#x}')
            code = self.by_pc[pc]
            if code.symbol not in engines:
                engine = object.__new__(e._Flow)
                engine.code, engine.image, engine.names = code, self.image, self.names
                engine.overrides, engine.effects = {}, {}
                engines[code.symbol] = engine
            engine = engines[code.symbol]
            op, args = code.ins[pc]
            if self.observe: self.observe(pc, state)
            self.visited.add(pc)
            if op == 'svc':
                if args != ('#0x80',) or self.syscall is None:
                    raise ValueError('unmodeled/non-Darwin SVC in concrete replay')
                incoming = state.copy()
                for reg in (f'x{i}' for i in range(19)): state.regs.pop(reg, None)
                state.flags = None
                if self.syscall(state, incoming) is not True:
                    raise ValueError('unmodeled Darwin syscall contract')
                pc += 4; continue
            if op == 'ret':
                target = integer(state, args[0] if args else 'x30')
                if not stack:
                    if target != self.RETURN or integer(state, 'sp') != self.STACK + self.STACK_SIZE:
                        raise ValueError('binary replay corrupts return/stack lifetime')
                    self.state = state
                    return state.get('w0')
                if target != stack.pop(): raise ValueError('binary replay return address differs')
                pc = target
                continue
            if op in ('bl', 'blr', 'br') or op == 'b' and e._number(args[-1]) not in code.ins:
                target = engine.call(pc, state)
                self.calls.append((pc, target))
                if target in self.by_entry and (self.external is None or not self.external(target, state, probe=True)):
                    if op in ('bl', 'blr'):
                        stack.append(pc + 4)
                        state.put('x30', e._Value(64, pc + 4))
                    pc = target
                    continue
                incoming = state.copy()
                for reg in [*(f'x{i}' for i in range(19)), *(f'q{i}' for i in (*range(8), *range(16, 32)))]:
                    state.regs.pop(reg, None)
                state.flags = None
                for i in range(8, 16):
                    low = incoming.get('d' + str(i))
                    data = tuple((low.expr >> (8 * j)) & 255 for j in range(8)) if (
                        low is not None and isinstance(low.expr, int)) else (None,) * 8
                    state.regs['q' + str(i)] = e._Value(128, ('bytes', data + (None,) * 8))
                if op in ('bl', 'blr'): state.put('x30', e._Value(64, pc + 4))
                if self.external is None or not self.external(target, state, before=incoming):
                    raise ValueError('unmodeled binary callee: ' + self.by_address.get(target, str(target)))
                if op in ('br', 'b'):
                    target = integer(state, 'x30')
                    if not stack:
                        if target != self.RETURN or integer(state, 'sp') != self.STACK + self.STACK_SIZE:
                            raise ValueError('bad external tail return/stack')
                        self.state = state
                        return state.get('w0')
                    if target != stack.pop(): raise ValueError('external tail stack mismatch')
                    pc = target
                else: pc += 4
                continue
            if code.conditional(op):
                truth = state.truth(engine.predicate(pc, state))
                if truth is None: raise ValueError(f'unknown branch in concrete replay: {code.symbol}+{pc-code.entry:#x}')
                pc = e._number(args[-1]) if truth else pc + 4
                continue
            if op == 'b':
                pc = e._number(args[0]); continue
            if vector_step(op, args, state, self.memory, e):
                pc += 4; continue
            if op in ('cmp', 'cmn', 'tst') and len(args) > 2:
                bits = e._Flow.code_width(args[0])
                shift = re.fullmatch(r'(lsl|lsr|asr) #(\d+)', args[2])
                if len(args) != 3 or shift is None or not 0 <= int(shift[2]) < bits:
                    raise ValueError('unreviewed concrete comparison shift')
                a, operand = integer(state, args[0]), state.operand(args[1])
                if operand is None or not isinstance(operand.expr, int):
                    raise ValueError('unknown concrete comparison operand')
                if args[1].startswith('#') and (op == 'tst' or shift[1] != 'lsl' or
                        int(shift[2]) not in (0, 12) or not 0 <= operand.expr <= 0xfff):
                    raise ValueError('unreviewed concrete immediate comparison shift')
                b = operand.expr
                amount, mask = int(shift[2]), (1 << bits) - 1
                b &= mask
                if shift[1] == 'lsl': b <<= amount
                elif shift[1] == 'lsr': b >>= amount
                else: b = (b - (1 << bits) if b & (1 << (bits - 1)) else b) >> amount
                b &= mask
                if op == 'tst':
                    value = a & b
                    state.flags = ('nzcv', (8 if value & (1 << (bits - 1)) else 0) |
                                   (4 if value == 0 else 0))
                else:
                    state.flags = ('cmp' if op == 'cmp' else 'cmn',
                                   e._Value(bits, a), e._Value(bits, b))
                pc += 4; continue
            if op in ('add', 'sub', 'and', 'orr', 'eor', 'bic', 'lsl', 'lsr', 'adds', 'subs', 'ands', 'bics'):
                bits = e._Flow.code_width(args[0]); mask = (1 << bits) - 1
                a, operand = integer(state, args[1]), state.operand(args[2])
                if operand is None or not isinstance(operand.expr, int):
                    raise ValueError('unknown concrete arithmetic operand')
                b = operand.expr & mask
                if len(args) > 3:
                    shift = re.fullmatch(r'(lsl|lsr|asr|[us]xt[bwh])(?: #(\d+))?', args[3])
                    if not shift or len(args) != 4: raise ValueError('unreviewed concrete arithmetic shift: ' + str((op, args)))
                    amount = int(shift[2] or 0)
                    if amount >= bits: raise ValueError('out-of-range concrete arithmetic shift')
                    if shift[1][1:3] == 'xt':
                        width = {'b': 8, 'h': 16, 'w': 32}[shift[1][-1]]
                        b &= (1 << width) - 1
                        if shift[1][0] == 's' and b & (1 << (width - 1)): b -= 1 << width
                        b <<= amount
                    elif shift[1] == 'lsl': b <<= amount
                    elif shift[1] == 'lsr': b >>= amount
                    else: b = (b - (1 << bits) if b & (1 << (bits - 1)) else b) >> amount
                b &= mask
                operation = op[:-1] if op in ('adds', 'subs', 'ands', 'bics') else op
                if operation in ('lsl', 'lsr') and not args[2].startswith('#'): b %= bits
                value = e._binary(operation, bits, e._Value(bits, a), e._Value(bits, b))
                if value is None: raise ValueError('unreviewed concrete arithmetic value')
                state.put(args[0], value)
                if op in ('adds', 'subs'):
                    state.flags = ('cmn' if op == 'adds' else 'cmp', e._Value(bits, a), e._Value(bits, b))
                elif op in ('ands', 'bics'):
                    state.flags = ('nzcv', (8 if value.expr & (1 << (bits - 1)) else 0) | (4 if value.expr == 0 else 0))
                pc += 4; continue
            if op in ('madd', 'mul', 'umull', 'umaddl', 'umulh'):
                a, b = integer(state, args[1]), integer(state, args[2])
                value = a * b
                if op == 'umulh': value >>= 64
                if op in ('madd', 'umaddl'): value += integer(state, args[3])
                state.put(args[0], e._Value(e._Flow.code_width(args[0]), value))
                pc += 4; continue
            if op == 'udiv':
                if len(args) != 3 or any(e._Flow.code_width(reg) != e._Flow.code_width(args[0]) for reg in args):
                    raise ValueError('unreviewed UDIV width')
                numerator, denominator = integer(state, args[1]), integer(state, args[2])
                state.put(args[0], e._Value(e._Flow.code_width(args[0]), numerator // denominator if denominator else 0))
                pc += 4; continue
            if op in ('neg', 'msub'):
                if len(args) != (2 if op == 'neg' else 4) or any(
                        not re.fullmatch(r'[wx](?:[12]?\d|30|zr)', reg) or
                        e._Flow.code_width(reg) != e._Flow.code_width(args[0]) for reg in args):
                    raise ValueError('unreviewed NEG/MSUB register geometry')
                value = -integer(state, args[1]) if op == 'neg' else (
                    integer(state, args[3]) - integer(state, args[1]) * integer(state, args[2]))
                state.put(args[0], e._Value(e._Flow.code_width(args[0]), value))
                pc += 4; continue
            allowed = ('adr', 'adrp', 'mov', 'movk', 'sxtw', 'sxth', 'sxtb', 'uxtw', 'uxth', 'uxtb',
                       'ubfx', 'ubfiz', 'cmp', 'tst', 'cmn', 'ccmp', 'cset', 'csetm', 'csel',
                       'csinc', 'csinv', 'csneg', 'add', 'sub', 'and', 'orr', 'eor', 'bic',
                       'lsl', 'lsr', 'adds', 'subs', 'ands', 'bics', 'ldr', 'ldrb', 'ldrh',
                       'ldur', 'ldurb', 'ldurh', 'str', 'strb', 'strh', 'stur', 'sturb', 'sturh',
                       'ldp', 'stp', 'nop', 'dmb', 'dsb', 'isb')
            if op not in allowed: raise ValueError('unsupported concrete instruction: ' + op)
            state = engine.step(pc, state)
            pc += 4
        raise ValueError('binary replay instruction budget exhausted')
