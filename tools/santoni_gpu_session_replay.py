"""Execute linked session instructions over owned synthetic state/MMIO.

PAs and GPU responses below are model inputs, never device measurements. The
old bootstrap's outcome is injected at its verified stable-pointer boundary;
all new session functions, BO validation/publication and queue code execute
their decoded instructions. Existing full legacy audit remains prerequisite.
"""
from santoni_gpu_binary_model import Machine, integer

CORE_BYTES = 2272
OFF = {'ops': 8, 'probe': 128, 'arena': 872, 'startup': 1776, 'working': 1968,
       'result': 2160, 'wptr': 2236, 'values': 2240, 'start_us': 2256, 'last_us': 2264}
CORE_NAMES = ('_sgpu_session_start', '_sgpu_session_prepare', '_sgpu_session_execute',
    '_sgpu_session_stop', '_sgpu_session_failure_result', '_session_readiness', '_session_check',
    '_session_poll', '_session_time', '_session_fail', '_sgpu_g3_begin', '_sgpu_g3_complete',
    '_sgpu_g3_abort', '_sgpu_g3_lookup', '_sgpu_g3_mapping', '_sgpu_memory_validate',
    '_sgpu_stock_check32', '_checked_write32', '_sgpu_failure', '_faults', '_has_fault',
    '_sgpu_packet7')
QUEUE_NAMES = ('_sgpu_session_queue_init', '_sgpu_session_enqueue', '_sgpu_session_take',
    '_sgpu_session_commit', '_sgpu_session_finish', '_sgpu_session_close',
    '_sgpu_session_fault_pending', '_sgpu_session_get', '_session_queue_settle', '_session_cancel_queued')


class QueueModel:
    def __init__(self, codes, image, names, e):
        self.e = e
        self.vm = Machine({n: codes[n] for n in QUEUE_NAMES}, image, names, e)
        self.m = self.vm.memory
        self.q, self.values, self.id, self.request, self.result, self.output = (
            0x51000000, 0x51001000, 0x51002000, 0x51003000, 0x51004000, 0x51005000)
        for address, size in ((self.q, 3056), (self.values, 16), (self.id, 4),
                              (self.request, 20), (self.result, 76), (self.output, 76)):
            self.m.map(address, size)
        self.vm.external = self.external

    def external(self, target, state, probe=False, before=None):
        name = self.vm.by_address.get(target)
        if name not in ('_bzero', '_memcpy'): return False
        if probe: return True
        dest, second = integer(before, 'x0'), integer(before, 'x1')
        length = second if name == '_bzero' else integer(before, 'x2')
        if length > 3056: raise ValueError('queue libc copy exceeds bounded storage')
        self.m.write(dest, bytes(length) if name == '_bzero' else self.m.bytes(second, length, partial=True))
        state.put('x0', self.e._Value(64, dest))
        return True

    def call(self, name, *args):
        value = self.vm.run('_sgpu_session_' + name, args)
        return None if value is None else value.expr

    def complete(self, seq, wptr, error=0):
        self.m.write(self.result, bytes(76))
        for off, value in ((0, 4), (4, seq), (8, wptr), (12, 0 if error else 4), (16, error)):
            self.m.put(self.result + off, value)
        self.m.put(self.result + 24, 1, 1)

    def status(self):
        return [self.m.get(self.q + 4 + i * 4) for i in range(15)]


def audit_queue(codes, image, names, e):
    executed, cases = set(), 0
    def require(ok, message):
        if not ok: raise ValueError('compiled session queue: ' + message)
    for close_at in range(5):
        for fault in (False, True):
            q = QueueModel(codes, image, names, e)
            require(q.call('queue_init', q.q) == 1, 'first initialization rejected')
            require(q.call('queue_init', q.q) == 0, 'second initialization accepted')
            for i in range(4):
                require(q.call('enqueue', q.q, 1, 1, q.values, q.id) == 0 and q.m.get(q.id) == i + 1,
                        'bounded enqueue/id differs')
            frozen = q.m.bytes(q.q, 3056)
            for owner, kind in ((0, 1), (2, 1), (1, 0), (1, 2)):
                require(q.call('enqueue', q.q, owner, kind, q.values, q.id) == 2, 'owner/kind bypass')
                require(q.m.bytes(q.q, 3056) == frozen, 'bad request modifies queue')
            require(q.call('enqueue', q.q, 1, 1, q.values, q.id) == 3, 'active+queued depth exceeds four')
            if close_at == 0: q.call('close', q.q, 1)
            taken = q.call('take', q.q, q.request)
            if close_at == 0:
                require(taken == 0 and q.status()[8] == 4 and q.status()[0] == 4, 'close does not cancel queued work')
            else:
                require(taken == 1 and q.m.get(q.request) == 1, 'take is not FIFO')
                if close_at == 1: q.call('close', q.q, 1)
                committed = q.call('commit', q.q, 1)
                if close_at == 1:
                    require(committed == 0 and q.status()[8] == 4 and q.status()[0] == 4,
                            'close before commit does not cancel all pending work')
                else:
                    require(committed == 1 and q.call('commit', q.q, 1) == 0, 'commit duplicates request')
                    if close_at == 2: q.call('close', q.q, 1)
                    q.complete(3, 181, 12 if fault else 0)
                    require(q.call('finish', q.q, 1, q.result) == 1, 'completion rejected')
                    require(q.call('finish', q.q, 1, q.result) == 0, 'completion counted twice')
                    if not fault:
                        if close_at >= 3: q.call('close', q.q, 1)
                        require(q.call('take', q.q, q.request) == 0, 'close admits another request')
                    status = q.status()
                    require(status[0] == (5 if fault else 4) and status[8] == 3 and
                            status[7] == int(not fault) and status[9] == int(fault), 'close/fault counts differ')
            require(q.status()[3:5] == [0, 0], 'terminal queue retains outstanding/active work')
            frozen = q.m.bytes(q.q, 3056)
            q.call('close', q.q, 1)
            require(q.m.bytes(q.q, 3056) == frozen, 'terminal close changes snapshots')
            executed.update(q.vm.visited); cases += 1
    q = QueueModel(codes, image, names, e); q.call('queue_init', q.q)
    for i in range(32):
        require(q.call('enqueue', q.q, 1, 1, q.values, q.id) == 0, 'quota rejects accepted range')
        require(q.call('take', q.q, q.request) == 1 and q.call('commit', q.q, i + 1) == 1, 'quota drain fails')
        q.complete(i + 3, 181 + i * 11)
        require(q.call('finish', q.q, i + 1, q.result) == 1, 'quota completion fails')
        require(q.call('get', q.q, 1, i + 1, q.output) == 1 and q.m.bytes(q.output, 76) == q.m.bytes(q.result, 76),
                'result is not an immutable by-value copy')
    require(q.status() == [4, 1, 32, 0, 0, 32, 32, 32, 0, 0, 128, 34, 522, 0, 0], 'terminal quota counters differ')
    require(q.call('enqueue', q.q, 1, 1, q.values, q.id) == 5, 'closed quota admits work')
    executed.update(q.vm.visited); cases += 1
    for published in (0, 1):
        q = QueueModel(codes, image, names, e); q.call('queue_init', q.q)
        for _ in range(4): q.call('enqueue', q.q, 1, 1, q.values, q.id)
        q.call('take', q.q, q.request); q.call('commit', q.q, 1)
        q.complete(3, 181); q.call('finish', q.q, 1, q.result)
        first = q.m.bytes(q.q + 112 + 16, 76)
        q.call('take', q.q, q.request)
        if published: q.call('commit', q.q, 2)
        q.m.write(q.result, bytes(76))
        for off, val in ((4, 4 * published), (8, 192 * published)): q.m.put(q.result + off, val)
        q.m.put(q.result + 24, published, 1)
        q.call('fault_pending', q.q, q.result)
        s = q.status()
        require(s[0:2] == [5, 3] and s[3:5] == [0, 0] and s[6:10] == [1 + published, 1, 2, 1] and
                s[11:15] == [3, 181, 1, 2], 'internal fault loses pending accounting/publication')
        require(q.m.bytes(q.q + 112 + 16, 76) == first, 'internal fault overwrites earlier completion')
        frozen = q.m.bytes(q.q, 3056)
        q.call('fault_pending', q.q, 0)
        require(q.m.bytes(q.q, 3056) == frozen, 'first internal fault is mutable')
        executed.update(q.vm.visited); cases += 1
    return {'cases': cases, 'executed_instruction_addresses': len(executed), 'hardware_verified': False}


class SessionModel:
    OPS, REPORT, VALUES, OUTPUT, POOL = 0x51000000, 0x51001000, 0x51002000, 0x51003000, 0x52000000
    IB, DATA, FENCE = POOL + 17 * 4096, POOL + 18 * 4096, POOL + 19 * 4096
    PTE = 3 | 4 | (2 << 8) | (1 << 10) | (1 << 11) | (3 << 53)

    def __init__(self, codes, image, names, e, extra=()):
        self.e, self.names = e, names
        self.vm = Machine({n: codes[n] for n in (*CORE_NAMES, *extra) if n in codes}, image, names, e)
        self.m = self.vm.memory
        self.core = next(iter(names['_session_core']))
        self.p, self.g = self.core + OFF['probe'], self.core + OFF['arena']
        for address, size in ((self.core, CORE_BYTES), (self.OPS, 120), (self.REPORT, 192),
                              (self.VALUES, 16), (self.OUTPUT, 76), (self.POOL, 98304)):
            self.m.map(address, size)
        self.addresses = {next(iter(names[n])): n for n in ('_sgpu_bootstrap', '_bzero', '_memcpy',
                         *e._CALLBACKS.values()) if n in names}
        for offset, name in e._CALLBACKS.items(): self.m.put(self.OPS + offset, next(iter(names[name])), 8)
        for offset in (104, 108, 112, 116): self.m.put(self.OPS + offset, 1)
        self.clock, self.time_step = 1000, 0
        self.callbacks, self.published, self.fence_reads = [], [], 0
        self.clean_pages, self.invalidated_pages = [], set()
        self.injection = None
        self.after_bootstrap = None
        self.after_callback = None
        self.before_callback = None
        self.bootstrap_count = 0
        self.regs = {(4, 0x3d000): 0, (4, 0x13d4): 1, (4, 0x2018): 170, (4, 0x201c): 170,
            (4, 0x20c8): 0, (4, 0xe0): 0, (4, 0x2000): 0x1020000, (4, 0x2004): 0,
            (4, 0x2008): (1 << 27) | (2 << 8) | 9, (4, 0x20e0): 0x1000000, (4, 0x20e4): 0,
            (4, 0x20d4): 0x1010000, (4, 0x20d8): 0, (5, 0x8000): 0x1127, (5, 0xc00): 0,
            (5, 0x1800): 1, (5, 0x1000): 0x1f300, (5, 0x8030): 0x00802560,
            (5, 0x8010): 0x38010, (5, 0x8038): 0xff44, (5, 0x803c): 0,
            (5, 0x8020): 0x98000000, (5, 0x8024): 0x10000,
            (4, 0x1384): 0, (5, 0x8058): 0, (5, 0x48): 0, (5, 0x8060): 0, (5, 0x8064): 0}
        self.vm.external = self.external
        self.vm.observe = self.observe

    def observe(self, pc, state):
        if pc in self.names['_sgpu_g3_complete'] and self.invalidated_pages != {self.FENCE, self.DATA}:
            raise ValueError('session completes without fence/data cache invalidation')

    def boot_state(self):
        m, p, g = self.m, self.p, self.g
        m.put(p, self.core + OFF['ops'], 8)
        m.put(p + 8, self.core + OFF['startup'], 8)
        m.put(p + 16, self.POOL, 8)
        for i in range(24): m.put(p + 24 + i * 8, 0x98000000 + i * 8192, 8)
        m.put(p + 728, 13)
        for i in range(732, 741): m.put(p + i, int(i != 735), 1)
        m.put(g, p + 16, 8)
        for i, (role, size) in enumerate(((2, 128), (1, 16), (3, 64))):
            bo, slot, physical = g + 8 + i * 56, 256 + i * 2, 17 + i
            for off, value in ((0, 1), (4, i + 1), (8, size), (12, slot), (16, 1), (20, role), (24, 2)):
                m.put(bo + off, value)
            m.put(bo + 28, physical, 1)
            m.put(g + 344 + physical, 1, 1)
            m.put(g + 368 + slot, 1, 1); m.put(g + 368 + slot + 1, 1, 1)
            m.put(self.POOL + 8192 + slot * 8, (0x98000000 + physical * 8192) |
                  self.PTE | ((3 if role == 2 else 1) << 6), 8)
        for off, val in ((880, 4), (884, 2), (888, 2), (892, 0)): m.put(g + off, val)
        m.put(g + 896, 1, 1)
        r = self.core + OFF['startup']
        for off, val in ((0, 11), (4, 16), (8, 16), (24, 256), (28, 1), (52, 13),
                         (180, 2), (184, 2), (188, 8)):
            m.put(r + off, val)
        for off in (56, 58, 168, 169, 170, 171, 172, 173, 174, 176, 177, 178): m.put(r + off, 1, 1)
        m.put(self.core + OFF['wptr'], 170)

    def external(self, target, state, probe=False, before=None):
        name = self.addresses.get(target)
        if name is None: return False
        if probe: return True
        m, e = self.m, self.e
        arg = lambda i: integer(before, 'x' + str(i))
        if name in ('_bzero', '_memcpy'):
            length = arg(1 if name == '_bzero' else 2)
            if length > 98304: raise ValueError('unbounded modeled libc operation')
            m.write(arg(0), bytes(length) if name == '_bzero' else m.bytes(arg(1), length, partial=True))
            state.put('x0', e._Value(64, arg(0)))
            return True
        if name == '_sgpu_bootstrap':
            expected = (self.core + 8, 3, 0, 0, self.core + 1776, self.p, self.g, self.core + 2236)
            if tuple(arg(i) for i in range(8)) != expected or m.get(self.core, 1) != 1:
                raise ValueError('bootstrap does not receive stable owned session storage')
            if m.bytes(self.core + 8, 120) != m.bytes(self.OPS, 120):
                raise ValueError('bootstrap Ops copy differs')
            self.bootstrap_count += 1
            if self.bootstrap_count != 1: raise ValueError('session retries bootstrap')
            self.boot_state()
            if self.after_bootstrap: self.after_bootstrap(self)
            state.put('w0', e._Value(32, 0))  # successful HELD startup returns false
            return True
        if arg(0) != 0: raise ValueError('session callback loses its NULL adapter context')
        if self.before_callback: self.before_callback(self, name, before)
        self.callbacks.append((name, self.vm.pc, tuple(arg(i) for i in range(1, 3)) if name in (
            '_clean', '_sgpu_cache_invalidate', '_sgpu_io_read32', '_sgpu_io_write32') else ()))
        if name == '_now_us':
            self.clock += self.time_step
            state.put('x0', e._Value(64, self.clock))
        elif name == '_sgpu_kernel_wait_us':
            delay = arg(1)
            if delay > 100: raise ValueError('session wait exceeds phase/shared-budget slice')
            if self.injection != 'stopped-clock': self.clock += delay
        elif name == '_sgpu_io_read32':
            key = arg(1), arg(2)
            if key not in self.regs: raise ValueError('session read leaves reviewed readiness/fault registers')
            value = self.regs[key]
            if self.injection == 'rptr-timeout' and key == (4, 0x2018) and self.published: value -= 11
            state.put('w0', e._Value(32, value))
        elif name == '_sgpu_io_write32':
            key, value = (arg(1), arg(2)), arg(3)
            seq = m.get(self.g + 892)
            if key != (4, 0x201c) or value != m.get(self.core + 2236) + 11 or not seq:
                raise ValueError('session publishes wrong register/pointer/sequence')
            if m.get(self.core + 2160 + 24, 1) != 1 or any(m.get(self.g + 8 + i * 56 + 24) != seq for i in range(3)):
                raise ValueError('publication precedes attempted/reference accounting')
            words = [m.get(self.POOL + 3 * 4096 + (value - 11 + i) * 4) for i in range(11)]
            expected = [0x70bf8003, 0x1100000, 0, 17, 0x70268000, 0x70460004, 4,
                        0x1104000, 0, seq, 0x70268000]
            if words != expected: raise ValueError('session ring batch differs from fixed owned IB/fence packet')
            if self.clean_pages != [self.IB, self.DATA, self.FENCE, self.POOL + 3 * 4096]:
                raise ValueError('session publication precedes ordered IB/data/fence/ring cache cleans')
            self.clean_pages = []; self.invalidated_pages.clear()
            self.published.append((value, seq))
            self.regs[key] = value if self.injection != 'wptr-echo' else value ^ 1
            self.regs[4, 0x2018] = value
            for i in range(4):
                opcode, va, high, datum = (m.get(self.IB + (i * 4 + j) * 4) for j in range(4))
                if (opcode, va, high) != (0x703d8003, 0x1102000 + i * 4, 0):
                    raise ValueError('session IB contents are not four fixed owned writes')
                m.put(self.DATA + i * 4, datum)
            m.put(self.FENCE, seq)
        elif name == '_clean':
            if arg(1) not in (self.IB, self.DATA, self.FENCE, self.POOL + 3 * 4096) or arg(2) != 4096:
                raise ValueError('session cache clean escapes owned pages')
            self.clean_pages.append(arg(1))
            if self.injection == 'cache-deadline': self.clock += 2000001
        elif name == '_sgpu_cache_invalidate':
            self.invalidated_pages.add(arg(1))
            if (arg(1), arg(2)) == (self.FENCE, 64):
                self.fence_reads += 1
                if self.injection in ('fence-timeout', 'stopped-clock'): m.put(self.FENCE, 0)
                if self.injection == 'future-fence': m.put(self.FENCE, m.get(self.g + 892) + 1)
            elif (arg(1), arg(2)) == (self.DATA, 4096):
                if self.injection == 'data-corrupt': m.put(self.DATA, 0)
                if self.injection == 'padding-corrupt': m.put(self.DATA + 4095, 0, 1)
            else: raise ValueError('session cache invalidate escapes data/fence')
        elif name == '_trace':
            address = arg(1); text = bytearray()
            for i in range(256):
                byte = m.get(address + i, 1)
                if byte == 0: break
                text.append(byte)
            else: raise ValueError('unterminated trace label')
            if text.startswith(b'before '): raise ValueError('session request reaches startup trace delay')
        else:
            raise ValueError('forbidden allocation/release/secure/wide callback in session: ' + name)
        if self.after_callback: self.after_callback(self, name, before)
        return True

    def call(self, name, *args):
        result = self.vm.run(name, args)
        if result is None or not isinstance(result.expr, int): raise ValueError('unknown session return')
        return result.expr

    def start(self):
        return self.call('_sgpu_session_start', self.OPS, 3, 0, 0, self.REPORT)

    def execute(self, values=(1, 2, 3, 4)):
        for i, value in enumerate(values): self.m.put(self.VALUES + i * 4, value)
        return self.call('_sgpu_session_execute', self.VALUES, self.OUTPUT)


def audit_core(codes, image, names, e):
    """Real session code; only old bootstrap outcome and hardware are modeled."""
    cases, instructions = 0, set()

    def terminal(model, error=None):
        nonlocal cases
        m, base = model.m, model.core
        if error is not None and m.get(base + OFF['result'] + 16) != error:
            raise ValueError('session failure error differs from injected fault')
        snapshot = m.bytes(base + OFF['result'], 76, partial=True)
        startup = m.bytes(base + OFF['startup'], 192)
        calls = len(model.callbacks)
        model.vm.run('_sgpu_session_stop')
        if model.call('_sgpu_session_prepare') != 0 or model.execute() != 0:
            raise ValueError('stopped session resumes a request')
        model.vm.run('_sgpu_session_stop')
        if len(model.callbacks) != calls or m.bytes(base + OFF['result'], 76, partial=True) != snapshot:
            raise ValueError('terminal session mutates first result or touches hardware')
        if m.bytes(base + OFF['startup'], 192) != startup:
            raise ValueError('terminal session overwrites startup evidence')
        if any(m.get(model.g + 8 + i * 56 + 53, 1) != 1 for i in range(3)):
            raise ValueError('terminal session fails to quarantine owned BOs')
        model.m.write(model.OPS, model.m.bytes(base + OFF['ops'], 120))
        if model.start() != 0 or model.bootstrap_count != 1:
            raise ValueError('terminal session retries bootstrap')
        instructions.update(model.vm.visited)
        cases += 1

    # Ready requires every startup field, not the false HELD return or one bit.
    required = [(8, 4, 16), (24, 4, 256), (180, 4, 2), (184, 4, 2), (188, 4, 8),
                (4, 4, 16), (64, 4, 0), (112, 4, 0), (171, 1, 1), (56, 1, 1),
                (57, 1, 0), (59, 1, 0), (60, 1, 0), (52, 4, 13),
                (173, 1, 1), (174, 1, 1), (177, 1, 1), (178, 1, 1)]
    for off, width, want in required:
        model = SessionModel(codes, image, names, e)
        model.after_bootstrap = lambda s, off=off, width=width, want=want: s.m.put(
            s.core + OFF['startup'] + off, want ^ 1, width)
        if model.start() != 0 or model.callbacks:
            raise ValueError('invalid startup snapshot reaches live readiness')
        terminal(model, 17 if off == 4 else 1)
    model = SessionModel(codes, image, names, e)
    model.after_bootstrap = lambda s: s.m.put(s.core + OFF['wptr'], 171)
    if model.start() != 0 or model.callbacks: raise ValueError('wrong bootstrap WPTR accepted')
    terminal(model, 1)

    # Every PA and all BO guard/owner/role fields participate in live readiness.
    changes = [(128 + 24 + i * 8, 8, 0) for i in range(24)]
    changes += [(128 + i, 1, 0) for i in (732, 733, 734, 736, 738, 739)]
    changes += [(128 + 735, 1, 1), (872, 8, 0), (872 + 896, 1, 0),
                (872 + 897, 1, 1), (872 + 892, 4, 3), (872 + 888, 4, 1)]
    for i in range(3):
        changes += [(872 + 8 + i * 56 + off, width, value)
                    for off, width, value in ((0, 4, 2), (16, 4, 2), (20, 4, 0), (52, 1, 1), (53, 1, 1))]
    for off, size, value in changes:
        model = SessionModel(codes, image, names, e)
        model.after_bootstrap = lambda s, off=off, size=size, value=value: s.m.put(s.core + off, value, size)
        if model.start() != 0:
            raise ValueError(f'bad startup ownership/mapping accepted: offset={off} size={size} value={value}')
        terminal(model, 8)
    for i in range(3):
        model = SessionModel(codes, image, names, e)
        model.after_bootstrap = lambda s, i=i: s.m.put(s.POOL + 8192 + (257 + i * 2) * 8, 3, 8)
        if model.start() != 0: raise ValueError('mapped BO guard page accepted')
        terminal(model, 8)

    model = SessionModel(codes, image, names, e)
    if model.start() != 1: raise ValueError('valid HELD bootstrap cannot start session')
    original = model.m.bytes(model.core + OFF['startup'], 192)
    if model.m.bytes(model.REPORT, 192) != original or model.m.get(model.p + 8, 8) != model.core + OFF['working']:
        raise ValueError('startup report copy/rebinding differs')
    # Destroy departed caller buffers. Subsequent requests must use final storage.
    model.m.write(model.OPS, b'\xcc' * 120)
    model.m.write(model.REPORT, b'\xcc' * 192)
    for i in range(32):
        if model.call('_sgpu_session_prepare') != 1 or model.execute(tuple(0xa5050000 + i * 4 + j for j in range(4))) != 1:
            raise ValueError('bounded live session request failed')
        m = model.m
        if [m.get(model.OUTPUT + off) for off in (0, 4, 8, 12, 16)] != [4, i + 3, 181 + i * 11, 4, 0]:
            raise ValueError('session completion sequence/WPTR/write count differs')
        if m.bytes(model.core + OFF['startup'], 192) != original:
            raise ValueError('request overwrites immutable bootstrap evidence')
    if model.published != [(181 + i * 11, i + 3) for i in range(32)]:
        raise ValueError('session does not publish 32 monotonic batches')
    terminal(model, 0)
    if model.m.get(model.g + 897, 1) != 0:
        raise ValueError('orderly quota stop is mislabeled as an engine fault')
    for field, value in ((OFF['arena'] + 888, 34), (OFF['wptr'], 1013)):
        model = SessionModel(codes, image, names, e)
        if model.start() != 1: raise ValueError('valid startup refused')
        model.m.put(model.core + field, value)
        if model.call('_sgpu_session_prepare') != 0:
            raise ValueError('session exceeds lifetime/ring capacity')
        terminal(model, 1)

    for injection, error, published in (('wptr-echo', 12, 1), ('rptr-timeout', 11, 1),
            ('fence-timeout', 11, 1), ('stopped-clock', 11, 1), ('future-fence', 12, 1),
            ('data-corrupt', 13, 1), ('padding-corrupt', 13, 1), ('cache-deadline', 11, 0)):
        model = SessionModel(codes, image, names, e)
        if model.start() != 1 or model.call('_sgpu_session_prepare') != 1:
            raise ValueError('could not enter request for fault scenario')
        model.injection = injection
        if model.execute((123, 456, 789, 1011)) != 0 or len(model.published) != published:
            raise ValueError('session fault did not stop at the intended exposure boundary: ' + injection)
        if injection in ('fence-timeout', 'stopped-clock') and model.fence_reads != 2001:
            raise ValueError('session fence lacks exact read-count bound')
        terminal(model, error)
    # Lost live TRUST and a late SMMU fault cannot be treated as another request.
    for offset, value, error in (((4, 0x3d000), 1, 9), ((5, 0x8058), 2, 12)):
        model = SessionModel(codes, image, names, e)
        if model.start() != 1: raise ValueError('valid startup refused')
        model.regs[offset] = value
        if model.call('_sgpu_session_prepare') != 0 or model.published:
            raise ValueError('lost live readiness does not terminalize before publication')
        terminal(model, error)
    # Every immutable configuration register is checked freshly and full-width.
    baseline = SessionModel(codes, image, names, e)
    if baseline.start() != 1: raise ValueError('valid startup refused')
    excluded = {(4, 0x13d4), (4, 0x1384), (5, 0x8058), (5, 0x48), (5, 0x8060), (5, 0x8064)}
    for key, expected in baseline.regs.items():
        if key in excluded: continue
        for changed in (expected ^ 1, expected ^ 0x80000000):
            model = SessionModel(codes, image, names, e)
            model.regs[key] = changed
            if model.start() != 0: raise ValueError('readiness ignores register mismatch: ' + str(key))
            terminal(model, 9)
    for adjustment in ('backward', 'deadline'):
        model = SessionModel(codes, image, names, e)
        if model.start() != 1: raise ValueError('valid startup refused')
        def overrun(s, name, before, adjustment=adjustment):
            if name == '_sgpu_io_read32':
                s.clock = 0 if adjustment == 'backward' else s.m.get(s.core + OFF['start_us'], 8) + 2000000
        model.after_callback = overrun
        if model.call('_sgpu_session_prepare') != 0 or model.published:
            raise ValueError('returning readiness callback escapes the shared deadline')
        model.after_callback = None
        terminal(model, 11)
    for injection in ('bad-IB', 'late-fault'):
        model = SessionModel(codes, image, names, e)
        if model.start() != 1 or model.call('_sgpu_session_prepare') != 1:
            raise ValueError('valid request refused')
        def corrupt(s, name, before, injection=injection):
            if injection == 'bad-IB' and name == '_clean' and integer(before, 'x1') == s.IB:
                s.m.put(s.IB, 0x40000001)
            if injection == 'late-fault' and name == '_sgpu_cache_invalidate' and integer(before, 'x1') == s.DATA:
                s.regs[5, 0x8058] = 2
        model.after_callback = corrupt
        if model.execute() != 0 or len(model.published) != int(injection == 'late-fault'):
            raise ValueError('IB/final-fault validation bypass')
        model.after_callback = None
        terminal(model, 1 if injection == 'bad-IB' else 12)
    model = SessionModel(codes, image, names, e)
    model.regs[5, 0x8058] = 0x400
    if model.start() != 1 or model.call('_sgpu_session_prepare') != 1 or model.execute() != 1:
        raise ValueError('Qualcomm non-fault status bit classified as FSR_FAULT')
    terminal(model, 0)
    return {'cases': cases, 'executed_instruction_addresses': len(instructions),
            'normal_additional_requests': 32, 'final_sequence': 34, 'final_wptr': 522,
            'hardware_verified': False}


class AdapterModel(SessionModel):
    """Actual worker/queue/core; producer admissions occur at modeled wakeups.

    Native pthread tests remain the concurrency oracle. This replay checks the
    linked adapter ABI, commitment/error paths, lock scope and printed snapshots.
    """
    def __init__(self, codes, image, names, e):
        super().__init__(codes, image, names, e, extra=(*QUEUE_NAMES, '_sgpu_session_loop'))
        self.q = next(iter(names['_session_queue']))
        self.queue_event = next(iter(names['_session_queue_event']))
        self.idle = next(iter(names['_session_idle_count']))
        self.lock = next(iter(names['_sgpu_session_lock']))
        for address, size in ((self.q, 3056), (self.queue_event, 4), (self.idle, 4), (0x53000000, 4)):
            self.m.map(address, size)
        self.queue_vm = Machine({n: codes[n] for n in QUEUE_NAMES}, image, names, e,
                                memory=self.m, stack_base=0x54000000)
        self.queue_vm.external = self.external
        self.locked, self.registered, self.sent, self.blocks = False, False, 0, 0
        self.fail_thread_start = False
        self.schedule = 'normal'
        self.spurious = 0
        self.close_when = None
        self.closed_once = False
        self.summaries = []
        self.adapter_addresses = {next(iter(names[n])): n for n in ('_lck_mtx_lock', '_lck_mtx_unlock',
            '_assert_wait', '_thread_block', '_kernel_thread_start', '_thread_deallocate',
            '_printf', '_sgpu_failure_summary') if n in names}
        self.vm.observe = self.observe

    def observe(self, pc, state):
        super().observe(pc, state)
        if self.injection == 'finish-rejected' and pc == next(iter(self.names['_sgpu_session_finish'])):
            self.m.put(integer(state, 'x2') + 12, 0)  # corrupt internal completion, as in native negative

    def admit(self):
        if not self.locked: raise ValueError('modeled wake admission without mutex')
        for _ in range(4):
            if self.sent >= 32: break
            for j in range(4): self.m.put(self.VALUES + j * 4, 0xa5060000 ^ ((self.sent + 1) << 8) ^ j)
            result = self.queue_call('enqueue', self.q, 1, 1, self.VALUES, 0x53000000)
            if result != self.e._Value(32, 0): raise ValueError('worker cannot accept bounded wakeup request')
            self.sent += 1

    def queue_call(self, name, *args):
        if not self.locked: raise ValueError('modeled producer mutates queue without mutex')
        return self.queue_vm.run('_sgpu_session_' + name, args)

    def external(self, target, state, probe=False, before=None):
        if self.injection == 'commit-rejected' and target in self.names['_sgpu_session_commit']:
            if not probe:
                if not self.locked: raise ValueError('commit rejection lacks queue mutex')
                state.put('w0', self.e._Value(32, 0))
            return True
        name = getattr(self, 'adapter_addresses', {}).get(target)
        if name is None:
            if not probe and before is not None and target in self.addresses:
                if self.addresses[target] not in ('_bzero', '_memcpy', '_sgpu_bootstrap'):
                    if self.locked: raise ValueError('compiled worker performs hardware operation under queue mutex')
                    if self.close_when and not self.closed_once:
                        active = self.m.get(self.q + 20)
                        if active:
                            request_state = self.m.get(self.q + 112 + (active - 1) * 92 + 16)
                            if request_state == (2 if self.close_when == 'before-commit' else 3):
                                self.locked = True
                                self.queue_call('close', self.q, 1)
                                self.locked = False
                                self.closed_once = True
            return super().external(target, state, probe=probe, before=before)
        if probe: return True
        arg = lambda i: integer(before, 'x' + str(i))
        if name == '_lck_mtx_lock':
            if arg(0) != self.lock or self.locked: raise ValueError('wrong/reentrant worker mutex')
            self.locked = True
        elif name == '_lck_mtx_unlock':
            if arg(0) != self.lock or not self.locked: raise ValueError('wrong/unbalanced worker unlock')
            if self.registered and self.schedule in ('already-awake', 'wake-before-block'):
                self.admit()
                if self.schedule == 'already-awake': self.registered = False
            self.locked = False
        elif name == '_kernel_thread_start':
            if self.locked or arg(0) != next(iter(self.names['_sgpu_session_producer'])) or arg(1) != 0:
                raise ValueError('worker launches wrong producer/argument/lock scope')
            if not self.fail_thread_start: self.m.put(arg(2), 0x42424242, 8)
            state.put('w0', self.e._Value(32, 5 if self.fail_thread_start else 0))
        elif name == '_thread_deallocate':
            if self.locked or arg(0) != 0x42424242: raise ValueError('producer thread reference ABI differs')
        elif name == '_assert_wait':
            if not self.locked or arg(0) != self.queue_event or arg(1) != 0:
                raise ValueError('worker loses atomic predicate/wait registration')
            self.registered = True
            state.put('w0', self.e._Value(32, 0 if self.schedule == 'already-awake' else 0xffffffff))
        elif name == '_thread_block':
            if self.locked or not self.registered or arg(0) != 0:
                raise ValueError('worker block without unlock/registration')
            self.registered = False; self.blocks += 1
            self.locked = True
            if self.schedule == 'spurious' and self.spurious < 3: self.spurious += 1
            elif self.schedule != 'wake-before-block': self.admit()
            self.locked = False
        elif name == '_printf':
            if self.locked: raise ValueError('worker formats output while holding queue lock')
            text = bytearray()
            for i in range(512):
                byte = self.m.get(arg(0) + i, 1)
                if not byte: break
                text.append(byte)
            else: raise ValueError('unterminated worker output format')
            if b'SESSION RESULT pass=' in text:
                values = [self.m.get(integer(before, 'sp') + i * 8, 8) for i in range(8)]
                status = [self.m.get(self.q + 4 + i * 4) for i in range(15)]
                expected = [int(status == [4, 1, 32, 0, 0, 32, 32, 32, 0, 0, 128, 34, 522, 0, 0]),
                            status[2], status[5], status[6], status[7], status[8], status[9], status[10]]
                if values != expected: raise ValueError('SESSION RESULT prints incorrect counters/pass')
                self.summaries.append(values)
            elif b'SESSION STATE state=' in text:
                values = [self.m.get(integer(before, 'sp') + i * 8, 8) for i in range(8)]
                status = [self.m.get(self.q + 4 + i * 4) for i in range(15)]
                expected = [*(status[i] for i in (0, 1, 11, 12, 13, 14)), self.m.get(self.idle), 98304]
                if values != expected: raise ValueError('SESSION STATE loses failure/retention snapshot')
        elif name == '_sgpu_failure_summary':
            if self.locked: raise ValueError('failure formatting under mutex')
            if self.m.bytes(arg(1), 48) != self.m.bytes(self.q + 4 + 60, 48):
                raise ValueError('worker summary does not preserve first failure snapshot')
        return True


def audit_worker(codes, image, names, e, scenarios=None):
    cases, executed = 0, set()
    for scenario in scenarios or ('normal', 'thread-failure', 'before-commit', 'after-commit', 'wptr-echo',
                     'rptr-timeout', 'cache-deadline', 'data-corrupt', 'commit-rejected',
                     'finish-rejected', 'spurious', 'already-awake', 'wake-before-block'):
        model = AdapterModel(codes, image, names, e)
        if model.start() != 1: raise ValueError('adapter replay startup failed')
        model.m.write(model.OPS, b'\xcc' * 120)
        model.m.write(model.REPORT, b'\xcc' * 192)
        if scenario == 'thread-failure': model.fail_thread_start = True
        elif scenario in ('before-commit', 'after-commit'): model.close_when = scenario
        elif scenario in ('spurious', 'already-awake', 'wake-before-block'): model.schedule = scenario
        elif scenario != 'normal': model.injection = scenario
        model.vm.run('_sgpu_session_loop', budget=4000000)
        status = [model.m.get(model.q + 4 + i * 4) for i in range(15)]
        if model.locked or status[3:5] != [0, 0] or status[2] != sum(status[i] for i in (7, 8, 9)):
            raise ValueError('worker exit leaves mutex or pending records')
        if scenario in ('normal', 'spurious', 'already-awake', 'wake-before-block'):
            if status != [4, 1, 32, 0, 0, 32, 32, 32, 0, 0, 128, 34, 522, 0, 0] or model.m.get(model.idle) < 2:
                raise ValueError('compiled worker does not drain quota across idle/wake')
        elif scenario == 'thread-failure':
            if status[0:2] != [5, 3] or status[2] or status[13] != 7:
                raise ValueError('failed producer creation does not terminalize')
        elif scenario in ('before-commit', 'after-commit'):
            complete = int(scenario == 'after-commit')
            if status[0:2] != [4, 2] or status[5:8] != [complete] * 3 or status[9] or status[13]:
                raise ValueError('worker close races are counted as failures or extra publication')
        else:
            if status[0:2] != [5, 3] or status[9] != 1 or status[14] != 1 or status[7]:
                raise ValueError('worker failure loses active/cancelled accounting')
            if scenario in ('commit-rejected', 'finish-rejected') and (
                    status[13] != 1 or status[6] != int(scenario == 'finish-rejected')):
                raise ValueError('worker internal rejection loses error/publication evidence')
        if scenario != 'thread-failure' and len(model.summaries) != 1:
            raise ValueError('worker terminal result missing or repeated')
        callbacks = len(model.callbacks)
        model.vm.run('_sgpu_session_stop')
        if model.call('_sgpu_session_prepare') != 0 or len(model.callbacks) != callbacks:
            raise ValueError('worker exit resumes hardware')
        executed.update(model.vm.visited); executed.update(model.queue_vm.visited); cases += 1
    return {'cases': cases, 'executed_instruction_addresses': len(executed), 'hardware_verified': False}


def audit_entry(codes, image, names, e):
    """Check both worker branches and the true-start-only session-loop edge."""
    from santoni_gpu_control_audit import _paths
    V, at = e._Value, e._scm_at
    code = codes['_sgpu_kernel_thread']; sg = V(64, next(iter(names['_sg'])))
    options = {'_sgpu_stock_options': 88, '_sgpu_pixel_options': 96,
               '_sgpu_g3_options': 100, '_sgpu_session_options': 104}
    addresses = {a: n for n, aa in names.items() for a in aa}
    # Newer workers validate additional roles before either startup branch.
    # Execute their actual mode3/absent-option parsers before injecting only
    # those checked disabled results at the worker's call boundaries.
    excluded = {}
    launcher_queries = set()
    if '_santoni_gpu_user_launch_options_ok' in codes:
        from santoni_gpu_launcher_audit import default_off as launcher_off
        proof = launcher_off(codes,image,names,e,mode=3)
        wanted = ('_santoni_gpu_user_launch_options_ok','_santoni_gpu_user_launch_worker_ready')
        if not proof or proof.get('success') is not True or proof.get('scope') != \
                'mode3; launcher option absent or explicitly zero' or \
                any(proof.get('return_values',{}).get(n)!=1 for n in wanted):
            raise ValueError('session entry lacks actual mode3 launcher exclusion')
        launcher_queries.update(wanted)
    from santoni_gpu_user_audit import scalar_option_wiring
    for name,offset in (('_sgpu_user_options',108),('_sgpu_user_test_options',112)):
        if name in codes:
            proof=scalar_option_wiring(codes[name],image,names,e,sg,modes=(3,),disabled_only=True)
            if proof.get('default_off_checked') is not True or proof.get('disabled_only') is not True or proof.get('modes') != [3] or proof.get('flag_offset') != offset:
                raise ValueError('session entry scalar exclusion differs')
            excluded[name]=((at(sg,offset),4),)
    from santoni_gpu_render_audit import default_off as render_off
    from santoni_gpu_ui_audit import default_off as ui_off
    from santoni_gpu_graphics_audit import default_off as graphics_off
    for name,check in (('_sgpu_render_options',render_off),('_sgpu_ui_options',ui_off),
                       ('_sgpu_graphics_options',graphics_off)):
        if name in codes:
            proof=check(codes,image,names,e)
            if not proof or proof.get('success') is not True or 3 not in proof.get('parsed_modes',()):
                raise ValueError('session entry lacks actual disabled role parser: '+name)
            flags=((V(64,proof['global']),1),)
            if name=='_sgpu_graphics_options':
                flags+=((V(64,proof['publication_global']),4),)
            excluded[name]=flags
    cases = []
    for enabled, valid, ready in ((0, 1, 0), (1, 0, 0), (1, 1, 0), (1, 1, 1)):
        state = e._initial(code.symbol)
        state.store(at(sg, 84), 4, V(32, 3))
        for off, value in ((88, 1), (96, 1), (100, 1), (104, enabled)):
            state.store(at(sg, off), 4, V(32, value))

        def call(pc, target, before, after, history):
            name = addresses.get(target)
            if name in options:
                if before.get('w0') != V(32, 3): raise ValueError('session option receives wrong mode')
                after.store(at(sg, options[name]), 4, V(32, enabled if name == '_sgpu_session_options' else 1))
                after.put('w0', V(32, valid if name == '_sgpu_session_options' else 1))
            elif name in launcher_queries or name in excluded:
                if before.get('w0')!=V(32,3):raise ValueError('session exclusion parser receives wrong mode')
                for address,width in excluded.get(name,()):after.store(address,width,V(width*8,0))
                after.put('w0',V(32,1))
            elif name=='_clock_interval_to_deadline':
                dest,stack=before.get('x2'),before.get('sp')
                if before.get('w0')!=V(32,40000000) or before.get('w1')!=V(32,1000) or \
                        dest is None or stack is None or not isinstance(dest.expr,tuple) or \
                        dest.expr[0]!='stack' or not stack.expr[1]<=dest.expr[1]<dest.expr[1]+8<=0:
                    raise ValueError('session inlined startup delay interval/scale/stack differs')
                after.store(dest,8,V(64,('session_entry_deadline',0)))
            elif name=='_assert_wait_deadline':
                if before.get('x0')!=at(sg,92) or before.get('w1')!=V(32,0) or \
                        before.get('x2')!=V(64,('session_entry_deadline',0)) or \
                        not set(names['_clock_interval_to_deadline'])&set(history):
                    raise ValueError('session inlined startup delay wait registration differs')
            elif name=='_thread_block':
                if before.get('x0')!=V(64,0) or not set(names['_assert_wait_deadline'])&set(history):
                    raise ValueError('session inlined startup delay block differs')
            elif name=='_sgpu_kernel_wait_us':
                if before.get('x0')!=V(64,0) or before.get('w1')!=V(32,40000000):
                    raise ValueError('session startup delay loses exact context/budget')
            elif name in ('_sgpu_pas_cache_preflight', '_sgpu_scm_capability_probe', '_sgpu_zap_allocation_preflight'):
                if not valid: raise ValueError('invalid session opt-in reaches another hardware role')
                after.put('w0', V(32, 0))  # stock1 rejects their conflicting arguments in the legacy audit
            elif name in ('_sgpu_probe', '_sgpu_session_start'):
                if not valid or name != ('_sgpu_session_start' if enabled else '_sgpu_probe'):
                    raise ValueError('session role reaches the wrong startup branch')
                ops = before.get('x0')
                if before.get('w1') != V(32, 3) or any(before.load(at(ops, off), 4, image) != V(32, value)
                        for off, value in ((104, 1), (108, 1), (112, 1), (116, enabled))):
                    raise ValueError('session options lost before startup')
                if not {next(iter(names[n])) for n in (*options,*excluded,*launcher_queries)} <= set(history):
                    raise ValueError('startup bypasses an option/exclusion validator')
                if any(before.load(address,width,image)!=V(width*8,0)
                       for flags in excluded.values() for address,width in flags):
                    raise ValueError('session startup enables a conflicting role')
                after.put('w0', V(32, ready))
                after.store(before.get('x4'), 192, None)
            elif name == '_sgpu_session_loop':
                if not enabled or not valid or not ready:
                    raise ValueError('session loop runs after absent/failed startup')
            elif name == '_sgpu_session_failure_result':
                if not enabled or not valid or ready:
                    raise ValueError('session failure report is on the wrong branch')
            elif name not in ('_printf', '_sgpu_failure_summary', '_SecureDTLookupEntry', '_SecureDTGetProperty',
                               '_thread_terminate_self', '_clock_interval_to_deadline', '_assert_wait_deadline',
                               '_thread_block', '_bzero'):
                raise ValueError('unreviewed session worker callee: '+str(name))

        def finish(state, history):
            count = lambda n: sum(a in names[n] for a in history)
            inline=count('_clock_interval_to_deadline')
            if count('_sgpu_kernel_wait_us')+inline!=1 or inline and \
                    (count('_assert_wait_deadline')!=1 or count('_thread_block')!=1):
                raise ValueError('session startup delay missing or repeated')
            if any(count(n)!=1 for n in launcher_queries) or any(count(n)!=int(bool(valid)) for n in excluded):
                raise ValueError('session exclusion parser missing or repeated')
            if count('_sgpu_session_start') != int(bool(enabled and valid)) or count('_sgpu_probe') != int(not enabled and valid):
                raise ValueError('worker startup call count differs')
            if count('_sgpu_session_loop') != int(bool(enabled and valid and ready)):
                raise ValueError('worker fails to enter a successfully started session exactly once')
            if count('_sgpu_session_failure_result') != int(bool(enabled and valid and not ready)):
                raise ValueError('worker loses failed startup report')
            if count('_thread_terminate_self') != 1: raise ValueError('worker does not terminate once')

        cases.append(_paths(code, image, names, e, state, call, finish))
    return cases


def audit_clock(codes, image, names, e):
    """Execute the adapter's actual ns-to-us conversion at boundary values."""
    vm = Machine({'_now_us': codes['_now_us']}, image, names, e)
    stamp = 0
    calls = []

    def external(target, state, probe=False, before=None):
        name = vm.by_address.get(target)
        if name not in ('_mach_absolute_time', '_absolutetime_to_nanoseconds'): return False
        if probe: return True
        calls.append(name)
        if name == '_mach_absolute_time': state.put('x0', e._Value(64, 0x12345678))
        else:
            if integer(before, 'x0') != 0x12345678: raise ValueError('clock conversion loses absolute-time argument')
            vm.memory.put(integer(before, 'x1'), stamp, 8)
        return True

    vm.external = external
    samples = (0, 1, 999, 1000, 1001, 999999, 1000000, 1999999999, 2000000000,
               99999999999, 100000000000, (1 << 32) - 1, (1 << 63), (1 << 64) - 1)
    for stamp in samples:
        calls.clear()
        vm.run('_now_us', (0,))
        if integer(vm.state, 'x0') != stamp // 1000 or calls != ['_mach_absolute_time', '_absolutetime_to_nanoseconds']:
            raise ValueError('clock callback is not bounded ns-to-us conversion')
    return {'conversion_cases': len(samples), 'hardware_clock_verified': False}


def audit_cold_arena(codes, image, names, e):
    """Execute original G3 cold allocation with the final session addresses."""
    model = SessionModel(codes, image, names, e,
                         extra=('_sgpu_g3_prepare', '_sgpu_g3_init', '_sgpu_g3_new', '_sgpu_g3_free'))
    model.boot_state()
    m = model.m
    m.write(model.core + OFF['ops'], m.bytes(model.OPS, 120))
    m.write(model.g, bytes(904)); m.write(model.POOL, bytes(98304))
    m.put(model.p + 734, 0, 1)
    m.put(model.POOL, m.get(model.p + 24 + 8, 8) | 3, 8)
    m.put(model.POOL + 4096 + 8 * 8, m.get(model.p + 24 + 16, 8) | 3, 8)
    firmware = 0x56000000; m.map(firmware, 40)
    m.put(firmware + 16, 20480); m.put(firmware + 20, 20480)
    if model.call('_sgpu_g3_prepare', model.p, model.g, firmware) != 1:
        raise ValueError('cold arena cannot prepare final session memory')
    if m.get(model.g, 8) != model.p + 16 or m.get(model.g + 896, 1) != 1 or model.callbacks:
        raise ValueError('cold arena loses descriptor/seal or reaches hardware')
    for i, role in enumerate((2, 1, 3)):
        bo = model.g + 8 + i * 56
        if [m.get(bo + off) for off in (0, 4, 12, 16, 20)] != [1, i + 2, 256 + 2 * i, 1, role]:
            raise ValueError('cold arena owner/handle/VA/role differs')
        if m.get(bo + 28, 1) != 17 + i or m.get(model.POOL + 8192 + (257 + i * 2) * 8, 8):
            raise ValueError('cold arena physical ownership/guard differs')
        if model.call('_sgpu_g3_mapping', model.g, bo) != 1:
            raise ValueError('cold arena PTE does not match descriptor')
    return {'stable_memory_descriptor': True, 'guarded_BOs': 3,
            'executed_instruction_addresses': len(model.vm.visited), 'hardware_verified': False}


class ProducerModel(QueueModel):
    """Linked producer plus linked queue, with scheduled CPU-only completions.

    The worker/core replay checks GPU completion separately. Here a wake runs
    real take/commit/finish on a second stack. This is deterministic scheduling,
    not a claim that the XNU scheduler will run within a wall-clock deadline.
    """
    def __init__(self, codes, image, names, e, scenario='normal'):
        super().__init__(codes, image, names, e)
        self.queue_vm = self.vm
        self.vm = Machine({'_sgpu_session_producer': codes['_sgpu_session_producer']},
                          image, names, e, memory=self.m, stack_base=0x54000000)
        self.vm.external = self.external
        self.names, self.scenario = names, scenario
        self.q, self.idle, self.event, self.lock = (next(iter(names[n])) for n in
            ('_session_queue', '_session_idle_count', '_session_queue_event', '_sgpu_session_lock'))
        if '_sgpu_user_options' in names:
            #0207 adds a default-off prefix. Its enabled paths have separate
            # proofs; these scenarios execute the same legacy producer role.
            sg = next(iter(names['_sg']))
            self.m.map(sg, 120)
            self.m.readonly.append((sg, sg + 120))
        self.m.map(self.q, 3056); self.m.map(self.idle, 4); self.m.map(self.event, 4)
        self.queue_vm.run('_sgpu_session_queue_init', (self.q,))
        self.m.put(self.idle, int(scenario != 'no-idle'))
        self.locked, self.waiting = False, False
        self.now, self.deadline = 1000000000, None  # synthetic nanoseconds
        self.wakes = self.blocks = self.attempts = self.terminated = self.closes = 0
        self.accepted = self.wave_waits = self.full = 0
        self.formats = []
        if scenario in ('closed', 'faulted'):
            self.m.put(self.q + 4, 4 if scenario == 'closed' else 5)

    def queue(self, name, *args):
        result = self.queue_vm.run('_sgpu_session_' + name, args)
        return result.expr if result is not None else None

    def drain(self):
        if self.scenario != 'normal': return
        # Delay the 16th completion, then the following idle transition, to
        # exercise both halves of the second-wave predicate independently.
        if self.accepted == 16 and self.wave_waits < 6:
            self.wave_waits += 1
            if self.wave_waits <= 3: return
        while self.queue('take', self.q, self.request):
            request = self.m.get(self.request)
            expected = [0xa5060000 ^ (request << 8) ^ j for j in range(4)]
            if [self.m.get(self.request + 4 + j * 4) for j in range(4)] != expected:
                raise ValueError('producer request payload/FIFO copy differs')
            if self.queue('commit', self.q, request) != 1:
                raise ValueError('producer modeled completion cannot commit')
            self.complete(request + 2, 170 + request * 11)
            if self.queue('finish', self.q, request, self.result) != 1:
                raise ValueError('producer modeled completion rejected')
        if self.accepted == 16 and self.wave_waits >= 6: self.m.put(self.idle, 2)

    def external(self, target, state, probe=False, before=None):
        name = self.vm.by_address.get(target)
        if name in ('_bzero', '_memcpy'):
            return super().external(target, state, probe=probe, before=before)
        allowed = ('_lck_mtx_lock', '_lck_mtx_unlock', '_sgpu_session_enqueue',
            '_sgpu_session_close', '_thread_wakeup_prim', '_mach_absolute_time',
            '_absolutetime_to_nanoseconds', '_clock_interval_to_deadline',
            '_assert_wait_deadline', '_thread_block', '_thread_terminate_self', '_printf')
        if name not in allowed: return False
        if probe: return True
        arg = lambda i: integer(before, 'x' + str(i))
        put = lambda val: state.put('x0', self.e._Value(64, val))
        if name == '_lck_mtx_lock':
            if self.locked or arg(0) != self.lock: raise ValueError('producer mutex acquire differs')
            self.locked = True
        elif name == '_lck_mtx_unlock':
            if not self.locked or arg(0) != self.lock: raise ValueError('producer mutex release differs')
            self.locked = False
        elif name == '_sgpu_session_enqueue':
            if not self.locked or tuple(arg(i) for i in range(3)) != (self.q, 1, 1):
                raise ValueError('producer queue/owner/WRITE4/lock differs')
            if self.accepted >= 16 and (self.m.get(self.q + 32) < 16 or self.m.get(self.idle) <= 1):
                raise ValueError('producer second wave precedes completed first wave and idle')
            if not self.m.get(self.idle) or self.accepted >= 32:
                raise ValueError('producer admits before idle or beyond lifetime bound')
            expected = [0xa5060000 ^ ((self.accepted + 1) << 8) ^ j for j in range(4)]
            if [self.m.get(arg(3) + j * 4) for j in range(4)] != expected:
                raise ValueError('producer WRITE4 values differ')
            self.attempts += 1
            if self.scenario == 'enqueue-error': rc = 2
            else: rc = self.queue('enqueue', *(arg(i) for i in range(5)))
            if rc == 0:
                self.accepted += 1
                if self.m.get(arg(4)) != self.accepted: raise ValueError('producer admitted ID differs')
            if rc == 3: self.full += 1
            # Poison the departed source to prove that queue data is by value.
            self.m.write(arg(3), b'\xcc' * 16)
            put(rc)
        elif name == '_sgpu_session_close':
            if not self.locked or (arg(0), arg(1)) != (self.q, 1):
                raise ValueError('producer close lacks owner/queue/mutex')
            self.closes += 1; put(self.queue('close', self.q, 1))
        else:
            if self.locked: raise ValueError('producer waits/formats/terminates under mutex')
            if name == '_thread_wakeup_prim':
                if tuple(arg(i) for i in range(3)) != (self.event, 0, 0):
                    raise ValueError('producer wake ABI differs')
                self.wakes += 1; self.drain()
            elif name == '_mach_absolute_time': put(self.now)
            elif name == '_absolutetime_to_nanoseconds':
                if arg(0) != self.now: raise ValueError('producer loses absolute-time input')
                self.m.put(arg(1), arg(0), 8)
            elif name == '_clock_interval_to_deadline':
                if (arg(0), arg(1)) != (10000, 1000): raise ValueError('producer delay is not 10ms')
                self.deadline = self.now + 10000000; self.m.put(arg(2), self.deadline, 8)
            elif name == '_assert_wait_deadline':
                if (arg(0), arg(1), arg(2)) != (next(iter(self.names['_sg'])) + 92, 0, self.deadline):
                    raise ValueError('producer timed-wait ABI differs')
                self.waiting = True; put(0xffffffff)
            elif name == '_thread_block':
                if not self.waiting or arg(0): raise ValueError('producer blocks without registered timed wait')
                self.waiting = False; self.blocks += 1
                if self.scenario == 'backward-clock': self.now -= 1
                elif self.scenario != 'stopped-clock':
                    self.now += 10000000 if self.scenario == 'normal' else 10000000000
            elif name == '_thread_terminate_self': self.terminated += 1
            elif name == '_printf': self.formats.append(arg(0))
        return True


def audit_producer(codes, image, names, e, scenarios=None):
    executed, results = set(), {}
    for scenario in scenarios or ('normal', 'full-deadline', 'stopped-clock', 'backward-clock',
                                   'no-idle', 'enqueue-error', 'closed', 'faulted'):
        model = ProducerModel(codes, image, names, e, scenario)
        model.vm.run('_sgpu_session_producer', (0, 0), budget=3000000)
        if scenario not in ('normal', 'closed', 'faulted'):
            # close() requests cancellation; the worker settles it at take().
            # A deliberately unscheduled worker need not have drained yet.
            if model.m.get(model.q + 1, 1) != 1 or model.status()[0] != 3:
                raise ValueError('producer exit fails to request close')
            if model.queue('take', model.q, model.request) != 0:
                raise ValueError('producer close permits another worker commitment')
        status = model.status()
        if model.locked or model.waiting or model.terminated != 1 or status[3:5] != [0, 0]:
            raise ValueError('producer exit leaves lock/wait/pending work or wrong termination count')
        if scenario == 'normal':
            if status != [4, 1, 32, 0, 0, 32, 32, 32, 0, 0, 128, 34, 522, 0, 0] or model.wave_waits != 6:
                raise ValueError('producer did not complete two separated waves')
            if model.closes or model.formats: raise ValueError('producer treats quota success as deadline failure')
        elif scenario in ('closed', 'faulted'):
            if model.attempts or model.closes or model.blocks: raise ValueError('producer reopens a terminal queue')
        else:
            if model.closes != 1 or status[:2] != [4, 2] or status[8] != model.accepted:
                raise ValueError('producer deadline/error does not close and cancel once')
            if scenario in ('full-deadline', 'stopped-clock') and (model.accepted != 4 or not model.full):
                raise ValueError('producer full-queue accounting differs')
            if scenario == 'stopped-clock' and (model.blocks != 10000 or model.attempts != 10000):
                raise ValueError('producer lacks the exact stopped-clock attempt bound')
            if scenario == 'backward-clock' and model.blocks != 1:
                raise ValueError('producer ignores a backward clock')
            if scenario == 'full-deadline' and model.blocks != 10:
                raise ValueError('producer ignores the 100-second elapsed deadline')
        executed.update(model.vm.visited); executed.update(model.queue_vm.visited)
        results[scenario] = {'accepted': model.accepted, 'attempts': model.attempts,
                             'blocks': model.blocks, 'wakes': model.wakes}
    return {'cases': results, 'executed_instruction_addresses': len(executed), 'hardware_verified': False}
