"""Linked scalar proofs; synthetic states are not hardware measurements.

Boundary components alone do not issue an enabled-client/preflight certificate.
Worker entry, producer selection and the full session prerequisites remain gates.
"""
from itertools import product
import struct

from santoni_gpu_binary_model import Machine, integer
from santoni_gpu_session_replay import QUEUE_NAMES

COMMANDS = tuple(0xc0804700 + i for i in range(1, 5))
USER_BOUNDARIES = ('_sgpu_user_open', '_sgpu_user_close', '_sgpu_user_ioctl',
                   '_sgpu_user_publish', '_sgpu_client_open', '_sgpu_client_close',
                   '_sgpu_client_call', '_sgpu_client_packet_valid')


def _require(ok, message):
    if not ok:
        raise ValueError('linked scalar boundary: ' + message)


def scalar_storage(image, names):
    """Validate actual nonexecuting storage and the indirect cdevsw roots."""
    result, spans = {}, []
    for name, size, protection in (('_sg', 120, 3), ('_session_queue', 3056, 3),
            ('_sgpu_user_client', 16, 3), ('_sgpu_user_major', 4, 3),
            ('_sgpu_user_published', 1, 3), ('_session_idle_count', 4, 3),
            ('_session_queue_event', 4, 3), ('_sgpu_session_lock', 16, 3),
            ('_sgpu_user_cdevsw', 112, 1)):
        _require(len(names.get(name, ())) == 1, 'missing/ambiguous storage ' + name)
        address = next(iter(names[name]))
        segs = [s for s in image.segs if s['vmaddr'] <= address and
                address + size <= s['vmaddr'] + s['vmsize']]
        _require(len(segs) == 1 and segs[0]['initprot'] == protection,
                 'wrong storage protection/extent ' + name)
        _require(not any(a < address + size and address < b for a, b in spans),
                 'overlapping scalar storage')
        spans.append((address, address + size))
        result[name] = address
    table = result['_sgpu_user_cdevsw']
    # XNU8796 cdevsw: thirteen pointers followed by d_type and tail padding.
    # Disabled eno_* macros resolve to _enodev; strategy uses _enodev_strat.
    expected = ('_sgpu_user_open', '_sgpu_user_close', '_enodev', '_enodev',
                '_sgpu_user_ioctl', '_enodev', '_enodev', None, '_enodev',
                '_enodev', '_enodev_strat', '_enodev', '_enodev')
    for i, name in enumerate(expected):
        _require(name is None or len(names.get(name, ())) == 1,
                 'ambiguous cdevsw method ' + str(name))
        address = 0 if name is None else next(iter(names[name]))
        _require(image.read(table + i * 8, 8) == address,
                 'unexpected cdevsw method at offset ' + str(i * 8))
    _require(image.read(table + 104, 4) == 0, 'unexpected cdevsw type')
    return result


class ScalarModel:
    """CPU-only linked wrappers/core with explicit XNU ABI contracts.

    Kernel task/credential/scheduler calls are injected. This does not model
    syscall copyin/copyout, application privilege enforcement or GPU execution.
    """
    PACKET, REQUEST, RESULT = 0x51000000, 0x51001000, 0x51002000
    TASK, OTHER_TASK, CRED, NODE = (0x53000000, 0x53001000, 0x53002000, 0x53004000)

    def __init__(self, codes, image, names, e, storage, extra=()):
        self.e, self.names, self.storage = e, names, storage
        self.vm = Machine({n: codes[n] for n in (*USER_BOUNDARIES, *QUEUE_NAMES, *extra)},
                          image, names, e)
        self.m = self.vm.memory
        self.sg, self.q, self.client, self.major, self.published, self.idle, self.event, self.lock = (
            storage[n] for n in ('_sg', '_session_queue', '_sgpu_user_client',
            '_sgpu_user_major', '_sgpu_user_published', '_session_idle_count',
            '_session_queue_event', '_sgpu_session_lock'))
        for address, size in ((self.sg, 120), (self.q, 3056), (self.client, 16),
                (self.major, 4), (self.published, 1), (self.idle, 4),
                (self.event, 4), (self.lock, 16), (self.PACKET, 128),
                (self.REQUEST, 20), (self.RESULT, 76)):
            self.m.map(address, size)
        self.m.put(self.major, 42)
        self.m.put(self.sg + 108, 1)
        self.m.put(self.published, 1, 1)
        self.m.put(self.idle, 0x13579)
        self.locked, self.root, self.task, self.refs = False, True, self.TASK, 0
        self.calls, self.wakeups = [], 0
        self.lock_injection = None
        self.add_major, self.node = 42, self.NODE
        self.vm.external, self.vm.observe = self.external, self.observe
        self.core_call('_sgpu_session_queue_init', self.q)
        self.calls.clear()
        self.vm.calls.clear()
        self.vm.visited.clear()
        self.m.write_hook = self.write_hook
        self.m.readonly.extend((a, a + n) for a, n in (
            (self.sg, 120), (self.idle, 4), (self.event, 4), (self.lock, 16)))

    def write_hook(self, address, size):
        # Any queue/client mutation and every reply copy require the mutex.
        protected = ((self.q, 3056), (self.client, 16), (self.PACKET, 128),
                     (self.published, 1))
        if any(address < a + n and a < address + size for a, n in protected):
            _require(self.locked, 'CPU mutation/reply outside mutex')

    def observe(self, pc, state):
        for name in ('_sgpu_client_open', '_sgpu_client_close', '_sgpu_client_call'):
            if pc == self.vm.codes[name].entry:
                _require(self.locked, 'client entry outside mutex')
                _require(integer(state, 'x0') == self.client and integer(state, 'x1') == self.q,
                         'client is not bound to owned global queue/storage')

    def external(self, target, state, probe=False, before=None):
        name = self.vm.by_address.get(target)
        allowed = ('_bzero', '_memcpy', '_kauth_cred_get', '_kauth_cred_issuser',
            '_current_task', '_task_reference_grp', '_task_deallocate_grp',
            '_lck_mtx_lock', '_lck_mtx_unlock', '_thread_wakeup_prim',
            '_cdevsw_add', '_devfs_make_node', '_printf')
        if name not in allowed: return False
        if probe: return True
        self.calls.append(name)
        arg = lambda i: integer(before, 'x' + str(i))
        put = lambda value, bits=64: state.put('x0' if bits == 64 else 'w0', self.e._Value(bits, value))
        if name in ('_bzero', '_memcpy'):
            length = arg(1 if name == '_bzero' else 2)
            _require(length <= 3056, 'unbounded CPU copy')
            self.m.write(arg(0), bytes(length) if name == '_bzero' else
                         self.m.bytes(arg(1), length, partial=True))
            put(arg(0))
        elif name == '_kauth_cred_get':
            _require(not self.locked, 'credential lookup under mutex')
            put(self.CRED)
        elif name == '_kauth_cred_issuser':
            _require(arg(0) == self.CRED and not self.locked, 'root credential contract')
            put(int(self.root), 32)
        elif name == '_current_task':
            _require(not self.locked, 'task lookup under mutex')
            put(self.task)
        elif name in ('_task_reference_grp', '_task_deallocate_grp'):
            _require(not self.locked and arg(0) == self.task and arg(1) == 0,
                     'task reference ABI/order')
            self.refs += 1 if name == '_task_reference_grp' else -1
            _require(self.refs >= 0, 'task reference underflow')
        elif name == '_lck_mtx_lock':
            _require(arg(0) == self.lock and not self.locked, 'wrong/reentrant mutex')
            self.locked = True
            if self.lock_injection:
                self.lock_injection(self)
        elif name == '_lck_mtx_unlock':
            _require(arg(0) == self.lock and self.locked, 'wrong/unbalanced unlock')
            self.locked = False
        elif name == '_thread_wakeup_prim':
            _require(not self.locked and (arg(0), arg(1), arg(2)) == (self.event, 0, 0),
                     'wakeup ABI/order')
            self.wakeups += 1
            put(0, 32)
        elif name == '_cdevsw_add':
            _require(not self.locked and arg(0) & 0xffffffff == 0xffffffff and
                     arg(1) == self.storage['_sgpu_user_cdevsw'], 'cdevsw registration ABI')
            put(self.add_major, 32)
        elif name == '_devfs_make_node':
            _require(not self.locked and tuple(arg(i) for i in range(5)) ==
                     ((self.add_major << 24) & 0xffffffff, 0, 0, 0, 0o600),
                     'device namespace/UID/GID/permissions differ')
            _require(self.vm.image.read(arg(5), 10) == int.from_bytes(b'santonigpu\0', 'little'),
                     'device literal differs')
            put(self.node)
        elif name == '_printf':
            _require(not self.locked, 'publication print under mutex')
            literal = b'SANTONI GPU: USER ready /dev/santonigpu; root, one task, WRITE4; no user DMA maps; NO UI\n\0'
            _require(self.vm.image.read(arg(0), len(literal)) == int.from_bytes(literal, 'little'),
                     'unreviewed publication print')
            put(0, 32)
        return True

    def setup(self, address, value, size=4):
        hook, readonly = self.m.write_hook, self.m.readonly
        self.m.write_hook, self.m.readonly = None, []
        try: self.m.put(address, value, size)
        finally: self.m.write_hook, self.m.readonly = hook, readonly

    def packet(self, id=0, values=None):
        hook = self.m.write_hook
        self.m.write_hook = None
        try:
            self.m.write(self.PACKET, bytes(128))
            self.m.put(self.PACKET, 1)
            self.m.put(self.PACKET + 4, 128)
            self.m.put(self.PACKET + 8, id)
            if values is not None:
                self.m.write(self.PACKET + 16, struct.pack('<4I', *values))
        finally: self.m.write_hook = hook

    def call(self, name, *args):
        value = self.vm.run(name, args)
        _require(not self.locked, 'wrapper returns holding mutex')
        return None if value is None else value.expr

    def core_call(self, name, *args):
        _require(not self.locked, 'nested modeled core caller')
        self.locked = True
        try:
            value = self.vm.run(name, args)
            return None if value is None else value.expr
        finally: self.locked = False

    def open(self):
        return self.call('_sgpu_user_open', 42 << 24, 0, 0, 0)

    def ioctl(self, command, dev=None, data=None):
        return self.call('_sgpu_user_ioctl', 42 << 24 if dev is None else dev,
                         command, self.PACKET if data is None else data, 0, 0)


def audit_scalar_boundaries(codes, image, names, e, components=('open', 'device_command',
        'packet', 'transactions', 'snapshots', 'publication'), record=None):
    """Return component evidence only; never authorize a boot role here."""
    storage = scalar_storage(image, names)
    executed, counts = set(), {}
    def model(): return ScalarModel(codes, image, names, e, storage)
    def done(label, m):
        executed.update(m.vm.visited)
        counts[label] = counts.get(label, 0) + 1

    def open():
        # Every admission condition and a publication race; no failed open retains
        # a reference or modifies queue/client. Boolean source fields use 0/1.
        variants = [('ready', None, 0, 0)]
        variants += [(label, address, value, size) for label, address, value, size in (
            ('user0', storage['_sg'] + 108, 0, 4), ('user2', storage['_sg'] + 108, 2, 4),
            ('preflight', storage['_sg'] + 112, 1, 4), ('unpublished', storage['_sgpu_user_published'], 0, 1),
            ('uninitialized', storage['_session_queue'], 0, 1),
            ('admitted', storage['_session_queue'] + 12, 1, 4),
            ('outstanding', storage['_session_queue'] + 16, 1, 4),
            ('active', storage['_session_queue'] + 20, 1, 4),
            ('attempted', storage['_sgpu_user_client'] + 8, 1, 1),
            ('closed', storage['_sgpu_user_client'] + 9, 1, 1),
            ('owner', storage['_sgpu_user_client'], ScalarModel.OTHER_TASK, 8))]
        variants += [('state' + str(s), storage['_session_queue'] + 4, s, 4) for s in (0, 2, 3, 4, 5)]
        for label, address, value, size in variants:
            m = model()
            if address is not None: m.setup(address, value, size)
            before = m.m.bytes(m.client, 16), m.m.bytes(m.q, 3056)
            expected = 0 if label == 'ready' else 6 if label.startswith('user') else 16
            _require(m.open() == expected, 'open denial ' + label)
            _require(m.refs == int(label == 'ready'), 'open reference balance ' + label)
            if label != 'ready':
                _require(before == (m.m.bytes(m.client, 16), m.m.bytes(m.q, 3056)),
                         'rejected open mutates CPU state ' + label)
            else:
                _require(m.m.get(m.client, 8) == m.TASK and m.m.get(m.client + 8, 1) == 1,
                         'accepted owner identity differs')
                _require(m.open() == 16 and m.refs == 1, 'second open retains another task')
            done('open', m)
        for task, root, expected in ((ScalarModel.TASK, False, 13), (0, True, 13)):
            m = model(); m.task, m.root = task, root
            _require(m.open() == expected and m.refs == 0, 'credential/null-task admission')
            done('open', m)
        m = model()
        m.lock_injection = lambda m: m.setup(m.published, 0, 1)
        _require(m.open() == 16 and m.refs == 0, 'publication race retains owner')
        done('open', m)


    def device_command():
        # Full-width device/command rejection before any task/lock/core operation.
        for boundary in ('_sgpu_user_open', '_sgpu_user_close', '_sgpu_user_ioctl'):
            for dev in ((42 << 24) | 1, 43 << 24, 0xffffffff):
                m = model(); m.packet()
                _require(m.call(boundary, dev, COMMANDS[0], m.PACKET, 0, 0) == 6 and not m.calls,
                         'bad device reaches external work')
                done('device', m)
        for command, data in [(c, ScalarModel.PACKET) for c in
                (0, COMMANDS[0] - 1, COMMANDS[-1] + 1, COMMANDS[0] | (1 << 32), 0xffffffffffffffff)] + [(COMMANDS[0], 0)]:
            m = model(); m.packet()
            _require(m.ioctl(command, data=data) == 22 and not m.calls,
                     'invalid full-width command/null data reaches core')
            done('command', m)


    def packet():
        # Independently perturb every reserved input byte, including bytes in the
        # vectorized/unrolled tail. Allowed SUBMIT values are arbitrary uint32s.
        m = model()
        for command in COMMANDS:
            for offset in range(12, 128):
                m.packet(id=1 if command == COMMANDS[2] else 0)
                m.setup(m.PACKET + offset, 0xa5, 1)
                before = m.m.bytes(m.PACKET, 128)
                valid = command == COMMANDS[1] and 16 <= offset < 32
                got = m.call('_sgpu_client_packet_valid', command, m.PACKET)
                _require(got == int(valid) and m.m.bytes(m.PACKET, 128) == before,
                         'reserved byte validation differs at ' + str(offset))
                done('packet_byte', m)
            for offset, values in ((0, (0, 2, 0xffffffff)), (4, (0, 127, 129, 0xffffffff)),
                                   (8, (0, 1, 32, 33, 0xffffffff))):
                for value in values:
                    m.packet(id=1 if command == COMMANDS[2] else 0)
                    m.setup(m.PACKET + offset, value)
                    valid = offset == 8 and (1 <= value <= 32 if command == COMMANDS[2] else value == 0)
                    _require(m.call('_sgpu_client_packet_valid', command, m.PACKET) == int(valid),
                             'version/size/id validation differs')
                    done('packet_header', m)
        _require(m.call('_sgpu_client_packet_valid', COMMANDS[0], 0) == 0, 'null packet accepted')
        done('packet_header', m)


    def transactions():
        m = model(); _require(m.open() == 0, 'normal scalar open')
        for task in (0, m.OTHER_TASK):
            m.task = task; m.packet()
            before = m.m.bytes(m.PACKET, 128), m.m.bytes(m.q, 3056)
            _require(m.ioctl(COMMANDS[0]) == 13 and before ==
                     (m.m.bytes(m.PACKET, 128), m.m.bytes(m.q, 3056)), 'owner denial changes packet/queue')
            done('owner', m)
        m.task = m.TASK
        for i in range(4):
            values = (0xffffffff, 0x80000000, i, 0xa5051234)
            m.packet(values=values)
            _require(m.ioctl(COMMANDS[1]) == 0 and m.m.get(m.PACKET + 12) == 0 and
                     m.m.get(m.PACKET + 8) == i + 1, 'scalar enqueue/id')
            _require(m.m.bytes(m.q + 112 + i * 92, 16) == struct.pack('<4I', *values),
                     'four values not copied into owned queue')
            reply = struct.unpack('<32I', m.m.bytes(m.PACKET, 128))
            _require(reply[:2] == (1, 128) and reply[4:8] == (0, 0, 0, 0) and
                     reply[23] == 0x13579 and reply[24:] == (0,) * 8, 'submit reply exposes private/input data')
            m.packet()  # caller changes its buffer after SUBMIT; queue must keep copy
            _require(m.m.bytes(m.q + 112 + i * 92, 16) == struct.pack('<4I', *values),
                     'queue aliases mutable caller packet')
            done('submit_copy', m)
        m.packet(values=(1, 2, 3, 4))
        _require(m.ioctl(COMMANDS[1]) == 0 and m.m.get(m.PACKET + 12) == 3,
                 'fifth outstanding request accepted')
        _require(m.call('_sgpu_user_close', 42 << 24, 0, 0, 0) == 0 and m.refs == 1 and
                 m.m.get(m.client, 8) == m.TASK and m.m.get(m.client + 9, 1) == 1,
                 'last-fd close frees/rebinds task')
        m.packet(values=(1, 2, 3, 4))
        _require(m.ioctl(COMMANDS[1]) == 0 and m.m.get(m.PACKET + 12) == 5,
                 'closed client submits new work')
        _require(m.open() == 16 and m.refs == 1, 'close permits reopening')
        done('close', m)


    def snapshots():
        # Seed an address-like raw failure and compare all128 public reply bytes.
        # Result/error/status are modeled CPU inputs, never a GPU pass.
        for command in (COMMANDS[0], COMMANDS[2]):
            m = model(); _require(m.open() == 0, 'snapshot open')
            for off in range(15): m.setup(m.q + 4 + off * 4, off + 1)
            m.setup(m.q + 12, 32)
            slot = m.q + 112 + 31 * 92 + 16
            for off in range(76): m.setup(slot + off, 0xa5, 1)
            public = (4, 34, 522, 4, 16, 12)
            for i, value in enumerate(public): m.setup(slot + i * 4, value)
            m.setup(slot + 24, 1, 1)
            m.packet(id=32 if command == COMMANDS[2] else 0)
            _require(m.ioctl(command) == 0, 'snapshot rejected')
            status = list(range(1, 16)); status[2] = 32
            expected = [1, 128, 32 if command == COMMANDS[2] else 0, 0, 0, 0, 0, 0,
                        *status, 0x13579, *(public + (1, 0) if command == COMMANDS[2] else (0,) * 8)]
            _require(m.m.bytes(m.PACKET, 128) == struct.pack('<32I', *expected),
                     'snapshot does not sanitize complete public packet')
            done('sanitized_snapshot', m)


    def publication():
        # Publication successes/failures leave the registration owned until reboot.
        for user, prior_major, added, node in ((0, -1, 42, 1), (2, -1, 42, 1),
                (1, 42, 42, 1), (1, -1, -1, 1), (1, -1, 42, 0), (1, -1, 42, 1)):
            m = model(); m.setup(m.sg + 108, user); m.setup(m.major, prior_major)
            m.setup(m.published, 0, 1); m.add_major, m.node = added, node
            expected = user == 1 and prior_major < 0 and added >= 0 and node != 0
            _require(m.call('_sgpu_user_publish') == int(expected) and
                     m.m.get(m.published, 1) == int(expected), 'publication failure/flag')
            registered = user == 1 and prior_major < 0 and added >= 0
            _require(m.m.get(m.major) == ((added if registered else prior_major) & 0xffffffff),
                     'registration not retained after node failure')
            done('publication', m)
    actions = {'open': open, 'device_command': device_command, 'packet': packet,
               'transactions': transactions, 'snapshots': snapshots, 'publication': publication}
    for component in components:
        _require(component in actions, 'unknown boundary component ' + component)
        old_counts = dict(counts)
        actions[component]()
        if record:
            record(component, {'cases': {k: v - old_counts.get(k, 0) for k, v in counts.items()
                                       if v != old_counts.get(k, 0)},
                               'executed_instruction_addresses': len(executed), 'success': True,
                               'hardware_verified': False, 'client_path_certified': False})
    return {'cases': counts, 'executed_instruction_addresses': len(executed),
            'cdevsw_namespace_checked': True,
            'owner_reference_and_mutex_checked': 'open' in components,
            'fixed_packet_copy_and_sanitization_checked':
                {'packet', 'transactions', 'snapshots'} <= set(components),
            'scope': 'linked CPU boundaries with injected XNU credentials/tasks; no syscall or GPU proof',
            'client_path_certified': False, 'preflight_path_certified': False,
            'hardware_verified': False}


def scalar_option_wiring(code, image, names, e, sg, modes=(1,), disabled_only=False):
    """Prove exact default-off options over decoded instructions.

    Offsets are expectations from0207's source layout. The decoded loads/stores
    and every return must establish them; a host layout alone cannot certify it.
    The default mode1 scope proves exclusion only, not the enabled client path.
    """
    from santoni_gpu_stock_audit import _single_return
    if type(disabled_only) is not bool:
        raise ValueError('scalar exclusion scope must be an explicit boolean')
    option_values=(None,0) if disabled_only else (None,0,1,2,0xffffffff)
    V, at = e._Value, e._scm_at
    if code.symbol == '_sgpu_user_options':
        literal, field, parents = b'santonigpu_user\0', 108, (88, 96, 100, 104)
    elif code.symbol == '_sgpu_user_test_options':
        literal, field, parents = b'santonigpu_user_test\0', 112, (88, 96, 100, 104, 108)
    else:
        raise ValueError('unexpected scalar option boundary')
    calls = code.calls_to(names.get('_PE_parse_boot_argn', ()))
    if len(calls) != 1:
        raise ValueError('scalar option parser missing or repeated')
    parsed, count = calls[0], 0
    for mode, values, option in product(modes, product((0, 1, 2, 0xffffffff), repeat=len(parents)),
                                        option_values):
        initial = e._initial(code.symbol)
        initial.put('w0', V(32, mode))
        for offset, value in zip(parents, values):
            initial.store(at(sg, offset), 4, V(32, value))
        initial.store(at(sg, field), 4, V(32, 0xffffffff))

        def parse(after, before):
            address, dest = before.get('x0'), before.get('x1')
            if (address is None or not isinstance(address.expr, int) or
                    image.read(address.expr, len(literal)) != int.from_bytes(literal, 'little') or
                    before.get('x2') != V(64, 4) or dest is None or
                    not isinstance(dest.expr, tuple) or dest.expr[0] != 'stack' or
                    before.load(dest, 4, image) != V(32, 0)):
                raise ValueError('scalar option literal/width/default differs')
            after.store(dest, 4, V(32, option or 0))
            after.put('w0', V(32, int(option is not None)))

        flow = e._Flow(code, image, names, initial=initial, effects={parsed: parse})
        enabled = mode == 3 and option == 1 and all(value == 1 for value in values)
        if parsed not in flow.before or _single_return(flow, e) != V(32, int(not option or enabled)):
            raise ValueError('scalar option mode/prerequisite permission bypass')
        for pc, state in flow.before.items():
            op, args = code.ins[pc]
            if op in ('bl', 'blr', 'br') or op == 'b' and e._number(args[-1]) not in code.ins:
                target = flow.call(pc, state)
                if pc in code.noreturn and target in names.get('___stack_chk_fail', ()):
                    continue
                if pc != parsed:
                    raise ValueError('scalar option invokes an unreviewed operation')
            if op.startswith(('str', 'stur')) or op == 'stp':
                dest, _ = state.address(args[2 if op == 'stp' else 1])
                if dest is None:
                    raise ValueError('scalar option store address is unresolved')
                stack = isinstance(dest.expr, tuple) and dest.expr[0] == 'stack'
                width = (1 if op.endswith('b') else 2 if op.endswith('h') else
                         e._Flow.code_width(args[0]) // 8) * (2 if op == 'stp' else 1)
                if not stack and (dest != at(sg, field) or width != 4):
                    raise ValueError('scalar option writes outside its owned flag')
            if op == 'ret':
                if state.load(at(sg, field), 4, image) != V(32, int(enabled)):
                    raise ValueError('scalar option flag is not reset/exactly enabled')
                if any(state.load(at(sg, offset), 4, image) != V(32, value)
                       for offset, value in zip(parents, values)):
                    raise ValueError('scalar option changes its prerequisite fields')
        count += 1
    return {'cases': count, 'modes': list(modes), 'flag_offset': field,
            'default_off_checked': True, 'disabled_only': disabled_only, 'client_path_certified': False,
            'hardware_verified': False}


def load_saved_boundaries(folder, extra=()):
    """Load new-proof inputs, binding each saved decoded word to kernel bytes.

    This consumes the recorded mode1 certificate; it never repeats that audit.
    The caller must record component results separately from the boot gate.
    """
    import hashlib
    import json
    import re
    import check_santoni_gpu_kernel as e
    data = (folder / 'kernel/kernel.development.santoni').read_bytes()
    certificate = json.loads((folder / 'gpu-binary-audit.json').read_text())
    run = json.loads((folder / 'run.json').read_text())
    digest = hashlib.sha256(data).hexdigest()
    _require(certificate.get('kernel_sha256') == digest and
             certificate.get('commit') == run.get('headSha') and
             run.get('status') == 'completed' and run.get('conclusion') == 'success' and
             run.get('repository_private') is True, 'component input identity differs from recorded evidence')
    names = e._symbols((folder / 'kernel.symbols.txt').read_text())
    image = e._Image(data)
    noreturn = e._stack_failure_terminal(names)[0] | names.get('_panic', set()) | names.get('_Assert', set())
    codes = {}
    for name in (*USER_BOUNDARIES, *QUEUE_NAMES, *extra):
        _require(len(names.get(name, ())) == 1, 'missing/ambiguous decoded input ' + name)
        text = (folder / (name[1:] + '.asm')).read_text()
        code = e._Code(text, name, next(iter(names[name])), noreturn=noreturn)
        bound = set()
        for line in text.splitlines():
            match = re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s', line)
            if match and int(match[1], 16) in code.ins:
                pc = int(match[1], 16)
                _require(image.read(pc, 4) == int(match[2], 16), 'saved decode differs from linked bytes ' + name)
                bound.add(pc)
        _require(bound == set(code.ins), 'saved decode has unbound instructions ' + name)
        codes[name] = code
    return codes, image, names, e, {'commit': run['headSha'], 'kernel_sha256': digest,
                                  'ci_run': run['databaseId']}


def main():
    import argparse
    import hashlib
    import json
    from datetime import datetime, timezone
    from pathlib import Path
    import traceback
    parser = argparse.ArgumentParser(description='New scalar boundary components; does not issue a boot gate')
    parser.add_argument('evidence', type=Path, help='existing out/ci-<commit> directory')
    parser.add_argument('--components', nargs='+', default=['open', 'device_command', 'packet',
                        'transactions', 'snapshots', 'publication'])
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    output = args.evidence / ('scalar-boundary-attempt-' + stamp)
    output.mkdir()
    try:
        codes, image, names, e, identity = load_saved_boundaries(args.evidence)
        def record(name, result):
            result.update(identity)
            (output / (name + '.json')).write_text(json.dumps(result, indent=2) + '\n')
        result = audit_scalar_boundaries(codes, image, names, e, args.components, record)
        result.update(identity, success=True)
    except Exception as error:
        result = {'success': False, 'error': str(error)}
        (output / 'traceback.txt').write_text(traceback.format_exc())
    result['components_requested'] = args.components
    result['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'evidence': str(output), 'result': result}, indent=2))
    return 0 if result['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
