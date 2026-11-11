"""Decoded session storage/ABI checks plus bounded linked-instruction replays.

The enclosing auditor also requires every legacy/ISA/CI identity gate. Modeled
callback results and deterministic schedules are not hardware/scheduler proof.
"""
from itertools import product

# Host layout of reconstructed 0206's standard-width portable types. These are
# expectations, not a discovered Darwin ABI: linked instruction checks must
# establish each argument/storage use before this layout can certify anything.
CORE_OFFSETS = {'ops': 8, 'probe': 128, 'arena': 872, 'startup': 1776, 'wptr': 2236}
CORE_BYTES = 2272


def session_start_storage(code, image, names, e):
    """Check one-shot opt-ins, Ops copy and stable bootstrap argument addresses.

    Stops at the bootstrap call. Readiness, report rebinding, lifetime of the
    adapter's callbacks and subsequent GPU work require separate checks.
    """
    V, at = e._Value, e._scm_at
    for name in ('_session_core', '_sgpu_bootstrap'):
        if len(names.get(name, ())) != 1:
            raise ValueError('missing/ambiguous session storage identity: ' + name)
    core = V(64, next(iter(names['_session_core'])))
    # The final object must lie wholly in one writable, non-executable segment.
    segments = [s for s in image.segs if s['vmaddr'] <= core.expr and
                core.expr + CORE_BYTES <= s['vmaddr'] + s['vmsize']]
    if len(segments) != 1 or (segments[0].get('initprot', 0) & 7) != 3:
        raise ValueError('session core is not stable writable non-executable storage')
    bootstrap = code.calls_to(names['_sgpu_bootstrap'])
    if len(bootstrap) != 1:
        raise ValueError('session bootstrap boundary missing/repeated')
    stop = bootstrap[0]
    count = 0
    # Full option product; missing pointers and repeat start are additional
    # independent negatives against otherwise valid arguments.
    cases = [(mode, stock, pixels, g3, opt, False, True, True)
             for mode, stock, pixels, g3, opt in product(
                 (0, 1, 2, 3, 4, 0xffffffff), *(4 * ((0, 1, 2, 0xffffffff),)))]
    cases += [(3, 1, 1, 1, 1, attempted, ops, out)
              for attempted, ops, out in product((False, True), repeat=3)]
    for mode, stock, pixels, g3, opt, attempted, have_ops, have_out in cases:
        state = e._initial(code.symbol)
        ops = V(64, ('ops', 0)) if have_ops else V(64, 0)
        out = V(64, ('report', 0)) if have_out else V(64, 0)
        state.put('x0', ops)
        state.put('w1', V(32, mode))
        state.put('x4', out)
        state.store(core, 1, V(8, int(attempted)))
        # Concrete callback-table bytes avoid inventing any unknown vector lane.
        # _State's symbolic Ops loads define callback provenance; a separate
        # source object here permits testing vector copies of arbitrary pointers.
        if have_ops:
            ops = V(64, 0x60000000)
            state.put('x0', ops)
            for i in range(13):
                state.store(at(ops, i * 8), 8, V(64, 0x12340000 + i * 256))
            for offset, val in ((104, stock), (108, pixels), (112, g3), (116, opt)):
                state.store(at(ops, offset), 4, V(32, val))
        flow = e._Flow(code, image, names, initial=state, stops=(stop,))
        enabled = have_ops and have_out and not attempted and mode == 3 and stock == pixels == g3 == opt == 1
        if (stop in flow.before) != enabled:
            raise ValueError('session start bypasses one-shot/exact opt-ins/pointer checks')
        if enabled:
            incoming = flow.before[stop]
            arguments = {0: at(core, CORE_OFFSETS['ops']), 1: V(64, 3),
                         2: state.get('x2'), 3: state.get('x3'),
                         4: at(core, CORE_OFFSETS['startup']), 5: at(core, CORE_OFFSETS['probe']),
                         6: at(core, CORE_OFFSETS['arena']), 7: at(core, CORE_OFFSETS['wptr'])}
            if any(incoming.get('x' + str(i)) != want for i, want in arguments.items()):
                raise ValueError('session bootstrap retains caller/stack storage or changes input ABI')
            if incoming.load(core, 1, image) != V(8, 1):
                raise ValueError('session attempt is not latched before bootstrap')
            for offset, size in [(i * 8, 8) for i in range(13)] + [(i, 4) for i in (104, 108, 112, 116)]:
                if incoming.load(at(core, CORE_OFFSETS['ops'] + offset), size, image) != state.load(at(ops, offset), size, image):
                    raise ValueError('session Ops copy loses callback/context/option bytes')
        elif not flow.returns(0):
            raise ValueError('invalid session start does not return false')
        for pc in flow.before:
            op, args = code.ins[pc]
            if pc == stop:
                continue
            if op.startswith(('str', 'stur')) or op == 'stp':
                dest, _ = flow.before[pc].address(args[2 if op == 'stp' else 1])
                if dest is None:
                    raise ValueError('unresolved store before session bootstrap')
                if not (isinstance(dest.expr, tuple) and dest.expr[0] == 'stack'):
                    width = (1 if op.endswith('b') else 2 if op.endswith('h') else
                             e._Flow.code_width(args[0]) // 8) * (2 if op == 'stp' else 1)
                    if (not enabled or not isinstance(dest.expr, int) or
                            not core.expr <= dest.expr or dest.expr + width > core.expr + CORE_BYTES):
                        raise ValueError('session start writes outside owned storage/before admission')
            if op in ('bl', 'blr', 'br') or op == 'b' and e._number(args[-1]) not in code.ins:
                target = flow.call(pc, flow.before[pc])
                if pc in code.noreturn and target in names.get('___stack_chk_fail', ()):
                    continue  # enclosing loader verifies the actual noreturn panic stub
                if target not in names.get('_memcpy', ()):
                    raise ValueError('unexpected operation before session bootstrap')
                if not enabled:
                    raise ValueError('invalid session start changes storage')
                call = flow.before[pc]
                if (call.get('x0') != at(core, CORE_OFFSETS['ops']) or
                        call.get('x1') != ops or call.get('x2') != V(64, 120)):
                    raise ValueError('session startup memcpy escapes the owned Ops copy')
        count += 1
    return {'start_cases': count, 'stable_bootstrap_arguments': True,
            'readiness_checked': False, 'hardware_verified': False}


def session_options(code, image, names, e, sg):
    """Check default-off parsing and exact mode/stock/pixel/G3 prerequisites."""
    from santoni_gpu_stock_audit import _single_return
    V, at = e._Value, e._scm_at
    calls = code.calls_to(names.get('_PE_parse_boot_argn', ()))
    if len(calls) != 1:
        raise ValueError('session option parser missing or repeated')
    parsed = calls[0]
    count = 0
    for mode, stock, pixels, g3, option in product(
            (0, 1, 2, 3, 4, 0xffffffff), (0, 1, 2, 0xffffffff),
            (0, 1, 2, 0xffffffff), (0, 1, 2, 0xffffffff),
            (None, 0, 1, 2, 0xffffffff)):
        state = e._initial(code.symbol)
        state.put('w0', V(32, mode))
        for offset, value in ((88, stock), (96, pixels), (100, g3), (104, 99)):
            state.store(at(sg, offset), 4, V(32, value))

        def parse(after, before):
            literal = b'santonigpu_session\0'
            address, dest = before.get('x0'), before.get('x1')
            if (address is None or not isinstance(address.expr, int) or
                    image.read(address.expr, len(literal)) != int.from_bytes(literal, 'little') or
                    before.get('x2') != V(64, 4) or dest is None or
                    not isinstance(dest.expr, tuple) or dest.expr[0] != 'stack' or
                    before.load(dest, 4, image) != V(32, 0)):
                raise ValueError('session parser literal/width/default storage differs')
            after.store(dest, 4, V(32, option or 0))
            after.put('w0', V(32, int(option is not None)))

        flow = e._Flow(code, image, names, initial=state, effects={parsed: parse})
        enabled = mode == 3 and stock == pixels == g3 == option == 1
        if parsed not in flow.before or _single_return(flow, e) != V(32, int(not option or enabled)):
            raise ValueError('session option permission bypass')
        for pc, incoming in flow.before.items():
            op, args = code.ins[pc]
            if op in ('bl', 'blr', 'br') or op == 'b' and e._number(args[-1]) not in code.ins:
                if pc != parsed:
                    raise ValueError('unexpected session option callee')
            if op == 'ret':
                if incoming.load(at(sg, 104), 4, image) != V(32, int(enabled)):
                    raise ValueError('session option was not reset/exactly enabled')
                for offset, value in ((88, stock), (96, pixels), (100, g3)):
                    if incoming.load(at(sg, offset), 4, image) != V(32, value):
                        raise ValueError('session parser changes prerequisite options')
        count += 1
    return count


def session_lock_wiring(code, image, names, e):
    """Check helper lock scope and XNU wait ABI on every decoded CFG path.

    XNU8796 kern/sched_prim.h: thread_wakeup(x) expands to
    thread_wakeup_prim(x, FALSE, THREAD_AWAKENED). THREAD_UNINT and
    THREAD_AWAKENED are zero; kern/kern_types.h defines THREAD_WAITING as -1.
    Its decoded 32-bit representation is 0xffffffff. Host pthread shims
    cannot establish this ABI. This component does not prove queue contents,
    commitment, thread-start success handling or actual scheduler progress.
    """
    V = e._Value
    producer = code.symbol == '_sgpu_session_producer'
    if code.symbol not in ('_sgpu_session_producer', '_sgpu_session_loop'):
        raise ValueError('unexpected session lock-audit root')

    def address(name):
        values = names.get(name, ())
        if len(values) != 1:
            raise ValueError('missing/ambiguous session ABI identity: ' + name)
        return next(iter(values))

    lock, queue, event = (V(64, address(name)) for name in
                          ('_sgpu_session_lock', '_session_queue', '_session_queue_event'))
    # sg.wait_channel at +92 is used by hardware-delay waits, never queue waits.
    if event == V(64, address('_sg') + 92):
        raise ValueError('queue and hardware-delay events alias')
    queue_calls = ('_sgpu_session_enqueue', '_sgpu_session_close') if producer else (
        '_sgpu_session_queue_init', '_sgpu_session_take', '_sgpu_session_commit',
        '_sgpu_session_finish', '_sgpu_session_fault_pending')
    unlocked = ('_printf', '_thread_terminate_self', '_now_us', '_sgpu_kernel_wait_us',
                '_mach_absolute_time', '_absolutetime_to_nanoseconds', '_clock_interval_to_deadline') if producer else (
        '_printf', '_kernel_thread_start', '_thread_deallocate', '_sgpu_session_prepare',
        '_sgpu_session_execute', '_sgpu_session_failure_result', '_sgpu_session_stop',
        '_sgpu_failure_summary', '_bzero', '_memcpy')
    if producer and '_sgpu_user_publish' in names:
        # The scalar producer-prefix/publication/preflight components check
        # their bodies and exact opt-ins separately. Here prove unlocked calls.
        unlocked += ('_sgpu_user_publish', '_sgpu_user_preflight')
    special = ('_lck_mtx_lock', '_lck_mtx_unlock', '_thread_wakeup_prim',
               '_assert_wait_deadline', '_thread_block') if producer else (
        '_lck_mtx_lock', '_lck_mtx_unlock', '_assert_wait', '_thread_block')
    allowed = {address(name): name for name in (*queue_calls, *unlocked, *special) if name in names}
    if len(allowed) != sum(name in names for name in (*queue_calls, *unlocked, *special)):
        raise ValueError('aliased session call identities')
    flow = e._Flow(code, image, names)
    calls = {}
    for pc, state in flow.before.items():
        op, args = code.ins[pc]
        if op in ('bl', 'blr', 'br') or op == 'b' and e._number(args[-1]) not in code.ins:
            target = flow.call(pc, state)
            if pc in code.noreturn and target in names.get('___stack_chk_fail', ()):
                calls[pc] = 'verified_stack_failure'
                continue
            if target not in allowed:
                raise ValueError('unreviewed session adapter call')
            calls[pc] = allowed[target]
    required = set(queue_calls) | {'_lck_mtx_lock', '_lck_mtx_unlock'}
    required |= {'_thread_wakeup_prim'} if producer else {'_assert_wait', '_thread_block'}
    if not required <= set(calls.values()):
        raise ValueError('session synchronization helper missing')
    # A returning assert_wait may report already awakened. Only THREAD_WAITING
    # permits thread_block; stop analysis at the next lock/predicate iteration.
    for pc, call in calls.items():
        if call != '_assert_wait':
            continue
        for result in (0, 1, 2, 3, 0xffffffff):
            state = flow.step(pc, flow.before[pc].copy())
            state.put('w0', V(32, result))
            after = e._Flow(code, image, names, pc + 4, state,
                            stops=tuple(q for q, name in calls.items() if name == '_lck_mtx_lock'))
            blocks = [q for q in after.before if calls.get(q) == '_thread_block']
            if len(blocks) != int(result == 0xffffffff):
                raise ValueError('queue block ignores assert_wait THREAD_WAITING result')
    pending, seen = [(code.entry, False, False)], set()
    while pending:
        pc, held, registered = pending.pop()
        item = (pc, held, registered)
        if item in seen:
            continue
        seen.add(item)
        if len(seen) > 40000:
            raise ValueError('session synchronization analysis exceeded bound')
        state, call = flow.before.get(pc), calls.get(pc)
        if state is None:
            continue
        if call in ('_lck_mtx_lock', '_lck_mtx_unlock'):
            if state.get('x0') != lock or held != (call == '_lck_mtx_unlock'):
                raise ValueError('session mutex identity/balance differs')
            held = call == '_lck_mtx_lock'
            if held:
                registered = False
        elif call in queue_calls:
            if not held or state.get('x0') != queue:
                raise ValueError('session queue helper outside its mutex/object')
        elif call == '_assert_wait':
            if not held or registered or state.get('x0') != event or state.get('w1') != V(32, 0):
                raise ValueError('queue wait registration must hold its mutex and use THREAD_UNINT')
            registered = True
        elif call == '_assert_wait_deadline':
            if not producer or held or state.get('x0') != V(64, address('_sg') + 92) or state.get('w1') != V(32, 0):
                raise ValueError('producer delay wait identity/lock/THREAD_UNINT differs')
            registered = True
        elif call == '_thread_block':
            if held or not registered or state.get('x0') != V(64, 0):
                raise ValueError('queue block before registration/unlock or nonnull continuation')
            registered = False
        elif call == '_thread_wakeup_prim':
            if (held or state.get('x0') != event or state.get('w1') != V(32, 0) or
                    state.get('w2') != V(32, 0)):
                raise ValueError('queue wake event/all/THREAD_AWAKENED ABI differs')
        elif call in unlocked and held:
            raise ValueError('session callback/operation under queue mutex')
        if call == '_clock_interval_to_deadline':
            if state.get('w0') != V(32, 10000) or state.get('w1') != V(32, 1000):
                raise ValueError('producer delay interval or time unit differs')
        if not code.succ[pc] and held:
            raise ValueError('session exits while holding queue mutex')
        pending.extend((n, held, registered) for n in code.succ[pc])
    return {'calls_checked': len(calls), 'lock_paths_checked': len(seen),
            'queue_event_distinct': True, 'hardware_or_scheduler_verified': False}


def session_bootstrap_storage(codes, image, names, e):
    """Bind the shared bootstrap to its caller's final storage, including WPTR.

    The legacy auditor checks hardware helpers and failure edges. Here concrete
    addresses avoid the general model's implicit ('probe',0) pointer aliases.
    The modeled G3 return is used only to examine the post-G3 HELD suffix.
    """
    V, at = e._Value, e._scm_at
    base = next(iter(names['_session_core']))
    ops, p, g, report, end = (V(64, base + CORE_OFFSETS[n]) for n in
                            ('ops', 'probe', 'arena', 'startup', 'wptr'))
    initial = e._initial('_sgpu_bootstrap')
    for reg, val in ((0, ops), (1, V(64, 3)), (4, report), (5, p), (6, g), (7, end)):
        initial.put('x' + str(reg), val)
    initial.store(ops, 8, V(64, 0))
    for off, name in e._CALLBACKS.items():
        initial.store(at(ops, off), 8, V(64, next(iter(names[name]))))
    for off in (104, 108, 112, 116): initial.store(at(ops, off), 4, V(32, 1))
    code = codes['_sgpu_bootstrap']; flow = e._Flow(code, image, names, initial=initial)
    expected = {'_sgpu_g3_prepare': {0: p, 1: g}, '_sgpu_power': {0: p},
                '_sgpu_smmu_start': {0: p}, '_marker_test': {0: p},
                '_sgpu_stock_transition': {0: p, 1: V(64, 3)},
                '_sgpu_stock_pixels_test': {0: p, 1: V(64, 3)},
                '_sgpu_g3_test': {0: p, 1: g, 2: V(64, 3)}}
    calls = {}
    for name, regs in expected.items():
        sites = code.calls_to(names[name], flow.before)
        if len(sites) != 1: raise ValueError('shared bootstrap boundary missing/repeated: ' + name)
        incoming = flow.before[sites[0]]; calls[name] = sites[0]
        if any(incoming.get('x' + str(i)) != want for i, want in regs.items()):
            raise ValueError('shared bootstrap loses final pointer/mode: ' + name)
        if incoming.load(p, 8, image) != ops or incoming.load(at(p, 8), 8, image) != report:
            raise ValueError('shared bootstrap fails to bind stable Ops/report')
    # The G3 prepare helper must pass the same stable memory descriptor to init.
    prepare = codes['_sgpu_g3_prepare']; start = initial.copy()
    start.put('x0', p); start.put('x1', g)
    start.store(p, 8, ops); start.store(at(p, 734), 1, V(8, 0))
    f = e._Flow(prepare, image, names, initial=start)
    sites = prepare.calls_to(names['_sgpu_g3_init'], f.before)
    if len(sites) != 1 or any(f.before[sites[0]].get(reg) != want for reg, want in
                            (('x0', g), ('x1', at(p, 16)))):
        raise ValueError('G3 arena init loses stable memory descriptor')
    pc = calls['_sgpu_g3_test']
    for passed in (0, 1):
        incoming = flow.before[pc]; state = flow.step(pc, incoming.copy())
        state.put('w0', V(32, passed))
        state.store(incoming.get('x3'), 4, V(32, 170))
        state.store(at(p, 728), 4, V(32, 13))
        for off, val in ((169, 1), (173, 1), (178, passed)):
            state.store(at(report, off), 1, V(8, val))
        suffix = e._Flow(code, image, names, pc + 4, state)
        returns = [s for q, s in suffix.before.items() if code.ins[q][0] == 'ret']
        if not returns: raise ValueError('shared bootstrap HELD return missing')
        for s in returns:
            if s.get('w0') != V(32, 0) or s.load(end, 4, image) != V(32, 170):
                raise ValueError('shared bootstrap loses final WPTR/HELD false result')
            for off, size, val in ((56, 1, 1), (57, 1, 0), (59, 1, 0), (60, 1, 0), (52, 4, 13)):
                if s.load(at(report, off), size, image) != V(size * 8, val):
                    raise ValueError('shared bootstrap incorrectly reports post-G3 cleanup')
        for q, s in suffix.before.items():
            op, args = code.ins[q]
            if op in ('bl', 'blr', 'br') or op == 'b' and e._number(args[-1]) not in code.ins:
                if suffix.call(q, s) not in names['_trace']:
                    raise ValueError('shared bootstrap performs post-G3 hardware/cleanup')
    return {'stable_call_boundaries': len(calls), 'held_suffix_cases': 2}


def session_identity(codes, image, names):
    """Close the decoded session namespace and stable storage identities."""
    from santoni_gpu_session_replay import QUEUE_NAMES
    # These two named XNU lock objects are storage, not executable helpers.
    # Keep every other session-prefixed identity in the closed helper set.
    lock_objects = {'_sgpu_session_lock', '_sgpu_session_group'}
    present = {n for n in names if (n.startswith('_sgpu_session_') and n not in lock_objects)
               or n == '_sgpu_bootstrap'}
    if not present: return None
    required = {'_sgpu_bootstrap', '_sgpu_session_options', '_sgpu_session_start',
        '_sgpu_session_loop', '_sgpu_session_producer', '_sgpu_session_prepare',
        '_sgpu_session_execute', '_sgpu_session_stop', '_sgpu_session_failure_result',
        *(n for n in QUEUE_NAMES if n.startswith('_sgpu_session_'))}
    if present != required or any(n not in codes or len(names[n]) != 1 for n in required):
        raise ValueError('persistent-session audit missing or unreviewed helper boundaries')
    if any(n in codes or len(names.get(n, ())) != 1 for n in lock_objects):
        raise ValueError('persistent-session lock storage missing/ambiguous or executable')
    spans = []
    for name, size in (('_session_core', CORE_BYTES), ('_session_queue', 3056),
                       ('_session_queue_event', 4), ('_session_idle_count', 4)):
        if len(names.get(name, ())) != 1: raise ValueError('missing/ambiguous session storage: ' + name)
        address = next(iter(names[name]))
        segments = [s for s in image.segs if s['vmaddr'] <= address and
                    address + size <= s['vmaddr'] + s['vmsize']]
        if len(segments) != 1 or segments[0].get('initprot') != 3:
            raise ValueError('session storage must fit writable nonexecuting segment')
        if any(a < address + size and address < b for a, b in spans):
            raise ValueError('session storage objects overlap')
        spans.append((address, address + size))
    return {'helpers': sorted(required), 'storage_spans': spans}


def audit_session(codes, image, names, e, launcher=None):
    """Return session evidence only after all components have actually passed."""
    from santoni_gpu_control_audit import audit_control
    from santoni_gpu_session_replay import (audit_queue, audit_core, audit_worker,
                                           audit_producer, audit_entry, audit_clock,
                                           audit_cold_arena)
    if session_identity(codes, image, names) is None:
        return None
    return {'control_isolation': audit_control(codes, image, names, e, launcher=launcher),
            'start_storage': session_start_storage(codes['_sgpu_session_start'], image, names, e),
            'bootstrap_storage': session_bootstrap_storage(codes, image, names, e),
            'cold_arena': audit_cold_arena(codes, image, names, e),
            'clock': audit_clock(codes, image, names, e),
            'worker_locks': session_lock_wiring(codes['_sgpu_session_loop'], image, names, e),
            'producer_locks': session_lock_wiring(codes['_sgpu_session_producer'], image, names, e),
            'entry': audit_entry(codes, image, names, e),
            'queue': audit_queue(codes, image, names, e),
            'core': audit_core(codes, image, names, e),
            'worker': audit_worker(codes, image, names, e),
            'producer': audit_producer(codes, image, names, e),
            'scope': 'decoded storage/ABI and bounded instruction replay with modeled callbacks/scheduling',
            'hardware_or_scheduler_verified': False}
