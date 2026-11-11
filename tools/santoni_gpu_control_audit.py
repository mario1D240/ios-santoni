"""A mode-1-only certificate; never certifies the persistent session.

The enclosing audit still checks all linked GPU code/legacy contracts. This
layer additionally proves that the packaged mode1/zero-options route cannot
enter session, firmware/CP submission, translation setup or DMA allocation.
"""
from santoni_gpu_session_audit import session_options
from santoni_gpu_user_audit import scalar_option_wiring

GATE = 'mode1_control_session_unreachable_checked'


def launch_control(code, image, names, e):
    """Bind the parsed boot mode to sg.mode and the once-only worker launch."""
    V, at = e._Value, e._scm_at
    sg = V(64, next(iter(names['_sg'])))
    parses = code.calls_to(names['_PE_parse_boot_argn'])
    if len(parses) != 1:
        raise ValueError('mode1 startup parser missing/repeated')
    mode1 = None
    for mode in (None, 0, 1, 2, 3, 4, 0xffffffff):
        state = e._initial(code.symbol)
        state.store(V(64, next(iter(names['_page_shift']))), 4, V(32, 12))
        state.store(V(64, next(iter(names['_page_size']))), 8, V(64, 4096))

        def parse(after, before):
            pointer, dest = before.get('x0'), before.get('x1')
            literal = b'santonigpu\0'
            if (pointer is None or not isinstance(pointer.expr, int) or
                    image.read(pointer.expr, len(literal)) != int.from_bytes(literal, 'little') or
                    before.get('x2') != V(64, 4) or before.load(dest, 4, image) != V(32, 0)):
                raise ValueError('startup boot option name/width/default differs')
            after.store(dest, 4, V(32, mode or 0))

        flow = e._Flow(code, image, names, initial=state, effects={parses[0]: parse})
        starts = code.calls_to(names['_kernel_thread_start'], flow.before)
        if len(starts) != int(mode in (1, 2, 3)):
            raise ValueError('startup mode bounds or missing-default refusal differs')
        for pc in starts:
            before = flow.before[pc]
            if (before.get('x0') != V(64, next(iter(names['_sgpu_kernel_thread']))) or
                    before.get('x1') != V(64, 0) or before.load(at(sg, 84), 4, image) != V(32, mode)):
                raise ValueError('startup worker identity or parsed-mode publication differs')
        if mode == 1: mode1 = flow
    loads = [pc for pc in mode1.before if code.ins[pc][0] == 'ldaxr']
    if len(loads) != 1:
        raise ValueError('startup once-only acquire load missing')
    pc = loads[0]
    load, store, retry = code.ins[pc], code.ins.get(pc + 4), code.ins.get(pc + 8)
    if (store is None or store[0] != 'stlxr' or retry is None or retry[0] != 'cbnz' or
            retry[1][0] != store[1][0] or e._number(retry[1][1]) != pc or
            mode1.before[pc].address(load[1][1])[0] != at(sg, 80) or
            mode1.before[pc + 4].address(store[1][2])[0] != at(sg, 80) or
            mode1.before[pc + 4].get(store[1][1]) != V(32, 1)):
        raise ValueError('startup once-only LL/SC address/store/retry differs')
    for attempted in (0, 1, 2, 0xffffffff):
        after = mode1.step(pc + 4, mode1.before[pc + 4].copy())
        after.put(store[1][0], V(32, 0))  # successful exclusive store
        after.put(load[1][0], V(32, attempted))
        tail = e._Flow(code, image, names, pc + 8, after)
        if len(code.calls_to(names['_kernel_thread_start'], tail.before)) != int(attempted == 0):
            raise ValueError('startup can relaunch an attempted worker')
    return {'parsed_modes': 7, 'once_only_cases': 4}


def _paths(code, image, names, e, initial, call, finish, budget=50000):
    """Explore each acyclic path separately, retaining common zeroed fields.

    The general Flow join deliberately drops differently partitioned memory
    ranges. Here a bounded path tree avoids assuming dropped ownership flags
    are zero. Unknown branches explore both arms; loops and excess work reject.
    """
    engine = e._Flow(code, image, names, initial=initial, stops=(code.entry,))
    pending, work, returns = [(code.entry, initial, frozenset(), ())], 0, 0
    while pending:
        pc, state, visited, history = pending.pop()
        work += 1
        if work > budget or pc in visited:
            raise ValueError('mode1 path proof exceeded bound or reached a loop')
        visited = visited | {pc}
        op, args = code.ins[pc]
        if op == 'ret':
            finish(state, history)
            returns += 1
            continue
        target = None
        if op in ('bl', 'blr', 'br') or op == 'b' and e._number(args[-1]) not in code.ins:
            target = engine.call(pc, state)
            if pc in code.noreturn and target in names.get('___stack_chk_fail', ()):
                continue  # actual panic stub is checked by the enclosing loader
        after = engine.step(pc, state.copy())
        if target is not None:
            call(pc, target, state, after, history)
            history += (target,)
        successors = code.succ[pc]
        if code.conditional(op):
            truth = state.truth(engine.predicate(pc, state))
            if truth is not None:
                successors = (e._number(args[-1]) if truth else pc + 4,)
        if not successors:
            raise ValueError('mode1 path has an unreviewed terminal')
        pending.extend((n, after.copy(), visited, history) for n in successors)
    if not returns:
        raise ValueError('mode1 proof has no returning path')
    return {'instruction_states': work, 'return_paths': returns}


def wrapper_control(code, image, names, e):
    V, at = e._Value, e._scm_at
    bootstrap = names['_sgpu_bootstrap']
    total = []
    for option in (0, 1, 2, 0xffffffff):
        for result in (0, 1):
            initial = e._initial(code.symbol)
            initial.put('w1', V(32, 1))
            initial.store(V(64, ('ops', 116)), 4, V(32, option))

            def call(pc, target, before, after, history):
                if target in names.get('_bzero', ()):
                    if option or before.get('x1') not in (V(64, 744), V(64, 904)):
                        raise ValueError('unexpected old-wrapper storage initialization')
                    return
                if target not in bootstrap or option:
                    raise ValueError('old wrapper bypasses session refusal or calls another helper')
                for reg, want in (('x0', V(64, ('ops', 0))), ('w1', V(32, 1)),
                                  ('x2', initial.get('x2')), ('x3', initial.get('x3')),
                                  ('x4', V(64, ('report', 0)))):
                    if before.get(reg) != want:
                        raise ValueError('old-wrapper bootstrap argument differs: ' + reg)
                spans = []
                stack = before.get('sp')
                for reg, size in (('x5', 744), ('x6', 904), ('x7', 4)):
                    address = before.get(reg)
                    if (address is None or not isinstance(address.expr, tuple) or
                            address.expr[0] != 'stack' or stack is None or
                            not stack.expr[1] <= address.expr[1] < address.expr[1] + size <= 0):
                        raise ValueError('old-wrapper bootstrap storage escapes live stack')
                    spans.append((address.expr[1], address.expr[1] + size))
                if any(a < d and c < b for i, (a, b) in enumerate(spans) for c, d in spans[i + 1:]):
                    raise ValueError('old-wrapper probe/arena/WPTR storage overlaps')
                after.put('w0', V(32, result))

            def finish(state, history):
                if sum(t in bootstrap for t in history) != int(option == 0):
                    raise ValueError('mode1 old wrapper does not call bootstrap exactly once')
                if state.get('w0') != V(32, 0 if option else result):
                    raise ValueError('old-wrapper result or session refusal differs')
                if option and state.load(V(64, ('report', 4)), 4, image) != V(32, 1):
                    raise ValueError('old-wrapper refusal does not report BAD_MODE')

            total.append(_paths(code, image, names, e, initial, call, finish))
    return total


def bootstrap_control(code, image, names, e):
    V, at = e._Value, e._scm_at
    p = V(64, ('stack', 0x20000))
    initial = e._initial(code.symbol)
    initial.put('w1', V(32, 1))
    initial.put('x5', p)  # avoid special probe loads: require actual pointer stores
    for off in (104, 108, 112, 116):
        initial.store(V(64, ('ops', off)), 4, V(32, 0))
    seen = set()
    allowed = {address: name for name in ('_bzero', '_sgpu_power', '_sgpu_restore_power',
        '_poll', '_faults', '_sgpu_failure') for address in names.get(name, ())}
    maps = ((0, 0x01859000, 0x1000), (1, 0x0185b000, 0x1000),
            (2, 0x01845000, 0x1000), (3, 0x01812000, 0x1000), (4, 0x01c00000, 0x40000))

    def call(pc, target, before, after, history):
        seen.add(target)
        if isinstance(target, tuple):
            if target not in (('callback', 8), ('callback', 16), ('callback', 56), ('callback', 96)):
                raise ValueError('mode1 bootstrap reaches DMA/cache/write callback')
            if before.get('x0') != V(64, ('ctx', 0)):
                raise ValueError('mode1 callback context differs')
            if target == ('callback', 8):
                args = tuple(before.get('w' + str(i)) for i in (1, 2, 3))
                if args not in [tuple(V(32, v) for v in row) for row in maps]:
                    raise ValueError('mode1 maps an unreviewed GPU/translation region')
            if target == ('callback', 16):
                pair = before.get('w1'), before.get('w2')
                if pair not in [(V(32, b), V(32, o)) for b, o in
                               ((4, 0xc000), (4, 0x1348), (4, 0x13d4), (0, 0x1c))]:
                    raise ValueError('mode1 reaches unexpected register access')
            if target == ('callback', 56) and before.get('w1') != V(32, 1000):
                raise ValueError('mode1 reaches unexpected hardware delay')
            return
        if target not in allowed:
            raise ValueError('mode1 bootstrap reaches submission/session/unreviewed helper')
        name = allowed[target]
        if name == '_bzero':
            if before.get('x0') != at(p, 16) or before.get('x1') != V(64, 728):
                raise ValueError('mode1 probe zero initialization differs')
            return
        if before.get('x0') != p:
            raise ValueError('mode1 helper loses its owned probe')
        if before.load(p, 8, image) != V(64, ('ops', 0)) or before.load(at(p, 8), 8, image) != V(64, ('report', 0)):
            raise ValueError('bootstrap did not bind the passed Ops/report')
        if name == '_sgpu_power':
            # The existing audited power helper can change saved clocks and GX
            # ownership; retain uncertainty rather than its zero initializer.
            after.store(at(p, 728), 4, None)
            after.store(at(p, 737), 1, None)  # probe.gx_touched; commands_started is +738
        if name == '_poll':
            wanted = (4, 0x13d4, 0xfffffffe, 0, 10000)
            if tuple(before.get('w' + str(i)) for i in range(1, 6)) != tuple(V(32, v) for v in wanted):
                raise ValueError('mode1 idle poll offset/mask/budget differs')

    result = _paths(code, image, names, e, initial, call, lambda state, history: None)
    if not names['_sgpu_power'].intersection(seen) or not names['_sgpu_restore_power'].intersection(seen):
        raise ValueError('mode1 lacks its audited power/restore path')
    result['no_session_DMA_translation_or_submit'] = True
    return result


def worker_control(code, image, names, e, launcher=None, render_default=None, ui_default=None, graphics_default=None):
    V, at = e._Value, e._scm_at
    sg = V(64, next(iter(names['_sg'])))
    initial = e._initial(code.symbol)
    initial.store(at(sg, 84), 4, V(32, 1))
    options = {'_sgpu_stock_options': 88, '_sgpu_pixel_options': 96,
               '_sgpu_g3_options': 100, '_sgpu_session_options': 104}
    if '_sgpu_user_options' in names:
        options.update(_sgpu_user_options=108, _sgpu_user_test_options=112)
    for offset in options.values():
        initial.store(at(sg, offset), 4, V(32, 0))
    option_addresses = {next(iter(names[name])): offset for name, offset in options.items()}
    diagnostics = {address for name in ('_sgpu_pas_cache_preflight', '_sgpu_scm_capability_probe',
                                       '_sgpu_zap_allocation_preflight') for address in names.get(name, ())}
    allowed = {address for name in ('_printf', '_sgpu_kernel_wait_us', '_SecureDTLookupEntry',
        '_SecureDTGetProperty', '_sgpu_failure_summary', '_thread_terminate_self', '_bzero',
        '_clock_interval_to_deadline', '_assert_wait_deadline', '_thread_block')
        for address in names.get(name, ())}
    probe = next(iter(names['_sgpu_probe']))
    launcher_addresses = {}
    render_address = next(iter(names['_sgpu_render_options'])) if '_sgpu_render_options' in names else None
    ui_address = next(iter(names['_sgpu_ui_options'])) if '_sgpu_ui_options' in names else None
    graphics_address=next(iter(names['_sgpu_graphics_options'])) if '_sgpu_graphics_options' in names else None
    if graphics_address and (not graphics_default or graphics_default.get('success') is not True):
        raise ValueError('mode1 worker lacks actual default-off graphics parser proof')
    if ui_address and (not ui_default or ui_default.get('success') is not True):
        raise ValueError('mode1 worker lacks actual default-off UI parser proof')
    if render_address and (not render_default or render_default.get('success') is not True):
        raise ValueError('mode1 worker lacks actual default-off render parser proof')
    if '_santoni_gpu_user_launch_options_ok' in names:
        wanted = ('_santoni_gpu_user_launch_options_ok', '_santoni_gpu_user_launch_worker_ready')
        if (not launcher or launcher.get('success') is not True or
                launcher.get('scope') != 'mode1; launcher option absent or explicitly zero' or
                any(launcher.get('return_values', {}).get(n) != 1 for n in wanted)):
            raise ValueError('mode1 worker lacks the actual launcher exclusion component')
        launcher_addresses = {next(iter(names[n])): n for n in wanted}

    def call(pc, target, before, after, history):
        if target in option_addresses:
            if before.get('w0') != V(32, 1):
                raise ValueError('worker changes mode before option validation')
            # Each default-off helper is independently replayed by the enclosing
            # stock/pixel/G3 audit and session_options below.
            after.store(at(sg, option_addresses[target]), 4, V(32, 0))
            after.put('w0', V(32, 1))
        elif target in diagnostics:
            if before.get('w0') != V(32, 1):
                raise ValueError('worker changes mode before diagnostic exclusion')
            after.put('w0', V(32, 0))  # their actual mode1 refusals are audited separately
        elif target in launcher_addresses:
            if before.get('w0') != V(32, 1):
                raise ValueError('worker changes mode before launcher exclusion')
            after.put('w0', V(32, 1))  # exact returning component, with no kernel writes
        elif target == render_address:
            if before.get('w0') != V(32,1): raise ValueError('worker changes mode before render exclusion')
            after.store(V(64,render_default['global']),4,V(32,0))
            after.put('w0',V(32,1))
        elif target == probe:
            ops = before.get('x0')
            if before.get('w1') != V(32, 1) or any(before.load(at(ops, off), 4, image) != V(32, 0)
                                                  for off in (104, 108, 112, 116)):
                raise ValueError('mode1 worker forwards an experimental role')
            if not set(option_addresses) <= set(history):
                raise ValueError('worker bypasses a default-off option check')
            if not set(launcher_addresses) <= set(history):
                raise ValueError('worker bypasses a launcher exclusion check')
            if render_address and render_address not in history:
                raise ValueError('worker bypasses actual render exclusion check')
            if ui_address and ui_address not in history:
                raise ValueError('worker bypasses actual UI exclusion check')
            if graphics_address and graphics_address not in history:
                raise ValueError('worker bypasses actual graphics exclusion check')
            if '_sgpu_user_options' in options and any(
                    before.load(at(sg, offset), 4, image) != V(32, 0) for offset in (108, 112)):
                raise ValueError('mode1 worker retains an enabled scalar user role')
            after.store(before.get('x4'), 192, None)  # report may change; never use old zeroes
        elif target == ui_address:
            if before.get('w0') != V(32, 1):
                raise ValueError('worker changes mode before UI exclusion')
            after.store(V(64, ui_default['global']), 4, V(32, 0))
            after.put('w0', V(32, 1))
        elif target == graphics_address:
            if before.get('w0')!=V(32,1):raise ValueError('worker changes mode before graphics exclusion')
            after.store(V(64,graphics_default['global']),1,V(8,0));after.put('w0',V(32,1))
        elif target not in allowed:
            raise ValueError('mode1 worker reaches session or unreviewed callee')
        if target in names.get('_clock_interval_to_deadline', ()):
            if before.get('w0') != V(32, 40000000) or before.get('w1') != V(32, 1000):
                raise ValueError('mode1 startup delay interval/unit differs')
            after.store(before.get('x2'), 8, V(64, ('deadline', pc)))
        if target in names.get('_assert_wait_deadline', ()):
            if (before.get('x0') != at(sg, 92) or before.get('w1') != V(32, 0) or
                    before.get('x2') is None or not isinstance(before.get('x2').expr, tuple) or
                    before.get('x2').expr[0] != 'deadline'):
                raise ValueError('mode1 startup wait event/deadline ABI differs')
        if target in names.get('_thread_block', ()) and before.get('x0') != V(64, 0):
            raise ValueError('mode1 startup sleep changes continuation')

    def finish(state, history):
        if history.count(probe) != 1 or not names['_thread_terminate_self'].intersection(history):
            raise ValueError('mode1 worker does not run/terminate the old diagnostic once')

    return _paths(code, image, names, e, initial, call, finish)


def audit_control(codes, image, names, e, launcher=None):
    if '_sgpu_bootstrap' not in codes:
        raise ValueError('control-only certificate is defined for the shared-bootstrap kernel')
    options = session_options(codes['_sgpu_session_options'], image, names, e,
                              e._Value(64, next(iter(names['_sg']))))
    scalar = {}
    if '_sgpu_user_options' in codes:
        for symbol in ('_sgpu_user_options', '_sgpu_user_test_options'):
            scalar[symbol] = scalar_option_wiring(codes[symbol], image, names, e,
                e._Value(64, next(iter(names['_sg']))))
    from santoni_gpu_render_audit import default_off
    render_default = default_off(codes,image,names,e)
    from santoni_gpu_ui_audit import default_off as ui_default_off
    ui_default = ui_default_off(codes, image, names, e)
    from santoni_gpu_graphics_audit import default_off as graphics_default_off
    graphics_default=graphics_default_off(codes,image,names,e)
    return {'scope': 'mode1; all experimental options absent', 'option_cases': options,
            'launch': launch_control(codes['_santoni_gpu_start'], image, names, e),
            'wrapper': wrapper_control(codes['_sgpu_probe'], image, names, e),
            'bootstrap': bootstrap_control(codes['_sgpu_bootstrap'], image, names, e),
            'worker': worker_control(codes['_sgpu_kernel_thread'], image, names, e,
                launcher=launcher, render_default=render_default, ui_default=ui_default,graphics_default=graphics_default),
            'graphics_default_off':graphics_default,
            'UI_default_off': ui_default,
            'render_default_off':render_default,
            'launcher_default_off': launcher,
            'scalar_options': scalar,
            'scalar_user_unreachable_checked': bool(scalar),
            'persistent_session_certified': False, 'hardware_verified': False}
