"""Fail-closed decoded wiring checks for the separately authorized stock route.

These checks use the actual linked instructions. Mocked helper/MMIO returns
exercise gates, not live hardware permission, memory ownership or TZ behavior.
"""
import itertools

HELPERS = ('_sgpu_stock_options', '_sgpu_stock_write_allowed',
           '_sgpu_stock_transition', '_sgpu_stock_check32')


def _single_return(flow, e):
    exits = [s.get('w0') for pc, s in flow.before.items() if flow.code.ins[pc][0] == 'ret']
    if (not exits or any(v != exits[0] for v in exits) or exits[0] is None or
            not isinstance(exits[0].expr, int)):
        raise ValueError('stock binary result is not a single known return')
    return exits[0]


def permission_cases(code, image, names, e):
    """Full public C shape; optimized private ABIs are checked at the writer too."""
    count = 0
    for mode, enabled, block, off, value in itertools.product(
            (0, 1, 2, 3, 4, 0xffffffff), (0, 1, 2, 0xffffffff), (0, 4, 5, 6),
            (0x3c000, 0x3d000, 0x3d004), (0, 1, 0xffffffff)):
        state = e._initial(code.symbol)
        for i, val in enumerate((mode, enabled, block, off, value)):
            state.put('w' + str(i), e._Value(32, val))
        result = _single_return(e._Flow(code, image, names, initial=state), e)
        expected = int((mode, enabled, block, off, value) == (3, 1, 4, 0x3d000, 0))
        if result != e._Value(32, expected):
            raise ValueError('stock exact mode/option/block/offset/zero permission differs')
        count += 1
    return count


def check32_cases(code, image, names, e):
    """The fresh-read helper itself must compare the complete observed word."""
    V = e._Value
    state = e._initial(code.symbol)
    for i,value in ((1,4),(2,0x2018),(3,75)): state.put('w'+str(i),V(32,value))
    discovery=e._Flow(code,image,names,initial=state)
    reads=[q for q,s in discovery.before.items() if code.ins[q][0] in ('blr','br') and
           discovery.call(q,s)==('callback',16)]
    if len(reads)!=1: raise ValueError('stock fresh guard needs exactly one read32 callback')
    q=reads[0]; incoming=discovery.before[q]
    if (incoming.get('x0')!=V(64,('ctx',0)) or incoming.get('w1')!=V(32,4) or incoming.get('w2')!=V(32,0x2018)):
        raise ValueError('stock fresh guard read identity differs')
    for got in (0,1,75,74,0x8000004b,0xffffffff):
        def read(after,before): after.put('w0',V(32,got))
        flow=e._Flow(code,image,names,initial=state,effects={q:read})
        if not flow.returns(int(got==75)):
            raise ValueError('stock fresh guard full-word comparison differs')
    return len(reads)


def write_precondition_cases(code, image, names, e):
    V=e._Value
    first=e._initial(code.symbol)
    for i,value in ((1,4),(2,0x3d000),(3,0xffffffff),(4,0)): first.put('w'+str(i),V(32,value))
    first.store(V(64,('ops',104)),4,V(32,1))
    first.store(V(64,('probe',735)),1,V(8,0))
    for off in (169,171): first.store(V(64,('report',off)),1,V(8,1))
    discovery=e._Flow(code,image,names,initial=first)
    reads=sorted(q for q,s in discovery.before.items() if code.ins[q][0] in ('blr','br') and discovery.call(q,s)==('callback',16))
    writes=sorted(q for q,s in discovery.before.items() if code.ins[q][0] in ('blr','br') and discovery.call(q,s)==('callback',32))
    if len(reads)!=2 or len(writes)!=1: raise ValueError('stock checked write callback shape differs')
    for old in (0,1,2,0xffffffff):
        def read(after,before): after.put('w0',V(32,old))
        flow=e._Flow(code,image,names,initial=first,effects={reads[0]:read})
        if (writes[0] in flow.before)!=(old==1) or (old!=1 and (reads[1] in flow.before or not flow.returns(0))):
            raise ValueError('stock last pre-store TRUST guard differs')
    return {'old_must_equal_one':True,'first_read':hex(reads[0]),'write':hex(writes[0])}


def audit_stock(codes, image, names, e):
    if not any(name in codes for name in HELPERS):
        return None
    if any(name not in codes for name in HELPERS) or len(names.get('_sg', ())) != 1:
        raise ValueError('stock helper/state identity incomplete')
    V, at = e._Value, e._scm_at
    check32_cases(codes[HELPERS[3]], image, names, e)
    pre_store=write_precondition_cases(codes['_checked_write32'],image,names,e)
    sites = lambda flow, symbols: e._scm_sites(flow, symbols)
    sg = V(64, next(iter(names['_sg'])))
    stock_global = at(sg, 88)
    bootstrap = '_sgpu_bootstrap' if '_sgpu_bootstrap' in codes else '_sgpu_probe'
    parents = {HELPERS[0]: ('_sgpu_kernel_thread',), HELPERS[1]: ('_sgpu_io_write32',),
               HELPERS[2]: (bootstrap,), HELPERS[3]: (HELPERS[2], '_sgpu_stock_pixels_test', '_sgpu_g3_test') +
               (('_session_check',) if bootstrap == '_sgpu_bootstrap' else ())}
    if '_sgpu_render_live_start' in codes:
        parents[HELPERS[3]] += ('_sgpu_render_live_state',)
    if '_sgpu_ui_state' in codes:
        parents[HELPERS[3]] += ('_sgpu_ui_state',) # read/compare only; no stock transition entry
    if '_sgpu_graphics_hw_state' in codes:
        parents[HELPERS[3]] += ('_sgpu_graphics_hw_state',) # same read/compare-only state proof
    for caller, code in codes.items():
        for callee, permitted in parents.items():
            if caller not in permitted and code.calls_to(names.get(callee, ())):
                raise ValueError('stock layer has an unreviewed caller: ' + caller)

    # Option values come from the exact named four-byte parser outputs. Neither
    # old cache nor scalar SCM entry is called on a conflicting stock request.
    entry = codes[HELPERS[0]]
    allowed_options = {b'santonigpu_stock\0', b'santonigpu_zap\0',
                       b'santonigpu_scm\0', b'santonigpu_cache\0'}
    parse_sites = entry.calls_to(names['_PE_parse_boot_argn'])
    if len(parse_sites) != 4:
        raise ValueError('stock needs four independent option parses')
    for mode, opt, zap, scm, cache in itertools.product(range(5), (0, 1, 2), range(2), range(2), range(2)):
        values = dict(zip(('santonigpu_stock', 'santonigpu_zap', 'santonigpu_scm', 'santonigpu_cache'),
                          (opt, zap, scm, cache)))
        seen = set()
        def parse(after, before):
            pointer = before.get('x0'); target = before.get('x1')
            if before.get('x2') != V(64, 4) or pointer is None or not isinstance(pointer.expr, int):
                raise ValueError('stock option parser width/name differs')
            matched = [v for v in allowed_options if image.read(pointer.expr, len(v)) == int.from_bytes(v, 'little')]
            if len(matched) != 1 or target is None:
                raise ValueError('stock option parser name/storage differs')
            key = matched[0][:-1].decode(); seen.add(key)
            after.store(target, 4, V(32, values[key]))
        state = e._initial(entry.symbol); state.put('w0', V(32, mode))
        state.store(stock_global, 4, V(32, 1))  # stale enable must be cleared
        flow = e._Flow(entry, image, names, initial=state, effects={pc: parse for pc in parse_sites})
        active = mode == 3 and opt == 1 and not (zap or scm or cache)
        if _single_return(flow, e) != V(32, int(opt == 0 or active)):
            raise ValueError('stock option exclusion/return differs')
        exits = [s for pc, s in flow.before.items() if entry.ins[pc][0] == 'ret']
        if any(s.load(stock_global, 4, image) != V(32, int(active)) for s in exits):
            raise ValueError('stock enable is not reset and exactly gated')
        if active and seen != {v[:-1].decode() for v in allowed_options}:
            raise ValueError('stock enable bypasses a required option parse')

    worker = codes['_sgpu_kernel_thread']; running = e._Flow(worker, image, names)
    calls = sites(running, (HELPERS[0],))
    if len(calls) != 1:
        raise ValueError('stock option worker hook missing')
    pc = calls[0]
    after = running.step(pc, running.before[pc].copy()); after.put('w0', V(32, 0))
    suffix = e._Flow(worker, image, names, pc + 4, after)
    if sites(suffix, ('_sgpu_pas_cache_preflight', '_sgpu_scm_capability_probe',
                      '_sgpu_zap_allocation_preflight', *e._gpu_entries(names))) or not sites(suffix, ('_thread_terminate_self',)):
        raise ValueError('invalid stock role continues to hardware')
    for value in (0, 1):
        state = running.step(pc, running.before[pc].copy()); state.put('w0', V(32, 1))
        state.store(stock_global, 4, V(32, value))
        flow = e._Flow(worker, image, names, pc + 4, state)
        calls = sites(flow, e._gpu_entries(names))
        if not calls or any(flow.before[q].load(at(flow.before[q].get('x0'), 104), 4, image) != V(32, value) for q in calls):
            raise ValueError('worker loses the validated stock option in Ops')

    # Do not depend on the private permission helper retaining constant C
    # arguments: execute it using the actual writer's argument registers.
    write = codes['_sgpu_io_write32']
    allow = codes[HELPERS[1]]
    permission_calls = write.calls_to(names[HELPERS[1]])
    if len(permission_calls) != 1:
        raise ValueError('stock 32-bit writer lacks its permission gate')
    stores = [int(pc, 16) for pc in e._mmio(write, 32, True)]
    def permission(after, before):
        state = before.copy(); state.put('sp', V(64, ('stack', -0x10000)))
        walked = e._Flow(allow, image, names, initial=state)
        after.put('w0', _single_return(walked, e))
    for mode, opt, block, off, value in itertools.product((0, 1, 2, 3, 4), (0, 1, 2), (0, 4, 5, 6),
            (0, 0x3bffc, 0x3c000, 0x3d000, 0x3d004, 0x3d001, 0x40000), (0, 1, 0xffffffff)):
        state = e._initial(write.symbol)
        for i, val in enumerate((0, block, off, value)): state.put('x' + str(i), V(64, val))
        for b in range(6):
            state.store(at(sg, b*8), 8, V(64, 0x10000000 + b*0x100000))
            state.store(at(sg, 56 + b*4), 4, V(32, 0x40000 if b==4 else 0x1000))
        state.store(at(sg, 84), 4, V(32, mode)); state.store(stock_global, 4, V(32, opt))
        flow = e._Flow(write, image, names, initial=state, effects={permission_calls[0]: permission})
        actual = [q for q in stores if q in flow.before]
        expected = block < 6 and off < (0x40000 if block==4 else 0x1000) and not off&3 and (
            block != 4 or off < 0x3c000 or (mode==3 and opt==1 and off==0x3d000 and value==0))
        if len(actual) != int(expected):
            raise ValueError('stock writer bounds/permission differs: ' + str((mode,opt,block,off,value)))
        if actual:
            q = actual[0]; reg, addr = write.ins[q][1]; before = flow.before[q]
            if before.get(reg) != V(32, value) or before.address(addr)[0] != V(64, 0x10000000 + block*0x100000 + off):
                raise ValueError('stock write address/value provenance differs')

    transition = codes[HELPERS[2]]
    first = e._initial(transition.symbol)
    first.put('w1', V(32, 3)); first.put('w2', V(32, 75))
    first.store(V(64, ('probe', 16)), 8, V(64, 0x98001000))
    first.store(V(64, ('probe', 24)), 8, V(64, 0x98000000))
    first.store(V(64, ('probe', 728)), 4, V(32, 13))
    for off in range(732, 741): first.store(V(64, ('probe', off)), 1, V(8, int(off != 735)))
    first.store(V(64, ('report', 0)), 172, V(1376, 0))
    first.store(V(64, ('report', 8)), 4, V(32, 16))
    first.store(V(64, ('ops', 104)), 4, V(32, 1))
    discovery = e._Flow(transition, image, names, initial=first)
    checked = sites(discovery, ('_checked_write32',))
    guards = sites(discovery, (HELPERS[3],))
    if len(checked) != 1 or len(guards) != 11:
        raise ValueError('stock transition needs eleven fresh guards and exactly one checked write')
    checked_edges = e._controlled_calls(transition, image, names, HELPERS[3],
        false_return=True, forbidden=(HELPERS[3], '_checked_write32'))
    expected_guards = [(4,0x2018,75),(4,0x201c,75),(4,0x20c8,0),(4,0xe0,0),
        (4,0x2000,0x1020000),(4,0x2004,0),(5,0x8000,0x1127),(5,0xc00,0),
        (5,0x1800,1),(5,0x8020,0x98000000),(5,0x8024,0x10000)]
    for q, want in zip(guards, expected_guards):
        if tuple(discovery.before[q].get('w'+str(i)) for i in (1,2,3)) != tuple(V(32,v) for v in want):
            raise ValueError('stock fresh guard register/value differs')
    cases=[(trust,echo,None) for trust,echo in ((0,0),(1,0),(1,1),(1,0x80000000),(2,0),(0xffffffff,0))]
    cases += [(1,0,(offset,value)) for offset,value in ((32,2),(36,2),(40,1),(36,0x400))]
    for initial_trust, echo, fault in cases:
        def model(after, before, target, q):
            if target == ('callback',16):
                block, off = before.get('w1'), before.get('w2')
                if block == V(32,4) and off == V(32,0x3d000): after.put('w0', V(32, initial_trust))
                else: after.put('w0', V(32,0))  # fault status inputs only
            elif target in names.get('_checked_write32', ()):
                if tuple(before.get('w'+str(i)) for i in range(1,5)) != (V(32,4),V(32,0x3d000),V(32,0xffffffff),V(32,0)):
                    raise ValueError('stock write is not exact full-word zero')
                if any(before.load(V(64,('report',off)),1,image) != V(8,1) for off in (169,171)):
                    raise ValueError('stock attempted/held must be published before write')
                after.put('w0', V(32,int(echo==0)))
                after.store(V(64,('report',96)),4,V(32,echo))  # first failure got
            elif any(target in names.get(n, ()) for n in ('_sgpu_memory_validate','_poll',HELPERS[3])):
                after.put('w0', V(32,1))
            elif target in names.get('_faults', ()) and fault:
                after.store(V(64,('report',fault[0])),4,V(32,fault[1]))
        effects = {}
        for q in discovery.before:
            if transition.ins[q][0] in ('bl','blr','br'):
                target = discovery.call(q, discovery.before[q])
                effects[q] = lambda a,b,t=target,q=q: model(a,b,t,q)
        flow = e._Flow(transition,image,names,initial=first,effects=effects)
        faulted = bool(fault and fault != (36,0x400))
        if len(sites(flow,('_checked_write32',))) != int(initial_trust==1 and not faulted):
            raise ValueError('stock unknown/already-zero TRUST handling differs')
        if faulted:
            if not flow.returns(0): raise ValueError('stock fault snapshot did not reject transition')
            continue
        for q,s in flow.before.items():
            if transition.ins[q][0]=='ret' and initial_trust==1:
                if s.load(V(64,('report',168)),4,image) != V(32,0x01010100 if echo==0 else 0x01000100):
                    # requested byte is zero in this direct helper fixture.
                    raise ValueError('stock attempt/echo/hold result differs')

    probe = codes[bootstrap]; initial = e._initial(probe.symbol)
    # This contract remains transition-only. The distinct pixel opt-in is
    # audited separately; never let an unknown new field weaken this gate.
    initial.store(V(64,('ops',108)),4,V(32,0))
    execution = e._Flow(probe,image,names,initial=initial)
    calls = sites(execution,(HELPERS[2],))
    if len(calls)!=1: raise ValueError('stock transition call missing in core')
    q=calls[0]; incoming=execution.before[q]; report=V(64,('report',0))
    for attempted in (0,1):
        after=execution.step(q,incoming.copy()); after.put('w0',V(32,1))
        after.store(at(report,160),12,V(96,0)); after.store(at(report,169),1,V(8,attempted))
        after.store(at(report,172),4,V(32,0))
        after.store(at(incoming.get('x0'),728),4,V(32,13))
        flow=e._Flow(probe,image,names,q+4,after)
        if sites(flow,('_render_test','_sgpu_blit_commands')):
            raise ValueError('stock transition continues into rendering')
        if attempted:
            if sites(flow,('_sgpu_a505_halt','_sgpu_a505_resume','_sgpu_smmu_restore','_sgpu_restore_power','_faults')):
                raise ValueError('stock attempted path resumes hardware cleanup')
            for pc,state in flow.before.items():
                if probe.ins[pc][0] in ('blr','br') and flow.call(pc,state) != ('callback',96):
                    raise ValueError('stock attempted path performs another hardware callback')
            if not flow.returns(0): raise ValueError('stock held state falsely reports overall success')
            for pc,state in flow.before.items():
                if probe.ins[pc][0]=='ret':
                    for off,size,want in ((56,1,1),(57,1,0),(59,1,0),(60,1,0),(52,4,13)):
                        if state.load(at(report,off),size,image)!=V(size*8,want):
                            raise ValueError('stock held memory/restoration report differs')
    return {'option_exclusion_checked': True, 'writer_exact_zero_exception_checked': True,
            'last_pre_store_TRUST_guard':pre_store,
            'fresh_guard_failure_edges':checked_edges,'fault_status_rejection_checked':True,
            'fresh_guard_sites': [hex(q) for q in guards], 'checked_write': hex(checked[0]),
            'attempt_published_before_write': True, 'no_post_attempt_MMIO_or_cleanup': True,
            'no_render_continuation': True, 'hardware_permission_or_safety_verified': False}
