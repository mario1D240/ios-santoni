"""Decoded cache-preflight contracts; full VM behavior remains host/hardware work."""
import re

HELPERS = ('_sgpu_pas_cache_preflight', '_sgpu_pas_cache_trial_run',
           '_sgpu_pas_cached_prepare', '_sgpu_pas_cached_release',
           '_sgpu_pas_cached_views', '_sgpu_pas_cache_view',
           '_pmap_santoni_pas_cache_control')


def audit_cache(codes, image, names, engine, bootstrap, terminals=(), slide=None):
    e = engine
    if HELPERS[0] not in codes:
        return None
    if any(name not in codes for name in HELPERS):
        raise ValueError('PAS cache helper boundaries missing')
    site = lambda flow, symbols: e._scm_sites(flow, symbols)
    parents = {
        HELPERS[0]: ('_sgpu_kernel_thread',), HELPERS[1]: (HELPERS[0],),
        HELPERS[2]: (HELPERS[1],), HELPERS[3]: (HELPERS[1],),
        HELPERS[4]: (HELPERS[2], HELPERS[3]), HELPERS[5]: (HELPERS[4],),
        HELPERS[6]: (HELPERS[2], HELPERS[3]),
        '_pmap_santoni_pas_aperture_pte': (HELPERS[6],),
    }
    for caller, code in codes.items():
        for callee, permitted in parents.items():
            if caller not in permitted and code.calls_to(names.get(callee, ())):
                raise ValueError('unreviewed caller bypasses the guarded PAS cache layer')
    entry = codes[HELPERS[0]]
    for mode in (0, 1, 2, 4, 0xffffffff):
        state = e._initial(entry.symbol); state.put('w0', e._Value(32, mode))
        flow = e._Flow(entry, image, names, initial=state)
        if site(flow, ('_PE_parse_boot_argn', HELPERS[1])) or not flow.returns(0):
            raise ValueError('PAS cache mode gate differs')
    state = e._initial(entry.symbol); state.put('w0', e._Value(32, 3))
    flow = e._Flow(entry, image, names, initial=state)
    parses = site(flow, ('_PE_parse_boot_argn',))
    if len(parses) != 3:
        raise ValueError('PAS cache requires three independent option parses')
    destinations = []
    for pc, literal in zip(parses, (b'santonigpu_cache\0', b'santonigpu_zap\0', b'santonigpu_scm\0')):
        before = flow.before[pc]; option, output = before.get('x0'), before.get('x1')
        if (option is None or not isinstance(option.expr, int) or
                image.read(option.expr, len(literal)) != int.from_bytes(literal, 'little') or
                before.get('x2') != e._Value(64, 4) or output is None or
                not isinstance(output.expr, tuple) or output.expr[0] != 'stack'):
            raise ValueError('PAS cache option name/width/storage differs')
        for previous in destinations:
            distance = e._State.distance(previous.expr, output.expr)
            if distance is None or abs(distance) < 4:
                raise ValueError('PAS cache option storage aliases')
        destinations.append(output)
    for enabled in (0, 1, 2, 0xffffffff):
        for zap in (0, 1, 2):
            for scm in (0, 1, 2):
                walked = flow
                for index, value in enumerate((enabled, zap, scm)):
                    pc = parses[index]
                    if pc not in walked.before:
                        if index and enabled != 1:
                            break
                        raise ValueError('PAS cache required parse is disconnected')
                    after = walked.step(pc, walked.before[pc].copy())
                    after.store(destinations[index], 4, e._Value(32, value))
                    walked = e._Flow(entry, image, names, pc + 4, after)
                calls = site(walked, (HELPERS[1],))
                active = enabled == 1 and zap == 1 and scm == 0
                if len(calls) != int(active) or not walked.returns(int(enabled == 1)):
                    raise ValueError('PAS cache opt-in/exclusion/handled result differs')

    allowed = {
        HELPERS[0]: ('_PE_parse_boot_argn', '_printf', '_trace', HELPERS[1],
                     '_strncmp', '_clock_interval_to_deadline', '_assert_wait_deadline', '_thread_block'),
        HELPERS[1]: ('_sgpu_pas_allocate', HELPERS[2], HELPERS[3], '_phystokv'),
        HELPERS[2]: (HELPERS[4], HELPERS[6], '_CleanPoC_DcacheRegion_Force'),
        HELPERS[3]: (HELPERS[4], HELPERS[6], '_sgpu_pas_release'),
        HELPERS[4]: ('_pmap_find_phys', '_phystokv', HELPERS[5]),
        HELPERS[5]: ('_ml_set_interrupts_enabled',),
        HELPERS[6]: ('_phystokv', '_pmap_santoni_pas_aperture_pte',
                     '_pmap_cache_attributes', '_pmap_update_cache_attributes_locked',
                     '_flush_mmu_tlb_region_asid_async', '_pmap_sync_wimg',
                     '_pvh_lock', '_pvh_unlock', '_wimg_to_pte',
                     '_hw_lock_bit', '_hw_unlock_bit', '_pmap_find_io_attr',
                     '_OSCompareAndSwap16', '_flush_dcache', '_CleanPoC_DcacheRegion_Force'),
    }
    for name, callees in allowed.items():
        code = codes[name]
        targets = {address for callee in (*callees, '_bzero', '_memcpy') for address in names.get(callee, ())}
        targets.update(e._number(code.ins[pc][1][-1]) for pc in code.noreturn)
        for pc in code.reachable:
            op, args = code.ins[pc]
            if op in ('smc', 'hvc', 'blr', 'br'):
                raise ValueError('unreviewed instruction/callee in PAS cache-only layer')
            if (op == 'bl' or op == 'b' and e._number(args[-1]) not in code.ins) and e._number(args[-1]) not in targets:
                raise ValueError('unreviewed direct callee in PAS cache-only layer: ' + name + ' -> ' + args[-1])

    # Required connected calls prevent a constant-success/no-op helper from
    # earning a wiring certificate. Host native contracts separately check the
    # complete owned-span, page-walk and mutation semantics.
    counts = {
        HELPERS[1]: {'_sgpu_pas_allocate': 2, HELPERS[2]: 2, HELPERS[3]: 2},
        HELPERS[2]: {HELPERS[4]: 2, HELPERS[6]: 2, '_CleanPoC_DcacheRegion_Force': 1},
        HELPERS[3]: {HELPERS[4]: 2, HELPERS[6]: 1, '_sgpu_pas_release': 1},
        HELPERS[4]: {'_pmap_find_phys': 1, '_phystokv': 1, HELPERS[5]: 2},
    }
    for name, required in counts.items():
        connected = e._Flow(codes[name], image, names)
        for callee, count in required.items():
            if len(site(connected, (callee,))) != count:
                raise ValueError('PAS cache required execution wiring differs: ' + name + ' -> ' + callee)
    checked = []
    for caller, callee, false_return, forbidden in (
            (HELPERS[1], '_sgpu_pas_allocate', False, ('_sgpu_pas_allocate', HELPERS[2])),
            (HELPERS[1], HELPERS[2], False, (HELPERS[2],)),
            (HELPERS[1], HELPERS[3], False, ()),
            (HELPERS[2], HELPERS[4], True, ()),
            (HELPERS[2], HELPERS[6], True, ()),
            (HELPERS[3], HELPERS[4], True, ('_sgpu_pas_release',)),
            (HELPERS[3], HELPERS[6], True, ('_sgpu_pas_release',))):
        checked += e._controlled_calls(codes[caller], image, names, callee,
            false_return=false_return, forbidden=forbidden)

    worker = codes['_sgpu_kernel_thread']; running = e._Flow(worker, image, names)
    calls = site(running, (HELPERS[0],))
    if len(calls) != 1:
        raise ValueError('PAS cache worker hook missing')
    pc = calls[0]
    for handled in (0, 1):
        after = running.step(pc, running.before[pc].copy()); after.put('w0', e._Value(32, handled))
        suffix = e._Flow(worker, image, names, pc + 4, after)
        later = site(suffix, ('_sgpu_scm_capability_probe', '_sgpu_zap_allocation_preflight', *e._gpu_entries(names)))
        if handled and (later or len(site(suffix, ('_thread_terminate_self',))) != 1):
            raise ValueError('PAS cache handled path continues into SCM/GPU work')
        if not handled and not site(suffix, e._gpu_entries(names)):
            raise ValueError('PAS cache disabled path disconnects normal GPU work')

    release = codes[HELPERS[3]]; base = e._Value(64, ('probe', 0x6000))
    for exposed, uncertain in ((1, 0), (0, 1), (1, 1)):
        state = e._initial(release.symbol); state.put('x0', base)
        state.store(base, 32, e._Value(256, 0))
        for offset, size, value in ((0, 8, 0x1000), (8, 8, 0x98000000), (16, 4, 8192),
                                    (20, 1, exposed), (24, 4, 2), (28, 1, uncertain)):
            state.store(e._scm_at(base, offset), size, e._Value(size * 8, value))
        guarded = e._Flow(release, image, names, initial=state)
        if site(guarded, (HELPERS[4], HELPERS[6], '_sgpu_pas_release')) or not guarded.returns(0):
            raise ValueError('PAS cache exposed/uncertain release is not contained')

    view = codes[HELPERS[5]]
    ats = [pc for pc in view.reachable if view.ins[pc][0] == 'at']
    pars = [pc for pc in view.reachable if view.ins[pc][0] == 'mrs' and view.ins[pc][1][-1].lower() == 'par_el1']
    if len(ats) != 1 or pars != [ats[0] + 8]:
        raise ValueError('PAS cache needs one inspected AT/PAR sequence')
    at, par = ats[0], pars[0]
    if (view.ins[at][1][0].lower() != 's1e1r' or
            view.ins.get(at - 4) != ('dsb', ('ish',)) or view.ins.get(at + 4) != ('isb', ()) or
            any(view.pred[where] != {where - 4} for where in (at, at + 4, par))):
        raise ValueError('PAS cache AT barriers have changed or have an interior entry')
    irqs = view.calls_to(names.get('_ml_set_interrupts_enabled', ()))
    if len(irqs) != 2 or not irqs[0] < at < par < irqs[1]:
        raise ValueError('PAS cache PAR read lacks its interrupt exclusion/restore pair')
    for previous in (0, 1):
        for attribute in (0x44, 0xff):
            state = e._initial(view.symbol)
            for reg, value in (('x0', 0x1000), ('x1', 0x98000000), ('x2', attribute)):
                state.put(reg, e._Value(64, value))
            def irq_return(after, before):
                if before.get('w0') != e._Value(32, 0):
                    raise ValueError('PAS cache interrupt exclusion was not requested')
                after.put('w0', e._Value(32, previous))
            prefix = e._Flow(view, image, names, initial=state, stops=(par,), effects={irqs[0]: irq_return})
            if prefix.before.get(at) is None or prefix.before[at].get(view.ins[at][1][1]) != e._Value(64, 0x1000):
                raise ValueError('PAS cache AT translates a different VA')
            for raw, passed in ((0x98000000 | attribute << 56, 1),
                    (0x98000001 | attribute << 56, 0), (0x98001000 | attribute << 56, 0),
                    (0x98000000 | (attribute ^ 0xff) << 56, 0)):
                after = prefix.step(par, prefix.before[par].copy())
                after.put(view.ins[par][1][0], e._Value(64, raw))
                suffix = e._Flow(view, image, names, par + 4, after)
                if irqs[1] not in suffix.before or suffix.before[irqs[1]].get('w0') != e._Value(32, previous):
                    raise ValueError('PAS cache lost the original interrupt state')
                if not suffix.returns(passed):
                    raise ValueError('PAS cache PAR fault/PA/attribute comparison differs')

    provider = codes[HELPERS[6]]
    updates = provider.calls_to(names.get('_pmap_update_cache_attributes_locked', ()))
    flushes = provider.calls_to(names.get('_flush_mmu_tlb_region_asid_async', ()))
    inline_flushes = [pc for pc in provider.reachable if provider.ins[pc][0] == 'tlbi' and
                      provider.ins[pc][1][0].lower() in ('vale1is', 'vaale1is') and
                      len(provider.ins[pc][1]) == 2 and
                      re.fullmatch(r'x\d+', provider.ins[pc][1][1])]
    def store_barrier(pc):
        # write_pte_strong's 4K store branches to a common DSB after the
        # compiler's distinct 16K implementation. Inspect that real edge.
        for _ in range(4):
            successors = provider.succ[pc]
            if len(successors) != 1:
                return False
            pc = successors[0]
            if provider.ins[pc] in (('dsb', ('ishst',)), ('dsb', ('sy',))):
                return True
            if provider.ins[pc][0] not in ('nop', 'b'):
                return False
        return False
    stores = [pc for pc in provider.reachable if provider.ins[pc][0] in ('str', 'stp') and
              re.fullmatch(r'x\d+', provider.ins[pc][1][0]) and
              not re.search(r'\[(?:sp|x29)(?:,|\])', provider.ins[pc][1][-1]) and
              store_barrier(pc)]
    syncs = [pc for pc in provider.reachable if provider.ins[pc] in (('dsb', ('ish',)), ('dsb', ('sy',)))
             and provider.ins.get(pc + 4) == ('isb', ())]
    if len(updates) != 1 or not (flushes or inline_flushes) or not stores or not syncs:
        raise ValueError('PAS cache provider is missing aperture/PV stores or TLB synchronization')
    if any(provider.ins[pc][0] in ('smc', 'hvc') for pc in provider.ins):
        raise ValueError('PAS cache provider contains a secure call')

    flags = bootstrap_flags(bootstrap, names, e, image, terminals, slide)
    return {'mode3_cache1_zap1_scm0': True, 'worker_terminates_without_SCM_or_GPU': True,
            'exposed_and_uncertain_release_rejected': True, 'AT_PAR_and_interrupt_restore_checked': True,
            'pmap_aperture_store_barriers': [hex(pc) for pc in stores],
            'pmap_tracked_alias_update': hex(updates[0]), 'pmap_TLB_sync_pairs': [hex(pc) for pc in syncs],
            'pmap_inline_leaf_TLBI': [hex(pc) for pc in inline_flushes],
            'bootstrap_physmap_granules': flags['values'],
            'bootstrap_physmap_ABI': flags['ABI'],
            'checked_cache_helper_edges': checked,
            'scope': 'decoded ABI/opt-in/PAR/retention/PTE-barrier wiring; owned-span/pmap contracts are host-tested, hardware unproven'}


def bootstrap_flags(text, names, engine, image, terminals=(), slide_text=None):
    """Prove literal granule arguments at the two compiled physmap-slide calls."""
    e = engine
    if len(names.get('_arm_vm_init', ())) != 1:
        raise ValueError('PAS aperture bootstrap symbol is ambiguous/missing')
    if not slide_text or len(names.get('_arm_vm_physmap_slide', ())) != 1:
        raise ValueError('PAS aperture slide ABI is missing/ambiguous')
    slide = e._Code(slide_text, '_arm_vm_physmap_slide',
                    next(iter(names['_arm_vm_physmap_slide'])), noreturn=terminals)
    state = e._initial(slide.symbol)
    state.put('w3', e._Value(32, ('arg', 3)))
    state.put('w4', e._Value(32, ('arg', 4)))
    flow = e._Flow(slide, image, names, initial=state)
    calls = e._scm_sites(flow, ('_arm_vm_page_granular_prot',))
    if len(calls) != 1:
        raise ValueError('PAS aperture slide does not call the expected page-granular builder')
    before = flow.before[calls[0]]
    if before.get('w3') != e._Value(32, 1) or before.get('w5') != e._Value(32, 1):
        raise ValueError('PAS aperture execute-never attributes differ')
    if before.get('w6') == e._Value(32, ('arg', 4)) and before.get('w4') == e._Value(32, ('arg', 3)):
        granule_register, abi = 'w4', 'original AP+granule'
    elif before.get('w6') == e._Value(32, ('arg', 3)) and before.get('w4') == e._Value(32, 0):
        granule_register, abi = 'w3', 'private AP_RWNA=0 specialization'
    else:
        raise ValueError('PAS aperture granule/AP private ABI is unreviewed')
    code = e._Code(text, '_arm_vm_init', next(iter(names['_arm_vm_init'])), noreturn=terminals)
    instructions = [(pc, op, ', '.join(args)) for pc, (op, args) in sorted(code.ins.items())]
    def literal_before(i, register):
        value = None
        for j in range(i - 1, max(-1, i - 33), -1):
            address, prior, operands = instructions[j]
            if (instructions[j + 1][0] != address + 4 or
                    code.pred[address + 4] != {address} or
                    prior in ('b', 'bl', 'blr', 'br', 'ret') or e._Code.conditional(prior)):
                break
            if prior in ('unknown', 'udf') or e._unsupported(prior, operands):
                break
            parts = tuple(re.split(r',\s*(?![^\[]*\])', operands))
            written = parts[:2] if prior == 'ldp' else parts[:1]
            if any(e._State.reg(part)[0] == e._State.reg(register)[0] for part in written):
                if prior != 'mov' or len(parts) != 2:
                    break
                if parts[1] in ('wzr', 'xzr'):
                    value = 0; break
                number = e._number(parts[1])
                if number is not None:
                    value = number; break
                if not re.fullmatch(r'[wx]\d+', parts[1]):
                    break
                register = parts[1]
        if value is None:
            raise ValueError('could not inspect actual physmap granule argument')
        return value
    found_flags = []
    for i, (pc, op, args) in enumerate(instructions):
        if op != 'bl' or e._number(args) not in names.get('_arm_vm_physmap_slide', ()):
            continue
        if granule_register == 'w4' and literal_before(i, 'w3') != 0:
            raise ValueError('PAS aperture caller does not supply AP_RWNA')
        found_flags.append(literal_before(i, granule_register))
    if found_flags != [3, 0]:
        raise ValueError('PAS general-use aperture is not compiled with unhinted page granularity')
    return {'values': found_flags, 'ABI': abi}
