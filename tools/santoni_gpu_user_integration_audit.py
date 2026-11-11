"""Missing linked scalar entry/producer components; no boot certificate alone."""
from itertools import product
from santoni_gpu_binary_model import Machine, integer
from santoni_gpu_user_audit import ScalarModel, scalar_storage, _require

EXTRA = ('_sgpu_user_options', '_sgpu_user_test_options', '_sgpu_kernel_thread',
         '_sgpu_session_producer', '_sgpu_user_preflight')


def audit_enabled_options(codes, image, names, e, symbol):
    """Concrete NEON prerequisite reduction; mode1's completed proof is reused."""
    sg = next(iter(names['_sg']))
    if symbol == '_sgpu_user_options':
        literal, field, parents = b'santonigpu_user\0', 108, (88, 96, 100, 104)
    elif symbol == '_sgpu_user_test_options':
        literal, field, parents = b'santonigpu_user_test\0', 112, (88, 96, 100, 104, 108)
    else: raise ValueError('unexpected scalar parser')
    vm = Machine({symbol: codes[symbol]}, image, names, e)
    vm.memory.map(sg, 120)
    vm.memory.readonly.extend(((sg, sg + field), (sg + field + 4, sg + 120)))
    option, parsed = None, 0
    def external(target, state, probe=False, before=None):
        nonlocal parsed
        if target not in names['_PE_parse_boot_argn']: return False
        if probe: return True
        dest = integer(before, 'x1')
        _require(image.read(integer(before, 'x0'), len(literal)) == int.from_bytes(literal, 'little') and
                 integer(before, 'x2') == 4 and vm.STACK <= dest and dest + 4 <= vm.STACK + vm.STACK_SIZE and
                 vm.memory.get(dest) == 0, 'enabled parser literal/width/default/stack')
        vm.memory.put(dest, option or 0)
        parsed += 1
        state.put('w0', e._Value(32, int(option is not None)))
        return True
    vm.external = external
    count = 0
    for mode, values, option in product((0, 2, 3), product((0, 1, 2, 0xffffffff), repeat=len(parents)),
                                         (None, 0, 1, 2, 0xffffffff)):
        readonly, vm.memory.readonly = vm.memory.readonly, []
        for offset, value in zip(parents, values): vm.memory.put(sg + offset, value)
        vm.memory.put(sg + field, 0xffffffff)
        vm.memory.readonly = readonly
        parsed = 0
        enabled = mode == 3 and option == 1 and all(value == 1 for value in values)
        got = vm.run(symbol, (mode,)).expr
        _require(got == int(not option or enabled) and parsed == 1 and vm.memory.get(sg + field) == int(enabled),
                 'enabled parser exact mode/parents/default permission')
        _require(all(vm.memory.get(sg + off) == value for off, value in zip(parents, values)),
                 'enabled parser changes prerequisite')
        count += 1
    return {'cases': count, 'modes': [0, 2, 3], 'flag_offset': field, 'success': True,
            'executed_instruction_addresses': len(vm.visited), 'hardware_verified': False,
            'scope': 'concrete linked vector reduction; mode1 completed component not repeated'}


def audit_worker_entry(codes, image, names, e, launcher_record=None, saved_cases=None, record_case=None):
    from santoni_gpu_control_audit import _paths
    from santoni_gpu_launcher_replay import PUBLIC, launcher_paths
    launcher_guards = {}
    if PUBLIC[0] in names:
        _require(isinstance(launcher_record, dict) and launcher_record.get('success') is True,
                 'completed launcher worker guard evidence required')
        cases = {case['case']: case for case in launcher_record.get('cases', ())}
        off = cases.get('off', {})
        _require(off.get('mode') == 3 and off.get('options_ok') == off.get('worker_ready') == 1 and
                 all(cases.get(name, {}).get('refusal_paths', {}).get('return_paths', 0) > 0
                     for name in ('reject-before-delay', 'reject-after-delay')),
                 'launcher worker mode3 off/refusal contract incomplete')
        launcher_guards = {PUBLIC[0]: off['options_ok'], PUBLIC[1]: off['worker_ready']}
        _paths = launcher_paths
    V, at = e._Value, e._scm_at
    code = codes['_sgpu_kernel_thread']
    from santoni_gpu_render_audit import default_off
    render_default = default_off(codes,image,names,e)
    from santoni_gpu_ui_audit import default_off as ui_default_off
    ui_default = ui_default_off(codes,image,names,e)
    from santoni_gpu_graphics_audit import default_off as graphics_default_off
    graphics_default=graphics_default_off(codes,image,names,e)
    sg = V(64, next(iter(names['_sg'])))
    options = {'_sgpu_stock_options': 88, '_sgpu_pixel_options': 96,
               '_sgpu_g3_options': 100, '_sgpu_session_options': 104,
               '_sgpu_user_options': 108, '_sgpu_user_test_options': 112}
    addresses = {a: n for n, aa in names.items() for a in aa}
    results = []
    cases = [(s, u, t, None, ready) for s, u, t in ((0, 0, 0), (1, 0, 0),
                (1, 1, 0), (1, 1, 1)) for ready in (0, 1)]
    cases += [(1, 0, 0, name, 0) for name in options]
    for session, user, test, rejected, ready in cases:
        label = f'{session}-{user}-{test}-{rejected or "none"}-{ready}'
        if saved_cases is not None and label in saved_cases:
            results.append(saved_cases[label]); continue
        initial = e._initial(code.symbol)
        initial.store(at(sg, 84), 4, V(32, 3))
        values = {88: 1, 96: 1, 100: 1, 104: session, 108: user, 112: test}
        for off, value in values.items(): initial.store(at(sg, off), 4, V(32, value))
        def call(pc, target, before, after, history):
            name = addresses.get(target)
            if name in launcher_guards:
                _require(before.get('w0') == V(32, 3), 'scalar launcher guard mode differs')
                if name == PUBLIC[1]:
                    _require(any(address in names[PUBLIC[0]] for address in history) and
                             any(address in names['_clock_interval_to_deadline'] for address in history),
                             'scalar launcher readiness bypasses initial guard/delay')
                after.put('w0', V(32, launcher_guards[name]))
            elif name in options:
                _require(before.get('w0') == V(32, 3), 'worker parser mode')
                after.store(at(sg, options[name]), 4, V(32, values[options[name]]))
                after.put('w0', V(32, int(name != rejected)))
            elif name == '_sgpu_render_options':
                _require(render_default and render_default['success'] and before.get('w0')==V(32,3),
                         'scalar worker lacks actual default-off render parser')
                after.store(V(64,render_default['global']),4,V(32,0));after.put('w0',V(32,1))
            elif name == '_sgpu_ui_options':
                _require(ui_default and ui_default['success'] and before.get('w0')==V(32,3),
                         'scalar worker lacks actual default-off UI parser')
                after.store(V(64,ui_default['global']),1,V(8,0));after.put('w0',V(32,1))
            elif name == '_sgpu_graphics_options':
                _require(graphics_default and graphics_default['success'] and before.get('w0')==V(32,3),
                         'scalar worker lacks actual default-off graphics parser')
                after.store(V(64,graphics_default['global']),1,V(8,0));after.put('w0',V(32,1))
            elif name in ('_sgpu_pas_cache_preflight', '_sgpu_scm_capability_probe', '_sgpu_zap_allocation_preflight'):
                _require(rejected is None and before.get('w0') == V(32, 3),
                         'rejected scalar parser reaches a hardware role')
                # Their stock1 conflict refusals are existing prerequisites.
                after.put('w0', V(32, 0))
            elif name in ('_sgpu_probe', '_sgpu_session_start'):
                _require(rejected is None and name == ('_sgpu_session_start' if session else '_sgpu_probe'),
                         'scalar worker reaches wrong startup')
                _require({next(iter(names[n])) for n in options} <= set(history),
                         'startup bypasses scalar/parent parsers')
                ops = before.get('x0')
                _require(before.get('w1') == V(32, 3) and all(before.load(at(ops, off), 4, image) == V(32, value)
                         for off, value in ((104, 1), (108, 1), (112, 1), (116, session))),
                         'startup loses parent options')
                _require(all(before.load(at(sg, off), 4, image) == V(32, values[off]) for off in (108, 112)),
                         'worker changes scalar flags before startup')
                after.put('w0', V(32, ready))
                after.store(before.get('x4'), 192, None)
            elif name == '_sgpu_session_loop':
                _require(rejected is None and session == 1 and ready == 1,
                         'scalar worker enters session after failed start')
            elif name == '_sgpu_session_failure_result':
                _require(rejected is None and session == 1 and ready == 0,
                         'scalar worker reports wrong start failure')
            elif name not in ('_printf', '_sgpu_failure_summary', '_SecureDTLookupEntry', '_SecureDTGetProperty',
                    '_thread_terminate_self', '_clock_interval_to_deadline', '_assert_wait_deadline', '_thread_block', '_bzero'):
                raise ValueError('unreviewed scalar worker callee ' + str(name))
        def finish(state, history):
            count = lambda n: sum(a in names[n] for a in history)
            _require(count('_sgpu_session_start') == int(rejected is None and session == 1) and
                     count('_sgpu_probe') == int(rejected is None and session == 0) and
                     count('_sgpu_session_loop') == int(rejected is None and session == 1 and ready == 1) and
                     count('_sgpu_session_failure_result') == int(rejected is None and session == 1 and ready == 0) and
                     count('_thread_terminate_self') == 1, 'scalar worker startup/termination counts')
            if launcher_guards:
                _require(count(PUBLIC[0]) == count(PUBLIC[1]) == 1,
                         'scalar worker skips/repeats proved launcher guards')
        result = _paths(code, image, names, e, initial, call, finish)
        results.append({'case': label, 'session': session, 'user': user, 'test': test, 'rejected': rejected,
                        'ready': ready, **result})
        if record_case is not None: record_case(results[-1])
    return {'cases': results, 'success': True, 'hardware_verified': False}


class ProducerStop(Exception):
    pass


class ProducerPrefixModel(ScalarModel):
    def __init__(self, codes, image, names, e, storage):
        self.publish_success, self.published_calls, self.preflights, self.terminated = True, 0, 0, 0
        self.legacy_boundary, self.failure_reports = False, 0
        super().__init__(codes, image, names, e, storage, EXTRA)

    def external(self, target, state, probe=False, before=None):
        name = self.vm.by_address.get(target)
        special = ('_sgpu_user_publish', '_sgpu_user_preflight', '_thread_terminate_self', '_mach_absolute_time', '_printf')
        if name not in special: return super().external(target, state, probe, before)
        if probe: return True
        _require(not self.locked, 'producer invokes publication/preflight/termination under mutex')
        self.calls.append(name)
        if name == '_sgpu_user_publish':
            _require(self.m.get(self.sg + 108) == 1, 'disabled producer publishes user node')
            self.published_calls += 1
            # The separately completed publication proof supplies this result.
            state.put('w0', self.e._Value(32, int(self.publish_success)))
        elif name == '_sgpu_user_preflight':
            _require(self.published_calls == 1 and self.publish_success and
                     self.m.get(self.sg + 112) == 1, 'producer preflight bypasses separate opt-in/publication')
            self.preflights += 1
        elif name == '_thread_terminate_self':
            self.terminated += 1
            raise ProducerStop()
        elif name == '_mach_absolute_time':
            _require(self.m.get(self.sg + 108) != 1 and not self.published_calls and not self.preflights,
                     'enabled producer falls through into old automatic workload')
            self.legacy_boundary = True
            raise ProducerStop()  # stop before the already-recorded legacy body
        elif name == '_printf':
            literal = b'SANTONI GPU: USER publication failed; close requested; no retry\n\0'
            _require(not self.publish_success and self.vm.image.read(integer(before, 'x0'), len(literal)) ==
                     int.from_bytes(literal, 'little'), 'unreviewed producer report')
            self.failure_reports += 1
            state.put('w0', self.e._Value(32, 0))
        return True


def audit_producer_prefix(codes, image, names, e):
    storage, results = scalar_storage(image, names), []
    for user, test, published in ((0, 0, True), (2, 1, True), (1, 0, True),
                                 (1, 1, True), (1, 2, True), (1, 0, False), (1, 1, False)):
        m = ProducerPrefixModel(codes, image, names, e, storage)
        m.setup(m.sg + 108, user); m.setup(m.sg + 112, test)
        m.publish_success = published
        try:
            m.call('_sgpu_session_producer', 0, 0)
            raise ValueError('producer unexpectedly returned before audited boundary')
        except ProducerStop: pass
        if user == 1:
            _require(m.published_calls == 1 and m.terminated == 1 and not m.legacy_boundary and
                     m.preflights == int(published and test == 1), 'producer user role selection/counts')
            _require(m.failure_reports == int(not published), 'producer publication failure report')
            if not published:
                _require(m.m.get(m.q + 1, 1) == 1 and m.m.get(m.q + 4) == 3 and m.wakeups == 1,
                         'publication failure does not request close/wake once')
        else:
            _require(m.legacy_boundary and not m.terminated and m.refs == 0,
                     'legacy producer prefix changes default path')
        _require(not m.locked and not m.refs, 'producer prefix owns a lock/task reference')
        results.append({'user': user, 'test': test, 'publication': published,
                        'preflight_calls': m.preflights, 'legacy_boundary': m.legacy_boundary})
    return {'cases': results, 'success': True, 'hardware_verified': False,
            'scope': 'producer prefix; publication/preflight results consume separate proofs; legacy body not repeated'}


def main():
    import argparse
    from datetime import datetime, timezone
    import hashlib
    import json
    from pathlib import Path
    import traceback
    from santoni_gpu_user_audit import load_saved_boundaries
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--components', nargs='+', default=['options_user', 'options_test', 'worker', 'producer'])
    parser.add_argument('--launcher-worker-record', help='relative exact-kernel completed launcher guard record')
    args = parser.parse_args()
    output = args.evidence / ('scalar-integration-attempt-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    output.mkdir()
    try:
        from check_santoni_gpu_kernel import _symbols
        inventory = _symbols((args.evidence/'kernel.symbols.txt').read_text())
        extra = EXTRA
        if '_sgpu_render_options' in inventory: extra += ('_sgpu_render_options',)
        if '_sgpu_ui_options' in inventory: extra += ('_sgpu_ui_options',)
        if '_sgpu_graphics_options' in inventory:
            extra += ('_sgpu_graphics_options', '_santoni_gpu_graphics_worker_ready')
        codes, image, names, e, identity = load_saved_boundaries(args.evidence, extra)
        sg = e._Value(64, next(iter(names['_sg'])))
        for component in args.components:
            if component in ('options_user', 'options_test'):
                symbol = '_sgpu_user_options' if component == 'options_user' else '_sgpu_user_test_options'
                result = audit_enabled_options(codes, image, names, e, symbol)
            elif component == 'worker':
                from santoni_gpu_scalar_certificate import proof
                launcher = proof(args.evidence, args.launcher_worker_record, identity) if args.launcher_worker_record else None
                cache = args.evidence / 'scalar-worker-scenarios'
                cache.mkdir(exist_ok=True)
                saved = {path.stem: proof(args.evidence, str(path.relative_to(args.evidence)), identity)['result']
                         for path in cache.glob('*.json')}
                def record_case(case):
                    with (cache / (case['case'] + '.json')).open('x') as stream:
                        stream.write(json.dumps({**identity, 'success': True, 'result': case,
                            'launcher_record': launcher, 'hardware_verified': False}, indent=2) + '\n')
                    print('Saved passed scalar worker scenario:', case['case'], flush=True)
                result = audit_worker_entry(codes, image, names, e, launcher, saved, record_case)
                result['launcher_guard_record'] = launcher
            elif component == 'producer': result = audit_producer_prefix(codes, image, names, e)
            else: raise ValueError('unknown scalar integration component ' + component)
            result.update(identity, success=True)
            (output / (component + '.json')).write_text(json.dumps(result, indent=2) + '\n')
        result = {'success': True, 'components': args.components, **identity}
    except Exception as error:
        result = {'success': False, 'error': str(error)}
        (output / 'traceback.txt').write_text(traceback.format_exc())
    result['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'evidence': str(output), 'result': result}, indent=2))
    return 0 if result['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
