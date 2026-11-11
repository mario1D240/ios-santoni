"""Resume missing scalar/session proofs without repeating completed components.

Consumes an exact-kernel legacy/mode1 certificate and immutable per-component
results. Emission requires every session/client/preflight component. Hardware
power acceptance is a separate controlled-packager gate, never a model output.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import traceback

from santoni_gpu_user_audit import _require

SESSION_COMPONENTS = ('identity', 'start_storage', 'bootstrap_storage', 'cold_arena',
                      'clock', 'worker_locks', 'producer_locks', 'queue', 'core', 'worker', 'producer')
SCALAR_COMPONENTS = ('open', 'device_command', 'packet', 'transactions', 'snapshots',
                     'publication', 'options_user', 'options_test', 'entry', 'producer_prefix')
PREFLIGHT_COMPONENTS = ('clock', 'attempt_bound', 'normal', 'user0', 'test0', 'test2', 'null_owner',
    'unpublished', 'deadline', 'backward', 'final_info_late', 'final_poll_late', 'stopped_clock_last_attempt',
    *(f'info_bad_{o}' for o in (64, 68, 84)),
    *(f'poll_bad_{o}' for o in (12, 96, 100, 104, 108, 112, 120)),
    *(f'submit_bad_{o}' for o in (8, 12)),
    *(f'terminal_bad_{o}' for o in (36, 40, 44, 48, 52, 56, 60, 72, 76, 80, 92)))
LEGACY_GATES = ('checked_changed_code_is_Cortex_A53_compatible',
    'GPU_driver_linked_and_BSD_startup_hook_present', 'MMIO_stores_use_real_registers_and_barriers',
    'explicit_result_cache_invalidation_present', 'request_and_pre_delay_worker_diagnostics_present',
    'first_failure_and_rollback_diagnostics_present', 'power_clock_path_is_separately_auditable',
    'checked_translation_and_clock_halt_helpers_linked', 'target_clock_setup_and_restore_wiring_checked',
    'a505_paired_stop_and_resume_wiring_checked', 'a505_vendor_SP_RMW_release_and_partial_failure_hold_checked',
    'firmware_is_not_embedded_in_CI_kernel', 'stock_A505_transition_wiring_checked',
    'stock_A505_pixel_wiring_checked', 'G3_kernel_IB_wiring_checked',
    'mode1_control_session_unreachable_checked', 'mode1_control_scalar_user_unreachable_checked')


def identity_of(record):
    return {k: record.get(k) for k in ('commit', 'ci_run', 'kernel_sha256')}


def consume(record, identity):
    _require(isinstance(record, dict) and record.get('success') is True and
             identity_of(record) == identity, 'missing/failed/different-kernel component')
    return record


def assemble(base, session, scalar, preflight, launcher=None, trace=None, evidence_folder=None):
    """No gate can become true from partial or different-kernel evidence."""
    _require(base.get('audit_scope') == 'mode1-control' and
             all(base.get(k) is True for k in LEGACY_GATES), 'incomplete legacy/control prerequisite')
    _require(re.fullmatch(r'[0-9a-f]{40}', base.get('commit', '')) is not None and
             re.fullmatch(r'[0-9a-f]{64}', base.get('kernel_sha256', '')) is not None and
             type(base.get('ci_run')) is int, 'invalid certificate identity')
    identity = identity_of(base)
    for records, required in ((session, SESSION_COMPONENTS), (scalar, SCALAR_COMPONENTS),
                              (preflight, PREFLIGHT_COMPONENTS)):
        _require(set(records) == set(required), 'missing/unreviewed aggregate component')
        for record in records.values(): consume(record, identity)
    launcher_proof = None
    if base.get('EL0_launcher_present') is True:
        from santoni_gpu_launcher_replay import (assemble_components, COMPONENTS, BASE_RUN_SHA256,
                                                LauncherMachine, _paths_tree)
        import ast
        import inspect
        import textwrap
        _require(base.get('EL0_launcher_changed_code_A53_checked') is True and
                 base.get('EL0_launcher_mount_registry_checked') is True and
                 base.get('mode1_control_EL0_launcher_unreachable_checked') is True,
                 'launcher ISA/default-off prerequisites incomplete')
        _require(isinstance(launcher, dict) and set(launcher) == {*COMPONENTS, 'interpreter'},
                 'enabled launcher requires every linked component and interpreter contract')
        linked = assemble_components({name: launcher[name] for name in COMPONENTS}, identity)
        extension = consume(launcher['interpreter'], identity)
        extra_ast = ast.dump(ast.parse(textwrap.dedent(inspect.getsource(LauncherMachine.extra_step))))
        _require(extension.get('tested_operations') == ['rev', 'mvn', 'cinc', 'ldar', 'stlr'] and
                 extension.get('shared_run_sha256') == BASE_RUN_SHA256 and
                 extension.get('extra_step_ast_sha256') == hashlib.sha256(extra_ast.encode()).hexdigest() and
                 extension.get('worker_paths_ast_sha256') == hashlib.sha256(ast.dump(_paths_tree).encode()).hexdigest() and
                 extension.get('shared_model_sha256') == hashlib.sha256(
                     (Path(__file__).parent / 'santoni_gpu_binary_model.py').read_bytes()).hexdigest() and
                 extension.get('new_contract_checks_passed') is True and
                 extension.get('completed_kernel_components_consumed_without_replay') is True and
                 extension.get('hardware_verified') is False,
                 'launcher-only interpreter evidence absent/stale/partial')
        launcher_proof = {**linked, 'interpreter': extension,
                          'launcher_certificate_complete': True, 'hardware_verified': False}
    else:
        _require(launcher is None, 'unreviewed launcher evidence for a kernel without the role')
    trace_proof = None
    default = base.get('wiring_evidence', {}).get('EL0_launcher_default_off', {})
    trace_present = default.get('trace_present', False)
    _require(type(trace_present) is bool, 'trace presence must be an explicit control boolean')
    if trace_present:
        from santoni_gpu_el0_trace_audit import validate_component
        bindings = default.get('trace_bindings', {})
        _require(launcher_proof is not None and bindings.get('success') is True and
                 isinstance(bindings.get('counter'), str), 'trace control/launcher prerequisites incomplete')
        diagnostic = bindings.get('diagnostic_address')
        if '_santoni_gpu_user_launch_trace_snapshot' in base.get('inspected_functions', ()):
            _require(bindings.get('diagnostic_present') is True and isinstance(diagnostic, str) and
                     bindings.get('diagnostic_bytes') == 40, 'trace diagnostic control binding incomplete')
        trace_proof = validate_component(trace, identity, launcher_proof['probe_sha256'],
                                         bindings['counter'], evidence_folder, diagnostic)
        from santoni_gpu_trace_dispatch_audit import validate as validate_dispatch
        _require(base.get('EL0_launcher_trace_dispatch_checked') is True,
                 'trace receiver requires the exact-kernel common vnode dispatcher')
        dispatch = validate_dispatch(base.get('wiring_evidence', {}).get('EL0_launcher_trace_dispatch'),
                                     identity, bindings)
        _require(set(dispatch['roots']) <= set(base.get('inspected_functions', ())),
                 'common trace dispatcher lacks this kernel A53 inspection')
        _require(set(trace_proof['roots']) <= set(base.get('inspected_functions', ())),
                 'trace receiver roots lack this kernel A53 inspection')
    else:
        _require(trace is None, 'unreviewed trace evidence for a kernel without the receiver')
    report = dict(base)
    report.update(audit_scope='full', permitted_modes=[0, 1, 2, 3],
                  G3_persistent_session_wiring_checked=True, G3_scalar_user_client_wiring_checked=True,
                  G3_scalar_user_preflight_wiring_checked=True, hardware_verified=False)
    wiring = dict(base['wiring_evidence'])
    wiring['G3_persistent_session'] = {**session, 'entry': scalar['entry'],
        'control_isolation': base['wiring_evidence']['mode1_control'],
        'scope': 'exact linked session components; modeled callbacks/scheduling, completed control consumed'}
    wiring['G3_scalar_user_client'] = scalar
    wiring['G3_scalar_user_preflight'] = preflight
    if launcher_proof is not None:
        wiring['EL0_launcher'] = launcher_proof
        report['EL0_launcher_wiring_checked'] = True
    if trace_proof is not None:
        wiring['EL0_launcher_trace'] = trace_proof
        report['EL0_launcher_trace_present'] = True
        report['EL0_launcher_trace_wiring_checked'] = True
    report['wiring_evidence'] = wiring
    report['review'] = 'complete linked instruction components; credentials/scheduling/GPU responses modeled, no application/hardware proof'
    report['completed_components_reused'] = True
    return report


def load_inputs(folder, decode=True):
    import check_santoni_gpu_kernel as e
    prior = folder / 'gpu-binary-audit-mode1.json'
    if not prior.exists(): prior = folder / 'gpu-binary-audit.json'
    base = json.loads(prior.read_text())
    run = json.loads((folder / 'run.json').read_text())
    data = (folder / 'kernel/kernel.development.santoni').read_bytes()
    _require(base.get('audit_scope') == 'mode1-control' and base.get('commit') == run.get('headSha') and
             base.get('ci_run') == run.get('databaseId') and run.get('status') == 'completed' and
             run.get('conclusion') == 'success' and run.get('repository_private') is True and
             base.get('kernel_sha256') == hashlib.sha256(data).hexdigest(), 'resume input identity differs')
    if not decode:
        return base, None, None, None, e
    names = e._symbols((folder / 'kernel.symbols.txt').read_text())
    image, codes = e._Image(data), {}
    noreturn = e._stack_failure_terminal(names)[0] | names.get('_panic', set()) | names.get('_Assert', set())
    # Consume the exact mode1 cold-terminal proof. Bind its saved LLVM words
    # before admitting the outlined call in its parents; never rerun mode1.
    cold = base['wiring_evidence'].get('EL0_launcher_cold_terminal_proofs', {})
    for name, record in cold.items():
        _require(isinstance(record, dict) and len(names.get(name, ())) == 1 and
                 record.get('entry') == hex(next(iter(names[name]))), 'cold component identity differs')
        text = (folder / (name[1:] + '.asm')).read_text()
        code = e._Code(text, name, next(iter(names[name])), noreturn=noreturn)
        exits = sorted(pc for pc in code.reachable if not code.succ[pc])
        _require(record.get('terminal_calls') == [hex(pc) for pc in exits] and
                 record.get('acyclic_instruction_count') == len(code.reachable) and
                 all(code.ins[pc][0] in ('bl', 'b') and e._number(code.ins[pc][1][-1]) in noreturn
                     for pc in exits), 'cold component terminal differs')
        for pc, word in re.findall(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s', text, re.M):
            _require(image.read(int(pc, 16), 4) == int(word, 16), 'cold component decoded word differs')
        noreturn.add(code.entry)
    # Resolve the inspected local identity from its saved LLVM header, then
    # bind every word to the linked bytes. Names like _io_map can also belong
    # to unrelated XNU-local functions; do not select by set iteration order.
    pending, texts = {}, {}
    for name in base['inspected_functions']:
        text = (folder / (name[1:] + '.asm')).read_text()
        texts[name] = text
        headers = [int(a, 16) for a, n in re.findall(r'^\s*([0-9a-f]+) <([^>]+)>:\s*$', text, re.M) if n == name]
        _require(headers and set(headers) <= names.get(name, set()), 'missing saved code identity ' + name)
        pending[name] = (text, set(headers))
    while pending:
        direct = {e._number(code.ins[pc][1][-1]) for code in codes.values() for pc in code.reachable
                  if code.ins[pc][0] in ('bl', 'b')}
        selected = {}
        for name, (text, candidates) in pending.items():
            callback = base['wiring_evidence']['Ops_callbacks'].get(name)
            chosen = {int(callback, 16)} & candidates if callback else candidates if len(candidates) == 1 else candidates & direct
            if len(chosen) == 1: selected[name] = (text, next(iter(chosen)))
        _require(selected, 'unresolved inspected local identities: ' + ','.join(pending))
        for name, (text, address) in selected.items():
            codes[name] = e._Code(text, name, address, noreturn=noreturn)
            names[name] = {address}
            del pending[name]
    for name, code in codes.items():
        text = texts[name]
        bound = set()
        for line in text.splitlines():
            match = re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s', line)
            if match and int(match[1], 16) in code.ins:
                pc = int(match[1], 16)
                _require(image.read(pc, 4) == int(match[2], 16), 'saved decoded input differs from linked word')
                bound.add(pc)
        _require(bound == set(code.ins), 'unbound saved decoded instruction')
    _require(e._scalar_user_helpers(names), 'scalar namespace absent')
    for name, address in base['wiring_evidence']['Ops_callbacks'].items():
        _require(codes[name].entry == int(address, 16), 'callback identity differs from completed legacy proof')
    return base, codes, image, names, e


def action(name, codes, image, names, e):
    from santoni_gpu_session_audit import (session_identity, session_start_storage,
                                          session_bootstrap_storage, session_lock_wiring)
    import santoni_gpu_session_replay as r
    if name == 'identity': return session_identity(codes, image, names)
    if name == 'start_storage': return session_start_storage(codes['_sgpu_session_start'], image, names, e)
    if name == 'bootstrap_storage': return session_bootstrap_storage(codes, image, names, e)
    if name in ('worker_locks', 'producer_locks'):
        symbol = '_sgpu_session_loop' if name == 'worker_locks' else '_sgpu_session_producer'
        return session_lock_wiring(codes[symbol], image, names, e)
    functions = {'cold_arena': r.audit_cold_arena, 'clock': r.audit_clock,
                 'queue': r.audit_queue, 'core': r.audit_core, 'worker': r.audit_worker, 'producer': r.audit_producer}
    _require(name in functions, 'unknown session component')
    return functions[name](codes, image, names, e)


def proof(folder, relative, identity):
    _require(isinstance(relative, str) and not Path(relative).is_absolute() and
             (folder / relative).resolve().is_relative_to(folder.resolve()), 'component path escapes evidence folder')
    path = folder / relative
    record = consume(json.loads(path.read_text()), identity)
    return {**record, 'record_path': relative, 'record_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def prior_scalar_proofs(folder, identity):
    # These completed, exact-kernel records are the resume checkpoint. They
    # are consumed, never regenerated by this tool. New identities reject.
    plan = json.loads((folder / 'scalar-proof-inputs.json').read_text())
    paths = plan.get('scalar')
    _require(isinstance(paths, dict) and set(paths) == set(SCALAR_COMPONENTS), 'scalar reuse plan incomplete/unreviewed')
    _require(all(isinstance(p, str) for p in paths.values()) and len(set(paths.values())) == len(paths),
             'scalar reuse plan aliases component records')
    return {k: proof(folder, relative, identity) for k, relative in paths.items()}


def prior_preflight_proofs(folder, identity):
    plan = json.loads((folder / 'scalar-proof-inputs.json').read_text())
    paths = plan.get('preflight')
    _require(isinstance(paths, dict) and set(paths) == set(PREFLIGHT_COMPONENTS), 'preflight reuse plan incomplete/unreviewed')
    _require(all(isinstance(p, str) for p in paths.values()) and len(set(paths.values())) == len(paths),
             'preflight reuse plan aliases component records')
    return {k: proof(folder, relative, identity) for k, relative in paths.items()}


def prior_launcher_proofs(folder, identity):
    from santoni_gpu_launcher_replay import COMPONENTS
    plan = json.loads((folder / 'scalar-proof-inputs.json').read_text())
    paths = plan.get('launcher')
    _require(isinstance(paths, dict) and set(paths) == {*COMPONENTS, 'interpreter'},
             'launcher reuse plan incomplete/unreviewed')
    _require(all(isinstance(path, str) for path in paths.values()) and len(set(paths.values())) == len(paths),
             'launcher reuse plan aliases component records')
    return {name: proof(folder, path, identity) for name, path in paths.items()}


def prior_trace_proof(folder, identity):
    plan = json.loads((folder / 'scalar-proof-inputs.json').read_text())
    relative = plan.get('trace')
    other = [path for group in ('scalar', 'preflight', 'launcher') for path in plan.get(group, {}).values()]
    _require(isinstance(relative, str) and relative not in other, 'trace receiver record is missing or aliased')
    return proof(folder, relative, identity)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--components', nargs='*', default=list(SESSION_COMPONENTS))
    parser.add_argument('--emit', action='store_true', help='emit only after every complete component is present')
    args = parser.parse_args()
    folder, cache = args.evidence, args.evidence / 'scalar-session-components'
    cache.mkdir(exist_ok=True)
    attempt = cache / ('attempt-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    attempt.mkdir()
    try:
        base, codes, image, names, e = load_inputs(folder, decode=bool(args.components))
        identity = identity_of(base)
        for name in args.components:
            _require(name in SESSION_COMPONENTS, 'unknown requested session component')
            path = cache / (name + '.json')
            if path.exists():
                consume(json.loads(path.read_text()), identity)
                print('Reused completed session component:', name, flush=True)
                continue
            print('Running missing session component:', name, flush=True)
            result = action(name, codes, image, names, e)
            record = {**identity, 'success': True, 'result': result,
                      'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
            with path.open('x') as stream: stream.write(json.dumps(record, indent=2) + '\n')
            print('Saved passed session component:', name, flush=True)
        if args.emit:
            session = {k: proof(folder, 'scalar-session-components/' + k + '.json', identity) for k in SESSION_COMPONENTS}
            report = assemble(base, session, prior_scalar_proofs(folder, identity), prior_preflight_proofs(folder, identity),
                              prior_launcher_proofs(folder, identity) if base.get('EL0_launcher_present') is True else None,
                              trace=prior_trace_proof(folder, identity) if base.get('wiring_evidence', {}).get(
                                  'EL0_launcher_default_off', {}).get('trace_present') is True else None,
                              evidence_folder=folder)
            report['certificate_tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            prior = folder / 'gpu-binary-audit-mode1.json'
            if not prior.exists():
                with prior.open('x') as stream: stream.write(json.dumps(base, indent=2) + '\n')
            target = folder / 'gpu-binary-audit.json'
            _require(json.loads(target.read_text()).get('audit_scope') == 'mode1-control', 'full certificate already exists; preserve it')
            text = json.dumps(report, indent=2) + '\n'
            (attempt / 'complete-certificate.json').write_text(text)
            temporary = folder / ('gpu-binary-audit-' + attempt.name + '.tmp')
            with temporary.open('x') as stream: stream.write(text)
            temporary.replace(target)
        result = {'success': True, **identity, 'emitted': args.emit}
    except Exception as error:
        result = {'success': False, 'error': str(error)}
        (attempt / 'traceback.txt').write_text(traceback.format_exc())
    (attempt / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'evidence': str(attempt), 'result': result}, indent=2))
    return 0 if result['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
