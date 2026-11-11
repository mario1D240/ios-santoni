#!/usr/bin/env python3
"""Consume unchanged host interpreter contracts and newly linked components.

Origin copies retain their original kernel labels as provenance. Only interpreter
semantics are reused; every linked component must belong to the destination CI.
This tool runs no tests, decoded instructions or hardware commands.
"""
import argparse
import ast
import hashlib
import inspect
import json
from pathlib import Path
import textwrap

import santoni_gpu_launcher_replay as launcher
from santoni_gpu_scalar_certificate import identity_of, load_inputs, proof

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def semantic_pins():
    extra = ast.dump(ast.parse(textwrap.dedent(inspect.getsource(launcher.LauncherMachine.extra_step))))
    return {
        'tested_operations': ['rev', 'mvn', 'cinc', 'ldar', 'stlr'],
        'shared_run_sha256': launcher.BASE_RUN_SHA256,
        'extra_step_ast_sha256': digest(extra.encode()),
        'worker_paths_ast_sha256': digest(ast.dump(launcher._paths_tree).encode()),
        'shared_model_sha256': digest((Path(__file__).parent / 'santoni_gpu_binary_model.py').read_bytes()),
    }


def host_chain(origin):
    """Follow the recorded copy path, never guess a conventional filename."""
    path, seen, chain = Path(origin).resolve(), set(), []
    pins = semantic_pins()
    for _ in range(8):
        launcher.require(path not in seen, 'cyclic interpreter host origin')
        seen.add(path)
        data = path.read_bytes()
        record = json.loads(data)
        launcher.require(isinstance(record, dict) and record.get('success') is True and
                         record.get('hardware_verified') is False and
                         record.get('new_contract_checks_passed') is True and
                         record.get('completed_kernel_components_consumed_without_replay') is True and
                         all(record.get(key) == value for key, value in pins.items()),
                         'interpreter host semantics or completed scope changed')
        chain.append({'path': str(path), 'sha256': digest(data), 'data': data,
                      'identity': identity_of(record)})
        relative = record.get('origin_record_copy')
        if relative is None:
            launcher.require(isinstance(record.get('initial_instruction_contract'), str) and
                             isinstance(record.get('initial_instruction_contract_sha256'), str) and
                             isinstance(record.get('additional_completed_checks'), list) and
                             record['additional_completed_checks'] and
                             all(type(check.get('tests')) is int and check['tests'] > 0 and
                                 type(check.get('exit_code')) is int and check['exit_code'] == 0
                                 for check in record['additional_completed_checks']),
                             'interpreter leaf lacks recorded executed host contracts')
            return pins, chain
        launcher.require(record.get('prior_kernel_linked_components_transferred') is False and
                         type(record.get('host_contract_tests_executed_in_this_resume')) is int and
                         record['host_contract_tests_executed_in_this_resume'] == 0 and
                         isinstance(relative, str) and not Path(relative).is_absolute(),
                         'interpreter wrapper transfers kernel proof or has an invalid origin')
        root = path.parent.parent.resolve()
        next_path = (root / relative).resolve()
        launcher.require(next_path.is_relative_to(root), 'interpreter origin copy escapes its CI folder')
        if not next_path.is_file():
            # A verbatim wrapper snapshot retains paths relative to its source CI.
            # Follow its declared original record, with the same hash/identity
            # checks below; never substitute a guessed filename or kernel record.
            original = record.get('independent_host_contract_origin')
            launcher.require(isinstance(original, str) and original,
                             'interpreter copy and recorded source origin are absent')
            next_path = (PROJECT_ROOT / original).resolve()
            launcher.require(next_path.is_relative_to((PROJECT_ROOT / 'out').resolve()),
                             'recorded interpreter source origin escapes project evidence')
        next_data = next_path.read_bytes()
        launcher.require(digest(next_data) == record.get('independent_host_contract_origin_sha256') and
                         identity_of(json.loads(next_data)) == record.get('origin_wrapper_identity'),
                         'interpreter origin copy hash or original identity changed')
        path = next_path
    raise ValueError('interpreter host origin chain exceeds eight records')


def emit(folder, origin):
    folder = Path(folder).resolve()
    base, *_ = load_inputs(folder, decode=False)
    identity = identity_of(base)
    records = {name: proof(folder, 'launcher-components/' + name + '.json', identity)
               for name in launcher.COMPONENTS}
    launcher.assemble_components(records, identity)
    pins, chain = host_chain(origin)
    cache = folder / 'launcher-components'
    target = cache / 'interpreter.json'
    launcher.require(not target.exists(), 'interpreter certificate already exists; preserve it')
    copies = cache / 'interpreter-origin'
    launcher.require(not copies.exists(), 'interpreter origin snapshots already exist; preserve them')
    copies.mkdir()
    origins = []
    for i, item in enumerate(chain):
        path = copies / ('level-' + str(i) + '.json')
        with path.open('xb') as stream:
            stream.write(item['data'])
        origins.append({key: value for key, value in item.items() if key != 'data'})
        origins[-1]['record_path'] = str(path.relative_to(folder))
    result = {
        **identity, **pins, 'success': True, 'hardware_verified': False,
        'new_contract_checks_passed': True,
        'completed_kernel_components_consumed_without_replay': True,
        'host_contract_tests_executed_in_this_resume': 0,
        'prior_kernel_linked_components_transferred': False,
        'new_kernel_linked_component_records': {
            name: {key: record[key] for key in ('record_path', 'record_sha256')}
            for name, record in records.items()},
        'independent_host_contract_origin': chain[-1]['path'],
        'independent_host_contract_origin_sha256': chain[-1]['sha256'],
        'origin_wrapper_identity': chain[-1]['identity'],
        'origin_record_copy': origins[-1]['record_path'], 'host_origin_chain': origins,
        'scope': 'unchanged independent host semantics only; all nine destination-kernel linked components consumed separately; hardware unproven',
    }
    with target.open('x') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    return {'success': True, **identity, 'record': str(target), 'origin_records': len(chain),
            'linked_components_consumed': len(records), 'executed_tests': 0,
            'executed_linked_cases': 0, 'hardware_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ci', type=Path)
    parser.add_argument('--origin', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(emit(args.ci, args.origin), indent=2))


if __name__ == '__main__':
    main()
