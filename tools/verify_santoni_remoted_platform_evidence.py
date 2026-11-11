#!/usr/bin/env python3
"""Read-only CI intake of new0212 contracts; never execute completed tests."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUTS = {
    'xnu/patches/0212-santoni-remoted-platform-workaround.patch',
    'tests/test_santoni_remoted_platform.c', 'tests/santoni_remoted_platform_stubs.h',
    'tests/verify_santoni_remoted_platform.py', 'tests/test_santoni_remoted_platform_other.c',
    'tests/verify_santoni_remoted_platform_other.py',
}
MUTANTS = {'mutant_default_on', 'mutant_path_identity', 'mutant_invent_signature',
           'mutant_invalid_blob', 'mutant_unconditional_exec', 'mutant_query_default_on'}


def verify(path):
    record = json.loads(Path(path).read_text())
    counts = {'santoni': {'O0': 52, 'O2': 52, 'UBSan': 52},
              'other_board': {'O0': 6, 'O2': 6, 'UBSan': 6}}
    if (record.get('success') is not True or record.get('native_cases') != counts or
            record.get('native_total') != 174 or record.get('compiled_rejected_mutants') != 6 or
            set(record.get('mutants', ())) != MUTANTS or
            record.get('mechanical_apply_and_bytes_verified') is not True or
            record.get('GPU_core_MMIO_PAS_BO_lifetime_unchanged') is not True or
            record.get('hardware_verified') is not False or record.get('kernel_certified') is not False or
            type(record.get('old_test_executions')) is not int or record['old_test_executions'] != 0 or
            set(record.get('sha256', {})) != INPUTS):
        raise ValueError('new remoted platform evidence is incomplete or incorrectly scoped')
    cases = record.get('case_names', {})
    if (set(cases) != {'santoni', 'other_board'} or len(set(cases['santoni'])) != 52 or
            len(cases['santoni']) != 52 or len(set(cases['other_board'])) != 6 or
            len(cases['other_board']) != 6 or not {
                'helper/default_off', 'helper/invalid_blob', 'helper/no_signature_claim',
                'helper/other_root_path', 'helper/cryptex_alias_refused',
                'exec/mac_policy_failure', 'exec/thread_signature_failure',
                'exec/inherited_platform_cleared'} <= set(cases['santoni'])):
        raise ValueError('new remoted platform contract scope is incomplete')
    for name, digest in record['sha256'].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            raise ValueError('recorded remoted platform source changed: ' + name)
    return {'success': True, 'recorded_native_cases': 174, 'recorded_compiling_rejected_mutants': 6,
            'executed_tests': 0, 'kernel_certified': False, 'hardware_verified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    print(json.dumps(verify(parser.parse_args().evidence), indent=2))
