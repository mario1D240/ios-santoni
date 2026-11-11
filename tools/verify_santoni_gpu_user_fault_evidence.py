#!/usr/bin/env python3
"""Consume exact recorded native observation contracts, without test replay."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUTS = ('xnu/patches/0216-santoni-gpu-user-fault-observation.patch',
          'xnu/patches/0217-santoni-gpu-user-fault-osfmk-declarations.patch',
          'xnu/patches/0218-santoni-gpu-user-fault-code-boundary.patch',
          'tests/test_santoni_gpu_user_fault.c', 'tests/verify_santoni_gpu_user_fault.py')
MUTANTS = ('kernel', 'other-process', 'mode1', 'disabled', 'unmounted', 'unready',
           'repeat', 'swapped-pc', 'swapped-esr', 'frame-write', 'successful-fault')


def verify(record, root=ROOT):
    if record.get('schema') != 1 or record.get('success') is not True or record.get('hardware_verified') is not False:
        raise ValueError('invalid native observation evidence identity/scope')
    expected = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in INPUTS}
    if record.get('inputs_sha256') != expected:
        raise ValueError('native observation inputs differ from the recorded executions')
    for row in record.get('baseline_applied', []):
        if hashlib.sha256((root / 'xnu/patches' / row['patch']).read_bytes()).hexdigest() != row['sha256']:
            raise ValueError('recorded exception baseline changed')
    if [r['patch'] for r in record.get('baseline_applied', [])] != [
            '0004-sweet-machine-config.patch', '0017-santoni-gicv2-rtclock.patch',
            '0081-topaz-armv8.0-no-lse-no-pan.patch', '0167-santoni-smp-irq.patch']:
        raise ValueError('incomplete actual exception baseline')
    if record.get('original_source_outside_helper_and_three_calls_identical') is not True:
        raise ValueError('exception handling preservation missing')
    wanted = {v: 24 for v in ('O0', 'O2', 'UBSan')}
    wanted.update({v + '-other-board': 3 for v in ('O0', 'O2', 'UBSan')})
    wanted.update({'mutant-' + m: None for m in MUTANTS})
    rows = record.get('runs', [])
    if len(rows) != len(wanted) or {r.get('label') for r in rows} != set(wanted):
        raise ValueError('native observation variant/mutant inventory differs')
    for r in rows:
        count = wanted[r['label']]
        if r.get('compile_exit') != 0:
            raise ValueError('noncompiling variant cannot count as a rejected mutant')
        if count is None:
            if r.get('run_exit') == 0 or r.get('mutant_rejected') is not True:
                raise ValueError('unsafe observation variant was not rejected')
        elif r.get('run_exit') != 0 or r.get('case_count') != count:
            raise ValueError('native observation cases incomplete')
    return {'success': True, 'consumed_native_cases': 72, 'consumed_other_board_cases': 9,
            'consumed_compiled_mutants': 11, 'test_executions': 0, 'hardware_verified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(json.loads(args.record.read_text())), indent=2))
