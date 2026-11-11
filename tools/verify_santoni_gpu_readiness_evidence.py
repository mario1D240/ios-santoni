#!/usr/bin/env python3
"""Consume recorded exact readiness contracts without native replay."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
INPUTS = ('xnu/patches/0219-santoni-gpu-el0-readiness-trace.patch',
          'tests/test_santoni_gpu_readiness.c', 'tests/verify_santoni_gpu_readiness.py',
          'tests/test_santoni_gpu_user_probe.c', 'tools/santoni_gpu_user_probe.c',
          'tests/verify_santoni_gpu_launcher.py', 'tests/reconstruct_santoni_touch.py')


def verify(record, root=ROOT):
    from tests.verify_santoni_gpu_readiness import MUTANTS
    from tests.reconstruct_santoni_touch import selected_sections
    if (record.get('success') is not True or record.get('hardware_verified') is not False or
            record.get('synthetic_schedule_only') is not True or record.get('probe_source_unchanged') is not True):
        raise ValueError('readiness evidence scope differs')
    expected = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in INPUTS}
    if record.get('inputs_sha256') != expected:
        raise ValueError('readiness evidence source inputs changed')
    targets = ('bsd/dev/santoni_gpu.c', 'bsd/dev/santoni_gpu_core.c', 'bsd/dev/santoni_gpu_core.h',
               'bsd/dev/santoni_gpu_launch.c', 'bsd/dev/santoni_gpu_launch.h',
               'bsd/dev/santoni_gpu_launch_core.c', 'bsd/dev/santoni_gpu_launch_core.h',
               'bsd/dev/santoni_gpu_launch_trace.h')
    baseline_paths = {str(p.relative_to(root)) for p in (root / 'xnu/patches').glob('*.patch')
                      if p.name[:4].isdigit() and int(p.name[:4]) <= 218 and
                      selected_sections(p.read_bytes(), targets)}
    if set(record.get('baseline_inputs_sha256', {})) != baseline_paths:
        raise ValueError('readiness baseline input inventory differs')
    for path, digest in record['baseline_inputs_sha256'].items():
        if hashlib.sha256((root / path).read_bytes()).hexdigest() != digest:
            raise ValueError('readiness baseline changed')
    rows = record.get('runs', [])
    labels = {'O0', 'O2', 'UBSan', 'O0-baseline', 'O2-baseline', 'UBSan-baseline'} | {'mutant-'+m for m in MUTANTS}
    if len(rows) != len(labels) or {r.get('label') for r in rows} != labels:
        raise ValueError('readiness native inventory differs')
    for row in rows:
        if row.get('compile_exit') != 0:
            raise ValueError('noncompiling readiness mutation cannot count')
        if row['label'].startswith('mutant-'):
            if row.get('run_exit') == 0 or row.get('mutant_rejected') is not True:
                raise ValueError('readiness mutation was not rejected')
        elif row.get('run_exit') != 0 or row.get('case_count') != 41:
            raise ValueError('readiness contract incomplete')
    if (record.get('baseline_readiness_us'), record.get('new_readiness_us')) != (106000000, 40000000):
        raise ValueError('synthetic readiness schedule differs')
    return {'success': True, 'consumed_native_cases': 246, 'consumed_compiled_mutants': 8,
            'test_executions': 0, 'hardware_verified': False}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('record', type=Path)
    print(json.dumps(verify(json.loads(p.parse_args().record.read_text())), indent=2))
