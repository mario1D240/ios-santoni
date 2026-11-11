#!/usr/bin/env python3
"""Consume recorded0214 native contracts and unchanged probe evidence in CI."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUTS = {'xnu/patches/0214-santoni-gpu-trace-path-diagnostics.patch',
          'tests/santoni_gpu_el0_trace_stubs.h', 'tests/test_santoni_gpu_el0_trace.c',
          'tests/verify_santoni_gpu_el0_trace.py', 'tests/test_santoni_gpu_late_launch.c',
          'tests/verify_santoni_gpu_late_launch.py'}
PROBE_INPUTS = {'tools/santoni_gpu_user_probe.c', 'tools/santoni_gpu_user_probe_start.S',
                'tools/build_santoni_gpu_user_probe.py', 'tools/check_santoni_gpu_user_probe.py',
                'tests/test_santoni_gpu_el0_trace_probe.c'}


def verify(path, probe_path):
    record, probe = (json.loads(Path(p).read_text()) for p in (path, probe_path))
    if (record.get('success') is not True or record.get('receiver_cases') != {'O0': 59, 'O2': 59, 'UBSan': 59} or
            record.get('late_cases') != {'O0': 33, 'O2': 33, 'UBSan': 33} or
            record.get('receiver_compiling_mutants_rejected') != 11 or
            record.get('late_compiling_mutants_rejected') != 6 or
            record.get('mechanical_apply_and_bytes_verified') is not True or
            record.get('GPU_core_MMIO_PAS_BO_lifetime_unchanged') is not True or
            record.get('hardware_verified') is not False or record.get('kernel_certified') is not False or
            set(record.get('sha256', {})) != INPUTS):
        raise ValueError('0214 native/copy/concurrency evidence incomplete')
    if (probe.get('success') is not True or probe.get('native_cases', {}).get('probe_entry') !=
            {'O0': 14, 'O2': 14, 'UBSan': 14} or probe.get('linked_probe_cases') != 22 or
            probe.get('hardware_verified') is not False or probe.get('kernel_certified') is not False or
            not PROBE_INPUTS <= set(probe.get('sha256', {}))):
        raise ValueError('unchanged independent probe evidence incomplete')
    for source, names in ((record, INPUTS), (probe, PROBE_INPUTS)):
        for name in names:
            if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != source['sha256'][name]:
                raise ValueError('recorded source changed: ' + name)
    return {'success': True, 'recorded_native_executions': 276, 'recorded_rejected_mutants': 17,
            'consumed_probe_native_executions': 42, 'consumed_independent_linked_probe_cases': 22,
            'executed_tests': 0, 'kernel_certified': False, 'hardware_verified': False}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('evidence', type=Path)
    p.add_argument('--probe-evidence', type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(verify(args.evidence, args.probe_evidence), indent=2))
