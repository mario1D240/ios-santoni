#!/usr/bin/env python3
"""Consume the recorded common-dispatch host contracts without rerunning them."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUTS = {'xnu/patches/0215-santoni-gpu-trace-vnode-dispatch.patch',
          'tests/verify_santoni_gpu_trace_dispatch.py', 'tests/test_santoni_gpu_trace_dispatch.c',
          'tests/santoni_gpu_trace_dispatch_stubs.h', 'tests/verify_santoni_gpu_launcher.py',
          'tests/verify_santoni_gpu_el0_trace.py'}


def verify(path):
    record = json.loads(Path(path).read_text())
    if (record.get('success') is not True or record.get('cases') != {'O0': 28, 'O2': 28, 'UBSan': 28} or
            record.get('baseline_cases') != {'O0': 2, 'O2': 2, 'UBSan': 2} or
            record.get('compiled_mutants_rejected') != 11 or
            record.get('mechanical_apply_and_bytes_verified') is not True or
            record.get('GPU_MMIO_PAS_lifetimes_unchanged') is not True or
            record.get('hardware_verified') is not False or record.get('kernel_certified') is not False or
            set(record.get('sha256', {})) != INPUTS):
        raise ValueError('incomplete or incorrectly scoped common-dispatch host evidence')
    for name in INPUTS:
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != record['sha256'][name]:
            raise ValueError('recorded common-dispatch input changed: ' + name)
    return {'success': True, 'recorded_native_executions': 90, 'recorded_compiled_mutants_rejected': 11,
            'executed_tests': 0, 'hardware_verified': False, 'kernel_certified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    print(json.dumps(verify(parser.parse_args().evidence), indent=2))
