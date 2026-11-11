#!/usr/bin/env python3
"""Read-only CI intake of new late-launch contracts; execute no completed tests."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUTS = {'xnu/patches/0213-santoni-gpu-late-launch-observation.patch',
          'tests/test_santoni_gpu_late_launch.c', 'tests/verify_santoni_gpu_late_launch.py'}


def verify(path):
    record = json.loads(Path(path).read_text())
    if (record.get('success') is not True or record.get('native_cases') != {'O0': 33, 'O2': 33, 'UBSan': 33} or
            record.get('compiling_rejected_mutants') != 3 or record.get('old_test_executions') != 0 or
            record.get('hardware_verified') is not False or
            record.get('mechanical_incremental_apply_and_bytes_verified') is not True or
            record.get('outside_publication_function_bytes_unchanged') is not True or
            set(record.get('sha256', {})) != INPUTS):
        raise ValueError('late-launch source/native evidence is incomplete or incorrectly scoped')
    for name, digest in record['sha256'].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            raise ValueError('late-launch evidence input changed: ' + name)
    return {'success': True, 'recorded_native_cases': 99, 'compiling_rejected_mutants': 3,
            'executed_tests': 0, 'hardware_verified': False}


def trace_native(path):
    """Consume unchanged native/probe inputs separately from updated audit tools."""
    record = json.loads(Path(path).read_text())
    if (record.get('success') is not True or record.get('native_cases') != {
            'receiver': {'O0': 50, 'O2': 50, 'UBSan': 50},
            'probe_entry': {'O0': 14, 'O2': 14, 'UBSan': 14}} or
            record.get('compiled_rejected_mutants') != 10 or record.get('linked_probe_cases') != 22 or
            record.get('hardware_verified') is not False or record.get('kernel_certified') is not False):
        raise ValueError('retained trace native/probe source evidence incomplete')
    # The metadata/late binary auditors have their separate host contracts. They
    # are not production kernel inputs and are not certified by this CI intake.
    excluded = {'tools/santoni_gpu_launcher_audit.py'}
    if not excluded <= set(record.get('sha256', {})):
        raise ValueError('retained trace record scope changed')
    for name, digest in record['sha256'].items():
        if name not in excluded and hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            raise ValueError('retained native/probe input changed: ' + name)
    return {'success': True, 'recorded_native_cases': 192, 'recorded_compiling_rejected_mutants': 10,
            'recorded_independent_probe_cases': 22, 'executed_tests': 0,
            'current_audit_tool_contracts_certified': False,
            'excluded_non_kernel_audit_inputs': sorted(excluded), 'hardware_verified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--trace-native-evidence', type=Path)
    args = parser.parse_args()
    result = verify(args.evidence)
    if args.trace_native_evidence:
        result['retained_trace_source'] = trace_native(args.trace_native_evidence)
    print(json.dumps(result, indent=2))
