#!/usr/bin/env python3
"""Read-only CI intake of the new EL0 observation contracts; executes no tests."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
INPUTS={'xnu/patches/0211-santoni-gpu-el0-outcome-trace.patch',
    'tools/santoni_gpu_user_probe.c','tools/santoni_gpu_user_probe_start.S',
    'tools/build_santoni_gpu_user_probe.py','tools/check_santoni_gpu_user_probe.py',
    'tests/santoni_gpu_el0_trace_stubs.h','tests/test_santoni_gpu_el0_trace.c',
    'tests/test_santoni_gpu_el0_trace_probe.c','tests/verify_santoni_gpu_el0_trace.py',
    'tools/santoni_gpu_launcher_audit.py','tools/santoni_gpu_launcher_gate.py',
    'tests/test_santoni_gpu_el0_trace_gates.py'}

def verify(path):
    record=json.loads(Path(path).read_text())
    counts={'receiver':{'O0':50,'O2':50,'UBSan':50},
            'probe_entry':{'O0':14,'O2':14,'UBSan':14}}
    if (record.get('success') is not True or record.get('native_cases')!=counts or
            record.get('compiled_rejected_mutants')!=10 or record.get('linked_probe_cases')!=22 or
            record.get('new_gate_tests')!=6 or record.get('GPU_core_MMIO_PAS_BO_lifetime_unchanged') is not True or
            record.get('mechanical_apply_and_bytes_verified') is not True or
            record.get('hardware_verified') is not False or record.get('kernel_certified') is not False or
            set(record.get('sha256',{}))!=INPUTS):
        raise ValueError('new EL0 trace evidence is incomplete or incorrectly scoped')
    for name,digest in record['sha256'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest:
            raise ValueError('recorded EL0 trace source changed: '+name)
    return {'success':True,'recorded_native_cases':192,'recorded_compiling_rejected_mutants':10,
        'recorded_linked_probe_cases':22,'recorded_new_gate_tests':6,'executed_tests':0,
        'kernel_certified':False,'hardware_verified':False}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('evidence',type=Path)
    print(json.dumps(verify(p.parse_args().evidence),indent=2))
