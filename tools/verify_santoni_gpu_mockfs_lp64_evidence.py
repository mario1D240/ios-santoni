#!/usr/bin/env python3
"""CI consumes the completed new LP64 contracts and source hashes; zero tests."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify(path):
    record = json.loads(Path(path).read_text())
    required = {'xnu/patches/0210-santoni-gpu-mockfs-lp64-registration.patch',
                'tests/test_santoni_gpu_mockfs_lp64.c', 'tests/verify_santoni_gpu_mockfs_lp64.py'}
    if (record.get('success') is not True or record.get('native_cases') != {'O0':18,'O2':18,'UBSan':18} or
            record.get('compiled_rejected_mutants') != 3 or record.get('hardware_verified') is not False or
            record.get('kernel_certified') is not False or set(record.get('sha256', {})) != required):
        raise ValueError('new LP64 host evidence incomplete or incorrectly scoped')
    for relative, digest in record['sha256'].items():
        if hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() != digest:
            raise ValueError('recorded LP64 source changed: ' + relative)
    return {'success': True, 'recorded_native_cases': 54, 'recorded_compiled_rejected_mutants': 3,
            'executed_tests': 0, 'kernel_certified': False, 'hardware_verified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    print(json.dumps(verify(parser.parse_args().evidence), indent=2))
