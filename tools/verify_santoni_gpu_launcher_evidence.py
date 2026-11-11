#!/usr/bin/env python3
"""Read-only CI intake of recorded local launcher passes; executes no tests."""
import hashlib
import json
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def verify(path, declaration_patch=None, declaration_sha=None):
    r = json.loads(Path(path).read_text())
    if (r.get('success') is not True or r.get('GPU_core_unchanged') is not True or
            r.get('kernel_certified') is not False or r.get('hardware_verified') is not False or
            r.get('core_cases') != {'O0': 22, 'O2': 22, 'UBSan': 22} or
            r.get('adapter_cases') != {'O0': 40, 'O2': 40, 'UBSan': 40} or
            r.get('compiled_rejected_mutants') != 8):
        raise ValueError('recorded launcher contracts incomplete or incorrectly scoped')
    required = {'xnu/patches/0208-santoni-gpu-boot-el0-launcher.patch',
                'tests/test_santoni_gpu_launch_core.c', 'tests/test_santoni_gpu_launcher.c',
                'tests/santoni_gpu_launcher_stubs.h', 'tests/verify_santoni_gpu_launcher.py'}
    if set(r.get('sha256', {})) != required:
        raise ValueError('launcher evidence input set differs')
    for name, digest in r['sha256'].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            raise ValueError('recorded launcher input changed: ' + name)
    if declaration_patch is not None:
        data = Path(declaration_patch).read_bytes()
        if hashlib.sha256(data).hexdigest() != declaration_sha:
            raise ValueError('declaration-only patch hash differs')
        lines = data.decode().splitlines()
        added = [s[1:] for s in lines if s.startswith('+') and not s.startswith('+++ ')]
        removed = [s for s in lines if s.startswith('-') and not s.startswith('--- ')]
        if (added != ['/* BSD pmap.h omits this SPI; same declaration as santoni_gpu.c. */',
                       'extern ppnum_t pmap_find_phys(pmap_t, addr64_t);'] or removed or
                [s for s in lines if s.startswith('diff --git ')] !=
                ['diff --git a/bsd/dev/santoni_gpu_launch.c b/bsd/dev/santoni_gpu_launch.c']):
            raise ValueError('patch changes more than the missing SPI declaration')
    return {'success': True, 'recorded_core_cases': 66, 'recorded_adapter_cases': 120,
            'recorded_compiled_rejected_mutants': 8, 'executed_tests': 0,
            'kernel_certified': False, 'hardware_verified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--declaration-patch', type=Path)
    parser.add_argument('--declaration-sha')
    args = parser.parse_args()
    print(json.dumps(verify(args.evidence, args.declaration_patch, args.declaration_sha), indent=2))
