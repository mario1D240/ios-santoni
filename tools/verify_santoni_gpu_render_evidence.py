#!/usr/bin/env python3
"""Consume the recorded 0220 actual-function native contracts without replay."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
INPUTS = ('xnu/patches/0220-santoni-gpu-render-contract.patch',
          'xnu/patches/0221-santoni-gpu-live-offscreen-blits.patch',
          'xnu/patches/0222-santoni-gpu-live-cp-readback.patch',
          'xnu/patches/0223-santoni-gpu-ui-presentation.patch',
          'tests/test_santoni_gpu_render.c', 'tests/test_santoni_gpu_render.py',
          'tests/reconstruct_santoni_touch.py')
MUTANTS = ('owner', 'guard', 'late-page', 'stride', 'format', 'source-address', 'stale-handle',
           'busy-alias', 'exposure-free', 'skip-clean', 'fence-match', 'no-idle', 'ignore-fault',
           'skip-invalidate', 'lost-first-error', 'timeout-cap')
ABI = 'ABI arena=4384 memory=88 bo=40 plane=24 ops=120; bo=96 next_handle=4352 busy=4364 error=4368 initialized=4376'


def verify(record, root=ROOT):
    if record.get('success') is not True or record.get('hardware_verified') is not False:
        raise ValueError('render native evidence scope differs')
    expected = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in INPUTS}
    if record.get('inputs_sha256') != expected:
        raise ValueError('render native input bytes differ')
    native_inputs = ('tests/native_santoni_gpu_core.py',)
    if record.get('native_link_inputs_sha256') != {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in native_inputs}:
        raise ValueError('render native VM link helper changed')
    from tests.native_santoni_gpu_core import reconstruct
    with tempfile.TemporaryDirectory(prefix='render-intake-') as directory:
        source = reconstruct(Path(directory) / 'source', targets=(
            'bsd/dev/santoni_gpu_core.c', 'bsd/dev/santoni_gpu_core.h'))
    if record.get('source') != source:
        raise ValueError('render native reconstructed source differs')
    labels = {'O0', 'O2', 'ubsan'} | {m + '-' + v for m in MUTANTS for v in ('O0', 'O2', 'ubsan')}
    rows = record.get('commands', [])
    if len(rows) != 51 or {r.get('name') for r in rows} != labels:
        raise ValueError('render native inventory is incomplete')
    for row in rows:
        if type(row.get('compile_exit')) is not int or row['compile_exit'] != 0:
            raise ValueError('noncompiling render mutant does not count')
        positive = row['name'] in ('O0', 'O2', 'ubsan')
        if positive:
            if type(row.get('exit_code')) is not int or row['exit_code'] != 0 or ABI not in row.get('stdout', ''):
                raise ValueError('render contract/ABI variant did not pass')
        elif type(row.get('exit_code')) is not int or row['exit_code'] == 0:
            raise ValueError('unsafe render mutant survived')
    return {'success': True, 'positive_variants': 3, 'compiled_rejected_mutants': 48,
            'test_executions': 0, 'hardware_verified': False, 'native_ABI_checked': True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('record', type=Path)
    print(json.dumps(verify(json.loads(parser.parse_args().record.read_text())), indent=2))
