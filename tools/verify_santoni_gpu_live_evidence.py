#!/usr/bin/env python3
"""Consume the new exact live-native source/contracts without replay."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
INPUTS = ('xnu/patches/0221-santoni-gpu-live-offscreen-blits.patch',
          'xnu/patches/0222-santoni-gpu-live-cp-readback.patch',
          'tests/test_santoni_gpu_live.c', 'tests/test_santoni_gpu_live_adapter.c',
          'tests/test_santoni_gpu_live.py', 'tests/test_santoni_gpu_session.c',
          'tests/test_santoni_gpu_mock.c', 'tests/reconstruct_santoni_touch.py')
MUTANTS = ('halt', 'disable-cb', 'fault-route', 'restore-route', 'skip-asid', 'skip-sync',
           'cp-unknown-bits', 'cp-state-bypass', 'cp-one-request', 'cp-other-request', 'cp-resume-unknown-bits',
           'skip-tlb-wait', 'actual-root', 'legacy-mapping', 'retention', 'padding', 'compare',
           'private-fence', 'offset', 'foreign-client', 'mode2', 'late-pmap', 'free-exposed', 'wrong-dispatch')


def verify(record):
    from tests.test_santoni_gpu_live import CORE_CASES, ADAPTER_CASES
    from tests.native_santoni_gpu_core import reconstruct
    if record.get('success') is not True or record.get('hardware_verified') is not False:
        raise ValueError('live native evidence scope differs')
    expected = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in INPUTS}
    if record.get('inputs_sha256') != expected: raise ValueError('live native input bytes changed')
    native_inputs = ('tests/native_santoni_gpu_core.py',)
    if record.get('native_link_inputs_sha256') != {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in native_inputs}:
        raise ValueError('live native VM link helper changed')
    with tempfile.TemporaryDirectory(prefix='live-intake-') as directory:
        source = reconstruct(Path(directory) / 'source', targets=('bsd/dev/santoni_gpu.c',
            'bsd/dev/santoni_gpu_core.c', 'bsd/dev/santoni_gpu_core.h'))
    if record.get('source') != source: raise ValueError('live native reconstructed bytes changed')
    labels = {v + '-' + k for v in ('O0', 'O2', 'ubsan') for k in ('core', 'adapter')} | {'mutant-' + n for n in MUTANTS} | {'baseline-captured'}
    rows = record.get('commands', [])
    if len(rows) != len(labels) or {r.get('name') for r in rows} != labels: raise ValueError('live native inventory incomplete')
    executions = 0
    for row in rows:
        if type(row.get('compile_exit')) is not int or row['compile_exit'] != 0:
            raise ValueError('noncompiling live mutant does not count')
        runs = row.get('runs', [])
        if row['name'].startswith('mutant-') or row['name'] == 'baseline-captured':
            if len(runs) != 1 or type(runs[0].get('exit_code')) is not int or runs[0]['exit_code'] == 0:
                raise ValueError('live unsafe mutant survived')
        else:
            cases = CORE_CASES if row['kind'] == 'core' else ADAPTER_CASES
            if len(runs) != len(cases) or [r.get('case') for r in runs] != list(cases) or any(type(r.get('case')) is not int or type(r.get('exit_code')) is not int or r['exit_code'] != 0 for r in runs):
                raise ValueError('live positive contracts incomplete')
            executions += len(runs)
    if executions != 189: raise ValueError('live native execution count differs')
    return {'success': True, 'native_positive_cases': 189, 'compiled_rejected_mutants': 24,
            'compiled_captured_baseline_rejected': True,
            'test_executions': 0, 'hardware_verified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('record', type=Path)
    print(json.dumps(verify(json.loads(parser.parse_args().record.read_text())), indent=2))
