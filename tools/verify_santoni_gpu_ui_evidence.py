#!/usr/bin/env python3
"""Consume the recorded actual UI contracts, bound to current production bytes.

The retained receipt records native execution with modeled MMIO and IOKit. It
does not certify a kernel binary or phone presentation. No tests are replayed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
FILES = ('bsd/dev/santoni_gpu.c', 'bsd/dev/santoni_gpu_core.c',
         'bsd/dev/santoni_gpu_core.h', 'iokit/Kernel/arm/SweetFramebuffer.cpp')
INPUTS = ('tests/test_santoni_gpu_ui.py', 'tests/test_santoni_gpu_ui.c',
          'tests/test_santoni_gpu_ui_adapter.c', 'tests/test_santoni_gpu_ui_framebuffer.cpp',
          'tests/test_santoni_gpu_live.c', 'tests/test_santoni_gpu_live_adapter.c',
          'tests/test_santoni_gpu_session.c')
MUTANTS = ('late-pa', 'duplicate', 'table-alias', 'owned-change', 'report-isolation',
           'stop', 'route', 'tlbi', 'readonly', 'fence', 'cpu-cache', 'wrap')
DISABLED_SNAPSHOT_STUB = '''void sgpu_ui_snapshot(struct sgpu_ui_result *out){
    (void)out;assert(!"legacy UI role must stay disabled");
}
'''


def input_equivalence(record, root):
    """Admit only a link stub inside the block excluded by the actual UI test.

    Reconstruct the prior complete fixture by removing these exact new bytes,
    bind it to the saved hash, then prove identical UI extraction. Any other
    harness/model edit still requires new execution evidence.
    """
    expected = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in INPUTS}
    recorded = record.get('inputs', {})
    if set(recorded) != set(expected):
        raise ValueError('UI native input inventory changed')
    changed = {p for p in INPUTS if recorded.get(p) != expected[p]}
    fixture = 'tests/test_santoni_gpu_live_adapter.c'
    if not changed:
        return False
    if changed != {fixture}:
        raise ValueError('UI native harness/model bytes changed')
    current = (root / fixture).read_text()
    if current.count(DISABLED_SNAPSHOT_STUB) != 1:
        raise ValueError('UI evidence cannot rebind another fixture delta')
    prior = current.replace(DISABLED_SNAPSHOT_STUB, '', 1)
    if hashlib.sha256(prior.encode()).hexdigest() != recorded[fixture]:
        raise ValueError('UI prior fixture reconstruction differs')
    def excluded(text):
        prefix = text.split('#include "santoni_gpu_live_adapter_actual.h"', 1)[0]
        begin = prefix.index('/* This legacy worker harness')
        end = prefix.index('static unsigned testcase', begin)
        return prefix[:begin] + prefix[end:]
    if excluded(current) != excluded(prior):
        raise ValueError('UI generated adapter input changed')
    return True


def verify(record, root=ROOT):
    from tests.native_santoni_gpu_core import reconstruct
    equivalent_fixture = input_equivalence(record, root)
    with tempfile.TemporaryDirectory(prefix='ui-intake-') as directory:
        manifest = reconstruct(Path(directory) / 'source', targets=FILES)
    hashes = manifest['sha256']
    native_inputs = ('tests/native_santoni_gpu_core.py', 'tests/reconstruct_santoni_touch.py')
    if record.get('native_link_inputs_sha256') != {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in native_inputs}:
        raise ValueError('UI native VM link helper changed')
    native_source = {**hashes, **manifest['dependencies'], **manifest['native_link_dependencies']}
    if record.get('native_source_sha256') != native_source:
        raise ValueError('UI native module/header bytes changed')
    identity = {'core_sha256': hashes[FILES[1]], 'adapter_sha256': hashes[FILES[0]],
                'framebuffer_sha256': hashes[FILES[3]]}
    if record.get('identity') != identity:
        raise ValueError('UI native reconstructed production bytes changed')
    inventory = {v: 20 for v in ('O0', 'O2', 'ubsan')}
    inventory.update({'adapter-' + v: 25 for v in ('O0', 'O2', 'ubsan')})
    inventory.update({'framebuffer-' + v: 20 for v in ('O0', 'O2', 'ubsan')})
    labels = set(inventory) | {'mutant-' + n for n in MUTANTS}
    rows = record.get('rows', [])
    if len(rows) != len(labels) or {r.get('name') for r in rows} != labels:
        raise ValueError('UI native variants or mutation inventory incomplete')
    for row in rows:
        if type(row.get('compile_exit')) is not int or row['compile_exit'] != 0:
            raise ValueError('noncompiling UI contract/mutant does not count')
        runs = row.get('runs', [])
        if row['name'].startswith('mutant-'):
            if len(runs) != 1 or type(runs[0].get('exit')) is not int or runs[0]['exit'] == 0:
                raise ValueError('compiled unsafe UI mutant survived')
        elif ([r.get('case') for r in runs] != list(range(inventory[row['name']])) or
              any(type(r.get('exit')) is not int or r['exit'] != 0 for r in runs)):
            raise ValueError('UI positive execution inventory differs')
        if row['name'] in ('O0', 'O2', 'ubsan'):
            if row.get('source_sha256') != identity['core_sha256']:
                raise ValueError('UI compiled core bytes differ')
            if 'frames=64 wraps=4' not in runs[0].get('stdout', ''):
                raise ValueError('UI alternating imports and circular ring were not exercised')
    return {'success': True, 'source_sha256': hashes, 'positive_executions': 195,
            'compiled_rejected_mutants': 12, 'test_executions': 0,
            'excluded_legacy_fixture_stub_equivalence_verified': equivalent_fixture,
            'hardware_verified': False, 'kernel_binary_verified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    print(json.dumps(verify(json.loads(parser.parse_args().record.read_text())), indent=2))
