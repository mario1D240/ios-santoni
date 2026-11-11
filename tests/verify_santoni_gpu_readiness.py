#!/usr/bin/env python3
"""Compile exact new trace/getters and existing probe with a synthetic schedule."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from tests.verify_santoni_gpu_launcher import function

ROOT = Path(__file__).resolve().parents[1]
MUTANTS = {
    'mode': ('mode != 3', 'mode == 3'),
    'enabled': ('enabled != 1', 'enabled == 1'),
    'options': ('enum sgpu_launch_role role=sgpu_launch_role(&o);', 'enum sgpu_launch_role role=SG_LAUNCH_ON;'),
    'worker': ('!santoni_gpu_user_launch_worker_ready(mode)', 'false'),
    'mount': ('!santoni_gpu_user_launch_mount_published()', 'false'),
    'prefix': ('strncmp(message, "before ", 7) == 0', 'strncmp(message, "before ", 7) != 0'),
    'pause': ('sgpu_kernel_wait_us(NULL, 11000000u)', 'sgpu_kernel_wait_us(NULL, 1000000u)'),
    'print': ('message, a, b, c);', 'message, b, a, c);'),
}


def amalgamate(source, baseline=False, mutant=None):
    source = Path(source)
    adapter = (source / 'bsd/dev/santoni_gpu.c').read_text()
    launcher = (source / 'bsd/dev/santoni_gpu_launch.c').read_text()
    core = (source / 'bsd/dev/santoni_gpu_launch_core.c').read_text()
    state = re.search(r'enum \{ LAUNCH_NEW,.*?\} launch=\{\.major=-1\};', launcher, re.S)
    if not state:
        raise ValueError('missing actual launcher state declaration')
    chunks = [state.group(0), function(core, 'sgpu_launch_role')]
    chunks += [function(launcher, name) for name in ('launch_options',
        'santoni_gpu_user_launch_options_ok', 'santoni_gpu_user_launch_worker_ready',
        'santoni_gpu_user_launch_mount_published')]
    if not baseline:
        chunks.append(function(adapter, 'sgpu_trace_pause_required'))
    chunks.append(function(adapter, 'trace'))
    text = '\n\n'.join(chunks) + '\n'
    if mutant:
        old, new = MUTANTS[mutant]
        if text.count(old) != 1:
            raise ValueError('ambiguous readiness mutation: ' + mutant)
        text = text.replace(old, new)
    return text


def run(source, baseline, output):
    output = Path(output); output.mkdir(exist_ok=False)
    fixture = (ROOT / 'tests/test_santoni_gpu_user_probe.c').read_text()
    old = 'm.scenario==OPEN_DELAY && m.waits<3'
    if fixture.count(old) != 1:
        raise ValueError('probe fixture startup condition changed')
    fixture = fixture.replace(old, 'm.scenario==OPEN_DELAY && m.clock<readiness_at')
    fixture = fixture.replace('int main(int argc,char **argv)', 'int probe_fixture_main(int argc,char **argv)')
    fixture = fixture.replace('../tools/santoni_gpu_user_probe.c', str(ROOT / 'tools/santoni_gpu_user_probe.c'))
    (output / 'readiness_probe_fixture.h').write_text(fixture)
    variants = [('O0', ['-O0']), ('O2', ['-O2']),
                ('UBSan', ['-O1', '-fsanitize=undefined', '-fno-sanitize-recover=all'])]
    jobs = [(v, flags, False, None) for v, flags in variants]
    jobs += [(v+'-baseline', flags, True, None) for v, flags in variants]
    jobs += [('mutant-'+m, ['-O2'], False, m) for m in MUTANTS]
    rows = []
    for label, flags, old, mutant in jobs:
        (output / 'actual_readiness.h').write_text(amalgamate(baseline if old else source, old, mutant))
        binary = output / label
        cmd = ['clang', '-std=c11', *flags, '-Wall', '-Wextra', '-Werror',
               '-Wno-unused-function', '-I', str(Path(source) / 'bsd/dev'), '-I', str(output),
               str(ROOT / 'tests/test_santoni_gpu_readiness.c'), '-o', str(binary)]
        if old: cmd.insert(2, '-DREADINESS_BASELINE')
        compiled = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        (output / (label+'-compile.log')).write_text(compiled.stdout+compiled.stderr)
        row = {'label': label, 'compile_exit': compiled.returncode}
        rows.append(row)
        if compiled.returncode:
            print(compiled.stderr); raise ValueError('noncompiling readiness variant: '+label)
        result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
        (output / (label+'-run.log')).write_text(result.stdout+result.stderr)
        row.update(run_exit=result.returncode, mutant_rejected=bool(mutant and result.returncode),
                   case_count=41 if not mutant else None)
        if bool(result.returncode) != bool(mutant):
            print(result.stdout+result.stderr); raise ValueError('readiness contract failed: '+label)
        print('Passed '+label, flush=True)
    record = {'schema': 1, 'success': True, 'hardware_verified': False, 'runs': rows,
              'source_sha256': hashlib.sha256((Path(source)/'bsd/dev/santoni_gpu.c').read_bytes()).hexdigest(),
              'synthetic_schedule_only': True, 'probe_source_unchanged': True,
              'baseline_readiness_us': 106000000, 'new_readiness_us': 40000000}
    (output / 'result.json').write_text(json.dumps(record, indent=2)+'\n')
    return record


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--baseline', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(run(a.source, a.baseline, a.output), indent=2))
