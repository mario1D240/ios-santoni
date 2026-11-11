#!/usr/bin/env python3
"""Execute only the new actual-publication observation contracts and mutants."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'bsd/dev/santoni_gpu.c'


def extract(source):
    text = (source / SOURCE).read_text()
    start = text.index('static bool __attribute__((noinline)) sgpu_user_publish(void)\n{')
    end = text.index('\n}\n', start) + 3
    body = text[start:end]
    if body.count('USER LAUNCH LATE') != 1 or body.count('if (sg.mode==3)') != 1:
        raise ValueError('late observation source missing or broadened')
    return body


def run(source, output, resume=False):
    if not resume: output.mkdir(parents=True, exist_ok=False)
    body = extract(source)
    result = {'success': False, 'source_sha256': hashlib.sha256((source / SOURCE).read_bytes()).hexdigest(),
              'function_sha256': hashlib.sha256(body.encode()).hexdigest(),
              'test_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in
                             ('tests/test_santoni_gpu_late_launch.c', 'tests/verify_santoni_gpu_late_launch.py')},
              'runs': [], 'mutants': [], 'hardware_verified': False, 'old_test_executions': 0}
    temporary = Path('/data/data/com.termux/files/usr/tmp/opencode')
    if not temporary.is_dir(): temporary = Path(tempfile.gettempdir())
    binaries = Path(tempfile.mkdtemp(prefix='late-launch-', dir=temporary))

    def one(label, options, code, mutant=False):
        dest = output / label
        if resume and (dest / 'result.json').is_file():
            record = json.loads((dest / 'result.json').read_text())
            if ((dest / 'santoni_gpu_late_launch_actual.h').read_text() != code or
                    record.get('compile_exit') != 0 or
                    (record.get('run_exit') != 0) != mutant or
                    (not mutant and len(record.get('cases', [])) != 33) or
                    (mutant and record.get('compiling_mutant_rejected') is not True)):
                raise ValueError('stale/incomplete native component: ' + label)
            print(label, 'consumed completed component; zero executions', flush=True)
            return record
        if dest.exists():
            if not resume: raise ValueError('existing native component: ' + label)
            dest = output / (label + '_resume')
        dest.mkdir()
        (dest / 'santoni_gpu_late_launch_actual.h').write_text(code)
        binary = binaries / label
        command = ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', *options,
                   '-I', str(dest), str(ROOT / 'tests/test_santoni_gpu_late_launch.c'), '-o', str(binary)]
        c = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (dest / 'compile.log').write_text(c.stdout + c.stderr)
        if c.returncode: raise RuntimeError(label + ': host compile failed')
        r = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
        (dest / 'run.log').write_text(r.stdout + r.stderr)
        cases = re.findall(r'^PASS (\S+)$', r.stdout, re.M)
        record = {'label': label, 'command': command, 'compile_exit': c.returncode,
                  'run_exit': r.returncode, 'cases': cases,
                  'compiling_mutant_rejected': mutant and r.returncode != 0}
        (dest / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
        if (r.returncode != 0) != mutant or (not mutant and len(cases) != 33):
            raise RuntimeError(label + ': unexpected contract outcome')
        print(label, 'compiling mutant rejected' if mutant else '33 new contracts passed', flush=True)
        return record

    try:
        for label, options in (('O0', ['-O0']), ('O2', ['-O2']),
                               ('UBSan', ['-O2', '-fsanitize=undefined', '-fno-sanitize-recover=all'])):
            result['runs'].append(one(label, options, body))
            (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        changes = (
            ('wrong_mode', 'if (sg.mode==3)', 'if (sg.user==1)'),
            ('locked_query', 'lck_mtx_unlock(&sgpu_session_lock);',
             'santoni_gpu_user_launch_worker_ready(sg.mode);\n    lck_mtx_unlock(&sgpu_session_lock);'),
            ('swapped_observations', 'sg.mode,ready?1u:0u,mounted?1u:0u',
             'sg.mode,mounted?1u:0u,ready?1u:0u'),
            ('swapped_diagnostics', 't.open_attempts,t.open_accepted,t.open_refused',
             't.open_accepted,t.open_attempts,t.open_refused'),
            ('locked_diagnostics', 'lck_mtx_unlock(&sgpu_session_lock);',
             'struct sgpu_launch_trace_diag locked_diag;\n'
             '    santoni_gpu_user_launch_trace_snapshot(&locked_diag);\n'
             '    lck_mtx_unlock(&sgpu_session_lock);'),
            ('empty_diagnostics', 'santoni_gpu_user_launch_trace_snapshot(&t);',
             'santoni_gpu_user_launch_trace_snapshot(&t);\n        memset(&t,0,sizeof(t));'))
        for label, old, new in changes:
            if body.count(old) != 1: raise ValueError('ambiguous mutation: ' + label)
            result['mutants'].append(one('mutant_' + label, ['-O2'], body.replace(old, new), True))
        result.update(success=True, native_cases=99, compiling_rejected_mutants=len(changes))
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        return result
    finally:
        shutil.rmtree(binaries)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--resume', action='store_true')
    args = parser.parse_args()
    if args.resume:
        retained = json.loads((args.output / 'result.json').read_text())
        expected = hashlib.sha256((args.source / SOURCE).read_bytes()).hexdigest()
        test_sha = hashlib.sha256((ROOT / 'tests/test_santoni_gpu_late_launch.c').read_bytes()).hexdigest()
        if retained.get('source_sha256') != expected or retained.get('test_sha256', {}).get(
                'tests/test_santoni_gpu_late_launch.c') != test_sha:
            raise ValueError('native source/harness changed; cannot consume retained runs')
    run(args.source.resolve(), args.output.resolve(), args.resume)
