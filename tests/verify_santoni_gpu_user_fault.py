#!/usr/bin/env python3
"""Compile actual reconstructed exception functions; no kernel or device runs."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from tests.verify_santoni_gpu_launcher import function

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'osfmk/arm64/sleh.c'
PATCHES = ('xnu/patches/0216-santoni-gpu-user-fault-observation.patch',
           'xnu/patches/0217-santoni-gpu-user-fault-osfmk-declarations.patch',
           'xnu/patches/0218-santoni-gpu-user-fault-code-boundary.patch')
HARNESS = 'tests/test_santoni_gpu_user_fault.c'
HANDLERS = ('handle_alignment_fault_from_user', 'handle_pc_align',
            'handle_sp_align', 'handle_user_abort')


def extract(text):
    return ('static uint32_t santoni_gpu_user_fault_reported;\n' +
            function(text, 'santoni_gpu_user_fault') + '\n' +
            '\n'.join(function(text, name) for name in HANDLERS))


def run(source, output):
    output.mkdir(parents=True, exist_ok=False)
    text = (source / TARGET).read_text()
    body = extract(text)
    rows = []
    preferred = Path('/data/data/com.termux/files/usr/tmp/opencode')
    with tempfile.TemporaryDirectory(prefix='user-fault-', dir=preferred if preferred.is_dir() else None) as tmp:
        temp = Path(tmp)

        def one(label, code, flags, mutant=False, baseline=False):
            dest = output / label
            dest.mkdir()
            (dest / 'santoni_gpu_user_fault_actual.h').write_text(code)
            binary = temp / label
            cmd = ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                   '-Wno-unused-function', *flags, '-I', str(dest),
                   str(ROOT / HARNESS), '-o', str(binary)]
            c = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            (dest / 'compile.log').write_text(c.stdout + c.stderr)
            row = {'label': label, 'command': cmd, 'compile_exit': c.returncode}
            if c.returncode:
                (dest / 'result.json').write_text(json.dumps(row, indent=2) + '\n')
                raise RuntimeError(label + ': compilation failed; mutant not counted')
            r = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
            (dest / 'run.log').write_text(r.stdout + r.stderr)
            cases = re.findall(r'^PASS (\S+)$', r.stdout, re.M)
            row.update(run_exit=r.returncode, cases=cases, mutant_rejected=mutant and r.returncode != 0)
            (dest / 'result.json').write_text(json.dumps(row, indent=2) + '\n')
            if (r.returncode != 0) != mutant or (not mutant and len(cases) != (3 if baseline else 24)):
                raise RuntimeError(label + ': wrong runtime outcome')
            print(label, 'compiled mutant rejected' if mutant else f'{len(cases)} cases passed', flush=True)
            rows.append(row)
            (output / 'progress.json').write_text(json.dumps(rows, indent=2) + '\n')

        variants = (('O0', ['-O0']), ('O2', ['-O2']),
                    ('UBSan', ['-O2', '-fsanitize=undefined', '-fno-sanitize-recover=all']))
        for label, flags in variants:
            one(label, body, [*flags, '-DARM64_BOARD_CONFIG_SANTONI'])
            one(label + '-other-board', body, [*flags, '-DSANTONI_FAULT_BASELINE'], baseline=True)
        changes = (
            ('kernel', '!PSR64_IS_USER(get_saved_state_cpsr(state))', 'false'),
            ('other-process', '!proc_isinitproc(p)', 'false'),
            ('mode1', 'mode!=3', 'mode==0'),
            ('disabled', 'enabled!=1', 'enabled==9'),
            ('unmounted', '!santoni_gpu_user_launch_mount_published()', 'false'),
            ('unready', '!santoni_gpu_user_launch_worker_ready(mode)', 'false'),
            ('repeat', 'true,__ATOMIC_RELAXED,__ATOMIC_RELAXED)) return;',
             'true,__ATOMIC_RELAXED,__ATOMIC_RELAXED)) {}'),
            ('swapped-pc', 'get_saved_state_pc(state),', 'get_saved_state_sp(state),'),
            ('swapped-esr', 'get_saved_state_esr(state),', '0u,'),
            ('frame-write', 'uint32_t expected=0;', 'state->pc=0;\n    uint32_t expected=0;'),
        )
        for label, old, new in changes:
            if body.count(old) != 1:
                raise ValueError('ambiguous mutant: ' + label)
            one('mutant-' + label, body.replace(old, new, 1), ['-O2', '-DARM64_BOARD_CONFIG_SANTONI'], mutant=True)
        hook = '#if defined(ARM64_BOARD_CONFIG_SANTONI)\n\tsantoni_gpu_user_fault(state, exc, codes[0], codes[1]);\n#endif\n'
        abort = function(body, 'handle_user_abort')
        if abort.count(hook) != 1:
            raise ValueError('abort hook changed')
        changed = abort.replace(hook, '').replace('\tif (is_vm_fault(fault_code)) {',
            '\tsantoni_gpu_user_fault(state, EXC_BAD_ACCESS, 0, fault_addr);\n\tif (is_vm_fault(fault_code)) {', 1)
        one('mutant-successful-fault', body.replace(abort, changed, 1),
            ['-O2', '-DARM64_BOARD_CONFIG_SANTONI'], mutant=True)
    result = {'success': True, 'source_sha256': hashlib.sha256(text.encode()).hexdigest(),
              'inputs_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
                                    for p in (*PATCHES, HARNESS, 'tests/verify_santoni_gpu_user_fault.py')},
              'native_cases': 72, 'other_board_cases': 9, 'compiled_mutants_rejected': 11,
              'runs': rows, 'hardware_verified': False, 'scope': 'actual helper and three exception routes; explicit host APIs'}
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.source.resolve(), args.output.resolve())
