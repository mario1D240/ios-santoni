#!/usr/bin/env python3
"""Test new launcher functions from a mechanically reconstructed XNU tree.

No old suites, probe builds, kernel builds, downloads, packaging or device calls.
The core's recorded 22-case O0/O2/UBSan pass is consumed separately; this runner
uses only new adapter/VFS/exec cases. Every result retains exact source hashes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CASES = ('normal', 'off', 'mode1', 'mode2', 'user-test', 'zap', 'scm', 'cache',
         'no-suffix', 'other-suffix', 'not-pid1', 'page16k', 'not-hfs', 'missing-dt',
         'allocation', 'noncontig', 'missing-last', 'major', 'node', 'mount',
         'mount-allocation', 'ubc', 'pager', 'bad-span', 'bad-eof', 'vnode',
         'mount-user', 'mount-no-kflag', 'mount-writable', 'mount-suid',
         'mount-noexec', 'mount-update', 'mount-root', 'mount-device',
         'mount-forged', 'mount-outside', 'init-off', 'init-fallback', 'init-single',
         'init-success')


def function(text, name):
    # Preserve actual function bytes, including comments and preprocessor guards.
    m = re.search(r'\b' + re.escape(name) + r'\([^;{}]*\)\s*\n\{', text)
    if not m:
        raise ValueError('missing actual function ' + name)
    line = text.rfind('\n', 0, m.start()) + 1
    start = line if text[line:m.start()].strip() else text.rfind('\n', 0, line - 1) + 1
    opening = text.index('{', m.start())
    depth = 0
    for end in range(opening, len(text)):
        depth += (text[end] == '{') - (text[end] == '}')
        if depth == 0:
            return text[start:end + 1]
    raise ValueError('unterminated function ' + name)


def amalgamate(source):
    targets = {'bsd/dev/santoni_gpu_launch.c': None,
               'bsd/miscfs/mockfs/mockfs_fsnode.c': ('mockfs_fsnode_create',
                   'mockfs_fsnode_destroy', 'mockfs_fsnode_adopt', 'mockfs_fsnode_orphan',
                   'mockfs_fsnode_child_by_type', 'mockfs_fsnode_vnode'),
               'bsd/miscfs/mockfs/mockfs_vfsops.c': ('mockfs_santoni_mount', 'mockfs_unmount'),
               'bsd/miscfs/mockfs/mockfs_vnops.c': ('mockfs_lookup', 'mockfs_getattr'),
               'bsd/kern/kern_exec.c': ('load_init_program_at_path', 'load_init_program')}
    chunks = ['#include "santoni_gpu_launcher_stubs.h"\n']
    for name, functions in targets.items():
        text = (source / name).read_text()
        if functions is None:
            # Only platform includes and outer board guard are removed.
            text = re.sub(r'^#include [<"].*[>"]\n', '', text, flags=re.M)
            text = text.replace('#if defined(ARM64_BOARD_CONFIG_SANTONI)\n', '', 1)
            assert text.rstrip().endswith('#endif')
            text = text.rstrip()[:-len('#endif')]
            chunks.append(text)
        else:
            if name.endswith('kern_exec.c'):
                m = re.search(r'static const char \* init_programs\[\] = \{.*?\n\};', text, re.S)
                if not m:
                    raise ValueError('missing original init selection')
                chunks.append(m.group(0))
            chunks.extend(function(text, f) for f in functions)
    chunks.append('#include "test_santoni_gpu_launcher.c"\n')
    return '\n\n'.join(chunks), targets


MUTANTS = (
    ('omit-copy-clean', 'CleanPoC_DcacheRegion_Force((vm_offset_t)kva,span_bytes);', '', 'normal'),
    ('omit-pid1-guard', 'proc_pid(current_proc())!=1', 'false', 'not-pid1'),
    ('drop-exec-failure-latch', '__atomic_load_n(&launch.stage,__ATOMIC_ACQUIRE)!=LAUNCH_PREPARING) return;',
     'false) return;', 'pager'),
    ('omit-dev-node', 'if (!error) error=mockfs_fsnode_create(mp,MOCKFS_DEV,&dev);', '', 'normal'),
    ('allow-noexec-mount', 'MNT_UPDATE|MNT_RELOAD|MNT_ROOTFS|MNT_NOEXEC',
     'MNT_UPDATE|MNT_RELOAD|MNT_ROOTFS', 'mount-noexec'),
    ('pass-pa-to-pager', 'mockfs_mnt->santoni_probe_kva,mockfs_mnt->santoni_probe_span_bytes)',
     'model.pa,mockfs_mnt->santoni_probe_span_bytes)', 'normal'),
    ('use-file-eof-as-pager-span', 'mockfs_mnt->santoni_probe_kva,mockfs_mnt->santoni_probe_span_bytes)',
     'mockfs_mnt->santoni_probe_kva,mockfs_mnt->santoni_probe_file_bytes)', 'normal'),
    ('skip-original-init-after-failed-probe', 'santoni_gpu_user_launch_exec_result(error);\n            if (!error) return;',
     'santoni_gpu_user_launch_exec_result(error);\n            return;', 'init-fallback'),
)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--probe', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--variants', nargs='+', choices=('O0', 'O2', 'UBSan'), default=['O0', 'O2', 'UBSan'])
    p.add_argument('--cases', nargs='+', choices=CASES, default=list(CASES))
    p.add_argument('--mutants', action='store_true')
    args = p.parse_args()
    if args.output.exists():
        p.error('refusing to overwrite an evidence directory')
    args.output.mkdir(parents=True)
    code, targets = amalgamate(args.source)
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    record = {'scope': 'new actual launcher functions; modeled kernel services only',
              'kernel_certified': False, 'hardware_verified': False, 'success': False,
              'sources_sha256': {n: digest(args.source / n) for n in targets},
              'test_sources_sha256': {n: digest(ROOT / 'tests' / n) for n in (
                  'verify_santoni_gpu_launcher.py', 'test_santoni_gpu_launcher.c',
                  'santoni_gpu_launcher_stubs.h')},
              'core_sha256': digest(args.source / 'bsd/dev/santoni_gpu_launch_core.c'),
              'probe_sha256': digest(args.probe), 'variants': {}, 'mutants': {}}
    result = args.output / 'result.json'
    def save():
        result.write_text(json.dumps(record, indent=2) + '\n')
    preferred = Path('/data/data/com.termux/files/usr/tmp/opencode')
    temp_root = preferred if preferred.is_dir() else None
    cc = shlex.split(os.environ.get('HOST_CC', 'clang'))
    with tempfile.TemporaryDirectory(prefix='sgpu-launch-new-', dir=temp_root) as tmp:
        tmp = Path(tmp)
        src = args.output / 'actual-launcher.c'
        src.write_text(code)
        def compile_source(path, binary, flags, log):
            cmd = [*cc, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                   '-Wno-unused-but-set-variable',  # stock mockfs_lookup's unused ctx
                   '-DARM64_BOARD_CONFIG_SANTONI', *flags, '-I', str(ROOT / 'tests'),
                   '-I', str(args.source / 'bsd/dev'), str(path),
                   str(args.source / 'bsd/dev/santoni_gpu_launch_core.c'), '-o', str(binary)]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            log.write_text(r.stdout + r.stderr)
            if r.returncode:
                raise ValueError('compile failed; see ' + str(log))
        try:
            for variant in args.variants:
                flags = ['-O0'] if variant == 'O0' else ['-O2']
                if variant == 'UBSan':
                    flags += ['-fsanitize=undefined', '-fno-sanitize-recover=all']
                binary = tmp / variant
                compile_source(src, binary, flags, args.output / (variant + '-compile.txt'))
                cases = record['variants'][variant] = {}
                for case in args.cases:
                    r = subprocess.run([str(binary), str(args.probe), case], capture_output=True,
                                       text=True, timeout=15)
                    cases[case] = {'exit_code': r.returncode, 'output': r.stdout + r.stderr}
                    save()
                    if r.returncode:
                        raise ValueError(variant + ' ' + case + ' failed')
                print(variant + ': ' + str(len(cases)) + ' new adapter cases passed', flush=True)
            if args.mutants:
                for name, old, new, case in MUTANTS:
                    if code.count(old) != 1:
                        raise ValueError('ambiguous compiling mutant ' + name)
                    mutated = args.output / (name + '.c')
                    mutated.write_text(code.replace(old, new, 1))
                    binary = tmp / name
                    compile_source(mutated, binary, ['-O2'], args.output / (name + '-compile.txt'))
                    r = subprocess.run([str(binary), str(args.probe), case], capture_output=True,
                                       text=True, timeout=15)
                    record['mutants'][name] = {'compiled': True, 'rejected': r.returncode != 0,
                                              'case': case, 'exit_code': r.returncode,
                                              'output': r.stdout + r.stderr}
                    save()
                    if not r.returncode:
                        raise ValueError('compiled mutant survived ' + name)
                print(str(len(MUTANTS)) + ' compiling mutants rejected', flush=True)
            record['success'] = True
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            record['error'] = str(error)
        save()
    print(json.dumps({'evidence': str(result), 'success': record['success'], 'error': record.get('error')}))
    return 0 if record['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
