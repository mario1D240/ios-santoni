#!/usr/bin/env python3
"""Execute the actual ioctl -> fo_ioctl -> vn_ioctl -> mockfs trace route.

Function bytes are extracted unchanged from a supplied reconstruction. Kernel
services and structure layouts are explicit host contracts, not hardware proof.
The supplied pre-0215 vnode function is also compiled to demonstrate ENOTTY.
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

import verify_santoni_gpu_launcher as extract
import verify_santoni_gpu_el0_trace as receiver

ROOT = Path(__file__).resolve().parents[1]
CASES = ('entry', 'result', 'failure-result', 'other-vector', 'directory',
         'other-command', 'wide-command', 'copyin-error', 'file-mac', 'vnode-mac',
         'vnode-get', 'bad-fd', 'no-access', 'off', 'mode1', 'mode2', 'nonroot',
         'kernel-context', 'other-executable', 'backing', 'record', 'reserved',
         'quota', 'write-descriptor', 'character', 'block', 'fifo', 'fionread')
MUTANTS = (
    ('drop-vector', 'com == SGPU_LAUNCH_TRACE_IOCTL && vp->v_op == mockfs_vnodeop_p',
     'com == SGPU_LAUNCH_TRACE_IOCTL', 'other-vector'),
    ('wide-command', 'com == SGPU_LAUNCH_TRACE_IOCTL &&',
     '(uint32_t)com == (uint32_t)SGPU_LAUNCH_TRACE_IOCTL &&', 'wide-command'),
    ('drop-command', 'com == SGPU_LAUNCH_TRACE_IOCTL && vp->v_op == mockfs_vnodeop_p',
     'vp->v_op == mockfs_vnodeop_p', 'other-command'),
    ('directory-route', '\tcase VREG:\n', '\tcase VDIR:\n\tcase VREG:\n', 'directory'),
    ('drop-vnode-mac', 'error = mac_vnode_check_ioctl(ctx, vp, com);',
     'error = 0;', 'vnode-mac'),
    ('drop-file-mac', 'error = mac_file_check_ioctl(context.vc_ucred, fp->fp_glob, com);',
     'error = 0;', 'file-mac'),
    ('ignore-copyin', 'error = copyin(uap->data, datap, size);',
     '(void)copyin(uap->data, datap, size); error = 0;', 'copyin-error'),
    ('drop-put', '(void)vnode_put(vp);', '(void)vp;', 'entry'),
    ('drop-fp', 'fp_drop(p, fd, fp, 1);', '(void)fp;', 'entry'),
    ('copyout-in', 'error == 0 && (com & IOC_OUT) && size', 'error == 0 && (com & (IOC_IN | IOC_OUT)) && size', 'entry'),
    ('wrong-flags', '\t\t\terror = VNOP_IOCTL(vp, com, data, fp->fp_glob->fg_flag, ctx);',
     '\t\t\terror = VNOP_IOCTL(vp, com, data, FREAD, ctx);', 'write-descriptor'),
)


def amalgamate(source, generic, descriptor, vnops):
    code = receiver.amalgamations(source)['receiver']
    code = code.replace('#include "santoni_gpu_el0_trace_stubs.h"',
                        '#include "santoni_gpu_trace_dispatch_stubs.h"', 1)
    code = code.replace('#include "test_santoni_gpu_el0_trace.c"', '')
    functions = {'vn_ioctl': extract.function(vnops, 'vn_ioctl'),
                 'fo_ioctl': extract.function(descriptor, 'fo_ioctl'),
                 'ioctl': extract.function(generic, 'ioctl')}
    code += '\n\n' + '\n\n'.join(functions.values())
    code += '\n#include "test_santoni_gpu_trace_dispatch.c"\n'
    return code, functions


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--generic', type=Path, required=True)
    p.add_argument('--descriptor', type=Path, required=True)
    p.add_argument('--vnops', type=Path, required=True)
    p.add_argument('--baseline-vnops', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--mutants', action='store_true')
    p.add_argument('--resume', type=Path)
    args = p.parse_args()
    if args.output.exists():
        p.error('refusing to overwrite evidence')
    args.output.mkdir(parents=True)
    inputs = (args.generic, args.descriptor, args.vnops, args.baseline_vnops)
    code, functions = amalgamate(args.source, *(n.read_text() for n in inputs[:3]))
    baseline = extract.function(args.baseline_vnops.read_text(), 'vn_ioctl')
    if 'SGPU_LAUNCH_TRACE_IOCTL' in baseline or code.count(functions['vn_ioctl']) != 1:
        raise ValueError('baseline or extraction is ambiguous')
    # The original VDIR label must move, not duplicate, in the type mutant.
    mutants = list(MUTANTS)
    source_inputs = [args.source / n for n in ('bsd/dev/santoni_gpu_launch.c',
        'bsd/dev/santoni_gpu_launch_core.c', 'bsd/dev/santoni_gpu_launch.h',
        'bsd/dev/santoni_gpu_launch_trace.h', 'bsd/miscfs/mockfs/mockfs_vnops.c')]
    tests = [ROOT / 'tests' / n for n in ('verify_santoni_gpu_trace_dispatch.py',
        'santoni_gpu_trace_dispatch_stubs.h', 'test_santoni_gpu_trace_dispatch.c',
        'verify_santoni_gpu_launcher.py', 'verify_santoni_gpu_el0_trace.py')]
    sha = lambda data: hashlib.sha256(data).hexdigest()
    record = {'success': False, 'kernel_certified': False, 'hardware_verified': False,
              'scope': __doc__, 'sha256': {str(n): sha(n.read_bytes()) for n in [*inputs, *source_inputs, *tests]},
              'extracted_sha256': {n: sha(t.encode()) for n, t in functions.items()},
              'cases': {}, 'baseline': {}, 'mutants': {}}
    prior = json.loads((args.resume / 'result.json').read_text()) if args.resume else {}
    if prior:
        # Orchestration may change; compiled source and every other input may not.
        runner = str(Path(__file__).resolve())
        if {n: v for n, v in prior['sha256'].items() if n != runner} != {
                n: v for n, v in record['sha256'].items() if n != runner}:
            raise ValueError('resume inputs changed')
        record['consumed_from'] = str(args.resume)
    def saved_source(name):
        folder, seen = args.resume, set()
        while folder is not None and len(seen) < 8 and folder not in seen:
            seen.add(folder)
            if (folder / name).is_file():
                return (folder / name).read_text()
            origin = json.loads((folder / 'result.json').read_text()).get('consumed_from')
            folder = Path(origin) if origin else None
        raise ValueError('missing preserved compiled source: ' + name)
    def save():
        (args.output / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    cc = shlex.split(os.environ.get('HOST_CC', 'clang'))
    preferred = Path('/data/data/com.termux/files/usr/tmp/opencode')
    with tempfile.TemporaryDirectory(prefix='sgpu-dispatch-', dir=preferred if preferred.is_dir() else None) as tmp:
        def compile_code(text, name, flags, board=True):
            src = args.output / (name + '.c'); src.write_text(text)
            binary = Path(tmp) / name
            cmd = [*cc, '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                   '-Wno-unused-function', '-Wno-unused-but-set-variable', '-Wimplicit-fallthrough', '-pthread', *flags,
                   '-I', str(ROOT / 'tests'), '-I', str(args.source / 'bsd/dev')]
            if board:
                cmd.append('-DARM64_BOARD_CONFIG_SANTONI')
            cmd += [str(src), str(args.source / 'bsd/dev/santoni_gpu_launch_core.c'), '-o', str(binary)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            (args.output / (name + '-compile.txt')).write_text(result.stdout + result.stderr)
            if result.returncode:
                raise ValueError('compile failed: ' + name)
            return binary
        def run(binary, case):
            result = subprocess.run([str(binary), case], capture_output=True, text=True, timeout=15)
            return {'exit_code': result.returncode, 'output': result.stdout + result.stderr}
        try:
            for variant, flags in (('O0', ['-O0']), ('O2', ['-O2']),
                    ('UBSan', ['-O2', '-fsanitize=undefined', '-fno-sanitize-recover=all'])):
                old_cases = prior.get('cases', {}).get(variant, {})
                old_baselines = {n: prior.get('baseline', {}).get(n + '-' + variant)
                                 for n in ('baseline', 'other-board')}
                if old_cases:
                    if (set(old_cases) != set(CASES) or any(v['exit_code'] != 0 for v in old_cases.values()) or
                            saved_source(variant + '.c') != code or
                            any(not v or v['exit_code'] != 0 for v in old_baselines.values()) or
                            saved_source('baseline-' + variant + '.c') !=
                            code.replace(functions['vn_ioctl'], baseline, 1) or
                            saved_source('other-board-' + variant + '.c') != code):
                        raise ValueError('completed native variant differs')
                    record['cases'][variant] = old_cases
                    record['baseline'].update({n + '-' + variant: v for n, v in old_baselines.items()})
                    print(variant + ': consumed 28 route cases + baseline/other-board; 0 executions', flush=True)
                    save(); continue
                binary = compile_code(code, variant, flags)
                cases = record['cases'][variant] = {}
                for case in CASES:
                    cases[case] = run(binary, case); save()
                    if cases[case]['exit_code']:
                        raise ValueError(variant + ' ' + case + ' failed')
                for name, text, board in (('baseline', code.replace(functions['vn_ioctl'], baseline, 1), True),
                                          ('other-board', code, False)):
                    old = compile_code(text, name + '-' + variant, flags, board)
                    result = run(old, 'baseline')
                    record['baseline'][name + '-' + variant] = result; save()
                    if result['exit_code']:
                        raise ValueError(name + ' ' + variant + ' failed')
                print(variant + ': ' + str(len(cases)) + ' route cases + baseline/other-board passed', flush=True)
            if args.mutants:
                for name, old, new, case in mutants:
                    if code.count(old) != 1:
                        raise ValueError('ambiguous mutant ' + name)
                    text = code.replace(old, new, 1)
                    if name == 'directory-route':
                        text = text.replace('\tcase VDIR:\n\t\tif (com == FIONREAD)',
                                            '\t\tif (com == FIONREAD)', 1)
                        text = text.replace('\t\tOS_FALLTHROUGH;\n#endif\n\t\tif (com == FIONREAD)',
                                            '#endif\n\t\tif (com == FIONREAD)', 1)
                    old_result = prior.get('mutants', {}).get(name)
                    if old_result:
                        if (old_result.get('compiled') is not True or old_result.get('rejected') is not True or
                                old_result.get('exit_code') == 0 or
                                saved_source('mutant-' + name + '.c') != text):
                            raise ValueError('completed mutant differs')
                        record['mutants'][name] = old_result; save()
                        print('Consumed compiling mutant: ' + name + '; 0 executions', flush=True)
                        continue
                    binary = compile_code(text, 'mutant-' + name, ['-O2'])
                    result = run(binary, case)
                    record['mutants'][name] = {**result, 'compiled': True, 'rejected': result['exit_code'] != 0}
                    save()
                    if not result['exit_code']:
                        raise ValueError('compiled mutant survived: ' + name)
                print(str(len(mutants)) + ' compiling mutants rejected', flush=True)
            record['success'] = True
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            record['error'] = str(error)
        save()
    print(json.dumps({'success': record['success'], 'error': record.get('error'), 'evidence': str(args.output)}))
    return 0 if record['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
