#!/usr/bin/env python3
"""New mockfs registration/VFS dispatch contracts; no old suites or kernel build."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.verify_santoni_gpu_launcher import function

CASES = ('registration', 'registered64', 'registered32', 'callee-error', 'wrong-ready-bit',
         'generic-only64', 'missing-callback', 'dead-mount', 'unrelated-flags')


def extract(source, reference):
    conf = (source / 'bsd/vfs/vfs_conf.c').read_text()
    begin = conf.index('#if MOCKFS\n\t/* If we are configured')
    end = conf.index('#endif /* MOCKFS */', begin)
    entry = conf[begin:end] + '\n#endif\n'
    header = (reference / 'bsd/sys/mount_internal.h').read_text()
    start = header.index('struct vfstable {')
    table = header[start:header.index('\n};', start) + 3]
    kpi = (reference / 'bsd/vfs/kpi_vfs.c').read_text()
    funcs = function(kpi, 'vfs_64bitready') + '\n\n' + function(kpi, 'VFS_MOUNT')
    return entry, table, funcs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists(): parser.error('preserve existing attempt; use a distinct output')
    args.output.mkdir(parents=True)
    entry, table, functions = extract(args.source, args.reference)
    snapshots = {'mockfs_registration_under_test.inc': entry, 'vfstable_under_test.inc': table,
                 'vfs_functions_under_test.inc': functions}
    for name, text in snapshots.items(): (args.output / name).write_text(text)
    harness = ROOT / 'tests/test_santoni_gpu_mockfs_lp64.c'
    (args.output / harness.name).write_bytes(harness.read_bytes())
    record = {'success': False, 'scope': 'actual reconstructed registration and extracted XNU VFS functions; thread/mount services simulated',
              'kernel_build_performed': False, 'hardware_verified': False,
              'snapshots_sha256': {name: hashlib.sha256(text.encode()).hexdigest() for name, text in snapshots.items()},
              'harness_sha256': hashlib.sha256(harness.read_bytes()).hexdigest(), 'variants': {}, 'mutants': {}}
    save = lambda: (args.output / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    save()
    preferred = Path('/data/data/com.termux/files/usr/tmp/opencode')
    with tempfile.TemporaryDirectory(prefix='mockfs-lp64-', dir=preferred if preferred.is_dir() else None) as temporary:
        work = Path(temporary)
        for name, text in snapshots.items(): (work / name).write_text(text)
        for variant, flags in (('O0', ['-O0']), ('O2', ['-O2']),
                               ('UBSan', ['-O2', '-fsanitize=undefined', '-fno-sanitize-recover=all'])):
            record['variants'][variant] = {}
            for board in ('Santoni', 'other-board'):
                board_flags = ['-DARM64_BOARD_CONFIG_SANTONI'] if board == 'Santoni' else []
                binary = work / (variant + '-' + board)
                command = ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', *flags, *board_flags,
                           '-I', str(work), str(harness), '-o', str(binary)]
                compile_result = subprocess.run(command, text=True, capture_output=True)
                (args.output / (variant + '-' + board + '-compile.log')).write_text(compile_result.stdout + compile_result.stderr)
                if compile_result.returncode: raise ValueError('new native contract compile failed: ' + variant + '/' + board)
                results = record['variants'][variant][board] = {}
                for case in CASES:
                    result = subprocess.run([str(binary), case], text=True, capture_output=True)
                    results[case] = {'success': result.returncode == 0, 'exit_code': result.returncode,
                                     'stdout': result.stdout, 'stderr': result.stderr}
                    save()
                    if result.returncode: raise ValueError('new native contract failed: ' + variant + '/' + board + '/' + case)
                print('Passed new native VFS contracts:', variant, board, len(results), flush=True)
        token = 'VFC_VFSGENERICARGS | VFC_VFS64BITREADY'
        assert entry.count(token) == 1
        mutants = [('omit-ready', entry.replace(token, 'VFC_VFSGENERICARGS'), 'Santoni'),
                   ('wrong-ready-bit', entry.replace(token, 'VFC_VFSGENERICARGS | VFC_VFSREADDIR_EXTENDED'), 'Santoni'),
                   ('leak-ready-to-other-boards', entry.replace('#if defined(ARM64_BOARD_CONFIG_SANTONI)', '#if 1'), 'other-board')]
        for name, text, board in mutants:
            (work / 'mockfs_registration_under_test.inc').write_text(text)
            binary = work / name
            flags = ['-DARM64_BOARD_CONFIG_SANTONI'] if board == 'Santoni' else []
            command = ['clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', *flags,
                       '-I', str(work), str(harness), '-o', str(binary)]
            compiled = subprocess.run(command, text=True, capture_output=True)
            if compiled.returncode: raise ValueError('mutant did not compile: ' + name)
            result = subprocess.run([str(binary), 'registration'], text=True, capture_output=True)
            record['mutants'][name] = {'compiled': True, 'rejected': result.returncode != 0,
                                      'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
            save()
            if result.returncode == 0: raise ValueError('mutant accepted: ' + name)
            print('Rejected compiling new VFS mutant:', name, flush=True)
    record['success'] = True
    record['native_executions'] = 54
    record['compiled_rejected_mutants'] = 3
    save()
    print('New VFS contracts complete: 54 O0/O2/UBSan executions; 3 compiling mutants rejected', flush=True)


if __name__ == '__main__':
    main()
