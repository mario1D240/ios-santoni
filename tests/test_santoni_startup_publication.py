#!/usr/bin/env python3
"""Execute real startup publication and reset lookup with separate cache/PoC views."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

from reconstruct_santoni_smp import ROOT, originals, reconstruct
from test_santoni_secondary import Machine, preprocess
from test_santoni_ui import function

CPU = 'osfmk/arm64/cpu.c'
ASM = 'osfmk/arm64/start.s'
CASES = ('startup', 'idle', 'holes', 'records-visible', 'self',
         'cpu1', 'cpu2', 'cpu3', 'cpu4', 'cpu5', 'cpu6', 'cpu7')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--through', type=int)
    parser.add_argument('--upstream', type=Path)
    parser.add_argument('--case', choices=CASES)
    args = parser.parse_args()
    cases = (args.case,) if args.case else CASES
    preferred = Path('/data/data/com.termux/files/usr/tmp/opencode')
    with tempfile.TemporaryDirectory(prefix='santoni-publication-', dir=preferred if preferred.is_dir() else None) as tmp:
        work = Path(tmp)
        reconstruct(work / 'src', args.through, originals(args.upstream, startup=True))
        actual = function((work / 'src' / CPU).read_text(), 'kern_return_t\ncpu_start(')
        (work / 'startup_publication_actual.h').write_text(actual)
        startup = (work / 'src' / ASM).read_text()
        lookup = startup[startup.index('LEXT(reset_vector)'):startup.index('LEXT(LowResetVectorEnd)')]
        reset = preprocess(lookup, 0)
        for generic in (False, True):
            binary = work / ('generic' if generic else 'santoni')
            flags = ['-DGENERIC_CONTROL=1'] if generic else []
            subprocess.run([*shlex.split(os.environ.get('HOST_CC', 'clang')), '-std=c11', '-O2',
                            '-Wall', '-Wextra', '-Werror', *flags, '-I', str(work),
                            str(ROOT / 'tests/test_santoni_startup_publication.c'), '-o', str(binary)],
                           check=True, timeout=60)
            for case in cases:
                result = subprocess.run([str(binary), case], text=True, capture_output=True, timeout=15)
                if not generic and case != 'self':
                    if 'POC: ' not in result.stdout:
                        raise RuntimeError(result.stderr or 'fixture did not report its published memory view')
                    state = json.loads(next(line[5:] for line in result.stdout.splitlines() if line.startswith('POC: ')))
                    target = state['target']
                    vm = Machine(reset, 4, 0x80000000 | state['mpidr'], target, 0)
                    vm.mem[vm.external['ResetHandlerData'] + 16] = 0x30000000
                    for i, record in enumerate(state['records']):
                        data = 0x20000000 + i * 0x1000
                        vm.mem[0x30000000 + i * 16 + 8] = data if record['present'] else 0
                        vm.mem[data + 4] = record['logical']
                        vm.mem[data + 8] = record['phys']
                        vm.mem[data + 16] = vm.external['start_cpu'] if record['handler'] else 0
                    outcome = vm.run('reset_vector')
                    assert outcome == 'handler' and vm.reg['x21'] == 0x20000000 + target * 0x1000, (
                        f'actual reset assembly selected {vm.reg.get("x21"):#x}, outcome={outcome}; '
                        f'CPU{target} must not match an unclean registered record')
                if result.returncode:
                    raise RuntimeError(result.stderr or result.stdout or f'{case}: exit {result.returncode}')
                for line in result.stdout.splitlines():
                    if not line.startswith('POC: '):
                        print(line)
        print('ok   actual reset assembly consumes published records; logical/physical IDs retained')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
