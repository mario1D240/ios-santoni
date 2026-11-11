#!/usr/bin/env python3
"""Execute the shipped cpu_idle WFI block with cache/CPU instructions mocked."""
import argparse
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
from urllib.request import urlopen

from reconstruct_santoni_smp import STARTUP, URL, reconstruct

CPU = 'osfmk/arm64/cpu.c'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--through', type=int)
    parser.add_argument('--upstream', type=Path)
    args = parser.parse_args()
    if args.upstream:
        original = (args.upstream / CPU).read_bytes()
    else:
        with urlopen(URL + CPU, timeout=45) as response:
            original = response.read()
    if hashlib.sha256(original).hexdigest() != STARTUP[CPU]:
        raise ValueError('Idle test needs the pinned pristine XNU cpu.c')
    approved = Path('/data/data/com.termux/files/usr/tmp/opencode')
    with tempfile.TemporaryDirectory(prefix='santoni-idle-',
                                     dir=approved if approved.is_dir() else None) as tmp:
        out = Path(tmp)
        manifest = reconstruct(out / 'source', args.through, {CPU: original})
        text = (out / 'source' / CPU).read_text()
        start = text.index('\tif (wfi) {', text.index('cpu_idle(void)'))
        end = text.index('\n\tClearIdlePop(TRUE);', start)
        block = text[start:end]
        fixture = '''#include <assert.h>
#define DEVELOPMENT 0
#define DEBUG 0
#define HAS_RETENTION_STATE 0
#define DSB_SY 15
static unsigned waits, fences, cleans;
static int wfi;
static void __attribute__((unused)) platform_cache_idle_enter(void) { cleans++; }
#define __builtin_arm_dsb(scope) ((void)(scope), fences++)
#define __builtin_arm_wfi() (waits++)
static void run_idle(void) {
'''
        fixture += block + '''
}
int main(void) {
    run_idle();
    assert(waits == 0 && fences == 0 && cleans == 0);
    wfi = 1;
    for (unsigned i = 0; i < 1000; i++) run_idle();
    assert(waits == 1000 && fences == 1000 && cleans == EXPECTED_CLEANS);
    return 0;
}
'''
        source = out / 'idle.c'
        source.write_text(fixture)
        failures = 0
        for name, defines, expected in [('Santoni', ['-DSANTONI=1'], 0),
                                        ('generic ARM', [], 1000),
                                        ('Apple ARM', ['-DAPPLE_ARM64_ARCH_FAMILY=1'], 0)]:
            binary = out / 'idle-host'
            command = [*shlex.split(os.environ.get('HOST_CC', 'clang')), '-std=c11',
                       '-O2', '-Wall', '-Wextra', '-Werror', *defines,
                       f'-DEXPECTED_CLEANS={expected}', str(source), '-o', str(binary)]
            subprocess.run(command, check=True, timeout=60)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=5)
            failures += bool(result.returncode)
            print(('FAIL ' if result.returncode else 'ok   ') + name + ' WFI cache policy')
        print('Actual cpu.c SHA256:', manifest['sha256'][CPU])
        print(f'Santoni actual idle checks: {3 - failures}/3 passed')
        return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
