#!/usr/bin/env python3
"""Execute only six new other-board getter contracts at O0/O2/UBSan."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from verify_santoni_remoted_platform import function

ROOT = Path(__file__).resolve().parents[1]


def run(source, output):
    output.mkdir(parents=True, exist_ok=False)
    code = (source / 'bsd/kern/kern_cs.c').read_text()
    header = function(code, 'csproc_get_blob') + function(code, 'csproc_get_platform_binary')
    (output / 'santoni_remoted_platform_other_actual.h').write_text(header)
    temporary = Path('/data/data/com.termux/files/usr/tmp/opencode')
    if not temporary.is_dir():
        temporary = Path(tempfile.gettempdir())
    binaries = temporary / ('santoni-remoted-other-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    binaries.mkdir()
    result = {'success': False, 'hardware_verified': False, 'old_test_executions': 0, 'runs': [],
              'source_sha256': hashlib.sha256((source / 'bsd/kern/kern_cs.c').read_bytes()).hexdigest(),
              'test_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                              for name in ('tests/test_santoni_remoted_platform_other.c',
                                           'tests/verify_santoni_remoted_platform_other.py')}}
    try:
        for label, options in (('O0', ['-O0']), ('O2', ['-O2']),
                               ('UBSan', ['-O2', '-fsanitize=undefined', '-fno-sanitize-recover=all'])):
            binary = binaries / label
            cmd = ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', *options,
                   '-DARM64_BOARD_CONFIG_SWEET', '-UARM64_BOARD_CONFIG_SANTONI',
                   '-I', str(output), str(ROOT / 'tests/test_santoni_remoted_platform_other.c'), '-o', str(binary)]
            compiled = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            (output / (label + '-compile.log')).write_text(compiled.stdout + compiled.stderr)
            if compiled.returncode:
                raise RuntimeError('new other-board compile failed: ' + label)
            executed = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
            (output / (label + '-run.log')).write_text(executed.stdout + executed.stderr)
            cases = re.findall(r'^PASS (\S+)$', executed.stdout, re.MULTILINE)
            if executed.returncode or len(cases) != 6:
                raise RuntimeError('new other-board contract failed: ' + label)
            result['runs'].append({'label': label, 'command': cmd, 'compile_exit': 0,
                                   'run_exit': 0, 'cases': cases})
            (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
            print(label, '6 new other-board contracts passed', flush=True)
        result.update(success=True, native_cases=18)
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        return result
    finally:
        shutil.rmtree(binaries)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.source.resolve(), args.output.resolve())
