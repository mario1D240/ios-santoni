#!/usr/bin/env python3
"""Run only new reconstructed0212 CPU/exec contracts, with immutable attempts."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ('bsd/kern/kern_exec.c', 'bsd/kern/kern_cs.c')


def function(source, name):
    match = re.search(r'(?m)^(?:static )?(?:struct cs_blob \*|int|void(?: __attribute__\(\(noinline\)\))?)\n'
                      + re.escape(name) + r'\([^;]*?\)\n\{', source)
    if not match:
        raise ValueError('missing actual function: ' + name)
    start = match.start()
    braces = 0
    tokens = re.finditer(r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]',
                         source[match.end() - 1:])
    for token in tokens:
        if token.group() == '{':
            braces += 1
        elif token.group() == '}':
            braces -= 1
            if braces == 0:
                return source[start:match.end() - 1 + token.end()] + '\n'
    raise ValueError('unterminated actual function: ' + name)


def actual_header(source):
    exec_source = (source / TARGETS[0]).read_text()
    cs_source = (source / TARGETS[1]).read_text()
    definitions = ('TUNABLE(uint32_t, santoni_remoted_platform, "santoni_remoted_platform", 0);\n'
                   'static uint32_t santoni_remoted_platform_logged;\n')
    if definitions.strip() not in exec_source:
        raise ValueError('changed/default-on tunable declarations')
    return (definitions + function(cs_source, 'csproc_get_blob') +
            function(cs_source, 'csproc_get_platform_binary') +
            function(exec_source, 'santoni_remoted_platform_exec') +
            function(exec_source, 'process_signature'))


def run(source, output, mutants=False):
    output.mkdir(parents=True, exist_ok=False)
    header = actual_header(source)
    (output / 'santoni_remoted_platform_actual.h').write_text(header)
    hashes = {name: hashlib.sha256((source / name).read_bytes()).hexdigest() for name in TARGETS}
    test_files = ('tests/test_santoni_remoted_platform.c', 'tests/santoni_remoted_platform_stubs.h',
                  'tests/verify_santoni_remoted_platform.py')
    result = {'source_sha256': hashes, 'test_sha256': {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in test_files},
        'hardware_verified': False, 'old_test_executions': 0, 'runs': [], 'mutants': [], 'success': False}
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    temp_root = Path('/data/data/com.termux/files/usr/tmp/opencode')
    if not temp_root.is_dir():
        import tempfile
        temp_root = Path(tempfile.gettempdir())
    native_dir = temp_root / ('santoni-remoted-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    native_dir.mkdir()

    def one(label, options, supplied_header, expect_rejection=False):
        variant = output / label
        variant.mkdir()
        (variant / 'santoni_remoted_platform_actual.h').write_text(supplied_header)
        binary = native_dir / label
        command = ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                   '-DARM64_BOARD_CONFIG_SANTONI', *options, '-I', str(variant),
                   '-I', str(ROOT / 'tests'), str(ROOT / test_files[0]), '-o', str(binary)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (variant / 'compile.log').write_text(compiled.stdout + compiled.stderr)
        record = {'label': label, 'compile_command': command, 'compile_exit': compiled.returncode}
        if compiled.returncode:
            (variant / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
            raise RuntimeError(label + ': compile failed; see ' + str(variant / 'compile.log'))
        executed = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
        (variant / 'run.log').write_text(executed.stdout + executed.stderr)
        record.update(run_exit=executed.returncode,
                      cases=re.findall(r'^PASS (\S+)$', executed.stdout, re.MULTILINE),
                      compiling_mutant_rejected=expect_rejection and executed.returncode != 0)
        (variant / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
        if (executed.returncode == 0) == expect_rejection:
            raise RuntimeError(label + ': unexpected native outcome; see ' + str(variant / 'run.log'))
        print(label, 'compiling mutant rejected' if expect_rejection else str(len(record['cases'])) + ' new contracts passed', flush=True)
        return record

    try:
        for label, options in (('O0', ['-O0']), ('O2', ['-O2']),
                               ('UBSan', ['-O2', '-fsanitize=undefined', '-fno-sanitize-recover=all'])):
            record = one(label, options, header)
            if result['runs'] and record['cases'] != result['runs'][0]['cases']:
                raise ValueError('native variants disagree on contract scope')
            result['runs'].append(record)
            (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        if mutants:
            changes = (
                ('default_on', 'santoni_remoted_platform != 1 || p == NULL', 'p == NULL'),
                ('path_identity', 'if (exact && (before & CS_KILLED)', 'if (root && (before & CS_KILLED)'),
                ('invent_signature', 'proc_csflags_set(p, CS_PLATFORM_BINARY);',
                 'proc_csflags_set(p, CS_PLATFORM_BINARY | CS_SIGNED | CS_VALID);'),
                ('invalid_blob', '(blob == NULL || blob_valid) &&', 'true &&'),
                ('unconditional_exec', '\tif (0 == error) {\n#if defined(ARM64_BOARD_CONFIG_SANTONI)\n'
                 '\t\tsantoni_remoted_platform_exec(p);\n#endif\n',
                 '\tsantoni_remoted_platform_exec(p);\n\tif (0 == error) {\n'),
                ('query_default_on', 'santoni_remoted_platform == 1 && p != NULL', 'p != NULL'),
            )
            for label, old, new in changes:
                if header.count(old) != 1:
                    raise ValueError('ambiguous/missing compiling mutation: ' + label)
                mutated = header.replace(old, new)
                result['mutants'].append(one('mutant_' + label, ['-O2'], mutated, True))
                (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        result['success'] = True
        result['native_cases'] = sum(len(x['cases']) for x in result['runs'])
        result['compiling_rejected_mutants'] = len(result['mutants'])
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        return result
    finally:
        shutil.rmtree(native_dir)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--mutants', action='store_true')
    args = parser.parse_args()
    run(args.source.resolve(), args.output.resolve(), args.mutants)


if __name__ == '__main__':
    main()
