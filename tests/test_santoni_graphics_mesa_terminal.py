"""Pinned Mesa error macro: real release abort, diagnostics and port isolation."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import unittest

from tests.reconstruct_santoni_touch import selected_sections

ROOT = Path(__file__).resolve().parents[1]
MESA = Path(os.environ.get('SANTONI_MESA_SOURCE', str(ROOT / 'out/mesa-a505-25.0.7-reference')))
FILE = 'src/util/macros.h'
VARIANTS = (('O0', ['-O0']), ('O2', ['-O2']),
            ('ubsan', ['-O2', '-fsanitize=undefined', '-fno-sanitize-recover=all']))
LANGUAGES = (('c', 'clang', 'c11'), ('c++', 'clang++', 'c++17'))
MUTANTS = (
    ('return-after-diagnostic', '   abort();', '   (void)0;'),
    ('omit-diagnostic', '   fprintf(stderr, "Mesa(Santoni): %s\\n", "" str);', '   (void)("" str);'),
    ('disable-port-terminal', '#if defined(SANTONI_GFX_MESA)', '#if 0'),
)
INPUTS = ('tests/test_santoni_graphics_mesa_terminal.py', 'tests/test_santoni_graphics_mesa_terminal.c',
          'tests/reconstruct_santoni_touch.py', 'tools/santoni-graphics/mesa-reference.json',
          'tools/santoni-graphics/mesa-ios.patch')
DIAGNOSTIC = 'Mesa(Santoni): Unsupported explicit IO variable mode'


class MesaTerminal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        preferred = Path('/data/data/com.termux/files/usr/tmp/opencode')
        cls.temp = tempfile.TemporaryDirectory(prefix='mesa-terminal-', dir=preferred if preferred.is_dir() else None)
        cls.work = Path(cls.temp.name)
        cls.rows = []
        lock = json.loads((ROOT / 'tools/santoni-graphics/mesa-reference.json').read_text())
        assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=MESA, text=True).strip() == lock['commit']
        cls.baseline = subprocess.check_output(['git', 'show', lock['commit'] + ':' + FILE], cwd=MESA)
        assert hashlib.sha256(cls.baseline).hexdigest() == lock['source_sha256'][FILE]
        assert cls.baseline == (MESA / FILE).read_bytes()
        source = cls.work / 'source'
        path = source / FILE
        path.parent.mkdir(parents=True)
        path.write_bytes(cls.baseline)
        subprocess.run(['git', 'init', '--quiet', str(source)], check=True, timeout=15)
        section = selected_sections((ROOT / 'tools/santoni-graphics/mesa-ios.patch').read_bytes(), targets=(FILE,))
        assert section
        for command in (['git', 'apply', '--check', '-'], ['git', 'apply', '-']):
            subprocess.run(command, cwd=source, input=section, check=True, capture_output=True, timeout=15)
        cls.fixed = path.read_text()
        cls.fixture = ROOT / 'tests/test_santoni_graphics_mesa_terminal.c'

    @classmethod
    def tearDownClass(cls):
        output = os.environ.get('SANTONI_MESA_TERMINAL_RECORD')
        if output:
            record = {'rows': cls.rows, 'patched_macros_sha256': hashlib.sha256(cls.fixed.encode()).hexdigest(),
                      'inputs_sha256': {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in INPUTS},
                      'hardware_verified': False}
            with Path(output).open('x') as stream:
                json.dump(record, stream, indent=2)
        cls.temp.cleanup()

    def execute(self, language, compiler, standard, label, flags, body, cases, mutant=False):
        directory = self.work / (language + '-' + label)
        directory.mkdir()
        (directory / 'macros.h').write_text(body)
        binary = directory / 'test'
        command = [*shlex.split(os.environ.get('CXX' if language == 'c++' else 'CC', compiler)),
                   '-x', language, '-std=' + standard, *flags, '-DNDEBUG', '-DSANTONI_GFX_MESA',
                   '-Wall', '-Wextra', '-Werror', '-I', str(directory), str(self.fixture), '-o', str(binary)]
        build = subprocess.run(command, capture_output=True, text=True, timeout=45)
        row = {'label': language + '-' + label, 'command': command, 'compile_exit': build.returncode,
               'compile_stderr': build.stderr, 'source_sha256': hashlib.sha256(body.encode()).hexdigest(), 'runs': []}
        self.rows.append(row)
        self.assertEqual(build.returncode, 0, build.stderr)
        for case in cases:
            try:
                run = subprocess.run([str(binary), str(case)], capture_output=True, text=True, timeout=1 if mutant else 10)
            except subprocess.TimeoutExpired as error:
                self.assertTrue(mutant, 'enabled production terminal failed to abort')
                row['runs'].append({'case': case, 'exit': None, 'timed_out': True,
                                    'stdout': (error.stdout or b'').decode(errors='replace'),
                                    'stderr': (error.stderr or b'').decode(errors='replace')})
                continue
            row['runs'].append({'case': case, 'exit': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr})
            fatal = run.returncode == -signal.SIGABRT and DIAGNOSTIC in run.stderr
            if mutant:
                self.assertFalse(fatal, label + ' survived the complete terminal contract')
            elif case > 1:
                self.assertTrue(fatal, run.stdout + run.stderr)
            else:
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertIn('value=' + str(91 + case), run.stdout)
                self.assertNotIn(DIAGNOSTIC, run.stderr)

    def test_actual_release_C_and_Cpp_O0_O2_UBSan(self):
        for language, compiler, standard in LANGUAGES:
            for label, flags in VARIANTS:
                self.execute(language, compiler, standard, 'actual-' + label, flags, self.fixed, (0, 1, 2, 0xffffffff))

    def test_compiling_missing_abort_diagnostic_and_opt_in_variants_rejected(self):
        for language, compiler, standard in LANGUAGES:
            for name, old, new in MUTANTS:
                self.assertEqual(self.fixed.count(old), 1)
                for label, flags in VARIANTS:
                    self.execute(language, compiler, standard, name + '-' + label, flags,
                                 self.fixed.replace(old, new, 1), (2,), mutant=True)

    def test_disabled_port_preprocessed_C_and_Cpp_tokens_are_identical(self):
        for language, compiler, standard in LANGUAGES:
            bodies = []
            for name, body in (('baseline', self.baseline.decode()), ('patched', self.fixed)):
                directory = self.work / ('preprocess-' + language + '-' + name)
                directory.mkdir()
                (directory / 'macros.h').write_text(body)
                run = subprocess.run([compiler, '-x', language, '-std=' + standard, '-DNDEBUG', '-E', '-P',
                                      '-I', str(directory), str(self.fixture)], capture_output=True, check=True, timeout=30)
                bodies.append(run.stdout)
            self.assertEqual(*bodies, language + ' disabled-port tokens differ')


if __name__ == '__main__':
    unittest.main()
