"""Native contracts for the prepared render arena, not live GPU execution."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from tests.native_santoni_gpu_core import reconstruct, core_link_dependencies
from tests.test_santoni_gpu_prepare import source_function

ROOT = Path(__file__).resolve().parents[1]
FILES = ('bsd/dev/santoni_gpu_core.c', 'bsd/dev/santoni_gpu_core.h')
VARIANTS = (('O0', ['-O0']), ('O2', ['-O2']),
            ('ubsan', ['-O2', '-fsanitize=undefined', '-fno-sanitize-recover=all']))


class RenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        preferred = Path('/data/data/com.termux/files/usr/tmp/opencode')
        cls.temp = tempfile.TemporaryDirectory(prefix='render0220-', dir=preferred if preferred.is_dir() else None)
        cls.root = Path(cls.temp.name)
        cls.provenance = reconstruct(cls.root / 'current', targets=FILES)
        cls.dev = cls.root / 'current/bsd/dev'
        cls.core = (cls.dev / 'santoni_gpu_core.c').read_text()
        cls.rows = []

    @classmethod
    def tearDownClass(cls):
        evidence = os.environ.get('SANTONI_RENDER_NATIVE_RESULT')
        if evidence:
            inputs = ('xnu/patches/0220-santoni-gpu-render-contract.patch',
                      'xnu/patches/0221-santoni-gpu-live-offscreen-blits.patch',
                      'xnu/patches/0222-santoni-gpu-live-cp-readback.patch',
                      'xnu/patches/0223-santoni-gpu-ui-presentation.patch',
                      'tests/test_santoni_gpu_render.c', 'tests/test_santoni_gpu_render.py',
                      'tests/reconstruct_santoni_touch.py')
            import hashlib
            Path(evidence).write_text(json.dumps({'source': cls.provenance, 'commands': cls.rows,
                'success': True, 'hardware_verified': False,
                'inputs_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
                                  for p in inputs}}, indent=2) + '\n')
        cls.temp.cleanup()

    def run_native(self, name, flags, source=None, success=True):
        folder = self.root / name
        folder.mkdir()
        core = self.dev / 'santoni_gpu_core.c'
        if source is not None:
            core = folder / 'santoni_gpu_core.c'; core.write_text(source)
        command = [*shlex.split(os.environ.get('HOST_CC', 'clang')), '-std=c11', *flags,
                   '-Wall', '-Wextra', '-Werror', '-DARM64_BOARD_CONFIG_SANTONI',
                   '-I', str(self.dev), str(ROOT / 'tests/test_santoni_gpu_render.c'),
                   str(core), *core_link_dependencies(self.dev), '-o', str(folder / 'test')]
        built = subprocess.run(command, capture_output=True, text=True, timeout=60)
        row = {'name': name, 'command': command, 'compile_exit': built.returncode,
               'compile_stdout': built.stdout, 'compile_stderr': built.stderr}
        self.rows.append(row)
        self.assertEqual(built.returncode, 0, built.stderr)
        ran = subprocess.run([str(folder / 'test')], capture_output=True, text=True, timeout=45)
        row.update(exit_code=ran.returncode, stdout=ran.stdout, stderr=ran.stderr)
        if success:
            self.assertEqual(ran.returncode, 0, ran.stderr)
        else:
            self.assertNotEqual(ran.returncode, 0, 'compiled mutant survived: ' + name)

    def test_actual_render_contracts(self):
        for name, flags in VARIANTS:
            self.run_native(name, flags)

    def test_compiled_unsafe_mutants(self):
        changes = (
            ('owner', 'a->bo[i].owner == owner &&', 'true &&'),
            ('guard', 'if (l3[slot] != want ||', 'if ((want && l3[slot] != want) ||'),
            ('late-page', 'for (unsigned i = 0; i < m->pages; i++) {',
             'for (unsigned i = 0; i + 1 < m->pages; i++) {'),
            ('stride', 'span <= b->bytes - p->offset',
             '(uint64_t)p->width * p->height * 4 <= b->bytes - p->offset'),
            ('format', 'sp.format != dp.format', 'false'),
            ('source-address', 'reg == 0x2107 ? s : d', 'reg == 0x2107 ? d : s'),
            ('stale-handle', '.handle = a->next_handle++', '.handle = a->next_handle'),
            ('busy-alias', '!bytes || a->busy || a->error || offset', '!bytes || a->error || offset'),
            ('exposure-free', 'if (a->exposed || a->busy || a->error)', 'if (a->busy || a->error)'),
            ('skip-clean', 'ops->clean(ops->ctx, out, n * 4);', '(void)out;'),
            ('fence-match', 'got == a->busy', 'got != 0'),
            ('no-idle', '!(status & SG_IDLE_MASK)', '!(status & 0u)'),
            ('ignore-fault', '(cb & SG_SMMU_FSR_FAULT)', '(cb & 0u)'),
            ('skip-invalidate', 'ops->invalidate(ops->ctx, a->memory.pixels + d->physical * SGPU_PAGE, d->pages * SGPU_PAGE);',
             '(void)d;'),
            ('lost-first-error', 'if (!a->error) a->error =', 'a->error ='),
            ('timeout-cap', 'i <= SGPU_RENDER_WAIT_US / 100;', 'i < SGPU_RENDER_WAIT_US / 100;'),
        )
        start = self.core.index('/* First render bridge wave:')
        end = self.core.index('/* Live full-size copy diagnostic.', start)
        prefix, section, suffix = self.core[:start], self.core[start:end], self.core[end:]
        for name, old, new in changes:
            self.assertEqual(section.count(old), 1, name)
            changed = prefix + section.replace(old, new, 1) + suffix
            for variant, flags in VARIANTS:
                self.run_native(name + '-' + variant, flags, changed, False)

    def test_wave_has_no_platform_publication_or_display_call(self):
        section = self.core[self.core.index('/* First render bridge wave:'):]
        section = section.split('/* Live full-size copy diagnostic.', 1)[0]
        for forbidden in ('write32(', 'write64(', 'kmem_alloc', 'smc', 'TRUST', 'sgpu_session_start(',
                          'sgpu_client_call(', 'SweetSurface', 'SG_RESET'):
            self.assertNotIn(forbidden, section)
        for name in ('sgpu_blit_commands', 'sgpu_probe', 'sgpu_session_execute'):
            self.assertNotIn('sgpu_render_', source_function(self.core, name))


if __name__ == '__main__':
    unittest.main()
