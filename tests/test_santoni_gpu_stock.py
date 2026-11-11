"""Reconstructed 0203 contracts: host proof only, no hardware access."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from tests.native_santoni_gpu_core import reconstruct, core_link_dependencies
from tests.test_santoni_gpu_prepare import source_function

ROOT = Path(__file__).resolve().parents[1]
FILES = ('bsd/dev/santoni_gpu.c', 'bsd/dev/santoni_gpu_core.c', 'bsd/dev/santoni_gpu_core.h')
VARIANTS = (('O0', ['-O0']), ('O2', ['-O2']),
            ('ubsan', ['-O2', '-fsanitize=undefined', '-fno-sanitize-recover=all']))


class StockTransitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        preferred = Path('/data/data/com.termux/files/usr/tmp/opencode')
        cls.temp = tempfile.TemporaryDirectory(prefix='stock-a505-', dir=preferred if preferred.is_dir() else None)
        cls.root = Path(cls.temp.name)
        reconstruct(cls.root / 'current', targets=FILES)
        reconstruct(cls.root / 'previous', through=202, targets=FILES)
        cls.dev = cls.root / 'current/bsd/dev'
        cls.core = (cls.dev / 'santoni_gpu_core.c').read_text()
        cls.adapter = (cls.dev / 'santoni_gpu.c').read_text()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def compile_run(self, folder, harness, flags, *, core=None, header=None, success=True):
        folder.mkdir()
        if core is not None:
            (folder / 'santoni_gpu_core.c').write_text(core)
        if header is not None:
            (folder / 'santoni_gpu_stock_adapter_actual.h').write_text(header)
        cmd = [*shlex.split(os.environ.get('HOST_CC', 'clang')), '-std=c11', *flags,
               '-Wall', '-Wextra', '-Werror', '-DARM64_BOARD_CONFIG_SANTONI',
               '-I', str(folder), '-I', str(self.dev), str(ROOT / 'tests' / harness)]
        if harness == 'test_santoni_gpu_stock.c':
            cmd.append(str(folder / 'santoni_gpu_core.c' if core is not None else self.dev / 'santoni_gpu_core.c'))
        if harness != 'test_santoni_gpu_stock_adapter.c':
            cmd += core_link_dependencies(self.dev)
        cmd += ['-o', str(folder / 'test')]
        compiled = subprocess.run(cmd, text=True, capture_output=True, timeout=60)
        self.assertEqual(compiled.returncode, 0, compiled.stderr)  # uncompiled mutants never count
        ran = subprocess.run([str(folder / 'test')], text=True, capture_output=True, timeout=30)
        if success:
            self.assertEqual(ran.returncode, 0, ran.stderr)
            self.assertIn('PASS stock', ran.stdout)
        else:
            self.assertNotEqual(ran.returncode, 0, 'compiled unsafe mutant survived: ' + folder.name)

    def adapter_header(self):
        text = '\n'.join(source_function(self.adapter, name) for name in
                         ('address', 'sgpu_stock_write_allowed', 'sgpu_io_write32', 'sgpu_io_write64'))
        for reg, width in (('%w0', 4), ('%0', 8)):
            assembly = ('__asm__ volatile("dmb sy\\n\\tstr ' + reg +
                        ', [%1]\\n\\tdsb sy" : : "r"(value), "r"(addr) : "memory");')
            self.assertEqual(text.count(assembly), 1)
            text = text.replace(assembly, f'host_store({width}, addr, value);')
        self.assertNotIn('__asm__', text)
        return text

    def test_actual_native_state_machine_and_private_guards(self):
        for variant, flags in VARIANTS:
            for harness in ('test_santoni_gpu_stock.c', 'test_santoni_gpu_stock_guards.c'):
                with self.subTest(variant=variant, harness=harness):
                    self.compile_run(self.root / (variant + harness), harness, flags)

    def test_actual_adapter_permission_bounds(self):
        header = self.adapter_header()
        for variant, flags in VARIANTS:
            self.compile_run(self.root / ('adapter-' + variant), 'test_santoni_gpu_stock_adapter.c',
                             flags, header=header)

    def test_default_modes_have_identical_full_MMIO_cache_and_cleanup_traces(self):
        output = []
        for label in ('previous', 'current'):
            dev = self.root / label / 'bsd/dev'
            binary = self.root / ('trace-' + label)
            subprocess.run([*shlex.split(os.environ.get('HOST_CC', 'clang')), '-std=c11', '-O2',
                '-Wall', '-Wextra', '-Werror', '-DARM64_BOARD_CONFIG_SANTONI',
                '-DSANTONI_GPU_TRACE_CLEANUP', '-I', str(dev),
                str(ROOT / 'tests/fixtures/santoni_gpu_forward_trace.c'),
                str(dev / 'santoni_gpu_core.c'), *core_link_dependencies(dev), '-o', str(binary)], check=True, timeout=60)
            output.append(subprocess.check_output([str(binary)], text=True, timeout=30))
        self.assertEqual(*output, 'stock opt-in must not alter default modes1/2/3 hardware operations')

    def test_cache_and_SCM_bodies_are_byte_preserved(self):
        old = (self.root / 'previous/bsd/dev/santoni_gpu.c').read_text()
        start, end = '/* PAS preparation only:', 'static void __attribute__((noinline)) sgpu_failure_summary'
        self.assertEqual(old[old.index(start):old.index(end)],
                         self.adapter[self.adapter.index(start):self.adapter.index(end)])

    def test_compiled_core_mutants_are_rejected(self):
        transition = source_function(self.core, 'sgpu_stock_transition')
        mutations = [
            ('fresh-old', 'old != 1 || value != 0', 'old == 42 || value != 0'),
            ('value', 'checked_write32(p, SG_GPU, SG_TRUST, ~0u, 0)', 'checked_write32(p, SG_GPU, SG_TRUST, ~0u, 1)'),
            ('mask', 'checked_write32(p, SG_GPU, SG_TRUST, ~0u, 0)', 'checked_write32(p, SG_GPU, SG_TRUST, 1u, 0)'),
            ('before-call', 'r->stock.attempted = true;', 'r->stock.attempted = false;'),
            ('hold', 'r->stock.held = true;', 'r->stock.held = false;'),
            ('cleanup', 'if (report->stock.attempted || report->pixel.started) {', 'if (false) {'),
            ('render', 'goto done; /* Stock-only never renders; the pixel opt-in still never cleans up. */',
             '(void)passed; /* unsafe continuation */'),
            ('unknown', 'if (r->stock.before != 1)', 'if (false)'),
            ('faults', 'if (has_fault(r)) { r->error = SG_FAULT; return false; }',
             'if (false) { r->error = SG_FAULT; return false; }'),
        ]
        # Drop each live readback gate independently, not a token-only scope test.
        for index, line in enumerate(transition.splitlines()):
            if '!sgpu_stock_check32(p,' in line:
                expr = line.strip().removesuffix(' {').removesuffix(')') if line.endswith(' {') else line.strip().removesuffix(' ||')
                mutations.append((f'live-{index}', expr, 'false'))
        for name, old, new in mutations:
            if transition.count(old) == 1:
                mutated = self.core.replace(transition, transition.replace(old, new, 1), 1)
            else:
                self.assertEqual(self.core.count(old), 1, name)
                mutated = self.core.replace(old, new, 1)
            for variant, flags in VARIANTS:
                with self.subTest(mutant=name, variant=variant):
                    self.compile_run(self.root / (name + '-' + variant), 'test_santoni_gpu_stock.c', flags,
                                     core=mutated, success=False)

    def test_compiled_adapter_mutants_are_rejected(self):
        original = self.adapter_header()
        for name, old in (('mode', 'mode == 3'), ('opt', 'enabled == 1'),
                          ('block', 'block == SG_GPU'), ('offset', 'off == SG_TRUST'), ('value', 'value == 0')):
            # Keep the parameters used so -Werror doesn't create vacuous rejections.
            new = f'({old} || true)'
            self.assertIn(old, original)
            for variant, flags in VARIANTS:
                self.compile_run(self.root / ('adapter-mutant-' + name + '-' + variant),
                                 'test_santoni_gpu_stock_adapter.c', flags,
                                 header=original.replace(old, new, 1), success=False)


if __name__ == '__main__':
    unittest.main()
