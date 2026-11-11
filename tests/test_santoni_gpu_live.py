"""Actual live copy, allocator/options/dispatch and compiling negative contracts."""
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
FILES = ('bsd/dev/santoni_gpu.c', 'bsd/dev/santoni_gpu_core.c', 'bsd/dev/santoni_gpu_core.h')
VARIANTS = (('O0', ['-O0']), ('O2', ['-O2']),
            ('ubsan', ['-O2', '-fsanitize=undefined', '-fno-sanitize-recover=all']))
CORE_CASES = (*range(36), 100, 101, 102, 104)
ADAPTER_CASES = (*range(21), 30, 31)


def adapter_header(adapter, core):
    start = adapter.index('static struct {')
    end = adapter.index('} sg;', start) + len('} sg;')
    parts = ['#define SG_RENDER_FN __attribute__((noinline, used))', adapter[start:end]]
    for name in ('sgpu_stock_options', 'sgpu_pixel_options', 'sgpu_g3_options',
                 'sgpu_session_options', 'sgpu_user_options', 'sgpu_user_test_options'):
        parts.append(source_function(adapter, name))
    start = adapter.index('/* Once-only full-buffer diagnostic,')
    end = adapter.index('static void sgpu_kernel_thread', start)
    parts += [adapter[start:end], source_function(adapter, 'sgpu_kernel_thread')]
    for name in ('sgpu_render_overlap', 'sgpu_render_memory_valid', 'sgpu_render_validate'):
        parts.append(source_function(core, name))
    return '\n\n'.join(parts)


class LiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        preferred = Path('/data/data/com.termux/files/usr/tmp/opencode')
        cls.temp = tempfile.TemporaryDirectory(prefix='live0221-', dir=preferred if preferred.is_dir() else None)
        cls.root = Path(cls.temp.name)
        cls.source = reconstruct(cls.root / 'current', targets=FILES)
        cls.dev = cls.root / 'current/bsd/dev'
        cls.core = (cls.dev / 'santoni_gpu_core.c').read_text()
        cls.adapter = (cls.dev / 'santoni_gpu.c').read_text()
        cls.rows = []
        session = (ROOT / 'tests/test_santoni_gpu_session.c').read_text().split('static bool boot_session(', 1)[0]
        (cls.root / 'santoni_gpu_session_model.h').write_text(session)

    @classmethod
    def tearDownClass(cls):
        evidence = os.environ.get('SANTONI_LIVE_NATIVE_RESULT')
        if evidence:
            Path(evidence).write_text(json.dumps({'source': cls.source, 'commands': cls.rows}, indent=2) + '\n')
        cls.temp.cleanup()

    def native(self, name, kind, flags, source=None, cases=(), positive=True):
        folder = self.root / name; folder.mkdir()
        core = self.core if kind == 'adapter' or source is None else source
        adapter = self.adapter if kind == 'core' or source is None else source
        (folder / 'santoni_gpu_live_adapter_actual.h').write_text(adapter_header(adapter, core))
        cfile = folder / 'santoni_gpu_core.c'; cfile.write_text(core)
        harness = ROOT / ('tests/test_santoni_gpu_live' + ('_adapter' if kind == 'adapter' else '') + '.c')
        args = [*shlex.split(os.environ.get('HOST_CC', 'clang')), '-std=c11', *flags,
                '-Wall', '-Wextra', '-Werror', '-DARM64_BOARD_CONFIG_SANTONI',
                '-I', str(self.dev), '-I', str(folder), '-I', str(self.root), '-I', str(ROOT / 'tests'), str(harness)]
        if kind == 'core': args += [str(cfile), *core_link_dependencies(self.dev)]
        args += ['-o', str(folder / 'test')]
        built = subprocess.run(args, capture_output=True, text=True, timeout=90)
        row = {'name': name, 'kind': kind, 'command': args, 'compile_exit': built.returncode,
               'compile_stdout': built.stdout, 'compile_stderr': built.stderr, 'runs': []}
        self.rows.append(row)
        self.assertEqual(built.returncode, 0, built.stderr)
        for case in cases:
            ran = subprocess.run([str(folder / 'test'), str(case)], capture_output=True, text=True, timeout=45)
            row['runs'].append({'case': case, 'exit_code': ran.returncode, 'stdout': ran.stdout, 'stderr': ran.stderr})
            if positive: self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            else: self.assertNotEqual(ran.returncode, 0, 'compiled unsafe mutant survived: ' + name)

    def test_actual_live_core_and_adapter(self):
        for name, flags in VARIANTS:
            self.native(name + '-core', 'core', flags, cases=CORE_CASES)
            self.native(name + '-adapter', 'adapter', flags, cases=ADAPTER_CASES)

    def test_compiled_live_core_mutants_rejected(self):
        changes = (
            ('halt', 'sgpu_render_live_link', '!checked_write32(p, SG_GPU, SG_ME_CNTL, SG_CP_LIVE_READBACK_MASK, SG_CP_STOP_MASK)', 'false', 0),
            ('cp-unknown-bits', 'sgpu_render_live_link', 'SG_CP_LIVE_READBACK_MASK, SG_CP_STOP_MASK', 'SG_CP_STOP_MASK, SG_CP_STOP_MASK', 27),
            ('cp-state-bypass', 'sgpu_render_live_state', '!sgpu_render_live_cp_state(me)', '(sgpu_render_live_cp_state(me) && false)', 32),
            ('cp-one-request', 'sgpu_render_live_link', 'SG_CP_LIVE_READBACK_MASK, SG_CP_STOP_MASK', '~0xdu, SG_CP_STOP_MASK', 30),
            ('cp-other-request', 'sgpu_render_live_link', 'SG_CP_LIVE_READBACK_MASK, SG_CP_STOP_MASK', '~0xeu, SG_CP_STOP_MASK', 29),
            ('cp-resume-unknown-bits', 'sgpu_render_live_link', 'SG_CP_LIVE_READBACK_MASK, 0', 'SG_CP_STOP_MASK, 0', 28),
            ('disable-cb', 'sgpu_render_live_link', '!checked_write32(p, SG_SMMU, SG_CB, ~0u, 0x1126u)', 'false', 0),
            ('fault-route', 'sgpu_render_live_link', '!checked_write32(p, SG_SMMU, SG_S2CR0, ~0u, SG_S2CR_FAULT)', 'false', 0),
            ('restore-route', 'sgpu_render_live_link', '!checked_write32(p, SG_SMMU, SG_S2CR0, ~0u, 0)', 'false', 0),
            ('skip-asid', 'sgpu_render_live_link', '!checked_write32(p, SG_SMMU, SG_CB_TLBIASID, 0, 1)', 'false', 0),
            ('skip-sync', 'sgpu_render_live_link', '!checked_write32(p, SG_SMMU, SG_CB_TLBSYNC, 0, 0)', 'false', 0),
            ('skip-tlb-wait', 'sgpu_render_live_link', '!poll(p, SG_SMMU, SG_CB_TLBSTATUS, 1, 0, 10000)', 'false', 1),
            ('actual-root', 'sgpu_render_live_tables', 'if (l2[i] != want) return false;',
             'if (!linked && l2[i] != want) return false;', 12),
            ('legacy-mapping', 'sgpu_render_live_tables', 'if (l3[i] != sgpu_render_live.legacy_l3[i]) return false;',
             '(void)l3;', 15),
            ('retention', 'sgpu_render_live_link', 'a->exposed = r->exposed = true;',
             'a->exposed = r->exposed = false;', 4),
            ('padding', 'sgpu_render_live_compare', 'i < stride; i++', 'i < width * 4; i++', 11),
            ('compare', 'sgpu_render_live_job', '!sgpu_render_live_compare(source,destination,SGPU_RENDER_WIDTH,SGPU_RENDER_HEIGHT,SGPU_RENDER_STRIDE)',
             '!sgpu_render_live_compare(source,destination,SGPU_RENDER_WIDTH,SGPU_RENDER_HEIGHT,SGPU_RENDER_STRIDE) && false', 10),
            ('private-fence', 'sgpu_render_live_job', '!sgpu_render_wait(a)', '!sgpu_render_wait(a) && false', 9),
            ('offset', 'sgpu_render_live_job', 'ring[r->wptr+i] = sgpu_render_live.commands[i];',
             'ring[r->wptr+i] = sgpu_render_live.commands[i] ^ (sgpu_render_live.commands[i] == SGPU_RENDER_VA + SGPU_PAGE ? 4096u : 0u);', 0),
        )
        for name, function, old, new, case in changes:
            body = source_function(self.core, function)
            self.assertEqual(body.count(old), 1, name)
            changed = self.core.replace(body, body.replace(old, new, 1), 1)
            self.native('mutant-' + name, 'core', ['-O2'], changed, (case,), False)

    def test_captured_response_rejects_the_actual_previous_core(self):
        previous = reconstruct(self.root / 'captured-baseline', through=221, targets=FILES)
        old = (self.root / 'captured-baseline/bsd/dev/santoni_gpu_core.c').read_text()
        self.assertTrue(previous['sha256'])
        self.native('baseline-captured', 'core', ['-O2'], old, (0,), False)

    def test_compiled_adapter_mutants_rejected(self):
        changes = (
            ('foreign-client', 'sgpu_render_options', 'sg.user || sg.user_test ||', 'sg.user_test ||', 12),
            ('mode2', 'sgpu_render_options', 'enabled != 1 || mode != 3', 'enabled != 1 || mode == 42', 18),
            ('late-pmap', 'sgpu_render_allocate', '!sgpu_render_validate(&sgpu_render_owned)',
             '!sgpu_render_validate(&sgpu_render_owned) && false', 3),
            ('free-exposed', 'sgpu_render_release', 'if (sgpu_render_allocation_retained) return;',
             'if (false) return;', 7),
            ('wrong-dispatch', 'sgpu_kernel_thread', 'if (sgpu_render_enabled == 1) {',
             'if (sgpu_render_enabled == 2) {', 30),
        )
        for name, function, old, new, case in changes:
            body = source_function(self.adapter, function)
            self.assertEqual(body.count(old), 1, name)
            changed = self.adapter.replace(body, body.replace(old, new, 1), 1)
            self.native('mutant-' + name, 'adapter', ['-O2'], changed, (case,), False)

    def test_legacy_state_machines_and_ops_ABI_unchanged(self):
        previous = reconstruct(self.root / 'previous', through=220, targets=FILES)
        old = (self.root / 'previous/bsd/dev/santoni_gpu_core.c').read_text()
        for name in ('sgpu_bootstrap', 'sgpu_session_start', 'sgpu_session_prepare', 'sgpu_session_stop',
                     'sgpu_session_execute', 'sgpu_blit_commands', 'sgpu_tables_build'):
            self.assertEqual(source_function(old, name), source_function(self.core, name))
        current_h = (self.dev / 'santoni_gpu_core.h').read_text()
        old_h = (self.root / 'previous/bsd/dev/santoni_gpu_core.h').read_text()
        self.assertEqual(old_h.split('struct sgpu_ops {', 1)[1].split('};', 1)[0],
                         current_h.split('struct sgpu_ops {', 1)[1].split('};', 1)[0])
        self.assertTrue(previous['sha256'])


if __name__ == '__main__':
    unittest.main()
