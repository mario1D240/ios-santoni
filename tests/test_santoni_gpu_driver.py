#!/usr/bin/env python3
"""Execute the shipped A505 core, not a duplicate driver or a stale checkout."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'tests'))
from reconstruct_santoni_touch import selected_sections
from tests.native_santoni_gpu_core import reconstruct, core_link_dependencies
import santoni_gpu_prepare as prep
import santoni_gpu_boot as boot
from test_santoni_gpu_prepare import source_function

FILES = ('bsd/dev/santoni_gpu_core.c', 'bsd/dev/santoni_gpu_core.h', 'bsd/dev/santoni_gpu.c')
TMP = Path('/data/data/com.termux/files/usr/tmp/opencode')
TMP_ROOT = TMP if TMP.is_dir() else None
CC = shlex.split(os.environ.get('HOST_CC', 'clang'))


class FirmwareView(ctypes.Structure):
    _fields_ = [('pm4', ctypes.c_void_p), ('pfp', ctypes.c_void_p),
                ('pm4_bytes', ctypes.c_uint32), ('pfp_bytes', ctypes.c_uint32),
                ('pm4_version', ctypes.c_uint32), ('pfp_version', ctypes.c_uint32)]


class DriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='a505-actual-', dir=TMP_ROOT)
        cls.path = Path(cls.temp.name)
        cls.meta = reconstruct(cls.path / 'source', targets=FILES)
        cls.dev = cls.path / 'source/bsd/dev'
        cls.core = (cls.dev / 'santoni_gpu_core.c').read_text()
        cls.adapter = (cls.dev / 'santoni_gpu.c').read_text()
        cls.binary = cls.path / 'driver-tests'
        subprocess.run([*CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-DARM64_BOARD_CONFIG_SANTONI', '-I', str(cls.dev),
                        str(ROOT / 'tests/test_santoni_gpu_mock.c'),
                        str(cls.dev / 'santoni_gpu_core.c'), *core_link_dependencies(cls.dev), '-o', str(cls.binary)],
                       check=True, timeout=60)
        cls.library = cls.path / ('driver.dylib' if sys.platform == 'darwin' else 'driver.so')
        subprocess.run([*CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-shared',
                        '-DARM64_BOARD_CONFIG_SANTONI', '-fPIC',
                        str(cls.dev / 'santoni_gpu_core.c'), *core_link_dependencies(cls.dev), '-o', str(cls.library)],
                       check=True, timeout=60)
        cls.lib = ctypes.CDLL(str(cls.library))
        cls.lib.sgpu_firmware_validate.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
        cls.lib.sgpu_firmware_validate.restype = ctypes.c_bool
        cls.lib.sgpu_packet7.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
        cls.lib.sgpu_packet7.restype = ctypes.c_uint32

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_actual_state_machine_cases(self):
        output = subprocess.check_output([str(self.binary)], text=True, timeout=30)
        self.assertIn('PASS 40 actual-driver scenarios', output)

    def test_actual_power_failure_records_and_cleanup_order(self):
        binary = self.path / 'power-failures'
        subprocess.run([*CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-DARM64_BOARD_CONFIG_SANTONI', '-I', str(self.dev),
                        str(ROOT / 'tests/test_santoni_gpu_power.c'),
                        str(self.dev / 'santoni_gpu_core.c'), *core_link_dependencies(self.dev), '-o', str(binary)],
                       check=True, timeout=60)
        output = subprocess.check_output([str(binary)], text=True, timeout=30)
        self.assertIn('owners=6 readbacks=13 polls=13', output)
        self.assertIn('immutable evidence; clocks before GX collapse', output)

    def test_actual_private_guards_and_timeout_boundaries(self):
        binary = self.path / 'helper-failures'
        subprocess.run([*CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-DARM64_BOARD_CONFIG_SANTONI', '-I', str(self.dev),
                        str(ROOT / 'tests/test_santoni_gpu_helpers.c'), *core_link_dependencies(self.dev), '-o', str(binary)],
                       check=True, timeout=60)
        output = subprocess.check_output([str(binary)], text=True, timeout=30)
        self.assertIn('PASS helper guards', output)

    def test_audit_safety_scenarios(self):
        binary = self.path / 'audit-safety'
        subprocess.run([*CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-DARM64_BOARD_CONFIG_SANTONI', '-I', str(self.dev),
                        str(ROOT / 'tests/test_santoni_gpu_safety.c'),
                        str(self.dev / 'santoni_gpu_core.c'), *core_link_dependencies(self.dev), '-o', str(binary)], check=True, timeout=60)
        output = subprocess.check_output([str(binary)], text=True, timeout=30)
        self.assertIn('PASS 133 audit safety scenarios', output)

    def test_actual_A505_stop_resume_contract(self):
        binary = self.path / 'cp-stop-resume'
        subprocess.run([*CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-DARM64_BOARD_CONFIG_SANTONI', '-I', str(self.dev),
                        str(ROOT / 'tests/test_santoni_gpu_cp.c'),
                        str(self.dev / 'santoni_gpu_core.c'), *core_link_dependencies(self.dev), '-o', str(binary)], check=True, timeout=60)
        output = subprocess.check_output([str(binary)], text=True, timeout=30)
        self.assertIn('PASS 26 A505 stop/resume scenarios', output)

    def pas_adapter_section(self):
        start = self.adapter.index('/* PAS preparation only:')
        end = self.adapter.index('/* PAS cache view:', start)
        return self.adapter[start:end]

    def cache_adapter_section(self):
        start = self.adapter.index('/* PAS cache view:')
        end = self.adapter.index('/* SCM query policy:', start)
        return self.adapter[start:end]

    def scm_adapter_section(self):
        start = self.adapter.index('/* SCM query policy:')
        end = self.adapter.index('static void __attribute__((noinline)) sgpu_failure_summary', start)
        return self.adapter[start:end]

    def adapter_without_scm(self):
        block = ('    if (sgpu_scm_capability_probe(sg.mode)) {\n'
                 '        thread_terminate_self();\n        return;\n    }\n')
        self.assertEqual(self.adapter.count(block), 1)
        cache_hook = ('    if (sgpu_pas_cache_preflight(sg.mode)) {\n'
                      '        thread_terminate_self();\n        return;\n    }\n')
        declarations = ('extern bool pmap_santoni_pas_cache_control(ppnum_t, unsigned int, unsigned int);\n'
                        'extern vm_map_address_t phystokv(uint64_t);\n'
                        'extern boolean_t ml_set_interrupts_enabled(boolean_t);\n')
        self.assertEqual(self.adapter.count(cache_hook), 1)
        self.assertEqual(self.adapter.count(declarations), 1)
        self.assertEqual(self.adapter.count('#include <arm/memory_types.h>\n'), 1)
        return (self.adapter.replace(self.scm_adapter_section(), '', 1).replace(block, '', 1)
                .replace(self.cache_adapter_section(), '', 1).replace(cache_hook, '', 1)
                .replace(declarations, '', 1).replace('#include <arm/memory_types.h>\n', '', 1))

    def scm_host_header(self):
        section = self.scm_adapter_section()
        portable = section[:section.index('/* SCM capability probe:')]
        self.assertNotIn('__asm__', portable)
        self.assertNotIn('smc #', portable)
        return (f'/* Adapter SHA256: {hashlib.sha256(self.adapter.encode()).hexdigest()} */\n'
                + portable + '\n' + source_function(self.adapter, 'sgpu_scm_capability_probe')
                + '\n' + source_function(self.adapter, 'sgpu_stock_options')
                + '\n' + source_function(self.adapter, 'sgpu_pixel_options')
                + '\n' + source_function(self.adapter, 'sgpu_g3_options')
                + '\n' + source_function(self.adapter, 'sgpu_session_options')
                + '\n' + source_function(self.adapter, 'sgpu_user_options')
                + '\n' + source_function(self.adapter, 'sgpu_user_test_options')
                + '\n' + source_function(self.adapter, 'sgpu_kernel_thread') + '\n')

    def test_actual_scm_scalar_policy_entry_and_worker_contract(self):
        folder = self.path / 'scm-contract'
        folder.mkdir()
        (folder / 'santoni_gpu_scm_actual.h').write_text(self.scm_host_header())
        for label, flags in (('O0', ['-O0']), ('O2', ['-O2']),
                             ('ubsan', ['-O2', '-fsanitize=undefined', '-fno-sanitize-recover=all'])):
            with self.subTest(variant=label):
                binary = folder / label
                subprocess.run([*CC, '-std=c11', *flags, '-Wall', '-Wextra', '-Werror',
                                '-DARM64_BOARD_CONFIG_SANTONI', '-I', str(folder), '-I', str(self.dev),
                                str(ROOT / 'tests/test_santoni_gpu_scm.c'), '-o', str(binary)],
                               check=True, timeout=60)
                output = subprocess.check_output([str(binary)], text=True, timeout=30)
                self.assertIn('PASS actual SCM scalar policy/entry/worker', output)

    def test_scm_preserves_existing_core_and_adapter_bytes(self):
        previous = self.path / 'before-SCM'
        scm_only = self.path / 'through-SCM'
        reconstruct(previous, through=200, targets=FILES)
        reconstruct(scm_only, through=201, targets=FILES)
        for name in ('santoni_gpu_core.c', 'santoni_gpu_core.h'):
            self.assertEqual((previous / 'bsd/dev' / name).read_bytes(), (scm_only / 'bsd/dev' / name).read_bytes())
        old = (scm_only / 'bsd/dev/santoni_gpu.c').read_text()
        section = old[old.index('/* SCM query policy:'):old.index('static void __attribute__((noinline)) sgpu_failure_summary')]
        self.assertEqual(section, self.scm_adapter_section(), 'later work must preserve the full scalar SCM implementation')
        hook = ('    if (sgpu_scm_capability_probe(sg.mode)) {\n'
                '        thread_terminate_self();\n        return;\n    }\n')
        self.assertEqual(old.replace(section, '', 1).replace(hook, '', 1),
                         (previous / 'bsd/dev/santoni_gpu.c').read_text())
        patch_text = (ROOT / 'xnu/patches/0201-santoni-gpu-scm-capability-probe.patch').read_text()
        self.assertEqual(re.findall(r'(?m)^\+\+\+ b/(.+)$', patch_text), ['bsd/dev/santoni_gpu.c'])

    def test_CI_skip_guard_covers_0201_and_all_numbered_santoni_patches(self):
        workflow = (ROOT / '.github/workflows/xnu.yml').read_text()
        guard = re.search(r"if grep -E '([^']+)' build\.log; then", workflow)
        self.assertIsNotNone(guard)
        names = [p.name for p in (ROOT / 'xnu/patches').glob('*-santoni-*.patch')]
        self.assertIn('0201-santoni-gpu-scm-capability-probe.patch', names)
        for name in (*names, '0300-santoni-gpu-future.patch'):
            with self.subTest(patch=name):
                self.assertRegex('Skipping patch patches/' + name, guard[1])
        self.assertNotRegex('Skipping patch patches/0130-sailfish-gpu-zap-shader.patch', guard[1])

    def test_actual_scm_unsafe_mutations_are_rejected(self):
        header = self.scm_host_header()
        probe = source_function(self.adapter, 'sgpu_scm_capability_probe')
        self.assertEqual(probe.count('    return true;\n}'), 1)
        mutations = (
            ('mode', 'mode != 3 || zap != 1', 'mode == 42 || zap != 1'),
            ('zap', 'zap != 1 || probe != 1', 'zap == 42 || probe != 1'),
            ('scm', 'probe != 1 || request[1]', 'probe == 42 || request[1]'),
            ('session-argument', '|| request[6] ||', '|| (request[6] & 0) ||'),
            ('arginfo', 'request[1] != 1', 'request[1] == 42'),
            ('forbidden-PAS', 'fn != SGPU_SCM_PAS_SUPPORTED ||', 'fn != 0x02000201ull ||'),
            ('function-width', 'request[0] & ~(uint64_t)SGPU_SCM_64',
             '(uint32_t)request[0] & ~(uint32_t)SGPU_SCM_64'),
            ('interrupted-frame', 'continue; /* returned x0..x6/session x6, original convention */',
             'memcpy(frame, request, sizeof(frame)); continue;'),
            ('busy-frame', 'memcpy(frame, request, sizeof(frame));\n            continue; /* fresh',
             '/* lost original frame */\n            continue; /* fresh'),
            ('shared-call-budget', 'int32_t status = 0;', 'int32_t status = 0; budget->calls = 0;'),
            ('shared-time-budget', 'int32_t status = 0;',
             'int32_t status = 0; budget->start = ops->now_us(ops->ctx);'),
            ('shared-busy-budget', 'int32_t status = 0;', 'int32_t status = 0; budget->busy_retries = 0;'),
            ('deadline-boundary', 'result->elapsed_us >= SGPU_SCM_BUDGET_US',
             'result->elapsed_us > SGPU_SCM_BUDGET_US'),
            ('transport-vs-service', 'return status == 0;', 'return frame[1] == 1;'),
            ('immutable-failure', 'if (report->failed_phase) return;',
             'if (report->failed_phase == 42) return;'),
            ('availability', 'if (!ok || report->availability.raw[1] != 1)',
             'if (!ok && report->availability.raw[1] != 1)'),
            ('error-fallback', 'status == -1 || status == -4', 'status < 0'),
            ('worker-continuation', probe, probe.replace('    return true;\n}', '    return false;\n}')),
        )
        results = []
        for label, old, new in mutations:
            with self.subTest(mutant=label):
                self.assertIn(old, header, f'mutant {label} no longer targets production')
                folder = self.path / ('scm-mutant-' + label)
                folder.mkdir()
                (folder / 'santoni_gpu_scm_actual.h').write_text(header.replace(old, new))
                binary = folder / 'run'
                compiled = subprocess.run([*CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-DARM64_BOARD_CONFIG_SANTONI', '-I', str(folder), '-I', str(self.dev),
                    str(ROOT / 'tests/test_santoni_gpu_scm.c'), '-o', str(binary)],
                    capture_output=True, text=True, timeout=60)
                self.assertEqual(compiled.returncode, 0, f'{label} did not compile: {compiled.stderr}')
                rejected = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
                self.assertNotEqual(rejected.returncode, 0, f'unsafe mutant survived: {label}')
                results.append({'mutant': label, 'compile': compiled.returncode,
                                'run': rejected.returncode})
        self.assertEqual(len(results), len(mutations))
        print(f'SCM contracts rejected {len(results)} compiled unsafe mutations')

    def test_actual_pas_allocation_and_staging_contract(self):
        folder = self.path / 'pas-memory'
        folder.mkdir()
        (folder / 'santoni_gpu_pas_actual.h').write_text(self.pas_adapter_section())
        for label, flags in (('O0', ['-O0']), ('O2', ['-O2']),
                             ('ubsan', ['-O2', '-fsanitize=undefined', '-fno-sanitize-recover=all'])):
            with self.subTest(variant=label):
                binary = folder / label
                subprocess.run([*CC, '-std=c11', *flags, '-Wall', '-Wextra', '-Werror',
                                '-I', str(folder), str(ROOT / 'tests/test_santoni_gpu_pas_memory.c'),
                                '-o', str(binary)], check=True, timeout=60)
                output = subprocess.check_output([str(binary)], text=True, timeout=10)
                self.assertIn('PASS actual PAS allocation', output)

    def test_pas_preflight_leaves_core_and_existing_adapter_paths_unchanged(self):
        previous = self.path / 'before-PAS-preflight'
        preflight_only = self.path / 'through-PAS-preflight'
        reconstruct(previous, through=198, targets=FILES)
        reconstruct(preflight_only, through=200, targets=FILES)
        for name in ('santoni_gpu_core.c', 'santoni_gpu_core.h'):
            self.assertEqual((previous / 'bsd/dev' / name).read_bytes(), (preflight_only / 'bsd/dev' / name).read_bytes())
        old = (previous / 'bsd/dev/santoni_gpu.c').read_text()
        new = (preflight_only / 'bsd/dev/santoni_gpu.c').read_text()
        section = new[new.index('/* PAS preparation only:'):new.index('static void __attribute__((noinline)) sgpu_failure_summary')]
        self.assertEqual(section, self.pas_adapter_section(), 'later work must preserve the full allocation preflight')
        new = new.replace(section, '', 1)
        self.assertEqual(new.replace('    sgpu_zap_allocation_preflight(sg.mode);\n', '', 1), old)
        worker = source_function(self.adapter, 'sgpu_kernel_thread')
        self.assertLess(worker.index('40000000u'), worker.index('sgpu_zap_allocation_preflight'))
        preflight = source_function(self.adapter, 'sgpu_zap_allocation_preflight')
        self.assertLess(preflight.index('mode != 3'), preflight.index('PE_parse_boot_argn'))
        self.assertLess(preflight.index('enabled != 1'), preflight.index('SecureDTLookupEntry'))
        self.assertNotIn('smc #', self.pas_adapter_section())
        self.assertNotIn('CP_SET_SECURE_MODE', self.pas_adapter_section())

    def test_actual_SP_clock_photo_oracle_and_full_final_echo(self):
        previous = self.path / 'SP-before-0194'
        reconstruct(previous, through=193, targets=FILES)
        for label, dev, flags in (('captured', previous / 'bsd/dev',
                                   ['-DEXPECT_LEGACY_SP_FAILURE', '-DSANTONI_GPU_ALLOW_LEGACY_CP']),
                                  ('current', self.dev, [])):
            binary = self.path / ('SP-clock-' + label)
            subprocess.run([*CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                            '-DARM64_BOARD_CONFIG_SANTONI', *flags, '-I', str(dev),
                            str(ROOT / 'tests/test_santoni_gpu_sp_clock.c'),
                            str(dev / 'santoni_gpu_core.c'), *core_link_dependencies(dev), '-o', str(binary)], check=True, timeout=60)
            output = subprocess.check_output([str(binary)], text=True, timeout=30)
            self.assertIn('PASS captured 545038a TOP echo failure oracle' if label == 'captured' else
                          'PASS 36 SP clock scenarios', output)

    def test_forward_mmio_changes_only_the_unused_gmem_clock(self):
        before = self.path / 'clock-before-0186'
        after = self.path / 'clock-after-0186'
        reconstruct(before, through=185, targets=FILES)
        reconstruct(after, through=186, targets=FILES)
        outputs = []
        for label, dev in (('before', before / 'bsd/dev'), ('after', after / 'bsd/dev')):
            binary = self.path / ('forward-' + label)
            subprocess.run([*CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                            '-DARM64_BOARD_CONFIG_SANTONI', '-DSANTONI_GPU_LEGACY_REPORT',
                            '-I', str(dev),
                            str(ROOT / 'tests/fixtures/santoni_gpu_forward_trace.c'),
                            str(dev / 'santoni_gpu_core.c'), *core_link_dependencies(dev), '-o', str(binary)],
                            check=True, timeout=60)
            outputs.append(subprocess.check_output([str(binary)], text=True, timeout=30))
        unused = re.compile(r'^[RW]32 0 00000024 ', re.MULTILINE)
        old_lines = outputs[0].splitlines(keepends=True)
        removed = [line for line in old_lines if unused.match(line)]
        self.assertEqual(len(removed), 9, 'old driver must access GMEM three times per mode')
        self.assertEqual([line for line in old_lines if not unused.match(line)],
                         outputs[1].splitlines(keepends=True))
        self.assertFalse(unused.search(outputs[1]))
        self.assertIn('MODE 3\n', outputs[0])
        self.assertIn('W32 0 00000004 00000001\n', outputs[0])

    def test_safety_checks_preserve_each_modes_clock_and_command_operations(self):
        before = self.path / 'safety-before-0187'
        after = self.path / 'safety-through-0191'
        reconstruct(before, through=186, targets=FILES)
        reconstruct(after, through=191, targets=FILES)
        outputs = []
        for label, dev, flags in (('before-safety', before / 'bsd/dev',
                                   ['-DSANTONI_GPU_LEGACY_REPORT']),
                                  ('after-safety', after / 'bsd/dev', [])):
            binary = self.path / ('forward-' + label)
            subprocess.run([*CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                            '-DARM64_BOARD_CONFIG_SANTONI', *flags, '-I', str(dev),
                            str(ROOT / 'tests/fixtures/santoni_gpu_forward_trace.c'),
                            str(dev / 'santoni_gpu_core.c'), *core_link_dependencies(dev), '-o', str(binary)],
                           check=True, timeout=60)
            outputs.append(subprocess.check_output([str(binary)], text=True, timeout=30))
        from collections import Counter
        modes = [re.split(r'(?m)^MODE [123]\n', text)[1:] for text in outputs]
        self.assertEqual([len(group) for group in modes], [3, 3])
        for mode, (old, new) in enumerate(zip(*modes), 1):
            with self.subTest(mode=mode):
                new_lines = new.splitlines()
                first_write = next(i for i, line in enumerate(new_lines) if line.startswith('W'))
                gate = 'R32 0 00000020 80000000'
                self.assertEqual(new_lines[:first_write].count(gate), 1)
                self.assertNotIn(gate, old.splitlines()[:first_write])
                new_lines.remove(gate)  # 0189's sole added clock operation: cold GFX ownership read
                if mode >= 2:
                    halt = 'W32 4 0000019c 00000055'
                    clock = 'W32 4 0000019c aaa8aa00'
                    isdb = 'W32 4 000014cc 00000182'
                    first_hwcg = 'W32 4 000001a0 02222222'
                    last_hwcg = 'W32 4 00000248 00002222'
                    for operation in (halt, clock, isdb):
                        self.assertEqual(new_lines.count(operation), 1)
                    self.assertLess(new_lines.index(halt), new_lines.index(first_hwcg))
                    self.assertLess(new_lines.index(last_hwcg), new_lines.index(clock))
                    self.assertLess(new_lines.index(clock), new_lines.index(isdb))
                    self.assertLess(new_lines.index(isdb), new_lines.index('W32 4 0000c124 00000003'))
                    old_lines = old.splitlines()
                    self.assertEqual(old_lines.count(halt), 1)
                    old_lines.remove(halt)
                    old = '\n'.join(old_lines)
                    for operation in (halt, clock, isdb):
                        new_lines.remove(operation)
                new = '\n'.join(new_lines)
                stable = lambda text: [line for line in text.splitlines()
                                       if not re.match(r'^R(?:32|64) [45] |^W(?:32|64) 5 ', line)]
                self.assertEqual(stable(old), stable(new))
                smmu_writes = lambda text: [line for line in text.splitlines()
                                           if re.match(r'^W(?:32|64) 5 ', line)]
                old_writes, new_writes = smmu_writes(old), smmu_writes(new)
                # The only reordered write sets the unmatched-stream FAULT policy
                # before enabling CB0/SID0. All address/format/route writes remain.
                policy = 'W32 5 00000000 00000412'
                if mode >= 2:
                    self.assertEqual(old_writes.count(policy), 1)
                    self.assertEqual(new_writes.count(policy), 1)
                    self.assertLess(new_writes.index(policy),
                                    new_writes.index('W32 5 00008000 00001127'))
                self.assertEqual([line for line in old_writes if line != policy],
                                 [line for line in new_writes if line != policy])
                reads = lambda text: Counter(line for line in text.splitlines()
                                             if re.match(r'^R(?:32|64) [45] ', line))
                self.assertFalse(reads(old) - reads(new), 'safety checks must not drop existing reads')

    def test_A505_fix_preserves_power_and_other_MMIO_through_cleanup(self):
        previous = self.path / 'pre-A505-stop'
        after = self.path / 'A505-through-0193'
        reconstruct(previous, through=191, targets=FILES)
        reconstruct(after, through=193, targets=FILES)
        outputs = []
        for label, dev in (('old-stop', previous / 'bsd/dev'), ('new-stop', after / 'bsd/dev')):
            binary = self.path / label
            subprocess.run([*CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                            '-DARM64_BOARD_CONFIG_SANTONI', '-DSANTONI_GPU_TRACE_CLEANUP',
                            '-I', str(dev), str(ROOT / 'tests/fixtures/santoni_gpu_forward_trace.c'),
                            str(dev / 'santoni_gpu_core.c'), *core_link_dependencies(dev), '-o', str(binary)], check=True, timeout=60)
            outputs.append(subprocess.check_output([str(binary)], text=True, timeout=30))
        old_modes, new_modes = [re.split(r'(?m)^MODE [123]\n', text)[1:] for text in outputs]
        self.assertEqual(old_modes[0], new_modes[0], 'mode1 power/readback/rollback must be identical')
        table = prep.block(self.core, 'hwcg[][2]')
        hwcg = {int(a, 0) for a in re.findall(r'\{\s*(0x[0-9a-f]+)\s*,', table)} | {0x19c, 0x14cc}
        def is_hwcg(line):
            fields = line.split()
            return len(fields) == 4 and fields[0] in ('R32', 'W32') and fields[1] == '4' and int(fields[2], 16) in hwcg
        for mode, old, new in zip((2, 3), old_modes[1:], new_modes[1:]):
            with self.subTest(mode=mode):
                old_lines, new_lines = old.splitlines(), new.splitlines()
                writes = lambda lines: [line for line in lines if line.startswith('W32') and is_hwcg(line)]
                self.assertEqual(writes(new_lines), writes(old_lines) * 2)
                status = lambda line: line.startswith('R32 4 000013d4 ')
                self.assertEqual(sum(map(status, new_lines)), sum(map(status, old_lines)) + 1)
                stable = lambda lines: [line.replace(' 10000000', ' 00000003')
                                       if re.match(r'^[RW]32 4 000020c8 ', line) else line
                                       for line in lines if not is_hwcg(line) and not status(line)]
                self.assertEqual(stable(old_lines), stable(new_lines))
                halts = [i for i, line in enumerate(new_lines) if line == 'W32 4 000020c8 00000003']
                resumes = [i for i, line in enumerate(new_lines) if line == 'W32 4 000014cc 00000182']
                self.assertEqual(len(halts), 3)
                self.assertEqual(len(resumes), 2)
                self.assertLess(resumes[0], halts[0])
                self.assertLess(halts[0], resumes[1])
                self.assertLess(resumes[1], halts[1])
                first_smmu_read = next(i for i, line in enumerate(new_lines) if line.startswith('R32 5 '))
                self.assertLess(halts[1], first_smmu_read)

    def test_SP_release_changes_only_the_vendor_TOP_ISDB_sequence(self):
        previous = self.path / 'SP-trace-through-0193'
        reconstruct(previous, through=193, targets=FILES)
        outputs = []
        for label, dev in (('SP-before', previous / 'bsd/dev'), ('SP-after', self.dev)):
            binary = self.path / label
            subprocess.run([*CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                            '-DARM64_BOARD_CONFIG_SANTONI', '-DSANTONI_GPU_TRACE_CLEANUP',
                            '-I', str(dev), str(ROOT / 'tests/fixtures/santoni_gpu_forward_trace.c'),
                            str(dev / 'santoni_gpu_core.c'), *core_link_dependencies(dev), '-o', str(binary)], check=True, timeout=60)
            outputs.append(subprocess.check_output([str(binary)], text=True, timeout=30))
        old_modes, new_modes = [re.split(r'(?m)^MODE [123]\n', text)[1:] for text in outputs]
        self.assertEqual(old_modes[0], new_modes[0], 'mode1 forward and cleanup must stay exact')
        clock = re.compile(r'^[RW]32 4 (?:0000019c|000014cc) ')
        smmu_format = re.compile(r'^[RW]32 5 00008030 ')
        for mode, old, new in zip((2, 3), old_modes[1:], new_modes[1:]):
            with self.subTest(mode=mode):
                old_lines, new_lines = old.splitlines(), new.splitlines()
                self.assertEqual(
                    [line for line in old_lines
                     if not clock.match(line) and not smmu_format.match(line)],
                    [line for line in new_lines
                     if not clock.match(line) and not smmu_format.match(line)])
                old_smmu = [line for line in old_lines if smmu_format.match(line)]
                new_smmu = [line for line in new_lines if smmu_format.match(line)]
                self.assertEqual(len(old_smmu), len(new_smmu))
                def normalize(lines):
                    return [line.replace('00802520', '00802560')
                            if line.endswith('00802520') else line
                            for line in lines]
                self.assertEqual(normalize(old_smmu), new_smmu)
                a = [line for line in old_lines if clock.match(line)]
                b = [line for line in new_lines if clock.match(line)]
                self.assertEqual(len(a), 18)
                self.assertEqual(len(b), 20)
                for epoch in range(2):
                    before, after = a[epoch * 9:(epoch + 1) * 9], b[epoch * 10:(epoch + 1) * 10]
                    self.assertEqual(after, before[:3] + [before[4]] + before[6:9] +
                                     [before[5], before[4], before[5]])

    def test_exact_hardware_gmem_failure_reproduction_and_target_fix(self):
        before = self.path / 'pre-0186'
        reconstruct(before, through=185, targets=FILES)
        for label, dev, flags in (('legacy', before / 'bsd/dev', ['-DEXPECT_LEGACY_GMEM_FAILURE',
                                                               '-DSANTONI_GPU_LEGACY_REPORT']),
                                  ('current', self.dev, [])):
            binary = self.path / ('gmem-oracle-' + label)
            subprocess.run([*CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                            '-DARM64_BOARD_CONFIG_SANTONI', *flags, '-I', str(dev),
                            str(ROOT / 'tests/fixtures/santoni_gpu_gmem_oracle.c'),
                            str(dev / 'santoni_gpu_core.c'), *core_link_dependencies(dev), '-o', str(binary)], check=True, timeout=60)
            output = subprocess.check_output([str(binary)], text=True, timeout=30)
            self.assertIn('PASS ' + label, output)

    def test_driver_branches_match_actual_device_clocks(self):
        if not prep.VENDOR.is_dir():
            self.skipTest('optional vendor tree absent; strict native GMEM-access gate still runs')
        body = prep.block(self.core, 'branches[]')
        offsets = [int(value, 0) for value in re.findall(r'0x[0-9a-f]+|\d+', body)]
        clocks = prep.vendor_target()['gpu_required_clocks']
        self.assertEqual(len(offsets), len(clocks))
        self.assertEqual({0x59000 + offset for offset in offsets},
                         {clock['byte_offset'] for clock in clocks})
        self.assertNotIn(0x24, offsets)

    def test_failure_evidence_is_printed_beside_result_without_hardware_reads(self):
        summary = source_function(self.adapter, 'sgpu_failure_summary')
        worker = source_function(self.adapter, 'sgpu_kernel_thread')
        self.assertNotIn('read32', summary)
        self.assertNotIn('wait_us', summary)
        self.assertLess(worker.index('sgpu_failure_summary("FIRST_FAIL"'), worker.index('SANTONI GPU: RESULT'))
        self.assertIn('sgpu_failure_summary("ROLLBACK_FAIL"', worker)
        self.assertIn('trust_read=%u', worker)
        self.assertIn('addr=%08x', summary)
        self.assertIn('saved=%u', summary)

    def test_actual_failure_summary_formats_physical_address_and_observed_values(self):
        summary = source_function(self.adapter, 'sgpu_failure_summary')
        addresses = re.search(r'(?ms)^static const uint32_t sgpu_block_pa\[SG_BLOCKS\] = \{.*?^\};',
                              self.adapter).group(0)
        code = '#include <stdio.h>\n#include "santoni_gpu_core.h"\n' + addresses + '\n' + summary
        code += '''
int main(void) {
    struct sgpu_failure f = {.stage=SG_POWER, .kind=SG_FAIL_READBACK, .block=SG_CC,
        .offset=4, .mask=0x371f, .want=1, .old=0, .written=1, .got=0, .saved_count=2};
    sgpu_failure_summary("FIRST_FAIL", &f);
    f.kind=SG_FAIL_POLL; f.block=SG_TCU; f.offset=0x20;
    f.mask=0x80000000; f.want=0; f.got=0x80000000; f.elapsed_us=10000; f.budget_us=10000;
    sgpu_failure_summary("ROLLBACK_FAIL", &f);
    f.kind=SG_FAIL_NONE; sgpu_failure_summary("MUST_NOT_PRINT", &f);
    return 0;
}
'''
        source, binary = self.path / 'failure-summary.c', self.path / 'failure-summary'
        source.write_text(code)
        subprocess.run([*CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-I', str(self.dev), str(source), '-o', str(binary)], check=True, timeout=60)
        output = subprocess.check_output([str(binary)], text=True, timeout=10)
        self.assertIn('FIRST_FAIL stage=2 kind=readback block=0 addr=01859004', output)
        self.assertIn('old=00000000 wrote=00000001 got=00000000 elapsed=0 budget=0 saved=2', output)
        self.assertIn('ROLLBACK_FAIL stage=2 kind=poll block=3 addr=01812020', output)
        self.assertIn('elapsed=10000 budget=10000', output)
        self.assertNotIn('MUST_NOT_PRINT', output)

    def test_patch_scope_and_startup_C_ABI(self):
        text = (ROOT / 'xnu/patches/0180-santoni-gpu-kernel-proof.patch').read_text()
        names = re.findall(r'(?m)^\+\+\+ b/(.+)$', text)
        self.assertEqual(set(names), {*FILES, 'bsd/conf/files', 'iokit/bsddev/IOKitBSDInit.cpp'})
        self.assertIn('extern "C" void santoni_gpu_start(void);', text)
        self.assertEqual(text.count('+\tsantoni_gpu_start();'), 1)
        self.assertIn('bsd/dev/santoni_gpu_core.c', text)
        self.assertNotIn('sweethidtest', text)

    def test_default_off_and_once_only_worker(self):
        start = self.adapter[self.adapter.index('void santoni_gpu_start(void)\n{'):]
        self.assertLess(start.index('mode == 0'), start.index('__atomic_exchange_n'))
        self.assertLess(start.index('__atomic_exchange_n'), start.index('kernel_thread_start'))
        self.assertIn('thread_terminate_self();', self.adapter)
        self.assertIn('wait_us(NULL, 40000000u)', self.adapter)
        self.assertNotIn('IOAccelerator', self.adapter)
        self.assertNotIn('IOUserClient', self.adapter)

    def test_actual_startup_with_runtime_page_macros_and_private_C_ABI(self):
        start = source_function(self.adapter, 'santoni_gpu_start')
        declaration = re.search(r'(?m)^extern void thread_terminate_self\(void\);$', self.adapter)
        self.assertIsNotNone(declaration)
        format_assert = re.search(r'(?m)^_Static_assert\([^\n]+;', self.adapter).group(0)
        code = '''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
int page_shift=14, bsd_page_shift=0;
unsigned long page_size=16384;
unsigned wanted=2, workers;
#define PAGE_SHIFT bsd_page_shift
#define PAGE_SIZE (1ul << bsd_page_shift)
#define SGPU_PAGE 4096u
#define KERN_SUCCESS 0
typedef unsigned long thread_t;
static struct { uint32_t attempted, mode; } sg;
static bool PE_parse_boot_argn(const char *name,void *out,unsigned n) {
    (void)name; assert(n==4); *(uint32_t *)out=wanted; return true;
}
static void sgpu_kernel_thread(void *a,int b) { (void)a; (void)b; }
static int kernel_thread_start(void (*f)(void *,int),void *arg,thread_t *out) {
    (void)f; (void)arg; workers++; *out=1; return 0;
}
static void thread_deallocate(thread_t t) { (void)t; }
void thread_terminate_self(void) {}
'''
        code += declaration.group(0) + '\n' + format_assert + '\n' + start
        code += '''
int main(void) {
    santoni_gpu_start(); assert(workers==0 && !sg.attempted);
    page_shift=12; santoni_gpu_start(); assert(workers==0 && !sg.attempted);
    page_size=4096; wanted=0; santoni_gpu_start(); assert(workers==0 && !sg.attempted);
    wanted=9; santoni_gpu_start(); assert(workers==0 && !sg.attempted);
    wanted=2; santoni_gpu_start(); assert(workers==1 && sg.mode==2 && sg.attempted);
    wanted=3; santoni_gpu_start(); assert(workers==1 && sg.mode==2);
    return 0;
}
'''
        source, binary = self.path / 'runtime-page-ABI.c', self.path / 'runtime-page-ABI'
        source.write_text(code)
        subprocess.run([*CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(source), '-o', str(binary)], check=True, timeout=60)
        subprocess.run([str(binary)], check=True, timeout=10)

    def test_launch_is_logged_before_delay_and_granule_gate(self):
        start = source_function(self.adapter, 'santoni_gpu_start')
        worker = source_function(self.adapter, 'sgpu_kernel_thread')
        self.assertLess(start.index('SANTONI GPU: request'), start.index('page_shift != 12'))
        self.assertIn('page_size != SGPU_PAGE', start)
        self.assertNotIn('if (PAGE_SHIFT', start)
        self.assertLess(worker.index('SANTONI GPU: worker entered'), worker.index('40000000u'))
        self.assertIn('SANTONI GPU: worker awake', worker)

    def test_trace_command_changes_only_console_visibility(self):
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        normal = boot.command_line(commit, 3)
        trace = boot.command_line(commit, 3, visible_console=True)
        self.assertEqual(normal.replace('sweetfb_noconsole=1', 'sweetfb_noconsole=0'), trace)
        self.assertIn('sweetlog=1', trace)
        self.assertIn('cpus=4', trace)
        self.assertIn('sweethidtest=0', trace)

    def test_packager_rejects_bare_duplicate_and_control_character_options(self):
        from unittest.mock import patch
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        recipe = subprocess.check_output(['git', 'show', f'{commit}:shim/build.sh'], cwd=ROOT, text=True)
        original = re.findall(r'^CMDLINE="([^"]+)"$', recipe, re.MULTILINE)[0]
        invalid = []
        for key in ('cpus', 'sweethidtest', 'sweetfb_noconsole', 'sweetfb_hz',
                    'sweetcpufreq', 'sweetlog', 'rd', 'rootrw', 'emmcrw'):
            invalid.extend((original + ' ' + key, key + ' ' + original,
                            original + ' ' + key + '=1'))
        for char in ('\0', '\t', '\n', '\r', '\x1f', '\x7f', '\x80'):
            invalid.append(original.replace(' ', char, 1))
        invalid.extend((original + ' -cpus=4', original + ' unknown_bare_flag',
                        original + ' santonigpu=1', original + ' cpus==4'))
        for line in invalid:
            for trace in (False, True):
                with self.subTest(line=repr(line), trace=trace), patch.object(
                        boot.subprocess, 'check_output', return_value='CMDLINE="' + line + '"\n'):
                    with self.assertRaises(ValueError):
                        boot.command_line(commit, 3, trace)

    def test_packager_requires_integer_modes_before_reading_artifacts(self):
        from unittest.mock import patch
        for mode in (-1, 4, 1.0, True, None, '1'):
            with self.subTest(mode=mode), patch.object(boot.subprocess, 'check_output') as read_recipe:
                with self.assertRaises(ValueError):
                    boot.command_line('a' * 40, mode)
                with self.assertRaises(ValueError):
                    boot.package('a' * 40, mode, self.path / 'unused')
                read_recipe.assert_not_called()

    def test_effective_controlled_arguments_against_actual_xnu_parser(self):
        # Private local buildtree is optional; portable grammar regressions always run.
        archive = ROOT / 'xnu-buildtree.zip'
        if not archive.is_file():
            self.skipTest('local XNU archive absent; portable strict-grammar tests still run')
        import tarfile
        import zipfile
        with zipfile.ZipFile(archive) as z, tarfile.open(fileobj=z.open('buildtree.tgz'), mode='r|gz') as tree:
            for entry in tree:
                if entry.name == 'xnu/pexpert/gen/bootargs.c':
                    text = tree.extractfile(entry).read().decode()
                    break
            else:
                self.fail('actual XNU boot-argument source absent')
        code = '''#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
typedef int boolean_t;
typedef boolean_t (*argsep_func_t)(char);
#define FALSE 0
#define TRUE 1
#define NUM 0
#define STR 1
struct i24 { int32_t i24 : 24; int32_t _pad : 8; };
static boolean_t isargsep(char);
static int argstrcpy2(char *, char *, unsigned);
static int argnumcpy(long long, void *, unsigned);
static int getval(char *, long long *, argsep_func_t, boolean_t);
'''
        code += '\n'.join(source_function(text, name) for name in (
            'PE_parse_boot_argn_internal', 'isargsep', 'argstrcpy2', 'argnumcpy', 'getval'))
        code += '''
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    uint32_t value=0;
    if (!PE_parse_boot_argn_internal(argv[1], argv[2], &value, sizeof(value), FALSE)) return 3;
    printf("%u\\n", value); return 0;
}
'''
        source, binary = self.path / 'actual-bootargs.c', self.path / 'actual-bootargs'
        source.write_text(code)
        subprocess.run([*CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(source), '-o', str(binary)], check=True, timeout=60)
        commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        for mode in range(4):
            for trace in (False, True):
                line = boot.command_line(commit, mode, trace)
                for name, value in (('cpus', 4), ('sweethidtest', 0), ('sweetfb_hz', 30),
                                    ('sweetfb_noconsole', int(not trace)), ('sweetcpufreq', 0),
                                    ('santonigpu', mode), ('santoniperf', 1), ('sweetlog', 1)):
                    actual = int(subprocess.check_output([str(binary), line, name], text=True, timeout=10))
                    self.assertEqual(actual, value, (name, line))

    def test_gpu_error_mask_matches_vendor_error_interrupts(self):
        header = (self.dev / 'santoni_gpu_core.h').read_text()
        value = int(re.search(r'#define SG_ERROR_IRQ_MASK\s+(0x[0-9a-f]+)u', header).group(1), 0)
        expected = (1, 2, 3, 4, 5, 6, 7, 9, 22, 23, 24, 25)
        self.assertEqual(value, sum(1 << bit for bit in expected))
        if prep.VENDOR.is_dir():
            defs = prep.defines((prep.VENDOR / 'drivers/gpu/msm/a5xx_reg.h').read_text())
            names = ('RBBM_AHB_ERROR', 'RBBM_TRANSFER_TIMEOUT', 'RBBM_ME_MS_TIMEOUT',
                     'RBBM_PFP_MS_TIMEOUT', 'RBBM_ETS_MS_TIMEOUT', 'RBBM_ATB_ASYNC_OVERFLOW',
                     'RBBM_GPC_ERROR', 'CP_HW_ERROR', 'RBBM_ATB_BUS_OVERFLOW',
                     'MISC_HANG_DETECT', 'UCHE_OOB_ACCESS', 'UCHE_TRAP_INTR')
            self.assertEqual(value, sum(1 << defs['A5XX_INT_' + name] for name in names))

    def test_actual_console_filter_never_hides_GPU_diagnostics(self):
        original_patch = ROOT / 'xnu/patches/0112-topaz-console-log-filter.patch'
        section = selected_sections(original_patch.read_bytes(), ('osfmk/console/serial_console.c',)).decode()
        added = '\n'.join(line[1:] for line in section.splitlines()
                          if line.startswith('+') and not line.startswith('+++'))
        function = source_function(added, 'sweet_log_wanted')
        folder = self.path / 'actual-console-filter'
        source = folder / 'osfmk/console/serial_console.c'
        source.parent.mkdir(parents=True)
        prefix = '''#include <stdbool.h>
#include <string.h>
#include <assert.h>
static char sweet_log_words[128]="1";
'''
        source.write_text(prefix + function + '\n')
        subprocess.run(['git', 'init', '--quiet', str(folder)], check=True, timeout=10)
        change = selected_sections((ROOT / 'xnu/patches/0184-santoni-gpu-startup-visibility.patch').read_bytes(),
                                   ('osfmk/console/serial_console.c',))
        for args in (['--check'], []):
            subprocess.run(['git', 'apply', *args, '-'], input=change, cwd=folder,
                           check=True, capture_output=True, timeout=10)
        code = source.read_text() + '''
int main(void) {
    const char *gpu="SANTONI GPU: kernel granule rejected, diagnostic skipped\\n";
    assert(sweet_log_wanted(gpu,(int)strlen(gpu)));
    assert(sweet_log_wanted("CPU1 online\\n",12));
    assert(!sweet_log_wanted("CPU0 online\\n",12));
    assert(!sweet_log_wanted("unrelated\\n",10));
    assert(!sweet_log_wanted("SANTONI GP",10));
    return 0;
}
'''
        source.write_text(code)
        binary = folder / 'filter-test'
        subprocess.run([*CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-DARM64_BOARD_CONFIG_SANTONI', str(source), '-o', str(binary)],
                       check=True, timeout=60)
        subprocess.run([str(binary)], check=True, timeout=10)

    def test_no_input_source_changes(self):
        before = reconstruct(self.path / 'input-before', through=179)
        after = reconstruct(self.path / 'input-after')
        self.assertEqual(before['sha256'], after['sha256'])

    def test_no_secure_or_wrong_SoC_writes(self):
        transition = source_function(self.core, 'sgpu_stock_transition')
        self.assertNotRegex(self.core.replace(transition, '', 1), r'write(?:32|64)\([^;]*SG_TRUST')
        self.assertEqual(re.findall(r'checked_write32\([^;]*SG_TRUST[^;]*;', transition),
                         ['checked_write32(p, SG_GPU, SG_TRUST, ~0u, 0);'])
        self.assertIn('off >= 0x3c000u', self.adapter)
        self.assertIn('SG_NEEDS_UNSECURE', self.core)
        self.assertIn('if (report->trust != 0)', self.core)
        self.assertNotIn('smc #', self.core)
        self.assertNotIn('smc #', self.adapter_without_scm())
        self.assertNotIn('smc #', self.pas_adapter_section())
        wrapper = source_function(self.adapter, 'sgpu_smc_frame')
        self.assertEqual(wrapper.count('smc #0'), 1)
        self.assertNotIn('smc #', self.adapter.replace(wrapper, '', 1))
        self.assertNotIn('0x008c0000', self.adapter)
        self.assertNotIn('0x00b00000', self.adapter)
        self.assertNotIn('0x03d00000', self.adapter)
        self.assertNotIn('0x0f523000', self.adapter)
        self.assertNotIn('santoni_spmi', self.core)

    def test_real_cache_maintenance_and_no_zero_register_MMIO(self):
        self.assertIn('CleanPoC_DcacheRegion_Force', self.adapter)
        self.assertIn('dc ivac', self.adapter)
        self.assertNotIn('flush_dcache64', self.adapter)
        self.assertIn('noinline)) sgpu_io_write32', self.adapter)
        self.assertIn('str %w0, [%1]', self.adapter)
        self.assertIn('str %0, [%1]', self.adapter)
        self.assertNotIn('str wzr', self.adapter.split('static void __attribute__((noinline)) sgpu_io_write32')[1])

    def test_Darwin_assembler_instruction_separators(self):
        strings = re.findall(r'__asm__\s+volatile\("([^"]+)"', self.adapter)
        self.assertGreater(len(strings), 5)
        self.assertFalse(any(';' in text for text in strings),
                         'Darwin ARM64 treats semicolons as comments, not instruction separators')
        self.assertIn(r'dmb sy\n\tstr %w0, [%1]\n\tdsb sy', self.adapter)
        self.assertIn(r'yield\n\tmrs %0, cntvct_el0', self.adapter)

    def test_parity_matches_vendor_all_boundaries(self):
        for opcode in range(128):
            for count in (0, 1, 2, 3, 8, 127, 256, 0x3fff):
                self.assertEqual(self.lib.sgpu_packet7(opcode, count), prep.type7(opcode, count))
        self.assertEqual(self.lib.sgpu_packet7(128, 1), 0)
        self.assertEqual(self.lib.sgpu_packet7(1, 0x4000), 0)

    def test_bounded_pages_and_no_identity_map(self):
        self.assertIn('SGPU_POOL_PAGES 24u', (self.dev / 'santoni_gpu_core.h').read_text())
        self.assertIn('PTE_RO', self.core)
        self.assertIn('PTE_RW', self.core)
        self.assertIn('p->dma_exposed = true; /* page-table walk references', self.core)
        # 0206's shared bootstrap owns a stable caller-provided probe; the
        # release predicate and target must remain unchanged by that refactor.
        self.assertIn('if (p->memory.va && !p->dma_exposed) ops->release(ops->ctx, &p->memory);', self.core)
        self.assertNotIn('0x40000000ull |', self.core)
        self.assertNotIn('smmu_identity', self.core)

    def test_host_render_packet_reference_oracle(self):
        oracle = ROOT / 'tests/fixtures/santoni_gpu_blit_oracle.c'
        original = ROOT / 'out/sailfish-gpu-reference/bsd/dev/sweet_gpu.c'
        if original.is_file():
            normalize = lambda text: re.sub(r'\s+', '', prep.uncomment(text))
            self.assertEqual(normalize(source_function(oracle.read_text(), 'emit_blit')),
                             normalize(source_function(original.read_text(), 'emit_blit')))
        binary = self.path / 'render-oracle'
        subprocess.run([*CC, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-DARM64_BOARD_CONFIG_SANTONI', '-I', str(self.dev),
                        str(oracle), str(self.dev / 'santoni_gpu_core.c'), *core_link_dependencies(self.dev), '-o', str(binary)],
                       check=True, timeout=60)
        subprocess.run([str(binary)], check=True, timeout=10)

    def test_vendor_hw_cg_and_memory_geometry(self):
        if not prep.VENDOR.is_dir():
            self.skipTest('optional vendor tree absent; native MMIO/packet/memory tests still run')
        target = prep.vendor_target()
        table = prep.block(self.core, 'hwcg[][2]')
        values = [(int(a, 0), int(b, 0)) for a, b in re.findall(r'\{\s*(0x[0-9a-f]+|\d+)\s*,\s*(0x[0-9a-f]+|\d+)\s*\}', table)]
        self.assertEqual(values, [(item['byte_offset'], item['value']) for item in target['hwcg']])
        self.assertEqual(target['gmem_bytes'], 139264)
        self.assertIn('0x371fu', self.core)
        self.assertIn('0x01859000', self.adapter)
        source = prep.uncomment((prep.VENDOR / 'drivers/iommu/arm-smmu.c').read_text())
        values = re.search(r'enum arm_smmu_s2cr_type\s*\{([^}]+)\}', source).group(1)
        self.assertEqual([word.strip() for word in values.split(',') if word.strip()],
                          ['S2CR_TYPE_TRANS', 'S2CR_TYPE_BYPASS', 'S2CR_TYPE_FAULT'])

    def test_A505_top_level_clock_completion_matches_the_vendor_sequence(self):
        init = source_function(self.core, 'sgpu_a505_resume')
        self.assertLess(init.index('SG_CLOCK_CNTL, ~0u, 0x55'), init.index('COUNT(hwcg)'))
        self.assertLess(init.index('COUNT(hwcg)'), init.index('SG_CLOCK_CNTL, 0xaaa8aa00u'))
        self.assertLess(init.index('SG_CLOCK_CNTL, 0xaaa8aa00u'), init.index('SG_ISDB_CNT, ~0u, 0x182u'))
        self.assertLess(init.index('SG_ISDB_CNT, ~0u, 0x182u'), init.index('sgpu_a505_sp_release(p)'))
        release = source_function(self.core, 'sgpu_a505_sp_release')
        self.assertIn('written = old & ~SG_SP_INPUT_CLOCK_MASK', release)
        self.assertIn('got == written && !(got & SG_SP_INPUT_CLOCK_MASK)', release)
        self.assertIn('SG_CLOCK_CNTL, ~0u', release)
        self.assertIn('#define SG_SP_INPUT_CLOCK_MASK 0xffu', (self.dev / 'santoni_gpu_core.h').read_text())
        if not prep.VENDOR.is_dir():
            return  # native ME-start assertions still check both final values
        vendor = (prep.VENDOR / 'drivers/gpu/msm/adreno_a5xx.c').read_text()
        complete = source_function(vendor, 'a5xx_hwcg_set')
        regulator = source_function(vendor, 'a5xx_regulator_enable')
        registers = prep.defines((prep.VENDOR / 'drivers/gpu/msm/a5xx_reg.h').read_text())
        header = (self.dev / 'santoni_gpu_core.h').read_text()
        for symbol, name, value in (('A5XX_RBBM_CLOCK_CNTL', 'SG_CLOCK_CNTL', 0xaaa8aa00),
                                    ('A5XX_RBBM_ISDB_CNT', 'SG_ISDB_CNT', 0x182)):
            found = re.search(re.escape(symbol) + r',\s*on\s*\?\s*(0x[0-9a-fA-F]+)', complete)
            self.assertIsNotNone(found)
            self.assertEqual(int(found.group(1), 0), value)
            offset = int(re.search(r'#define ' + name + r'\s+(0x[0-9a-f]+)u', header).group(1), 0)
            self.assertEqual(offset, registers[symbol] * 4)
        self.assertIn('A5XX_RBBM_CLOCK_CNTL, 0x00000055', regulator)
        self.assertIn('A5XX_RBBM_CLOCK_CNTL, 0xFF, 0', regulator)

    def test_A505_stop_mask_is_from_the_target_vendor_branch(self):
        header = (self.dev / 'santoni_gpu_core.h').read_text()
        self.assertIn('#define SG_CP_STOP_MASK 3u', header)
        self.assertNotIn('SG_ME_HALT', self.core + header)
        halt = source_function(self.core, 'sgpu_a505_halt')
        self.assertIn('old | SG_CP_STOP_MASK', halt)
        self.assertIn('(got & SG_CP_STOP_MASK) == SG_CP_STOP_MASK', halt)
        if not prep.VENDOR.is_dir():
            return  # portable independent low-bit/preservation C oracle always runs
        vendor = prep.uncomment((prep.VENDOR / 'drivers/gpu/msm/adreno_dispatch.c').read_text())
        stop = re.search(r'if\s*\(adreno_is_a5xx\(adreno_dev\)\s*\|\|\s*adreno_is_a6xx\(adreno_dev\)\)\s*'
                         r'reg\s*\|=\s*([^;]+);\s*else\s*reg\s*\|=\s*([^;]+);', vendor)
        self.assertIsNotNone(stop)
        self.assertEqual(re.sub(r'\s+', '', stop[1]), '1|(1<<1)')
        self.assertEqual(re.sub(r'\s+', '', stop[2]), '(1<<27)|(1<<28)')
        defs = prep.defines((prep.VENDOR / 'drivers/gpu/msm/a5xx_reg.h').read_text())
        self.assertEqual(defs['A5XX_CP_ME_CNTL'] * 4, 0x20c8)
        reset = source_function((prep.VENDOR / 'drivers/gpu/msm/adreno.c').read_text(), '_soft_reset')
        self.assertLess(reset.index('ADRENO_REG_RBBM_SW_RESET_CMD, 0'), reset.index('gpudev->regulator_enable'))

    def make_bundle(self, path):
        firmware = path / 'firmware'
        firmware.mkdir(parents=True)
        entries = []
        for index, name in enumerate(boot.NAMES):
            raw = struct.pack('<4I', 0, 0x12345674 + index, 0x55667788, 0x99887766)
            info, payload = prep.ucode(raw, name)
            (firmware / name).write_bytes(raw)
            (firmware / (name + '.payload')).write_bytes(payload)
            entries.append(info)
        (path / 'target.json').write_text(json.dumps(
            {'chipid': 0x05000500, 'gmem_bytes': 139264, 'kernel_page_bytes': 4096}))
        (path / 'firmware-intake.json').write_text(json.dumps({'ucode': entries}))

    def validate_blob(self, blob):
        data = ctypes.create_string_buffer(blob)
        view = FirmwareView()
        valid = self.lib.sgpu_firmware_validate(data, len(blob), ctypes.byref(view))
        return valid, view

    def test_packager_firmware_agrees_with_actual_kernel_parser(self):
        bundle = self.path / 'synthetic-bundle'
        self.make_bundle(bundle)
        blob, records = boot.firmware_blob(bundle)
        valid, view = self.validate_blob(blob)
        self.assertTrue(valid)
        self.assertEqual((view.pm4_bytes, view.pfp_bytes), (12, 12))
        self.assertEqual((view.pm4_version, view.pfp_version), tuple(item['version'] for item in records))
        for offset in (0, 8, 12, 16, 20, 24, 28, 35, 51):
            bad = bytearray(blob)
            bad[offset] ^= 1
            self.assertFalse(self.validate_blob(bytes(bad))[0], f'corruption at {offset}')
        self.assertFalse(self.validate_blob(blob[:-4])[0])
        self.assertFalse(self.validate_blob(blob + bytes(4))[0])

    def test_packager_refuses_changed_intake_bytes(self):
        bundle = self.path / 'changed-bundle'
        self.make_bundle(bundle)
        raw = bundle / 'firmware/a530_pm4.fw'
        data = bytearray(raw.read_bytes())
        data[8] ^= 1
        raw.write_bytes(data)
        with self.assertRaises(ValueError):
            boot.firmware_blob(bundle)

    def test_firmware_property_preserves_other_ADT_properties(self):
        import adt
        root, chosen, cpu = adt.Node(), adt.Node(), adt.Node()
        root.props = [('name', 0, b'device-tree\0')]
        chosen.props = [('name', 0, b'chosen\0'), ('dram-base', 0, struct.pack('<Q', 0x98000000))]
        cpu.props = [('name', 0, b'cpu0\0'), ('reg', 0, struct.pack('<I', 0x100)), ('state', 0, b'running\0')]
        root.children = [chosen, cpu]
        before = adt.serialize(root)
        after = boot.add_firmware(before, b'checked firmware')
        boot.verify_tree_preservation(before, after)
        with self.assertRaises(ValueError):
            boot.add_firmware(after, b'other firmware')
        altered, _ = adt.parse(after)
        altered.children[1].props.append(('bad-input-change', 0, b'yes'))
        with self.assertRaises(ValueError):
            boot.verify_tree_preservation(before, adt.serialize(altered))

    def test_actual_local_firmware_corpus(self):
        bundle = ROOT / 'out/santoni-gpu-msm49-fw-working'
        if not (bundle / 'firmware-intake.json').is_file():
            self.skipTest('private device firmware absent; synthetic firmware/parser tests still run')
        blob, records = boot.firmware_blob(bundle)
        valid, view = self.validate_blob(blob)
        self.assertTrue(valid)
        self.assertEqual((view.pm4_version, view.pfp_version), (0x5ff066, 0x5ff114))
        self.assertEqual((view.pm4_bytes, view.pfp_bytes), (19648, 17104))
        self.assertFalse(any(item['authenticity_verified'] for item in records))

    def test_packaging_requires_actual_binary_gate_not_only_CI_success(self):
        path = self.path / 'gpu-binary-audit.json'
        commit, run_id, digest = 'a' * 40, 123, 'b' * 64
        with self.assertRaises(ValueError):
            boot.require_binary_audit(path, commit, run_id, digest)
        report = {'commit': commit, 'ci_run': run_id, 'kernel_sha256': digest}
        keys = ('GPU_driver_linked_and_BSD_startup_hook_present',
                'checked_changed_code_is_Cortex_A53_compatible',
                'MMIO_stores_use_real_registers_and_barriers',
                'explicit_result_cache_invalidation_present',
                'first_failure_and_rollback_diagnostics_present',
                'power_clock_path_is_separately_auditable',
                'checked_translation_and_clock_halt_helpers_linked',
                'target_clock_setup_and_restore_wiring_checked',
                'a505_paired_stop_and_resume_wiring_checked',
                'a505_vendor_SP_RMW_release_and_partial_failure_hold_checked',
                'firmware_is_not_embedded_in_CI_kernel')
        report.update({key: True for key in keys})
        path.write_text(json.dumps(report))
        boot.require_binary_audit(path, commit, run_id, digest)
        with self.assertRaises(ValueError):
            boot.require_binary_audit(path, commit, 124, digest)
        for key in keys:
            bad = dict(report, **{key: False})
            path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError):
                boot.require_binary_audit(path, commit, run_id, digest)


if __name__ == '__main__':
    unittest.main(verbosity=2)
