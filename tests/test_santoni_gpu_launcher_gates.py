"""New default-off launcher delivery gates; no existing suite is executed."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import adt
import santoni_gpu_boot as boot
import santoni_gpu_launcher_gate as gate


class LauncherGates(unittest.TestCase):
    def test_separate_explicit_mode3_role(self):
        boot.validate_probe_options(3, False, False, user_exec=True)
        for mode in (0, 1, 2):
            with self.assertRaises(ValueError):
                boot.validate_probe_options(mode, False, False, user_exec=True)
        for value in (1, 0, None, '1'):
            with self.assertRaises(ValueError):
                boot.validate_probe_options(3, False, False, user_exec=value)
        for name in ('zap_preflight', 'zap_scm_probe', 'zap_cache_preflight',
                     'stock_unsecure', 'stock_pixels', 'g3', 'session', 'user', 'user_preflight'):
            options = dict(mode=3, zap_preflight=False, zap_scm_probe=False, user_exec=True)
            options[name] = True
            with self.assertRaises(ValueError):
                boot.validate_probe_options(**options)

    def test_launcher_cannot_borrow_prior_kernel_certificate(self):
        with self.assertRaisesRegex(ValueError, 'recorded'):
            gate.require_kernel_gates({}, 1, present=True)
        with self.assertRaisesRegex(ValueError, 'A53'):
            gate.require_kernel_gates({gate.PRESENT: True}, 1)
        report = {gate.PRESENT: True, gate.ISA_GATE: True}
        for mode in range(4):
            with self.assertRaisesRegex(ValueError, 'binary gate'):
                gate.require_kernel_gates(report, mode)
        report[gate.CONTROL_GATE] = True
        gate.require_kernel_gates(report, 1)
        for mode in (0, 2, 3):
            with self.assertRaises(ValueError):
                gate.require_kernel_gates(report, mode)
        report[gate.LAUNCH_GATE] = True
        report.update(EL0_launcher_mount_registry_checked=True,
                      EL0_launcher_trace_present=True, EL0_launcher_trace_wiring_checked=True,
                      EL0_launcher_trace_dispatch_checked=True)
        gate.require_kernel_gates(report, 3, enabled=True)
        for key in (gate.PRESENT, gate.ISA_GATE, gate.LAUNCH_GATE):
            bad = {**report, key: 1}
            with self.assertRaises(ValueError):
                gate.require_kernel_gates(bad, 3, enabled=True)

    def test_packager_invokes_launcher_gate_before_legacy_gates(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = Path(tmp) / 'audit.json'
            audit.write_text('{}')
            for options in ({'mode': 1, 'launcher_present': True},
                            {'mode': 3, 'user_exec': True}):
                with self.assertRaisesRegex(ValueError, 'EL0 launcher'):
                    boot.require_binary_audit(audit, 'a' * 40, 1, 'b' * 64, **options)

    def test_original_recipe_and_runtime_role(self):
        recipe = __import__('subprocess').check_output(
            ['git', 'show', 'HEAD:shim/build.sh'], cwd=ROOT, text=True)
        with patch.object(boot.subprocess, 'check_output', return_value=recipe):
            line = boot.command_line('a' * 40, 3, True, user_exec=True)
            args = boot.command_args(line)
            for key in ('santonigpu_stock', 'santonigpu_pixels', 'santonigpu_submit',
                        'santonigpu_session', 'santonigpu_user', 'santonigpu_user_exec'):
                self.assertEqual(args[key], '1')
            self.assertEqual(args['cpus'], '4')
            self.assertEqual(args['sweethidtest'], '0')
            self.assertEqual(args['launchdsuffix'], 'release')
            self.assertLess(len(line.encode()), 608)
            for key in ('santonigpu_zap', 'santonigpu_scm', 'santonigpu_cache', 'santonigpu_user_test'):
                self.assertNotIn(key, args)
        for changed in (recipe.replace('CMDLINE="', 'CMDLINE="launchdsuffix=debug ', 1),
                        recipe.replace('CMDLINE="', 'CMDLINE="santonigpu_user_exec=1 ', 1)):
            with patch.object(boot.subprocess, 'check_output', return_value=changed):
                with self.assertRaises(ValueError):
                    boot.command_line('a' * 40, 3, user_exec=True)

    def test_probe_is_only_an_additive_chosen_property(self):
        root, chosen = adt.Node(), adt.Node()
        root.props = [('name', 0, b'device-tree\0')]
        chosen.props = [('name', 0, b'chosen\0'), ('keep', 0, b'old')]
        root.children = [chosen]
        before = adt.serialize(root)
        data = b'x' * 16635
        after = boot.add_probe_input(before, data)
        boot.verify_tree_preservation(before, after, user_exec=True)
        root, _ = adt.parse(after)
        self.assertEqual(root.children[0].prop(gate.PROPERTY), data)
        with self.assertRaises(ValueError):
            boot.add_probe_input(after, data)
        with self.assertRaises(ValueError):
            boot.add_probe_input(before, data[:-1])
        with self.assertRaises(ValueError):
            boot.verify_tree_preservation(before, after)

    def test_probe_paths_require_role_and_completed_evidence(self):
        with self.assertRaisesRegex(ValueError, 'explicit probe'):
            boot.package('a' * 40, 3, Path('/unused'), user_exec=True)
        with self.assertRaisesRegex(ValueError, 'separate --user-exec'):
            boot.package('a' * 40, 1, Path('/unused'), probe_dir=Path('/unused'))
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp)
            for report in ({'success': False}, {'success': True, 'complete_scenario_scope': False},
                           {'success': True, 'complete_scenario_scope': True, 'cases': {}}):
                (evidence / 'result.json').write_text(json.dumps(report))
                with self.assertRaisesRegex(ValueError, 'complete independent'):
                    gate.consume_probe(evidence, evidence)


if __name__ == '__main__':
    unittest.main()
