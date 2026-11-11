"""Only new0212 proof/recipe/context contracts; all images here are synthetic."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import santoni_gpu_boot as boot
import santoni_remoted_platform_gate as gate
import verify_santoni_remoted_platform_evidence as host

COMMIT, RUN, KERNEL_SHA = 'a' * 40, 123, 'b' * 64
RECIPE = ('CMDLINE="-v santoni cpus=8 sweethidtest=0 sweetfb_noconsole=1 '
          'sweetfb_hz=30 sweetcpufreq=0 sweetfb_native=1 sweetfb_stayon=1 '
          'sweetlog=1 sweetbattery=0 santoni_varfix=1 rd=emmcroot0 emmcrw=1 rootrw=1"\n')


class RemotedDelivery(unittest.TestCase):
    def setUp(self):
        tmp = Path('/data/data/com.termux/files/usr/tmp/opencode')
        self.temp = tempfile.TemporaryDirectory(prefix='remoted-new-', dir=tmp if tmp.is_dir() else None)
        self.addCleanup(self.temp.cleanup)
        self.ci = Path(self.temp.name)
        self.audit = {'success': True, 'commit': COMMIT, 'ci_run': RUN,
                      'kernel_sha256': KERNEL_SHA, 'hardware_verified': False,
                      **{name: True for name in gate.CHECKS}}

    def write_audit(self, record=None):
        (self.ci / 'remoted-platform-binary-audit.json').write_text(json.dumps(self.audit if record is None else record))

    def power(self, enabled=True):
        name = 'gpu-power-remoted-platform-trace-4core' if enabled else 'gpu-power-trace-4core'
        dest = self.ci / name
        dest.mkdir()
        line = 'cpus=4 santonigpu=1' + (' santoni_remoted_platform=1' if enabled else '')
        data = bytearray(2048)
        data[:8] = b'ANDROID!'
        data[64:64 + len(line)] = line.encode()
        (dest / 'boot.img').write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        manifest = {'commit': COMMIT, 'ci_run': RUN, 'kernel_sha256': KERNEL_SHA,
                    'role': 'power', 'gpu_mode': 1, 'cpus': 4,
                    'boot_sha256': digest, 'cmdline': line, 'remoted_platform': enabled}
        (dest / 'manifest.json').write_text(json.dumps(manifest))
        report = {'commit': COMMIT, 'ci_run': RUN, 'kernel_sha256': KERNEL_SHA,
                  'user_confirmed': True, 'identified': True, 'input_confirmed': True,
                  'manifest': name + '/manifest.json', 'boot_sha256': digest,
                  'result': {'pass': 1, 'stage': 3, 'error': 0, 'markers': 0, 'pixels': 0,
                             'restored': 1, 'retained': 0, 'trust_read': 0, 'quiescent': 1,
                             'smmu_restored': 1, 'power_pending': 0}}
        (self.ci / 'power-hardware-result.json').write_text(json.dumps(report))
        return dest, manifest, report

    def test_new_role_matrix_is_exact(self):
        for mode in range(4):
            for user in (False, True):
                for enabled in (False, True):
                    good = not enabled or (mode == 1 and not user) or (mode == 3 and user)
                    if good:
                        gate.validate(mode, user, enabled)
                    else:
                        with self.assertRaises(ValueError): gate.validate(mode, user, enabled)

    def test_new_role_types_are_closed(self):
        for value in (None, 0, 1, '1', 1.0):
            with self.assertRaises(ValueError): gate.validate(1, False, value)
            with self.assertRaises(ValueError): gate.validate(1, value, True)
        for mode in (True, 1.0, None, 4):
            with self.assertRaises(ValueError): gate.validate(mode, False, True)

    def test_new_recipe_adds_only_the_explicit_option(self):
        with patch.object(boot.subprocess, 'check_output', return_value=RECIPE):
            before = boot.command_args(boot.command_line(COMMIT, 1, visible_console=True))
            after = boot.command_args(boot.command_line(COMMIT, 1, visible_console=True, remoted_platform=True))
            self.assertEqual(after, {**before, 'santoni_remoted_platform': '1'})
            traced = boot.command_args(boot.command_line(COMMIT, 3, visible_console=True, user_exec=True, remoted_platform=True))
            self.assertEqual((traced['cpus'], traced['santonigpu_user_exec'], traced['santoni_remoted_platform']), ('4', '1', '1'))

    def test_new_recipe_refuses_preexisting_workaround_args(self):
        for value in (0, 1):
            recipe = RECIPE.replace('cpus=8', 'cpus=8 santoni_remoted_platform=' + str(value))
            with patch.object(boot.subprocess, 'check_output', return_value=recipe):
                with self.assertRaises(ValueError): boot.command_line(COMMIT, 1, remoted_platform=True)

    def test_legacy_absence_and_missing_new_proof(self):
        self.assertIsNone(gate.require_audit(self.ci, COMMIT, RUN, KERNEL_SHA, False, False))
        with self.assertRaises(ValueError): gate.require_audit(self.ci, COMMIT, RUN, KERNEL_SHA, False, True)
        for enabled in (False, True):
            with self.assertRaises(ValueError): gate.require_audit(self.ci, COMMIT, RUN, KERNEL_SHA, True, enabled)

    def test_new_proof_is_required_even_when_the_option_is_off(self):
        self.write_audit()
        for enabled in (False, True):
            self.assertEqual(gate.require_audit(self.ci, COMMIT, RUN, KERNEL_SHA, True, enabled), self.audit)

    def test_new_proof_rejects_identity_or_scope_changes(self):
        for key, value in (('commit', 'c' * 40), ('ci_run', RUN + 1), ('kernel_sha256', 'd' * 64),
                           ('success', 1), ('hardware_verified', True)):
            self.write_audit({**self.audit, key: value})
            with self.assertRaises(ValueError): gate.require_audit(self.ci, COMMIT, RUN, KERNEL_SHA, True, True)
        for name in gate.CHECKS:
            for value in (False, 1, None):
                self.write_audit({**self.audit, name: value})
                with self.assertRaises(ValueError): gate.require_audit(self.ci, COMMIT, RUN, KERNEL_SHA, True, True)

    def test_new_proof_role_inputs_are_boolean(self):
        for value in (0, 1, None):
            with self.assertRaises(ValueError): gate.require_audit(self.ci, COMMIT, RUN, KERNEL_SHA, value, True)
            with self.assertRaises(ValueError): gate.require_audit(self.ci, COMMIT, RUN, KERNEL_SHA, True, value)

    def test_power_context_must_match_the_selected_workaround(self):
        self.power(True)
        boot.require_hardware_power(self.ci, COMMIT, RUN, KERNEL_SHA, True)
        with self.assertRaises(ValueError): boot.require_hardware_power(self.ci, COMMIT, RUN, KERNEL_SHA, False)
        with self.assertRaises(ValueError): boot.require_hardware_power(self.ci, COMMIT, RUN, KERNEL_SHA, 1)

    def test_ordinary_power_context_cannot_enable_the_workaround(self):
        self.power(False)
        with self.assertRaises(ValueError): boot.require_hardware_power(self.ci, COMMIT, RUN, KERNEL_SHA, True)

    def test_workaround_power_checks_the_actual_header(self):
        dest, manifest, report = self.power(True)
        data = bytearray((dest / 'boot.img').read_bytes())
        data[64:576] = bytes(512)
        wrong = 'cpus=4 santonigpu=1'
        data[64:64 + len(wrong)] = wrong.encode()
        (dest / 'boot.img').write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        manifest['boot_sha256'] = report['boot_sha256'] = digest
        (dest / 'manifest.json').write_text(json.dumps(manifest))
        (self.ci / 'power-hardware-result.json').write_text(json.dumps(report))
        with self.assertRaises(ValueError): boot.require_hardware_power(self.ci, COMMIT, RUN, KERNEL_SHA, True)

    def test_host_record_refuses_changed_contract_scope(self):
        original = json.loads((ROOT / 'tests/santoni_remoted_platform_host_evidence.json').read_text())
        for key, value in (('compiled_rejected_mutants', 5), ('old_test_executions', 1), ('hardware_verified', True),
                           ('native_total', 173), ('mechanical_apply_and_bytes_verified', False)):
            record = copy.deepcopy(original); record[key] = value
            path = self.ci / 'host.json'; path.write_text(json.dumps(record))
            with self.assertRaises(ValueError): host.verify(path)

    def test_new_cli_selects_the_named_explicit_variant(self):
        with patch.object(sys, 'argv', ['boot', COMMIT, '--mode', '1', '--remoted-platform']), \
                patch.object(boot, 'package', return_value={}) as package:
            boot.main()
            self.assertIs(package.call_args.kwargs['remoted_platform'], True)


if __name__ == '__main__':
    unittest.main()
