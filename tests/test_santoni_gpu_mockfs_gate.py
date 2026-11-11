"""New LP64 provider delivery gate only; no previously completed suites."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from santoni_gpu_launcher_gate import require_kernel_gates


class MockfsProviderGate(unittest.TestCase):
    def test_enabled_launcher_rejects_missing_false_or_untyped_provider_gate(self):
        report = {'EL0_launcher_present': True, 'EL0_launcher_changed_code_A53_checked': True,
                  'EL0_launcher_wiring_checked': True,
                  'EL0_launcher_trace_present': True, 'EL0_launcher_trace_wiring_checked': True, 'EL0_launcher_trace_dispatch_checked': True,'EL0_launcher_trace_dispatch_checked': True}
        for value in (None, False, 1, 'true'):
            candidate = dict(report)
            if value is not None: candidate['EL0_launcher_mount_registry_checked'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'LP64'):
                require_kernel_gates(candidate, 3, enabled=True, present=True)

    def test_complete_provider_gate_and_existing_mode1_control_remain_distinct(self):
        report = {'EL0_launcher_present': True, 'EL0_launcher_changed_code_A53_checked': True,
                  'EL0_launcher_wiring_checked': True, 'EL0_launcher_mount_registry_checked': True,
                  'EL0_launcher_trace_present': True, 'EL0_launcher_trace_wiring_checked': True, 'EL0_launcher_trace_dispatch_checked': True,
                  'mode1_control_EL0_launcher_unreachable_checked': True}
        require_kernel_gates(report, 3, enabled=True, present=True)
        del report['EL0_launcher_mount_registry_checked']
        require_kernel_gates(report, 1, enabled=False, present=True)


if __name__ == '__main__':
    unittest.main()
