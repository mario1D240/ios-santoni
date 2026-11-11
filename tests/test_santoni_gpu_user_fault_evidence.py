import copy
import json
from pathlib import Path
import unittest
from tools.verify_santoni_gpu_user_fault_evidence import verify

ROOT = Path(__file__).resolve().parents[1]


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads((ROOT / 'tests/santoni_gpu_user_fault_host_evidence.json').read_text())

    def test_consumes_actual_record_without_native_replay(self):
        self.assertEqual(verify(self.record)['test_executions'], 0)

    def test_rejects_changed_scope_inputs_inventory_and_failed_compilation(self):
        changes = (
            lambda r: r.update(hardware_verified=True),
            lambda r: r['inputs_sha256'].update({'tests/test_santoni_gpu_user_fault.c': '0' * 64}),
            lambda r: r['baseline_applied'].pop(),
            lambda r: r.update(original_source_outside_helper_and_three_calls_identical=False),
            lambda r: r['runs'].pop(),
            lambda r: r['runs'][0].update(case_count=23),
            lambda r: r['runs'][-1].update(compile_exit=1),
            lambda r: r['runs'][-1].update(run_exit=0),
        )
        for change in changes:
            with self.subTest(change=change):
                candidate = copy.deepcopy(self.record)
                change(candidate)
                with self.assertRaises(ValueError):
                    verify(candidate)


if __name__ == '__main__':
    unittest.main()
