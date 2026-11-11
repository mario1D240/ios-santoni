"""Reject partial, changed, or falsely scoped new native CI intake."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import verify_santoni_gpu_trace_dispatch_evidence as intake


class NativeDispatchIntake(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.record = json.loads((ROOT / 'tests/santoni_gpu_trace_dispatch_host_evidence.json').read_text())

    def verify(self, record):
        path = Path(self.tmp.name) / 'record.json'; path.write_text(json.dumps(record))
        return intake.verify(path)

    def test_complete_record_consumed_without_execution(self):
        result = self.verify(self.record)
        self.assertEqual(result['recorded_native_executions'], 90)
        self.assertEqual(result['executed_tests'], 0)
        self.assertFalse(result['hardware_verified'])

    def test_partial_false_scope_and_changed_inputs_reject(self):
        for key, value in (('success', 1), ('cases', {'O2': 28}), ('baseline_cases', {'O2': 2}),
                           ('compiled_mutants_rejected', 10), ('hardware_verified', True),
                           ('kernel_certified', True), ('mechanical_apply_and_bytes_verified', False)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify({**self.record, key: value})
        for name in intake.INPUTS:
            record = deepcopy(self.record); record['sha256'][name] = '0' * 64
            with self.subTest(name=name), self.assertRaises(ValueError): self.verify(record)


if __name__ == '__main__':
    unittest.main()
