"""0214 CI intake must reject incomplete counts or changed native/probe bytes."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import verify_santoni_gpu_trace_diag_evidence as intake


class DiagnosticEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.record = json.loads((ROOT / 'tests/santoni_gpu_trace_diag_host_evidence.json').read_text())
        self.probe = json.loads((ROOT / 'tests/santoni_gpu_el0_trace_host_evidence.json').read_text())

    def verify(self, record, probe):
        a, b = (Path(self.tmp.name) / n for n in ('native.json', 'probe.json'))
        a.write_text(json.dumps(record)); b.write_text(json.dumps(probe))
        return intake.verify(a, b)

    def test_complete_intake_executes_no_native_or_linked_tests(self):
        result = self.verify(self.record, self.probe)
        self.assertEqual(result['recorded_native_executions'], 276)
        self.assertEqual(result['executed_tests'], 0)
        self.assertFalse(result['kernel_certified'])

    def test_partial_counts_mutants_and_false_scope_reject(self):
        for key, value in (('success', 1), ('receiver_cases', {'O2': 59}),
                           ('late_cases', {'O0': 33}), ('receiver_compiling_mutants_rejected', 10),
                           ('late_compiling_mutants_rejected', 5), ('hardware_verified', True),
                           ('mechanical_apply_and_bytes_verified', False)):
            record = {**self.record, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError): self.verify(record, self.probe)

    def test_changed_inputs_or_independent_probe_reject(self):
        for name in intake.INPUTS:
            record = deepcopy(self.record); record['sha256'][name] = '0' * 64
            with self.subTest(name=name), self.assertRaises(ValueError): self.verify(record, self.probe)
        for name in intake.PROBE_INPUTS:
            probe = deepcopy(self.probe); probe['sha256'][name] = '0' * 64
            with self.subTest(name=name), self.assertRaises(ValueError): self.verify(self.record, probe)


if __name__ == '__main__': unittest.main()
