"""Challenge new native VM/source bindings and exact result framing."""
import copy
import json
from pathlib import Path
import sys
import unittest

PROJECT = Path(__file__).resolve().parents[1]
RECEIPTS = PROJECT / 'tests'
sys.path.insert(0, str(PROJECT))
from tools import verify_santoni_gpu_live_evidence as live
from tools import verify_santoni_gpu_render_evidence as render
from tools import verify_santoni_gpu_ui_evidence as ui

class RemainingIntake(unittest.TestCase):
    def test_exact_native_and_VM_helper_inputs(self):
        for name, verifier in (('live', live), ('render', render), ('ui', ui)):
            record = json.loads((RECEIPTS / ('santoni_gpu_' + name + '_host_evidence.json')).read_text())
            self.assertTrue(verifier.verify(record)['success'])
            for mutation in ('missing-helper', 'helper-byte', 'source-byte'):
                with self.subTest(name=name, mutation=mutation):
                    bad = copy.deepcopy(record)
                    if mutation == 'missing-helper':
                        bad.pop('native_link_inputs_sha256')
                    elif mutation == 'helper-byte':
                        bad['native_link_inputs_sha256']['tests/native_santoni_gpu_core.py'] = '0' * 64
                    elif name == 'ui':
                        bad['native_source_sha256']['bsd/dev/santoni_gpu_vm.c'] = '0' * 64
                    else:
                        bad['source']['native_link_dependencies']['bsd/dev/santoni_gpu_vm.c'] = '0' * 64
                    with self.assertRaises(ValueError):
                        verifier.verify(bad)

    def test_boolean_compile_and_execution_results_are_not_numeric_receipts(self):
        for name, verifier in (('live', live), ('render', render), ('ui', ui)):
            record = json.loads((RECEIPTS / ('santoni_gpu_' + name + '_host_evidence.json')).read_text())
            for mutation in ('compile', 'execution'):
                with self.subTest(name=name, mutation=mutation):
                    bad = copy.deepcopy(record)
                    row = (bad['rows'] if name == 'ui' else bad['commands'])[0]
                    if mutation == 'compile':
                        row['compile_exit'] = False
                    elif name == 'render':
                        row['exit_code'] = False
                    else:
                        row['runs'][0]['exit' if name == 'ui' else 'exit_code'] = False
                    with self.assertRaises(ValueError):
                        verifier.verify(bad)

if __name__ == '__main__':
    unittest.main(verbosity=2)
