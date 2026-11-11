"""New provenance contracts; fixtures do not certify a kernel or hardware."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import santoni_gpu_interpreter_evidence as evidence


class InterpreterEvidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cache = self.root / 'launcher-components'
        self.cache.mkdir()
        self.pins = evidence.semantic_pins()
        self.leaf = {**self.pins, 'success': True, 'hardware_verified': False,
                     'new_contract_checks_passed': True,
                     'completed_kernel_components_consumed_without_replay': True,
                     'commit': 'a' * 40, 'ci_run': 123, 'kernel_sha256': 'b' * 64,
                     'initial_instruction_contract': 'retained-result.json',
                     'initial_instruction_contract_sha256': 'c' * 64,
                     'additional_completed_checks': [{'tests': 7, 'exit_code': 0}]}

    def write(self, name, record):
        p = self.cache / name
        p.write_text(json.dumps(record))
        return p

    def wrapper(self, relative='launcher-components/actual-origin-name.json'):
        leaf = self.write('actual-origin-name.json', self.leaf)
        return self.write('interpreter.json', {
            **self.leaf, 'commit': 'd' * 40,
            'origin_record_copy': relative,
            'independent_host_contract_origin_sha256': hashlib.sha256(leaf.read_bytes()).hexdigest(),
            'origin_wrapper_identity': evidence.identity_of(self.leaf),
            'prior_kernel_linked_components_transferred': False,
            'host_contract_tests_executed_in_this_resume': 0})

    def test_recorded_filename_and_verbatim_leaf_consumed(self):
        pins, chain = evidence.host_chain(self.wrapper())
        self.assertEqual(pins, self.pins)
        self.assertEqual(len(chain), 2)
        self.assertEqual(chain[-1]['data'], (self.cache / 'actual-origin-name.json').read_bytes())

    def test_changed_origin_bytes_or_identity_reject(self):
        for key, value in (('ci_run', 124), ('hardware_verified', True)):
            origin = self.wrapper()
            changed = {**self.leaf, key: value}
            self.write('actual-origin-name.json', changed)
            with self.assertRaises(ValueError): evidence.host_chain(origin)
        origin = self.wrapper()
        record = json.loads(origin.read_text())
        record['origin_wrapper_identity']['ci_run'] = 124
        origin.write_text(json.dumps(record))
        with self.assertRaises(ValueError): evidence.host_chain(origin)

    def test_changed_interpreter_semantics_and_false_pass_reject(self):
        for key, value in ((*((key, '0' * 64) for key in self.pins if key != 'tested_operations'),
                            ('tested_operations', ['ldxr']), ('success', 1),
                            ('new_contract_checks_passed', False), ('hardware_verified', True))):
            with self.subTest(key=key):
                p = self.write('leaf.json', {**self.leaf, key: value})
                with self.assertRaises(ValueError): evidence.host_chain(p)

    def test_kernel_transfer_and_unrecorded_tests_reject(self):
        for key, value in (('prior_kernel_linked_components_transferred', True),
                           ('host_contract_tests_executed_in_this_resume', 1),
                           ('host_contract_tests_executed_in_this_resume', False)):
            p = self.wrapper()
            record = json.loads(p.read_text()); record[key] = value
            p.write_text(json.dumps(record))
            with self.assertRaises(ValueError): evidence.host_chain(p)

    def test_escaping_missing_and_failed_origin_reject(self):
        for relative in ('../../outside.json', '/absolute.json', 'launcher-components/absent.json'):
            p = self.wrapper(relative)
            with self.assertRaises((ValueError, FileNotFoundError)): evidence.host_chain(p)
        leaf = copy.deepcopy(self.leaf); leaf['additional_completed_checks'][0]['exit_code'] = 1
        with self.assertRaises(ValueError): evidence.host_chain(self.write('failed-leaf.json', leaf))

    def test_destination_cannot_transfer_different_kernel_components(self):
        identity = evidence.identity_of(self.leaf)
        with patch.object(evidence, 'load_inputs', return_value=(identity, None, None, None, None)), \
                patch.object(evidence, 'proof', side_effect=ValueError('different kernel')):
            with self.assertRaises(ValueError): evidence.emit(self.root, self.wrapper())
        self.assertFalse((self.cache / 'interpreter-origin').exists())

    def test_emitted_wrapper_preserves_leaf_and_remains_consumable(self):
        from tests import test_santoni_gpu_launcher_certificate as fixtures
        origin = self.wrapper()
        folder = self.root / 'new-ci'
        (folder / 'launcher-components').mkdir(parents=True)
        identity = {**evidence.identity_of(self.leaf), 'commit': 'e' * 40, 'ci_run': 456}
        records = fixtures.linked_fixture(identity)
        with patch.object(evidence, 'load_inputs', return_value=(identity, None, None, None, None)), \
                patch.object(evidence, 'proof', side_effect=lambda f, p, i: records[Path(p).stem]):
            result = evidence.emit(folder, origin)
            self.assertEqual((result['executed_tests'], result['executed_linked_cases']), (0, 0))
            target = folder / 'launcher-components/interpreter.json'
            _, chain = evidence.host_chain(target)
            self.assertEqual(chain[-1]['data'], (self.cache / 'actual-origin-name.json').read_bytes())
            self.assertEqual(chain[0]['identity'], identity)
            self.assertFalse(json.loads(target.read_text())['prior_kernel_linked_components_transferred'])
            with self.assertRaises(ValueError): evidence.emit(folder, origin)

    def test_verbatim_relocated_wrapper_uses_its_hash_bound_source_pointer(self):
        source = self.root / 'out/original-ci/launcher-components/interpreter.json'
        source.parent.mkdir(parents=True)
        source.write_text(json.dumps(self.leaf))
        wrapper = {**self.leaf, 'origin_record_copy': 'launcher-components/missing-copy.json',
                   'independent_host_contract_origin': str(source.relative_to(self.root)),
                   'independent_host_contract_origin_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                   'origin_wrapper_identity': evidence.identity_of(self.leaf),
                   'prior_kernel_linked_components_transferred': False,
                   'host_contract_tests_executed_in_this_resume': 0}
        p = self.write('relocated.json', wrapper)
        with patch.object(evidence, 'PROJECT_ROOT', self.root):
            _, chain = evidence.host_chain(p)
            self.assertEqual(chain[-1]['data'], source.read_bytes())
            source.write_text(json.dumps({**self.leaf, 'ci_run': 999}))
            with self.assertRaises(ValueError): evidence.host_chain(p)
            wrapper['independent_host_contract_origin'] = '../outside.json'
            p.write_text(json.dumps(wrapper))
            with self.assertRaises(ValueError): evidence.host_chain(p)


if __name__ == '__main__':
    unittest.main()
