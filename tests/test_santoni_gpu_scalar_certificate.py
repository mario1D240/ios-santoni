"""New aggregate rejection gates and counter-proof mutations, no old suites."""
import copy
from pathlib import Path
import sys
import json
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import check_santoni_gpu_kernel as e
from santoni_gpu_scalar_certificate import (assemble, LEGACY_GATES, SESSION_COMPONENTS,
                                            SCALAR_COMPONENTS, PREFLIGHT_COMPONENTS,
                                            proof, prior_scalar_proofs, prior_preflight_proofs)
from santoni_gpu_user_preflight_replay import audit_preflight_attempt_bound, EXTRA


class ScalarCertificate(unittest.TestCase):
    def fixture(self):
        identity = {'commit': 'a' * 40, 'ci_run': 123, 'kernel_sha256': 'b' * 64}
        base = {**identity, **dict.fromkeys(LEGACY_GATES, True), 'audit_scope': 'mode1-control',
                'G3_persistent_session_wiring_checked': False, 'G3_scalar_user_client_wiring_checked': False,
                'G3_scalar_user_preflight_wiring_checked': False,
                'wiring_evidence': {'mode1_control': {'synthetic': True}}}
        make = lambda keys: {k: {**identity, 'success': True, 'synthetic': True} for k in keys}
        return base, make(SESSION_COMPONENTS), make(SCALAR_COMPONENTS), make(PREFLIGHT_COMPONENTS)

    def test_complete_fixture_and_mode1_record_preservation(self):
        args = self.fixture(); before = copy.deepcopy(args[0])
        report = assemble(*args)
        self.assertTrue(report['G3_persistent_session_wiring_checked'])
        self.assertTrue(report['G3_scalar_user_client_wiring_checked'])
        self.assertTrue(report['G3_scalar_user_preflight_wiring_checked'])
        self.assertFalse(report['hardware_verified'])
        self.assertEqual(args[0], before)

    def test_every_missing_or_failed_component_rejects(self):
        for index, keys in enumerate((SESSION_COMPONENTS, SCALAR_COMPONENTS, PREFLIGHT_COMPONENTS), 1):
            for key in keys:
                for failure in ('missing', False, 1):
                    with self.subTest(group=index, key=key, failure=failure):
                        args = self.fixture()
                        if failure == 'missing': del args[index][key]
                        else: args[index][key]['success'] = failure
                        with self.assertRaises(ValueError): assemble(*args)

    def test_different_kernel_or_ci_cannot_supply_a_component(self):
        for index in (1, 2, 3):
            for key, value in (('commit', 'c' * 40), ('kernel_sha256', 'd' * 64), ('ci_run', 124)):
                with self.subTest(group=index, identity=key):
                    args = self.fixture(); next(iter(args[index].values()))[key] = value
                    with self.assertRaises(ValueError): assemble(*args)

    def test_legacy_control_and_identity_gates_cannot_be_skipped(self):
        for key in LEGACY_GATES:
            with self.subTest(key=key):
                args = self.fixture(); args[0][key] = False
                with self.assertRaises(ValueError): assemble(*args)
        for key, value in (('commit', 'a' * 39), ('kernel_sha256', 'b' * 63), ('ci_run', '123')):
            with self.subTest(key=key):
                args = self.fixture(); args[0][key] = value
                with self.assertRaises(ValueError): assemble(*args)


class AttemptCounterProof(unittest.TestCase):
    def code(self, override=None):
        instructions = {0x1000: 'mov w19, wzr', 0x1004: 'nop', 0x1008: 'nop',
                        0x100c: 'nop', 0x1010: 'nop', 0x1014: 'mov w27, #0x2710',
                        0x1018: 'nop', 0x101c: 'add w19, w19, #0x1',
                        0x1020: 'mov w24, w25', 0x1024: 'cmp w19, w27',
                        0x1028: 'b.ne 0x1010', 0x102c: 'ret'}
        instructions.update(override or {})
        text = '1000 <' + EXTRA[0] + '>:\n' + '\n'.join(
            f'{pc:x}: 00000000 {instruction}' for pc, instruction in instructions.items())
        return e._Code(text, EXTRA[0], 0x1000)

    def test_reviewed_counter_cfg(self):
        report = audit_preflight_attempt_bound({EXTRA[0]: self.code()}, None, {}, e)
        self.assertEqual(report['limit'], 10000)
        self.assertFalse(report['single_call_or_scheduler_bounded'])

    def test_changed_bound_counter_and_initial_lifetime_reject(self):
        # Synthetic decoded instructions, not compiled executable mutants.
        mutations = ({0x1000: 'mov w19, #1'}, {0x1014: 'mov w27, #0x270f'},
                     {0x101c: 'add w19, w19, #2'}, {0x1028: 'b.lo 0x1010'},
                     {0x1004: 'mov w19, #0x270f'}, {0x1018: 'ldp x20, x19, [sp]'})
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    audit_preflight_attempt_bound({EXTRA[0]: self.code(mutation)}, None, {}, e)


class ReusePlan(unittest.TestCase):
    def test_evidence_path_escape_rejects_before_reading(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for path in ('../outside.json', '/outside.json'):
                with self.subTest(path=path):
                    with self.assertRaisesRegex(ValueError, 'escapes evidence folder'):
                        proof(root, path, {})

    def test_aliased_component_records_cannot_fill_missing_proofs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'scalar-proof-inputs.json').write_text(json.dumps({
                'scalar': dict.fromkeys(SCALAR_COMPONENTS, 'one.json'),
                'preflight': dict.fromkeys(PREFLIGHT_COMPONENTS, 'one.json')}))
            for function in (prior_scalar_proofs, prior_preflight_proofs):
                with self.subTest(function=function.__name__):
                    with self.assertRaisesRegex(ValueError, 'aliases component records'):
                        function(root, {})


if __name__ == '__main__':
    unittest.main()
