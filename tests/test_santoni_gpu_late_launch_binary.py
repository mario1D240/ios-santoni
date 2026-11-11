"""New snapshot model/gate refusals; synthetic fixtures certify no kernel."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import check_santoni_gpu_late_launch_kernel as late
import santoni_gpu_late_launch_gate as gate
import check_santoni_gpu_kernel as e
from santoni_gpu_binary_model import Memory


class EmptyImage:
    segs = ()
    def read(self, address, size): return None


class LateModelContracts(unittest.TestCase):
    def model(self, name):
        m = object.__new__(late.LateModel)
        m.e, m.case = e, {'mode': 3, 'expected_ready': 0, 'mounted': 1}
        m.events, m.prints, m.writes = [], [{'kind': 'normal'}], []
        m.locked = False
        m.diag_locked, m.diag_locks, m.diag_unlocks, m.diag_lock = False, 0, 0, 0x4200
        m.sg, m.launch, m.major, m.published, m.lock = 0x3000, 0x3800, 0x3900, 0x4000, 0x4100
        m.m = Memory(EmptyImage()); m.m.map(0x1000, 256); m.m.map(0x4000, 1); m.m.map(0x8000, 64)
        m.m.put(m.published, 1, 1)
        m.m.write(0x1000, late.LATE)
        class VM: pass
        m.vm = VM(); m.vm.by_address = {0xa000: name}; m.vm.STACK = 0x8000; m.vm.STACK_SIZE = 64
        before = e._State({'x0': e._Value(64, 0x1000), 'sp': e._Value(64, 0x8000)})
        return m, before

    def test_unknown_callee_is_never_modeled(self):
        m, before = self.model('_unreviewed')
        self.assertFalse(m.external(0xa000, e._State(), before=before))
        self.assertEqual(m.events, [])

    def test_publication_and_unlocked_scope_required_for_print(self):
        for mutation in ('locked', 'unpublished'):
            m, before = self.model('_printf')
            if mutation == 'locked': m.locked = True
            else: m.m.put(m.published, 0, 1)
            with self.assertRaises(ValueError): m.external(0xa000, e._State(), before=before)
            self.assertEqual(m.prints, [{'kind': 'normal'}])

    def test_print_scalar_swap_rejects_without_recording_a_pass(self):
        m, before = self.model('_printf')
        for i, value in enumerate((3, 1, 0)): m.m.put(0x8000 + i * 8, value, 8)
        with self.assertRaises(ValueError): m.external(0xa000, e._State(), before=before)
        self.assertEqual(m.prints, [{'kind': 'normal'}])

    def test_wrong_store_width_lock_and_object_reject(self):
        m, _ = self.model('_printf')
        for address, size in ((m.published, 1), (m.major, 8), (m.launch, 4), (0x9000, 4)):
            with self.assertRaises(ValueError): m.write(address, size)
        self.assertEqual(m.writes, [])

    def test_diagnostic_printf_checks_actual_arguments_and_released_mutex(self):
        for mutation in ('none', 'swap', 'locked', 'no_copy', 'wrong_value'):
            m, before = self.model('_printf')
            m.m.map(0x9000, 256); m.m.write(0x9000, late.DIAG)
            m.vm.STACK, m.vm.STACK_SIZE = 0x8100, 128; m.m.map(0x8100, 128)
            before.put('x0', e._Value(64, 0x9000))
            before.put('sp', e._Value(64, 0x8100))
            m.case['diag'] = [3, 1, 2, 9, 5, 4, 3, 4, 1, 1]
            values = list(m.case['diag'])
            if mutation == 'swap': values[0], values[1] = values[1], values[0]
            if mutation == 'wrong_value': values[0] = 0xffffffff
            for i, value in enumerate(values): m.m.put(0x8100 + i * 8, value, 8)
            m.prints.append({'kind': 'late', 'values': [3, 0, 1]})
            m.diag_locks = m.diag_unlocks = 1
            if mutation == 'locked': m.diag_locked = True
            if mutation == 'no_copy': m.diag_locks = m.diag_unlocks = 0
            if mutation == 'none':
                self.assertTrue(m.external(0xa000, e._State(), before=before))
                self.assertEqual(m.prints[-1]['values'], values)
            else:
                with self.assertRaises(ValueError): m.external(0xa000, e._State(), before=before)

    def test_diagnostic_getter_is_executed_instead_of_mocked(self):
        m, before = self.model(late.DIAG_ROOT)
        self.assertFalse(m.external(0xa000, e._State(), probe=True, before=before))


class LateDeliveryContracts(unittest.TestCase):
    def setUp(self):
        tmp = Path('/data/data/com.termux/files/usr/tmp/opencode')
        self.tmp = tempfile.TemporaryDirectory(dir=tmp if tmp.is_dir() else None)
        self.addCleanup(self.tmp.cleanup); self.ci = Path(self.tmp.name)
        self.record = {'success': True, 'commit': 'a' * 40, 'ci_run': 123, 'kernel_sha256': 'b' * 64,
                       'hardware_verified': False, 'cases': 33, **{name: True for name in gate.CHECKS}}

    def consume(self):
        return gate.require_audit(self.ci, 'a' * 40, 123, 'b' * 64, True)

    def test_absence_missing_and_complete_proof(self):
        self.assertIsNone(gate.require_audit(self.ci, 'a' * 40, 123, 'b' * 64, False))
        with self.assertRaises(ValueError): self.consume()
        (self.ci / 'late-launch-binary-audit.json').write_text(json.dumps(self.record))
        self.assertEqual(self.consume(), self.record)

    def test_different_kernel_partial_scope_and_false_claim_reject(self):
        changes = [('commit', 'c' * 40), ('ci_run', 124), ('kernel_sha256', 'd' * 64),
                   ('success', 1), ('hardware_verified', True), ('cases', 32), ('cases', True)]
        changes += [(name, value) for name in gate.CHECKS for value in (False, 1, None)]
        for key, value in changes:
            (self.ci / 'late-launch-binary-audit.json').write_text(json.dumps({**self.record, key: value}))
            with self.assertRaises(ValueError): self.consume()

    def test_diagnostic_images_require_new_proof_without_invalidating_older_images(self):
        path = self.ci / 'late-launch-binary-audit.json'
        path.write_text(json.dumps(self.record))
        self.assertEqual(self.consume(), self.record)
        with self.assertRaises(ValueError): gate.require_audit(self.ci, 'a'*40, 123, 'b'*64, True, True)
        record = {**self.record, **dict.fromkeys(gate.DIAG_CHECKS, True)}
        path.write_text(json.dumps(record))
        self.assertEqual(gate.require_audit(self.ci, 'a'*40, 123, 'b'*64, True, True), record)
        for field in gate.DIAG_CHECKS:
            path.write_text(json.dumps({**record, field: 1}))
            with self.assertRaises(ValueError): gate.require_audit(self.ci, 'a'*40, 123, 'b'*64, True, True)


if __name__ == '__main__':
    unittest.main()
