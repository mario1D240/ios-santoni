import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import check_santoni_gpu_kernel as e
import check_santoni_gpu_user_fault_kernel as fault
import santoni_gpu_user_fault_gate as gate
from santoni_gpu_binary_model import Memory


class EmptyImage:
    segs = ()
    def read(self, address, size):
        return None


class FaultBinaryTests(unittest.TestCase):
    def test_section_requires_bounded_rx_bytes_and_unique_identity(self):
        good = {'section': b'__sgpu_fault', 'segment': b'__TEXT_EXEC', 'owner': b'__TEXT_EXEC',
                'address': 0x1030, 'size': 64, 'vmaddr': 0x1000, 'filesize': 256,
                'fileoff': 128, 'offset': 176, 'initprot': 5}
        names = {fault.ROOT: {0x1030}}
        with patch.object(fault, '_data_sections', return_value=[good]):
            self.assertEqual(fault.bounded_section(EmptyImage(), names), good)
            with self.assertRaises(ValueError):
                fault.bounded_section(EmptyImage(), {**names, '_interior': {0x1034}})
        for key, value in (('initprot', 7), ('owner', b'__DATA'), ('size', 4097),
                           ('filesize', 48), ('offset', 177), ('address', 0x1034)):
            with self.subTest(key=key), patch.object(fault, '_data_sections', return_value=[{**good, key: value}]), self.assertRaises(ValueError):
                fault.bounded_section(EmptyImage(), names)

    def test_shared_return_is_bounded_but_retry_cycle_is_rejected(self):
        class Code:
            ins = {0x1000: ('ret', ()), 0x1004: ('b', ('0x1000',))}
            succ = {0x1000: (), 0x1004: (0x1000,)}
        fault.require_acyclic(Code())
        cyclic = Code(); cyclic.succ = {0x1000: (0x1004,), 0x1004: (0x1000,)}
        with self.assertRaises(ValueError): fault.require_acyclic(cyclic)

    def machine(self):
        vm = object.__new__(fault.FaultMachine)
        vm.e, vm.flag, vm.exclusive, vm.fail_exclusive = e, 0x2000, None, False
        vm.memory = Memory(EmptyImage()); vm.memory.map(0x2000, 4)
        state = e._State({'x8': e._Value(64, 0x2000), 'x9': e._Value(64, 1)})
        return vm, state

    def test_exclusive_success_failure_and_refused_other_object(self):
        for failed in (False, True):
            vm, state = self.machine(); vm.fail_exclusive = failed
            vm.atomic_step('ldxr', ('w10', '[x8]'), state)
            vm.atomic_step('stxr', ('w11', 'w9', '[x8]'), state)
            self.assertEqual(vm.memory.get(0x2000, 4), int(not failed))
            self.assertEqual(state.get('w11').expr, int(failed))
            with self.assertRaises(ValueError):
                vm.atomic_step('stxr', ('w11', 'w9', '[x8]'), state)
        vm, state = self.machine(); state.put('x8', e._Value(64, 0x2004))
        with self.assertRaises(ValueError):
            vm.atomic_step('ldxr', ('w10', '[x8]'), state)
        with self.assertRaises(ValueError):
            vm.atomic_step('ldaxr', ('w10', '[x8]'), state)

    def test_gate_refuses_missing_partial_and_foreign_kernel_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            self.assertIsNone(gate.require_audit(folder, 'a'*40, 1, 'b'*64, False))
            with self.assertRaises(ValueError):
                gate.require_audit(folder, 'a'*40, 1, 'b'*64, True)

            good = {'success': True, 'hardware_verified': False, 'commit': 'a'*40,
                    'ci_run': 1, 'kernel_sha256': 'b'*64, 'cases': 22,
                    'terminal_route_cases': 3,
                    'tool_sha256': hashlib.sha256(Path(fault.__file__).read_bytes()).hexdigest(),
                    **{k: True for k in gate.CHECKS}}
            path = folder / 'user-fault-binary-audit.json'
            path.write_text(json.dumps(good))
            self.assertEqual(gate.require_audit(folder, 'a'*40, 1, 'b'*64, True), good)
            for key, value in [('commit', 'c'*40), ('hardware_verified', True), ('cases', 21),
                               ('tool_sha256', '0'*64), *[(k, False) for k in gate.CHECKS]]:
                bad = copy.deepcopy(good); bad[key] = value
                path.write_text(json.dumps(bad))
                with self.assertRaises(ValueError):
                    gate.require_audit(folder, 'a'*40, 1, 'b'*64, True)


    def test_actual_printf_widths_order_and_one_shot_claim(self):
        for second in (False, True):
            for mutation in ('none', 'swap', 'no-claim', 'wrong-format', 'wrong-order'):
                with self.subTest(second=second, mutation=mutation):
                    model = object.__new__(fault.FaultModel)
                    model.e, model.flag = e, 0x2000
                    model.m = Memory(EmptyImage())
                    model.m.map(0x1000, 256); model.m.map(0x2000, 4); model.m.map(0x8000, 64)
                    model.m.put(model.flag, int(mutation != 'no-claim'), 4)
                    fmt = fault.SECOND if second else fault.FIRST
                    model.m.write(0x1000, b'wrong\0' if mutation == 'wrong-format' else fmt)
                    class VM:
                        by_address = {0xa000: '_printf'}
                    model.vm = VM()
                    model.prints = [[1]] if second else []
                    if mutation == 'wrong-order': model.prints = [] if second else [[1]]
                    pc, sp, lr, esr, far = model.VALUES
                    values = [esr, far, 1, 0x101, 0xfedcba9876543210] if second else [pc, sp, lr]
                    widths = (4, 8, 4, 8, 8) if second else (8, 8, 8)
                    if mutation == 'swap': values[0], values[1] = values[1], values[0]
                    for i, (value, width) in enumerate(zip(values, widths)):
                        model.m.put(0x8000 + 8*i, value & ((1 << (width*8))-1), width)
                    before = e._State({'x0': e._Value(64, 0x1000), 'sp': e._Value(64, 0x8000)})
                    if mutation == 'none':
                        self.assertTrue(model.external(0xa000, e._State(), before=before))
                        self.assertEqual(model.prints[-1], values)
                    else:
                        with self.assertRaises(ValueError):
                            model.external(0xa000, e._State(), before=before)

    def test_readonly_frame_and_unknown_services_reject(self):
        model = object.__new__(fault.FaultModel)
        model.m = Memory(EmptyImage()); model.m.map(model.FRAME, 304)
        model.m.readonly.append((model.FRAME, model.FRAME+304))
        with self.assertRaises(ValueError): model.m.put(model.FRAME+264, 0, 8)
        class VM:
            by_address = {0xa000: '_unreviewed'}
            STACK, STACK_SIZE = 0x8000, 64
        model.vm = VM(); model.flag, model.writes = 0x2000, []
        for address, size in ((model.FRAME, 8), (model.flag, 8), (0x9000, 4)):
            with self.assertRaises(ValueError): model.write(address, size)
        self.assertFalse(model.external(0xa000, e._State(), probe=True))


if __name__ == '__main__':
    unittest.main()
