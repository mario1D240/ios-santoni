"""Common-dispatch evidence and isolated LDRSW semantics; no hardware claims."""
from copy import deepcopy
import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import check_santoni_gpu_kernel as kernel
import santoni_gpu_trace_dispatch_audit as dispatch


def dispatch_fixture(identity, binding):
    rows = []
    for case in dispatch.CASES:
        recv = int(case in ('entry', 'result', 'receiver-error', 'write-flags'))
        dev = int(case in ('character', 'block', 'fifo'))
        result = (2 if case == 'get-error' else 1 if case == 'mac-error' else 13 if case == 'receiver-error' else
                  22 if case == 'write-flags' else 0 if recv or dev else 25)
        calls = ['_vfs_context_proc', '_lck_mtx_unlock', '_fg_get_data_volatile', '_vnode_getwithref']
        if case != 'get-error':
            calls.append('_mac_vnode_check_ioctl')
            if recv or dev:
                calls += ['_current_uthread', '_uthread_is64bit',
                          '_mockfs_santoni_ioctl' if recv else '_dispatch_device_fixture']
            calls.append('_vnode_put')
        calls += ['_vfs_context_proc', '_lck_mtx_lock']
        rows.append({'case': case, 'result': result, 'receiver_calls': recv, 'device_calls': dev,
                     'receiver_arguments': [[0x9000, 0x62003000, dispatch.COMMAND, 0x6200b000,
                         3 if case == 'write-flags' else 1, 0x62006000]] if recv else [],
                     'record_immutable': True, 'refs_released': True, 'fd_mutex_restored': True,
                     'instruction_addresses': 10, 'service_calls': calls})
    return {**identity, 'success': True, 'synthetic': True, 'common_dispatch_checked': True,
            'diagnosis_only': False, 'hardware_verified': False, 'roots': list(dispatch.ROOTS),
            'ioctl_command': dispatch.COMMAND, 'record_bytes': 64, 'binding': deepcopy(binding),
            'decoded_graph_sha256': 'c' * 64, 'ioctl_descriptor': '0x9000', 'cases': rows,
            'tool_sha256': hashlib.sha256(Path(dispatch.__file__).read_bytes()).hexdigest()}


class EmptyImage:
    segs = ()
    def read(self, address, size):
        return None


class SwitchImage:
    def __init__(self, entries=(0, 2, 4, 6, 8, 8, 6), protection=1):
        self.entries = bytes(entries)
        self.segs = ({'vmaddr': 0x2000, 'vmsize': 4096, 'filesize': 4096,
                      'initprot': protection},)

    def read(self, address, size):
        offset = address - 0x2000
        if 0 <= offset and offset + size <= len(self.entries):
            return int.from_bytes(self.entries[offset:offset + size], 'little')
        return None


def switch_code():
    instructions = (
        'mov x19, x0', 'ldrh w8, [x19, #0x70]', 'sub w9, w8, #0x1',
        'cmp w9, #0x6', 'b.hi 0x1054', 'adrp x10, 0x2000',
        'add x10, x10, #0x0', 'adr x11, 0x102c', 'ldrb w12, [x10, x9]',
        'add x11, x11, x12, lsl #2', 'br x11',
        'mov w0, #0x1', 'ret', 'mov w0, #0x2', 'ret',
        'mov w0, #0x3', 'ret', 'mov w0, #0x4', 'ret',
        'mov w0, #0x0', 'ret', 'mov w0, #0x19', 'ret')
    text = '1000 <_vn_ioctl>:\n' + ''.join(
        f'{0x1000 + 4 * i:x}: d503201f {instruction}\n'
        for i, instruction in enumerate(instructions))
    # Synthetic decoder fixture, never claimed as instruction-byte evidence.
    return kernel._Code(text, '_vn_ioctl', 0x1000)


class CommonDispatch(unittest.TestCase):
    def setUp(self):
        self.identity = {'commit': 'a' * 40, 'ci_run': 123, 'kernel_sha256': 'b' * 64}
        self.binding = {'success': True, 'counter': '0x8000'}
        self.record = dispatch_fixture(self.identity, self.binding)

    def test_complete_exact_component_is_consumed(self):
        self.assertIs(dispatch.validate(self.record, self.identity, self.binding), self.record)

    def test_identity_scope_source_and_binding_cannot_transfer(self):
        for key, value in (('commit', 'd' * 40), ('ci_run', 124), ('kernel_sha256', 'd' * 64),
                           ('success', 1), ('common_dispatch_checked', False), ('diagnosis_only', True),
                           ('hardware_verified', True), ('roots', list(dispatch.ROOTS[:-1])),
                           ('ioctl_command', dispatch.COMMAND + (1 << 32)), ('record_bytes', 65),
                           ('tool_sha256', '0' * 64), ('binding', {'success': False}),
                           ('decoded_graph_sha256', None), ('ioctl_descriptor', 'unknown')):
            with self.subTest(key=key), self.assertRaises((ValueError, TypeError)):
                dispatch.validate({**self.record, key: value}, self.identity, self.binding)

    def test_each_missing_case_or_false_lifetime_rejects(self):
        for index in range(len(dispatch.CASES)):
            for field in ('record_immutable', 'refs_released', 'fd_mutex_restored'):
                record = deepcopy(self.record); record['cases'][index][field] = False
                with self.subTest(index=index, field=field), self.assertRaises(ValueError):
                    dispatch.validate(record, self.identity, self.binding)
            record = deepcopy(self.record); record['cases'].pop(index)
            with self.assertRaises(ValueError): dispatch.validate(record, self.identity, self.binding)

    def test_baseline_callback_width_MAC_and_fd_lock_mutations_reject(self):
        for mutation in ('baseline', 'wide', 'flags', 'MAC', 'fd-lock', 'descriptor', 'unmapped-service'):
            record = deepcopy(self.record); row = record['cases'][0]
            if mutation == 'baseline': row['result'] = 25; row['receiver_calls'] = 0
            elif mutation == 'wide': row['receiver_arguments'][0][2] += 1 << 32
            elif mutation == 'flags': row['receiver_arguments'][0][4] = 3
            elif mutation == 'MAC': row['service_calls'].remove('_mac_vnode_check_ioctl')
            elif mutation == 'fd-lock': row['service_calls'].remove('_lck_mtx_lock')
            elif mutation == 'descriptor': row['receiver_arguments'][0][0] += 8
            else: row['service_calls'].append('_sgpu_pas_allocate')
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                dispatch.validate(record, self.identity, self.binding)

    def test_signed_descriptor_load_positive_negative_and_alignment(self):
        code = kernel._Code('1000 <_signed>:\n1000: b9800020 ldrsw x0, [x1]\n1004: d65f03c0 ret\n',
                            '_signed', 0x1000)
        for value, expected in ((7, 7), (0xffffffff, (1 << 64) - 1), (0x80000000, (1 << 64) - (1 << 31))):
            vm = dispatch.DispatchMachine({'_signed': code}, EmptyImage(), {}, kernel)
            vm.memory.map(0x2000, 8); vm.memory.put(0x2000, value)
            vm.run('_signed', (0, 0x2000), budget=4)
            self.assertEqual(vm.state.get('x0').expr, expected)
        with self.assertRaises(ValueError): vm.run('_signed', (0, 0x2001), budget=4)

    def test_guarded_switch_all_types_preserve_return_stack_and_index(self):
        for vtype, expected in enumerate((25, 1, 2, 3, 4, 0, 0, 4, 25)):
            code = switch_code()
            vm = dispatch.DispatchMachine({'_vn_ioctl': code}, SwitchImage(), {}, kernel)
            vm.memory.map(0x3000, 128); vm.memory.put(0x3070, vtype, 2)
            vm.run('_vn_ioctl', (0x3000,), budget=40)
            with self.subTest(vtype=vtype):
                self.assertEqual(vm.state.get('w0').expr, expected)
                self.assertEqual(vm.state.get('x30').expr, vm.RETURN)
                self.assertEqual(vm.state.get('sp').expr, vm.STACK + vm.STACK_SIZE)
                self.assertEqual(vm.calls, [])
                self.assertEqual(vm.state.get('x19').expr, 0x3000)

    def test_switch_rejects_unbound_guard_table_target_and_interior_entry(self):
        for mutation in ('bound', 'table-address', 'target-base', 'entry', 'writable',
                         'missing-bytes', 'unused-target-escapes'):
            code, image = switch_code(), SwitchImage()
            if mutation == 'bound': code.ins[0x100c] = ('cmp', ('w9', '#0x7'))
            elif mutation == 'table-address': code.ins[0x1018] = ('add', ('x10', 'x10', '#0x1000'))
            elif mutation == 'target-base': code.ins[0x101c] = ('adr', ('x11', '0x1034'))
            elif mutation == 'entry': code.pred[0x1020].add(0x1000)
            elif mutation == 'writable': image = SwitchImage(protection=3)
            elif mutation == 'missing-bytes': image = SwitchImage(entries=(0,))
            else: image = SwitchImage(entries=(0, 2, 4, 6, 8, 8, 255))
            vm = dispatch.DispatchMachine({'_vn_ioctl': code}, image, {}, kernel)
            vm.memory.map(0x3000, 128); vm.memory.put(0x3070, 1, 2)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                vm.run('_vn_ioctl', (0x3000,), budget=40)

    def test_shared_interpreter_does_not_admit_dispatch_switch(self):
        from santoni_gpu_binary_model import Machine
        vm = Machine({'_vn_ioctl': switch_code()}, SwitchImage(), {}, kernel)
        vm.memory.map(0x3000, 128); vm.memory.put(0x3070, 1, 2)
        with self.assertRaisesRegex(ValueError, 'unmodeled binary callee'):
            vm.run('_vn_ioctl', (0x3000,), budget=40)


if __name__ == '__main__':
    unittest.main()
