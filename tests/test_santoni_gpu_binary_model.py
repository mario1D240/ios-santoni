"""Concrete instruction semantics and actual compiled CPU queue contracts."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import check_santoni_gpu_kernel as e
from santoni_gpu_binary_model import Machine, Memory, integer, state_type, vector_step
from tests.test_santoni_gpu_pixel_audit import decoded


class Image:
    def read(self, address, size): return None


class SemanticsTests(unittest.TestCase):
    def test_arithmetic_carry_overflow_and_register_shift(self):
        samples = ((0xffffffff, 1), (0x7fffffff, 1), (0x80000000, 0x80000000), (7, 11))
        for op in ('adds', 'subs'):
            code = decoded([f'{op} w2, w0, w1', 'cset w0, hs', 'cset w1, vs', 'ret'], '_math')
            for a, b in samples:
                vm = Machine({'_math': code}, Image(), {}, e); vm.run('_math', (a, b))
                total = a + b if op == 'adds' else a - b
                result = total & 0xffffffff
                carry = a + b > 0xffffffff if op == 'adds' else a >= b
                overflow = bool((~(a ^ b) if op == 'adds' else a ^ b) & (a ^ result) & 0x80000000)
                self.assertEqual(integer(vm.state, 'w0'), carry)
                self.assertEqual(integer(vm.state, 'w1'), overflow)
                self.assertEqual(integer(vm.state, 'w2'), result)
        for op, a, b, want in (('add w0, w0, w1, lsr #12', 7, 0x5000, 12),
                               ('add x0, x0, w1, uxtw #3', 7, 0xffffffff, 0x7ffffffff),
                               ('add w0, w0, w1, uxtb #3', 7, 0xfffffffe, 2039),
                               ('add x0, x0, w1, sxtb', 7, 0xfffffffe, 5),
                               ('lsr w0, w0, w1', 0x80000000, 32, 0x80000000)):
            code = decoded([op, 'ret'], '_math'); vm = Machine({'_math': code}, Image(), {}, e)
            vm.run('_math', (a, b)); self.assertEqual(integer(vm.state, 'x0'), want)

    def test_vector_bit_lane_moves_and_unsigned_multiply_high(self):
        memory = Memory(Image()); memory.map(0x8000, 4); memory.put(0x8000, 0xfedcba98)
        state = state_type(e)(memory)
        state.put('q0', e._Value(128, 0)); state.put('q1', e._Value(128, (1 << 128) - 1))
        state.put('q2', e._Value(128, 0x01010101)); state.put('x0', e._Value(64, 0x8000))
        vector_step('bit.16b', ('v0', 'v1', 'v2'), state, memory, e)
        self.assertEqual(integer(state, 'q0'), 0x01010101)
        vector_step('ld1.s', ('{ v0 }[2]', '[x0]'), state, memory, e)
        self.assertEqual(integer(state, 'q0'), (0xfedcba98 << 64) | 0x01010101)
        vector_step('mov.d', ('v0[0]', 'v1[1]'), state, memory, e)
        self.assertEqual(integer(state, 'q0'), (0xfedcba98 << 64) | ((1 << 64) - 1))
        code = decoded(['umulh x0, x0, x1', 'ret'], '_math')
        for a, b in ((0, 123), (1 << 63, 2), ((1 << 64) - 1, (1 << 64) - 1)):
            vm = Machine({'_math': code}, Image(), {}, e); vm.run('_math', (a, b))
            self.assertEqual(integer(vm.state, 'x0'), (a * b) >> 64)

    def test_vector_fill_compare_narrow_and_reduce(self):
        memory = Memory(Image()); state = state_type(e)(memory)
        vector_step('movi.16b', ('v0', '#0xa5'), state, memory, e)
        self.assertEqual(integer(state, 'q0'), int.from_bytes(b'\xa5' * 16, 'little'))
        state.put('q1', e._Value(128, integer(state, 'q0')))
        vector_step('cmeq.4s', ('v2', 'v0', 'v1'), state, memory, e)
        self.assertEqual(integer(state, 'q2'), (1 << 128) - 1)
        vector_step('mvn.16b', ('v2', 'v2'), state, memory, e)
        vector_step('xtn.4h', ('v2', 'v2'), state, memory, e)
        vector_step('umaxv.4h', ('h2', 'v2'), state, memory, e)
        vector_step('fmov', ('w0', 's2'), state, memory, e)
        self.assertEqual(integer(state, 'w0'), 0)
        for lane in range(4):
            state.put('q1', e._Value(128, integer(state, 'q0') ^ (1 << (lane * 32))))
            vector_step('cmeq.4s', ('v2', 'v0', 'v1'), state, memory, e)
            self.assertEqual(integer(state, 'q2'), ((1 << 128) - 1) ^ (0xffffffff << (lane * 32)))
        state.put('w3', e._Value(32, 1))
        vector_step('dup.2s', ('v3', 'w3'), state, memory, e)
        vector_step('shl.2s', ('v3', 'v3', '#31'), state, memory, e)
        vector_step('cmlt.2s', ('v4', 'v3', '#0'), state, memory, e)
        self.assertEqual(integer(state, 'd4'), (1 << 64) - 1)

    def test_partial_bytes_survive_copy_but_never_become_a_concrete_address(self):
        memory = Memory(Image()); memory.map(0x8000, 32, known=False)
        state = state_type(e)(memory)
        memory.put(0x8000, 7, 4)
        value = state.load(e._Value(64, 0x8000), 16, memory.image)
        state.store(e._Value(64, 0x8010), 16, value)
        self.assertEqual(memory.get(0x8010), 7)
        with self.assertRaises(ValueError): memory.get(0x8010, 8)
        with self.assertRaises(ValueError): memory.put(0x8020, 1)

    def test_scalar_multiply_and_restored_stack(self):
        code = decoded(['sub sp, sp, #16', 'str x30, [sp]', 'mov w1, #7',
                        'mov w2, #11', 'mov w3, #5', 'madd w0, w1, w2, w3',
                        'ldr x30, [sp]', 'add sp, sp, #16', 'ret'], '_model')
        machine = Machine({'_model': code}, Image(), {}, e)
        self.assertEqual(machine.run('_model'), e._Value(32, 82))
        bad = decoded(['sub sp, sp, #16', 'mov w0, #1', 'ret'], '_bad')
        with self.assertRaises(ValueError): Machine({'_bad': bad}, Image(), {}, e).run('_bad')

    def test_unknown_conditions_and_unsupported_ops_fail_closed(self):
        for lines in (['cbz w0, @done', 'done:', 'ret'], ['smc #0', 'ret'], ['again:', 'b @again']):
            code = decoded(lines, '_bad')
            with self.assertRaises(ValueError): Machine({'_bad': code}, Image(), {}, e).run('_bad', budget=10)

    def test_unmodeled_mutable_image_and_external_upper_lanes_are_unknown(self):
        class MutableImage:
            segs = [{'vmaddr': 0x1000, 'vmsize': 0x1000, 'initprot': 3}]
            def read(self, address, size): return 0
        with self.assertRaisesRegex(ValueError, 'mutable'):
            Memory(MutableImage()).get(0x1000)
        code = decoded(['sub sp, sp, #16', 'str x30, [sp]', 'movi.16b v8, #1',
                        'bl 0x9000', 'ldr x30, [sp]', 'add sp, sp, #16', 'ret'], '_call')
        vm = Machine({'_call': code}, Image(), {}, e)
        vm.external = lambda target, state, **kwargs: target == 0x9000
        vm.run('_call')
        self.assertEqual(integer(vm.state, 'd8'), 0x0101010101010101)
        with self.assertRaises(ValueError): integer(vm.state, 'q8')


class ActualQueueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ci = Path(__file__).resolve().parents[1] / 'out/ci-017713a'
        kernel = cls.ci / 'kernel/kernel.development.santoni'
        if not kernel.is_file(): raise unittest.SkipTest('downloaded exact kernel required')
        cls.image = e._Image(kernel.read_bytes())
        cls.names = e._symbols((cls.ci / 'symbols.txt').read_text())
        cls.codes = {}
        for name in ('_sgpu_session_queue_init', '_sgpu_session_enqueue', '_sgpu_session_take',
                     '_sgpu_session_commit', '_sgpu_session_finish', '_sgpu_session_close',
                     '_sgpu_session_fault_pending', '_sgpu_session_get', '_session_queue_settle',
                     '_session_cancel_queued'):
            cls.codes[name] = e._Code((cls.ci / (name[1:] + '.asm')).read_text(), name,
                next(iter(cls.names[name])), noreturn=e._stack_failure_terminal(cls.names)[0])

    def setUp(self):
        self.vm = Machine(self.codes, self.image, self.names, e)
        self.q, self.values, self.id, self.request, self.result, self.output = (
            0x51000000, 0x51001000, 0x51002000, 0x51003000, 0x51004000, 0x51005000)
        for address, size in ((self.q, 3056), (self.values, 16), (self.id, 4),
                              (self.request, 20), (self.result, 76), (self.output, 76)):
            self.vm.memory.map(address, size)

        def external(target, state, probe=False, before=None):
            name = self.vm.by_address.get(target)
            if name not in ('_bzero', '_memcpy'): return False
            if probe: return True
            dest, second = integer(before, 'x0'), integer(before, 'x1')
            if name == '_bzero':
                self.vm.memory.write(dest, bytes(second))
            else:
                length = integer(before, 'x2')
                self.vm.memory.write(dest, self.vm.memory.bytes(second, length, partial=True))
            state.put('x0', e._Value(64, dest))
            return True
        self.vm.external = external

    def run_fn(self, name, *args):
        result = self.vm.run('_sgpu_session_' + name, args)
        return None if result is None else result.expr

    def test_exact_compiled_queue_quota_immutable_results_and_owner(self):
        m = self.vm.memory
        self.assertEqual(self.run_fn('queue_init', self.q), 1)
        self.assertEqual(self.run_fn('queue_init', self.q), 0)
        for i in range(32):
            for j in range(4): m.put(self.values + 4 * j, i * 4 + j)
            frozen = m.bytes(self.q, 3056)
            self.assertEqual(self.run_fn('enqueue', self.q, 2, 1, self.values, self.id), 2)
            self.assertEqual(m.bytes(self.q, 3056), frozen)
            self.assertEqual(self.run_fn('enqueue', self.q, 1, 1, self.values, self.id), 0)
            self.assertEqual(m.get(self.id), i + 1)
            self.assertEqual(self.run_fn('take', self.q, self.request), 1)
            self.assertEqual(m.bytes(self.request + 4, 16), m.bytes(self.values, 16))
            self.assertEqual(self.run_fn('commit', self.q, i + 1), 1)
            for offset, value in ((0, 4), (4, i + 3), (8, 181 + i * 11), (12, 4)):
                m.put(self.result + offset, value)
            m.put(self.result + 24, 1, 1)
            self.assertEqual(self.run_fn('finish', self.q, i + 1, self.result), 1)
            self.assertEqual(self.run_fn('get', self.q, 1, i + 1, self.output), 1)
            self.assertEqual(m.bytes(self.output, 76), m.bytes(self.result, 76))
        status = [m.get(self.q + 4 + i * 4) for i in range(15)]
        self.assertEqual(status[:5], [4, 1, 32, 0, 0])
        self.assertEqual(status[5:13], [32, 32, 32, 0, 0, 128, 34, 522])
        frozen = m.bytes(self.q, 3056)
        self.assertEqual(self.run_fn('enqueue', self.q, 1, 1, self.values, self.id), 5)
        self.run_fn('close', self.q, 1)
        self.assertEqual(m.bytes(self.q, 3056), frozen)


if __name__ == '__main__': unittest.main()
