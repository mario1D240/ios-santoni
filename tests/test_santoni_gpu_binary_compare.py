"""New concrete comparison semantics used by scalar cdev entry replay."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import check_santoni_gpu_kernel as e
from santoni_gpu_binary_model import Machine, vector_step


class NoMemoryImage:
    segs = ()

    def read(self, address, size):
        raise AssertionError('comparison fixture must not read kernel memory')


class ShiftedCompare(unittest.TestCase):
    def run_compare(self, op, width, shift, condition, a, b):
        # Synthetic decoded instructions test interpreter semantics only.
        # No claim of compiled mutant or linked-kernel validation is made here.
        reg = 'w' if width == 32 else 'x'
        text = f'''1000 <_comparison>:
1000: 00000000 {op} {reg}0, {reg}1, {shift}
1004: 00000000 cset w0, {condition}
1008: d65f03c0 ret
'''
        code = e._Code(text, '_comparison', 0x1000)
        vm = Machine({'_comparison': code}, NoMemoryImage(), {}, e)
        return vm.run('_comparison', (a, b)).expr

    def test_shift_width_sign_and_truncation(self):
        for width, shift, a, b, expected in (
                (32, 'lsr #24', 42, 42 << 24, 1),
                (32, 'lsr #24', 43, 42 << 24, 0),
                (32, 'lsl #31', 0x80000000, 1, 1),
                (32, 'lsl #1', 0, 0x80000000, 1),
                (32, 'asr #31', 0xffffffff, 0x80000000, 1),
                (32, 'lsr #31', 0xffffffff, 0x80000000, 0),
                (64, 'asr #63', 0xffffffffffffffff, 1 << 63, 1),
                (64, 'lsr #63', 1, 1 << 63, 1)):
            with self.subTest(width=width, shift=shift):
                self.assertEqual(self.run_compare('cmp', width, shift, 'eq', a, b), expected)

    def test_comparison_flags(self):
        for op, cond, a, b, expected in (
                ('cmp', 'lo', 1, 4, 1),
                ('cmp', 'hs', 2, 4, 1),
                ('cmn', 'eq', 0xfffffffe, 4, 1),
                ('cmn', 'hs', 0xfffffffe, 4, 1),
                ('cmn', 'vs', 0x7ffffffe, 4, 1),
                ('tst', 'mi', 0xffffffff, 0xffffffff, 1),
                ('tst', 'lo', 1, 4, 1),
                ('tst', 'eq', 1, 4, 1)):
            with self.subTest(op=op, condition=cond):
                self.assertEqual(self.run_compare(op, 32, 'asr #1', cond, a, b), expected)

    def test_unreviewed_shifts_reject(self):
        for width, shift in ((32, 'lsr #32'), (64, 'asr #64'), (32, 'ror #1'),
                             (32, 'lsl #-1'), (64, 'uxtw #1'), (32, 'lsr #1, #0')):
            with self.subTest(width=width, shift=shift):
                with self.assertRaisesRegex(ValueError, 'unreviewed concrete comparison shift'):
                    self.run_compare('cmp', width, shift, 'eq', 0, 0)


class PreflightVector(unittest.TestCase):
    def test_rev64_reverses_two_words_and_clears_upper_half(self):
        state = e._State()
        state.put('q1', e._Value(128, (0xa5 << 120) | 0x1122334455667788))
        self.assertTrue(vector_step('rev64.2s', ['v0', 'v1'], state, None, e))
        self.assertEqual(state.get('q0'), e._Value(128, 0x5566778811223344))
        self.assertEqual(state.get('q1').expr >> 120, 0xa5)

    def test_unreviewed_rev64_geometry_rejects(self):
        for args in (['v0'], ['d0', 'v1'], ['v0', 'v1', '#0']):
            with self.subTest(args=args):
                with self.assertRaisesRegex(ValueError, 'unreviewed REV64 vector geometry'):
                    vector_step('rev64.2s', args, e._State(), None, e)


class ShiftedImmediateCompare(unittest.TestCase):
    def compare(self, op, immediate, shift, condition, a):
        text = f'''1000 <_comparison>:
1000: 00000000 {op} w0, #{immediate}, {shift}
1004: 00000000 cset w0, {condition}
1008: d65f03c0 ret
'''
        code = e._Code(text, '_comparison', 0x1000)
        return Machine({'_comparison': code}, NoMemoryImage(), {}, e).run('_comparison', (a,)).expr

    def test_valid_immediate_comparisons(self):
        for op, imm, shift, condition, a, expected in (
                ('cmp', 1, 'lsl #12', 'eq', 4096, 1),
                ('cmp', 1, 'lsl #12', 'lo', 4095, 1),
                ('cmp', 4095, 'lsl #12', 'eq', 4095 * 4096, 1),
                ('cmn', 1, 'lsl #12', 'eq', 0xfffff000, 1),
                ('cmn', 1, 'lsl #12', 'hs', 0xfffff000, 1),
                ('cmp', 1, 'lsl #0', 'eq', 1, 1)):
            with self.subTest(op=op, immediate=imm, shift=shift, condition=condition):
                self.assertEqual(self.compare(op, imm, shift, condition, a), expected)

    def test_invalid_immediate_forms_reject(self):
        for op, imm, shift in (('cmp', 1, 'lsr #12'), ('cmn', 1, 'asr #12'),
                               ('cmp', 4096, 'lsl #12'), ('cmp', 1, 'lsl #1'),
                               ('tst', 1, 'lsl #12')):
            with self.subTest(op=op, immediate=imm, shift=shift):
                with self.assertRaisesRegex(ValueError, 'unreviewed concrete immediate comparison shift'):
                    self.compare(op, imm, shift, 'eq', 0)


if __name__ == '__main__':
    unittest.main()
