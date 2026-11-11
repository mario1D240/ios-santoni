"""New launcher-only instruction contracts; no old probe/kernel replay."""
import ast
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import check_santoni_gpu_kernel as e
import santoni_gpu_launcher_replay as r
from santoni_gpu_binary_model import integer
from tests.test_santoni_gpu_pixel_audit import decoded


class Image:
    def read(self, address, size):
        return None


class LauncherInstructionTests(unittest.TestCase):
    def machine(self, lines):
        code = decoded(lines, '_extension')
        return r.LauncherMachine({'_extension': code}, Image(), {}, e)

    def test_mvn_width_zero_extension_and_flags(self):
        samples = ((0, 0xffffffffffffffff, 0xffffffff),
                   (0xffffffffffffffff, 0, 0),
                   (0x12345678a55a00ff, 0xedcba9875aa5ff00, 0x5aa5ff00),
                   (0x8000000000000000, 0x7fffffffffffffff, 0xffffffff),
                   (0x80000000, 0xffffffff7fffffff, 0x7fffffff))
        for prefix, index in (('x', 1), ('w', 2)):
            for sample in samples:
                with self.subTest(prefix=prefix, value=sample[0]):
                    vm = self.machine(['cmp w1, w1', f'mvn {prefix}0, {prefix}0',
                                       'cset w2, hs', 'cset w3, vs', 'ret'])
                    vm.run('_extension', (sample[0], 7))
                    self.assertEqual(integer(vm.state, 'x0'), sample[index])
                    self.assertEqual(integer(vm.state, 'w2'), 1)
                    self.assertEqual(integer(vm.state, 'w3'), 0)
                    self.assertEqual(vm.atomic_events, [])

    def test_mvn_zero_register_and_unknown_source(self):
        for prefix, expected in (('w', 0xffffffff), ('x', 0xffffffffffffffff)):
            vm = self.machine([f'mvn {prefix}0, {prefix}zr', f'mvn {prefix}zr, {prefix}0', 'ret'])
            vm.run('_extension')
            self.assertEqual(integer(vm.state, 'x0'), expected)
            self.assertEqual(integer(vm.state, prefix + 'zr'), 0)
        with self.assertRaisesRegex(ValueError, 'unknown concrete register'):
            self.machine(['mvn x0, x1', 'ret']).run('_extension')

    def test_rev_width_and_flags(self):
        for prefix, sample, expected in (('x', 0x0123456789abcdef, 0xefcdab8967452301),
                                         ('w', 0x1234567889abcdef, 0xefcdab89)):
            vm = self.machine(['cmp w1, w1', f'rev {prefix}0, {prefix}0', 'cset w2, eq', 'ret'])
            vm.run('_extension', (sample, 7))
            self.assertEqual(integer(vm.state, 'x0'), expected)
            self.assertEqual(integer(vm.state, 'w2'), 1)

    def test_acquire_release_width_adjacent_bytes_and_event_order(self):
        for prefix, width, value, expected in (('w', 32, 0x1234567889abcdef, 0x89abcdef),
                                               ('x', 64, 0x0123456789abcdef, 0x0123456789abcdef)):
            vm = self.machine(['cmp w2, w2', f'stlr {prefix}0, [x1]',
                               f'ldar {prefix}3, [x1]', 'cset w4, eq', 'ret'])
            vm.memory.map(0x8000, 16, fill=0xa5)
            vm.run('_extension', (value, 0x8000, 7))
            self.assertEqual(integer(vm.state, 'x3'), expected)
            self.assertEqual(integer(vm.state, 'w4'), 1)
            size = width // 8
            self.assertEqual(vm.memory.bytes(0x8000, 16),
                             expected.to_bytes(size, 'little') + b'\xa5' * (16 - size))
            self.assertEqual([(v['op'], v['address'], v['width']) for v in vm.atomic_events],
                             [('stlr', '0x8000', width), ('ldar', '0x8000', width)])

    def test_extra_operations_refuse_unreviewed_geometry(self):
        for line in ('mvn x0, w1', 'mvn x0, x1, lsl #1', 'mvn sp, x1',
                     'rev w0, x1', 'rev x0, x1, lsl #1',
                     'ldar x0, [w1]', 'ldar x0, [x1, #8]',
                     'stlr x0, [x1, #8]', 'stlr x31, [x1]'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                self.machine([line, 'ret']).run('_extension', (1, 0x8000))

    def test_acquire_release_refuse_unknown_unowned_or_readonly_memory(self):
        for op in ('ldar', 'stlr'):
            with self.subTest(op=op), self.assertRaises(ValueError):
                self.machine([f'{op} x0, [x1]', 'ret']).run('_extension', (7, 0x8000))
        vm = self.machine(['stlr x0, [x1]', 'ret'])
        vm.memory.map(0x8000, 8)
        vm.memory.readonly.append((0x8000, 0x8008))
        with self.assertRaises(ValueError):
            vm.run('_extension', (7, 0x8000))
        vm = self.machine(['ldar x0, [x1]', 'ret'])
        vm.memory.map(0x8000, 8, known=False)
        vm.run('_extension', (7, 0x8000))
        with self.assertRaisesRegex(ValueError, 'unknown concrete register'):
            integer(vm.state, 'x0')

    def test_shared_run_ast_is_preserved_and_budget_still_holds(self):
        extended = copy.deepcopy(r._tree)
        loops = [n for n in ast.walk(extended) if isinstance(n, ast.For) and
                 ast.dump(n.iter) == ast.dump(ast.parse('range(budget)', mode='eval').body)]
        self.assertEqual(len(loops), 1)
        hook = ast.parse("if op in ('rev', 'mvn', 'cinc', 'ldar', 'stlr'):\n state=self.extra_step(pc,state)\n pc+=4\n continue\n").body[0]
        indexes = [i for i, n in enumerate(loops[0].body) if ast.dump(n) == ast.dump(hook)]
        self.assertEqual(len(indexes), 1)
        del loops[0].body[indexes[0]]
        self.assertEqual(ast.dump(extended), ast.dump(ast.parse(r._run_source)))
        with self.assertRaises(ValueError):
            self.machine(['again:', 'mvn x0, x0', 'b @again']).run('_extension', (0,), budget=4)


class LauncherConditionalIncrementTests(unittest.TestCase):
    machine = LauncherInstructionTests.machine
    def test_cinc_condition_width_wrap_and_preserved_flags(self):
        for prefix, value, incremented in (('w', 0x12345678ffffffff, 0),
                                           ('x', 0xffffffffffffffff, 0), ('x', 7, 8)):
            for comparison, condition, expected in ((0, 'eq', incremented), (1, 'eq', value),
                                                    (0, 'ne', value), (1, 'ne', incremented)):
                vm = self.machine(['cmp w1, #0', f'cinc {prefix}0, {prefix}0, {condition}',
                                   'cset w2, eq', 'ret'])
                vm.run('_extension', (value, comparison))
                self.assertEqual(integer(vm.state, 'x0'), expected & (0xffffffff if prefix == 'w' else 0xffffffffffffffff))
                self.assertEqual(integer(vm.state, 'w2'), int(comparison == 0))

    def test_cinc_unknown_condition_and_unreviewed_forms_refuse(self):
        for line in ('cinc x0, x0, eq', 'cinc x0, w0, ne', 'cinc x0, x0, al',
                     'cinc x0, x0, gt', 'cinc x0, x0, ne, lsl #1'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                self.machine([line, 'ret']).run('_extension', (7,))


class LauncherWorkerTerminalTests(unittest.TestCase):
    def test_only_named_tail_terminal_with_restored_stack_is_admitted(self):
        names = {'_thread_terminate_self': {0x9000}}
        for instructions, expected in ((['b 0x9000'], True), (['b 0x9004'], False),
                                        (['sub sp, sp, #16', 'b 0x9000'], False)):
            code = decoded(instructions, '_terminal')
            completed = []
            action = lambda: r.launcher_paths(code, Image(), names, e, e._initial('_terminal'),
                lambda *args: None, lambda state, history: completed.append(history))
            if expected:
                self.assertEqual(action()['return_paths'], 1)
                self.assertEqual(completed, [(0x9000,)])
            else:
                with self.assertRaises(ValueError): action()

    def test_all_pending_paths_are_checked_after_a_terminal(self):
        code = decoded(['cbz w0, @bad', 'b 0x9000', 'bad:', 'b 0x9004'], '_terminal')
        with self.assertRaises(ValueError):
            r.launcher_paths(code, Image(), {'_thread_terminate_self': {0x9000}}, e,
                e._initial('_terminal'), lambda *args: None, lambda *args: None)


class LauncherServiceTests(unittest.TestCase):
    def model(self):
        model = object.__new__(r.LauncherModel)
        model.e = e
        model.vm = r.LauncherMachine({}, Image(), {'_memmove': {0x9000}}, e)
        model.m, model.calls = model.vm.memory, []
        model.m.map(0x8000, 16)
        model.m.write(0x8000, b'0123456789abcdef')
        return model

    def copy(self, model, destination, source, count):
        before, after = model.vm.State(model.m), model.vm.State(model.m)
        for index, value in enumerate((destination, source, count)):
            before.put('x' + str(index), e._Value(64, value))
        self.assertTrue(model.external(0x9000, after, before=before))
        self.assertEqual(integer(after, 'x0'), destination)

    def test_memmove_preserves_forward_backward_and_identical_overlap(self):
        for destination, source, expected in ((0x8004, 0x8000, b'012301234567cdef'),
                                               (0x8000, 0x8004, b'456789ab89abcdef'),
                                               (0x8000, 0x8000, b'0123456789abcdef')):
            model = self.model()
            self.copy(model, destination, source, 8)
            self.assertEqual(model.m.bytes(0x8000, 16), expected)
            self.assertEqual(model.calls, ['_memmove'])

    def test_memmove_refuses_unowned_unknown_and_readonly_extents(self):
        for destination, source, count in ((0x800c, 0x8000, 8), (0x8000, 0x800c, 8),
                                            (0x8000, 0x8000, 131073)):
            model = self.model()
            with self.assertRaises(ValueError):
                self.copy(model, destination, source, count)
            self.assertEqual(model.m.bytes(0x8000, 16), b'0123456789abcdef')
        model = self.model()
        model.m.readonly.append((0x8000, 0x8010))
        with self.assertRaises(ValueError):
            self.copy(model, 0x8000, 0x8008, 8)
        model = self.model()
        model.m.map(0x8100, 8, known=False)
        with self.assertRaises(ValueError):
            self.copy(model, 0x8000, 0x8100, 8)
        self.assertFalse(model.external(0x9999, None, probe=True))


if __name__ == '__main__':
    unittest.main()
