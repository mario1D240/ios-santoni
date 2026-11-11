"""New contracts for the root-only interpreter and compiled hook guard."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import check_santoni_remoted_platform_kernel as root
from santoni_gpu_binary_model import Memory


class EmptyImage:
    segs = ()
    def read(self, address, size):
        return None


class Graph:
    """Small logical CFG fixture; never an actual kernel certificate."""
    def __init__(self, instructions):
        self.ins, self.entry = instructions, 0
        self.succ, self.pred = {}, {pc: set() for pc in instructions}
        for pc, (op, args) in instructions.items():
            successors = []
            if op in ('cbz', 'cbnz', 'b'):
                successors.append(int(args[-1], 0))
            if op not in ('ret', 'b') and pc + 4 in instructions:
                successors.append(pc + 4)
            self.succ[pc] = tuple(dict.fromkeys(successors))
            for p in self.succ[pc]: self.pred[p].add(pc)
    def walk(self, start, exclude=()):
        result, queue = set(), [start]
        while queue:
            pc = queue.pop()
            if pc in result or pc in exclude: continue
            result.add(pc); queue.extend(self.succ[pc])
        return result
    def calls_to(self, addresses):
        return sorted(pc for pc, (op, args) in self.ins.items()
                      if op == 'bl' and int(args[0], 0) in addresses)


class RootBinaryContracts(unittest.TestCase):
    def machine(self):
        vm = object.__new__(root.RootMachine)
        vm.e = root.e
        vm.memory = Memory(EmptyImage())
        vm.memory.map(0x1000, 8)
        vm.log_addr, vm.reservation = 0x1000, None
        vm.exclusive_failures, vm.exclusive_attempts = 0, 0
        vm.by_pc = {}
        state = root.e._State({'x1': root.e._Value(64, 0x1000),
                               'x2': root.e._Value(64, 1), 'x3': root.e._Value(64, 7)})
        return vm, state

    def step(self, vm, state, op, args):
        class Code: pass
        code = Code(); code.ins = {0: (op, args)}
        vm.by_pc[0] = code
        return vm.root_step(0, state)

    def normal_graph(self):
        return Graph({0: ('bl', ('0x100',)), 4: ('cbz', ('w0', '0xc')),
                      8: ('ret', ()), 12: ('mov', ('x0', 'x19')),
                      16: ('bl', ('0x200',)), 20: ('ret', ())})

    def test_owned_four_byte_exchange(self):
        vm, state = self.machine()
        self.step(vm, state, 'ldxr', ('w4', '[x1]'))
        self.assertEqual(root.integer(state, 'w4'), 0)
        self.step(vm, state, 'stxr', ('w5', 'w2', '[x1]'))
        self.assertEqual((root.integer(state, 'w5'), vm.memory.get(0x1000, 4)), (0, 1))

    def test_failed_exclusive_does_not_write(self):
        vm, state = self.machine(); vm.exclusive_failures = 1
        self.step(vm, state, 'ldxr', ('w4', '[x1]'))
        self.step(vm, state, 'stxr', ('w5', 'w2', '[x1]'))
        self.assertEqual((root.integer(state, 'w5'), vm.memory.get(0x1000, 4)), (1, 0))

    def test_exclusive_requires_reservation(self):
        vm, state = self.machine()
        with self.assertRaises(ValueError): self.step(vm, state, 'stxr', ('w5', 'w2', '[x1]'))

    def test_exclusive_refuses_wrong_address_width_and_alignment(self):
        for address in (0x1001, 0x1004, 0x2000):
            vm, state = self.machine(); state.put('x1', root.e._Value(64, address))
            with self.assertRaises(ValueError): self.step(vm, state, 'ldxr', ('w4', '[x1]'))
        vm, state = self.machine()
        with self.assertRaises(ValueError): self.step(vm, state, 'ldxr', ('x4', '[x1]'))

    def test_scalar_csinc_ne_is_exact(self):
        for left, right, expected in ((1, 0, 7), (0, 0, 1)):
            vm, state = self.machine()
            state.flags = ('cmp', root.e._Value(32, left), root.e._Value(32, right))
            self.step(vm, state, 'csinc', ('w4', 'w3', 'wzr', 'ne'))
            self.assertEqual(root.integer(state, 'w4'), expected)

    def test_scalar_csinc_rejects_other_forms(self):
        for args in (('x4', 'x3', 'xzr', 'ne'), ('w4', 'w3', 'w2', 'ne'), ('w4', 'w3', 'wzr', 'eq')):
            vm, state = self.machine()
            with self.assertRaises(ValueError): self.step(vm, state, 'csinc', args)

    def test_zero_edge_guard_passes(self):
        result = root.success_callsite(self.normal_graph(), 0x200, 0x100)
        self.assertTrue(result[0]['zero_edge_dominates_hook'])

    def test_guard_rejects_reversed_condition(self):
        g = self.normal_graph(); instructions = dict(g.ins)
        instructions[4] = ('cbnz', ('w0', '0xc'))
        with self.assertRaises(ValueError): root.success_callsite(Graph(instructions), 0x200, 0x100)

    def test_guard_rejects_other_register(self):
        g = self.normal_graph(); instructions = dict(g.ins)
        instructions[4] = ('cbz', ('w1', '0xc'))
        with self.assertRaises(ValueError): root.success_callsite(Graph(instructions), 0x200, 0x100)

    def test_guard_rejects_unconditional_entry(self):
        g = self.normal_graph(); instructions = dict(g.ins)
        instructions[4] = ('b', ('0xc',))
        with self.assertRaises(ValueError): root.success_callsite(Graph(instructions), 0x200, 0x100)

    def test_guard_rejects_intervening_return_clobber(self):
        g = Graph({0: ('bl', ('0x100',)), 4: ('mov', ('w0', 'wzr')),
                   8: ('cbz', ('w0', '0x10')), 12: ('ret', ()),
                   16: ('mov', ('x0', 'x19')), 20: ('bl', ('0x200',)), 24: ('ret', ())})
        with self.assertRaises(ValueError): root.success_callsite(g, 0x200, 0x100)

    def test_guard_rejects_bypass(self):
        g = Graph({0: ('cbz', ('w3', '0x10')), 4: ('bl', ('0x100',)),
                   8: ('cbz', ('w0', '0x10')), 12: ('ret', ()),
                   16: ('mov', ('x0', 'x19')), 20: ('bl', ('0x200',)), 24: ('ret', ())})
        with self.assertRaises(ValueError): root.success_callsite(g, 0x200, 0x100)

    def test_guard_rejects_wrong_signature_callee(self):
        with self.assertRaises(ValueError): root.success_callsite(self.normal_graph(), 0x200, 0x300)


if __name__ == '__main__':
    unittest.main()
