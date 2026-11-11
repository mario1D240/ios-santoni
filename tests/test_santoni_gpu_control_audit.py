"""Control-certificate isolation and decoded negatives; no hardware proof."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import check_santoni_gpu_kernel as e
import santoni_gpu_control_audit as control
import santoni_gpu_boot as boot
from tests import test_santoni_gpu_boot_gates as fixture
from tests.test_santoni_gpu_pixel_audit import decoded

ROOT = Path(__file__).resolve().parents[1]


class ControlGateTests(unittest.TestCase):
    def setUp(self):
        fixture.BootGates.setUp(self)
        self.path = self.ci / 'gpu-binary-audit.json'
        original = json.loads(self.path.read_text())
        self.report = {**original, 'audit_scope': 'mode1-control', 'permitted_modes': [1],
            boot.CONTROL_BINARY_GATE: True, 'persistent_session_present': True,
            boot.SESSION_BINARY_GATE: False}
        self.path.write_text(json.dumps(self.report))

    def test_control_certificate_authorizes_only_explicit_mode1(self):
        boot.require_binary_audit(self.path, fixture.SHA, fixture.RUN, fixture.KERNEL_SHA, mode=1)
        for mode in (None, 0, 2, 3, True, '1'):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                boot.require_binary_audit(self.path, fixture.SHA, fixture.RUN, fixture.KERNEL_SHA, mode=mode)
        for role in ('zap_preflight', 'zap_scm_probe', 'zap_cache_preflight',
                     'stock_unsecure', 'stock_pixels', 'g3', 'session'):
            with self.subTest(role=role), self.assertRaises(ValueError):
                boot.require_binary_audit(self.path, fixture.SHA, fixture.RUN, fixture.KERNEL_SHA,
                                         mode=1, **{role: True})

    def test_scope_and_exact_artifact_identity_cannot_be_removed(self):
        for key, value in ((boot.CONTROL_BINARY_GATE, False), (boot.CONTROL_BINARY_GATE, 1),
                           ('audit_scope', 'unknown'), ('audit_scope', 'full'),
                           ('permitted_modes', [1, 3]), ('permitted_modes', [True])):
            self.path.write_text(json.dumps({**self.report, key: value}))
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                boot.require_binary_audit(self.path, fixture.SHA, fixture.RUN, fixture.KERNEL_SHA, mode=1)
        self.path.write_text(json.dumps(self.report))
        for sha, run, kernel in (('b' * 40, fixture.RUN, fixture.KERNEL_SHA),
                                (fixture.SHA, fixture.RUN + 1, fixture.KERNEL_SHA),
                                (fixture.SHA, fixture.RUN, 'b' * 64)):
            with self.assertRaises(ValueError):
                boot.require_binary_audit(self.path, sha, run, kernel, mode=1)

    def test_cmn_addition_flags_cover_wrap_and_signed_overflow(self):
        for bits in (32, 64):
            sign, mask = 1 << (bits - 1), (1 << bits) - 1
            for a, b in ((0, 3), (mask - 3, 3), (mask - 2, 3), (mask, 1), (sign - 1, 1), (sign, sign)):
                total = a + b; value = total & mask
                state = e._State(flags=('cmn', e._Value(bits, a), e._Value(bits, b)))
                expected = {'eq': value == 0, 'hs': total > mask, 'lo': total <= mask,
                            'mi': bool(value & sign), 'vs': bool(~(a ^ b) & (a ^ value) & sign)}
                for condition, answer in expected.items():
                    self.assertIs(state.truth(state.condition(condition)), answer)

    def test_path_explorer_refuses_loops_and_unreviewed_terminals(self):
        class Image:
            def read(self, address, size): return None
        for lines in (['again:', 'b @again'], ['brk #0']):
            code = decoded(lines, '_control_test')
            with self.assertRaises(ValueError):
                control._paths(code, Image(), {}, e, e._initial(code.symbol),
                               lambda *args: None, lambda *args: None)


class ActualControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ci = ROOT / 'out/ci-017713a'
        kernel = ci / 'kernel/kernel.development.santoni'
        if not kernel.is_file():
            raise unittest.SkipTest('exact locally downloaded 017713a kernel required')
        cls.names = e._symbols((ci / 'symbols.txt').read_text())
        cls.image = e._Image(kernel.read_bytes())
        cls.codes = {}
        cls.noreturn = e._stack_failure_terminal(cls.names)[0]
        for name in ('_santoni_gpu_start', '_sgpu_probe', '_sgpu_bootstrap',
                     '_sgpu_kernel_thread', '_sgpu_session_options'):
            cls.codes[name] = e._Code((ci / 'session-inspect' / (name + '.asm')).read_text(),
                                     name, next(iter(cls.names[name])), noreturn=cls.noreturn)

    def changed(self, symbol, pc, op, args=()):
        code = self.codes[symbol]
        lines = [f'{code.entry:x} <{symbol}>:']
        for address, instruction in code.ins.items():
            name, operands = (op, args) if address == pc else instruction
            lines.append(f'{address:x}: d503201f {name} {", ".join(operands)}')
        return e._Code('\n'.join(lines), symbol, code.entry, noreturn=self.noreturn)

    def test_exact_kernel_control_paths_do_not_certify_session(self):
        result = control.audit_control(self.codes, self.image, self.names, e)
        self.assertFalse(result['persistent_session_certified'])
        self.assertEqual(result['bootstrap']['return_paths'], 54)
        self.assertEqual(result['worker']['return_paths'], 24)

    def test_actual_worker_cannot_start_session_or_forward_a_role(self):
        code = self.codes['_sgpu_kernel_thread']
        probe = code.calls_to(self.names['_sgpu_probe'])[0]
        mutant = self.changed(code.symbol, probe, 'bl', (hex(next(iter(self.names['_sgpu_session_start']))),))
        with self.assertRaises(ValueError):
            control.worker_control(mutant, self.image, self.names, e)
        # Actual mode is loaded before probe; changing it cannot borrow the mode1 certificate.
        prior = max(pc for pc in code.ins if pc < probe and code.ins[pc][1][:1] == ('w1',))
        mutant = self.changed(code.symbol, prior, 'mov', ('w1', '#3'))
        with self.assertRaises(ValueError):
            control.worker_control(mutant, self.image, self.names, e)

    def test_actual_bootstrap_cannot_allocate_submit_or_write_registers(self):
        code = self.codes['_sgpu_bootstrap']
        power = code.calls_to(self.names['_sgpu_power'])[0]
        for target in ('_sgpu_session_execute', '_sgpu_g3_test', '_sgpu_smmu_start'):
            mutant = self.changed(code.symbol, power, 'bl', (hex(next(iter(self.names[target]))),))
            with self.subTest(target=target), self.assertRaises(ValueError):
                control.bootstrap_control(mutant, self.image, self.names, e)
        # Replace the fresh GPU read's loaded Ops slot with write32/allocate/release.
        for slot in (32, 64, 72):
            pc = next(pc for pc, (op, args) in code.ins.items() if op == 'ldr' and
                      args[0] == 'x9' and args[1] == '[x8, #0x10]')
            mutant = self.changed(code.symbol, pc, 'ldr', ('x9', f'[x8, #{slot}]'))
            with self.subTest(slot=slot), self.assertRaises(ValueError):
                control.bootstrap_control(mutant, self.image, self.names, e)

    def test_actual_wrapper_storage_and_refusal_mutations(self):
        code = self.codes['_sgpu_probe']
        call = code.calls_to(self.names['_sgpu_bootstrap'])[0]
        for reg in ('x5', 'x6', 'x7'):
            pc = max(pc for pc, (op, args) in code.ins.items() if pc < call and op == 'add' and args[0] == reg)
            mutant = self.changed(code.symbol, pc, 'mov', (reg, 'x4'))
            with self.subTest(reg=reg), self.assertRaises(ValueError):
                control.wrapper_control(mutant, self.image, self.names, e)
        pc = next(pc for pc, (op, args) in code.ins.items() if op == 'ldr' and args == ('w8', '[x22, #0x74]'))
        mutant = self.changed(code.symbol, pc, 'mov', ('w8', '#0'))
        with self.assertRaises(ValueError):
            control.wrapper_control(mutant, self.image, self.names, e)

    def test_actual_launch_mode_binding_and_one_shot_cannot_be_skipped(self):
        code = self.codes['_santoni_gpu_start']
        targets = [pc for pc, (op, args) in code.ins.items() if op == 'str' and args[0] == 'w8']
        self.assertEqual(len(targets), 1)
        mutant = self.changed(code.symbol, targets[0], 'nop')
        with self.assertRaises(ValueError):
            control.launch_control(mutant, self.image, self.names, e)
        pc = next(pc for pc, (op, args) in code.ins.items() if op == 'cbnz' and args[0] == 'w10')
        mutant = self.changed(code.symbol, pc, 'nop')
        with self.assertRaises(ValueError):
            control.launch_control(mutant, self.image, self.names, e)


if __name__ == '__main__':
    unittest.main()
