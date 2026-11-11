"""Exact downloaded instruction replays and decoded unsafe mutations.

The mutations change decoded instructions, not a rebuilt kernel. Generic
interpreter tests run without artifacts; these tests need the exact CI kernel.
"""
import hashlib
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import check_santoni_gpu_kernel as e
import santoni_gpu_session_replay as replay
import santoni_gpu_session_audit as audit


def load_actual():
    ci = Path(__file__).resolve().parents[1] / 'out/ci-017713a'
    kernel = ci / 'kernel/kernel.development.santoni'
    if not kernel.is_file(): raise unittest.SkipTest('exact downloaded 017713a kernel required')
    data = kernel.read_bytes()
    if hashlib.sha256(data).hexdigest() != 'ebdbaedbfde2b7160e8716bb23c932b05ff68fd5bbf18de8c971a9e3986b8124':
        raise ValueError('017713a replay fixture kernel hash differs')
    names = e._symbols(subprocess.check_output(['llvm-nm', '--defined-only', str(kernel)], text=True))
    codes = {}
    selected = (*replay.CORE_NAMES, *replay.QUEUE_NAMES, '_sgpu_session_producer',
                '_sgpu_session_loop', '_sgpu_kernel_thread', '_sgpu_bootstrap',
                '_sgpu_g3_prepare', '_sgpu_g3_init', '_sgpu_g3_new', '_sgpu_g3_free', '_now_us')
    for name in dict.fromkeys(selected):
        if name not in names: continue  # optional compiler-inlined helpers
        assembly = subprocess.check_output(['llvm-objdump', '--disassemble', '--disassemble-zeroes',
                            '--disassemble-symbols=' + name, str(kernel)], text=True)
        codes[name] = e._Code(assembly, name, next(iter(names[name])),
                              noreturn=e._stack_failure_terminal(names)[0])
    return codes, e._Image(data), names


def changed(codes, name, pc, op, args=()):
    code = codes[name]
    lines = [f'{code.entry:x} <{name}>:']
    for address, ins in code.ins.items():
        mnemonic, operands = (op, args) if address == pc else ins
        lines.append(f'{address:x}: d503201f {mnemonic} {", ".join(operands)}')
    return {**codes, name: e._Code('\n'.join(lines), name, code.entry,
            noreturn={e._number(code.ins[p][1][-1]) for p in code.noreturn})}


class ActualReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.codes, cls.image, cls.names = load_actual()

    def test_linked_producer_deadlines_two_waves_and_cancellation(self):
        result = replay.audit_producer(self.codes, self.image, self.names, e)
        self.assertEqual(len(result['cases']), 8)

    def test_linked_worker_internal_rejections_and_wake_races(self):
        result = replay.audit_worker(self.codes, self.image, self.names, e,
            scenarios=('commit-rejected', 'finish-rejected', 'spurious', 'already-awake', 'wake-before-block'))
        self.assertEqual(result['cases'], 5)

    def test_linked_bootstrap_cold_storage_and_clock(self):
        self.assertEqual(audit.session_bootstrap_storage(self.codes, self.image, self.names, e)['held_suffix_cases'], 2)
        self.assertEqual(replay.audit_cold_arena(self.codes, self.image, self.names, e)['guarded_BOs'], 3)
        self.assertEqual(replay.audit_clock(self.codes, self.image, self.names, e)['conversion_cases'], 14)

    def request(self, codes):
        model = replay.SessionModel(codes, self.image, self.names, e)
        if model.start() != 1 or model.call('_sgpu_session_prepare') != 1 or model.execute() != 1:
            raise ValueError('linked normal request rejected')
        return model

    def test_decoded_publication_reference_and_cache_omissions_reject(self):
        original = self.request(self.codes)
        name = '_sgpu_session_execute'; code = self.codes[name]
        write = code.calls_to(self.names['_checked_write32'])[0]
        mutations = [(name, write - 4, 'nop', (), 'attempted/reference'),
                     (name, write, 'mov', ('w0', '#1'), 'normal request rejected')]
        begin = self.codes['_sgpu_g3_begin']
        reference = next(pc for pc, (op, args) in begin.ins.items()
                         if op == 'str' and args == ('w10', '[x23, #0x18]'))
        mutations.append((begin.symbol, reference, 'nop', (), 'attempted/reference'))
        clean = next(pc for callback, pc, _ in original.callbacks if callback == '_clean')
        invalidate = next(pc for callback, pc, args in original.callbacks
                          if callback == '_sgpu_cache_invalidate' and args == (original.DATA, 4096))
        mutations += [(name, clean, 'nop', (), 'cache cleans'),
                      (name, invalidate, 'nop', (), 'cache invalidation')]
        for symbol, pc, op, args, reason in mutations:
            with self.subTest(symbol=symbol, pc=hex(pc)), self.assertRaisesRegex(ValueError, reason):
                self.request(changed(self.codes, symbol, pc, op, args))

    def test_decoded_bootstrap_pointer_wptr_and_startup_guard_reject(self):
        name = '_sgpu_bootstrap'; code = self.codes[name]
        call = code.calls_to(self.names['_sgpu_g3_test'])[0]
        pointer = max(pc for pc, (_, args) in code.ins.items() if pc < call and args[:1] == ('x1',))
        with self.assertRaisesRegex(ValueError, 'pointer'):
            audit.session_bootstrap_storage(changed(self.codes, name, pointer, 'mov', ('x1', 'x0')),
                                            self.image, self.names, e)
        store = next(pc for pc, (op, args) in code.ins.items() if op == 'str' and args == ('w8', '[x23]'))
        with self.assertRaisesRegex(ValueError, 'WPTR'):
            audit.session_bootstrap_storage(changed(self.codes, name, store, 'nop'), self.image, self.names, e)
        name = '_sgpu_session_start'; code = self.codes[name]
        pc = next(pc for pc, (op, args) in code.ins.items() if op == 'b.ne' and
                  code.ins.get(pc - 4) == ('cmp', ('w9', '#0x1')))
        with self.assertRaisesRegex(ValueError, 'invalid startup snapshot'):
            replay.audit_core(changed(self.codes, name, pc, 'nop'), self.image, self.names, e)

    def test_decoded_clock_scaling_and_deadline_bypass_reject(self):
        name = '_now_us'; code = self.codes[name]
        pc = next(pc for pc, (op, args) in code.ins.items() if op == 'lsr' and args[0] == 'x0')
        with self.assertRaisesRegex(ValueError, 'ns-to-us'):
            replay.audit_clock(changed(self.codes, name, pc, 'mov', ('x0', 'x8')), self.image, self.names, e)
        name = '_session_time'; code = self.codes[name]
        pc = next(pc for pc, (op, args) in code.ins.items() if op == 'b.hs')
        for mutated in (False, True):
            model = replay.SessionModel(changed(self.codes, name, pc, 'nop') if mutated else self.codes,
                                        self.image, self.names, e)
            self.assertEqual(model.start(), 1)
            model.clock = model.m.get(model.core + replay.OFF['start_us'], 8) + 2000000
            result = model.call('_session_time', 2, model.OUTPUT)
            self.assertEqual(result, int(mutated))

    def test_decoded_stop_and_cancel_omissions_are_rejected(self):
        name = '_sgpu_session_stop'
        codes = changed(self.codes, name, self.codes[name].entry, 'ret')
        with self.assertRaisesRegex(ValueError, 'quarantine'):
            replay.audit_core(codes, self.image, self.names, e)
        name = '_session_cancel_queued'
        codes = changed(self.codes, name, self.codes[name].entry, 'ret')
        with self.assertRaisesRegex(ValueError, 'cancel|counts|outstanding'):
            replay.audit_queue(codes, self.image, self.names, e)

    def test_decoded_producer_payload_and_wave_bypass_are_rejected(self):
        name = '_sgpu_session_producer'; code = self.codes[name]
        pc = next(pc for pc, (op, _) in code.ins.items() if op == 'eor.16b')
        with self.assertRaisesRegex(ValueError, 'WRITE4 values'):
            replay.audit_producer(changed(self.codes, name, pc, 'nop'), self.image, self.names, e, ('normal',))
        pc = next(pc for pc, (op, args) in code.ins.items() if op == 'tbnz' and args[0] == 'w10')
        with self.assertRaisesRegex(ValueError, 'second wave'):
            replay.audit_producer(changed(self.codes, name, pc, 'nop'), self.image, self.names, e, ('normal',))


if __name__ == '__main__': unittest.main()
