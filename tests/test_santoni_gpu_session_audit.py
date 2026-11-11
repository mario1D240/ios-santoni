"""Synthetic decoded session negatives; no CI/kernel/hardware certificate."""
import sys
import struct
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import check_santoni_gpu_kernel as e
import santoni_gpu_session_audit as session
from tests import test_santoni_gpu_pixel_audit as pixel_fixture
from tests import test_santoni_gpu_kernel_audit as kernel_fixture
decoded = pixel_fixture.decoded


class Image:
    segs = [{'vmaddr': 0x8000, 'vmsize': 0x1000, 'initprot': 3}]

    def read(self, address, size):
        literal = b'santonigpu_session\0'
        return int.from_bytes(literal, 'little') if (address, size) == (0x3000, len(literal)) else None


class SessionAuditTests(unittest.TestCase):
    def options(self):
        lines = [x.replace('#96', '#104') for x in pixel_fixture.PixelAuditTests().options()]
        pos = lines.index('cmp w8, #1')
        return lines[:pos] + [
            'ldr w9, [x20, #96]', 'cmp w9, #1', 'b.ne @bad',
            'ldr w9, [x20, #100]', 'cmp w9, #1', 'b.ne @bad'] + lines[pos:]

    def check_options(self, lines):
        return session.session_options(decoded(lines, '_sgpu_session_options'), Image(),
            {'_PE_parse_boot_argn': {0x4000}}, e, e._Value(64, 0x2000))

    def test_exact_options_missing_parser_value_and_full_prerequisites(self):
        self.assertEqual(self.check_options(self.options()), 1920)

    def test_option_mutations_fail_closed(self):
        changes = [('cmp w19, #3', 'cmp w19, #2'),
            ('cmp w8, #1', 'cmp w8, #2'), ('str wzr, [x20, #104]', 'nop'),
            ('str w8, [x20, #104]', 'nop'), ('str wzr, [sp]', 'nop'),
            ('mov w2, #4', 'mov w2, #8'), ('mov x0, #0x3000', 'mov x0, #0x3004'),
            ('bl 0x4000', 'nop'), ('mov w0, #1', 'mov w0, #0')]
        changes += [(f'ldr w9, [x20, #{off}]', 'mov w9, #1') for off in (88, 96, 100)]
        for old, new in changes:
            with self.subTest(change=old), self.assertRaises(ValueError):
                self.check_options([new if x == old else x for x in self.options()])
        with self.assertRaises(ValueError):
            self.check_options(self.options()[:-1] + ['bl 0x5000', 'ret'])

    def sync_fixture(self, producer=False):
        symbols = ('_lck_mtx_lock', '_lck_mtx_unlock', '_assert_wait', '_thread_block',
            '_thread_wakeup_prim', '_sgpu_session_queue_init', '_sgpu_session_take',
            '_sgpu_session_commit', '_sgpu_session_finish', '_sgpu_session_fault_pending',
            '_sgpu_session_enqueue', '_sgpu_session_close', '_sgpu_session_prepare',
            '_sgpu_session_execute', '_sgpu_session_stop', '_printf')
        names = {name: {0x4000 + 0x100 * i} for i, name in enumerate(symbols)}
        names.update({'_sgpu_session_lock': {0x2000}, '_session_queue': {0x2200},
                      '_session_queue_event': {0x2400}, '_sg': {0x2600}})

        def call(name, arg=None):
            return ([] if arg is None else [f'mov x0, #{arg}']) + [f'bl {next(iter(names[name])):#x}']

        lock = call('_lck_mtx_lock', 0x2000)
        unlock = call('_lck_mtx_unlock', 0x2000)
        if producer:
            lines = lock + call('_sgpu_session_enqueue', 0x2200) + call('_sgpu_session_close', 0x2200)
            lines += unlock + ['mov x0, #9216', 'mov w1, #0', 'mov w2, #0']
            lines += call('_thread_wakeup_prim') + ['ret']
            root = '_sgpu_session_producer'
        else:
            lines = lock + call('_sgpu_session_queue_init', 0x2200) + unlock
            lines += lock + call('_sgpu_session_take', 0x2200) + ['cbnz w0, @have']
            lines += ['mov x0, #9216', 'mov w1, #0'] + call('_assert_wait')
            lines += ['mov w19, w0'] + unlock + ['cmp w19, #-1', 'b.ne @done', 'mov x0, #0']
            lines += call('_thread_block') + ['b @done', 'have:'] + unlock
            lines += call('_sgpu_session_prepare') + lock + call('_sgpu_session_commit', 0x2200)
            lines += unlock + call('_sgpu_session_execute') + lock
            lines += call('_sgpu_session_finish', 0x2200) + call('_sgpu_session_fault_pending', 0x2200)
            lines += unlock + ['done:'] + call('_sgpu_session_stop') + ['ret']
            root = '_sgpu_session_loop'
        return lines, root, names

    def check_sync(self, lines, root, names):
        return session.session_lock_wiring(decoded(lines, root), Image(), names, e)

    def test_worker_and_producer_lock_and_wait_abi(self):
        for producer in (False, True):
            result = self.check_sync(*self.sync_fixture(producer))
            self.assertTrue(result['queue_event_distinct'])
            self.assertFalse(result['hardware_or_scheduler_verified'])

    def test_lock_scope_and_wait_mutations(self):
        for producer in (False, True):
            lines, root, names = self.sync_fixture(producer)
            lock_call = f'bl {next(iter(names["_lck_mtx_lock"])):#x}'
            unlock_call = f'bl {next(iter(names["_lck_mtx_unlock"])):#x}'
            changes = [(lock_call, 'nop'), (unlock_call, 'nop'),
                ('mov x0, #8192', 'mov x0, #8200'),
                ('mov x0, #8704', 'mov x0, #8712'),
                ('mov x0, #9216', 'mov x0, #9820'), # sg.wait_channel
                ('mov w1, #0', 'mov w1, #1')]
            if producer:
                changes += [('mov w2, #0', 'mov w2, #1')]
            else:
                changes += [('mov x0, #0', 'mov x0, #1'),
                            ('cmp w19, #-1', 'cmp w19, #0'),
                            ('cmp w19, #-1', 'cmp w19, #1'), ('b.ne @done', 'nop')]
            for old, new in changes:
                with self.subTest(root=root, change=old), self.assertRaises(ValueError):
                    self.check_sync([new if x == old else x for x in lines], root, names)
            with self.assertRaises(ValueError):
                self.check_sync(lines[:-1] + ['bl 0xff00', 'ret'], root, names)

    def test_worker_hardware_callback_inside_lock_rejected(self):
        lines, root, names = self.sync_fixture()
        call = f'bl {next(iter(names["_sgpu_session_execute"])):#x}'
        lines.remove(call)
        lines.insert(2, call)
        with self.assertRaises(ValueError):
            self.check_sync(lines, root, names)

    def test_ambiguous_mutex_and_aliased_wait_events_rejected(self):
        lines, root, names = self.sync_fixture()
        for key, value in (('_sgpu_session_lock', {0x2000, 0x2010}),
                           ('_session_queue_event', {0x2600 + 92})):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check_sync(lines, root, {**names, key: value})

    def ops_fixture(self):
        fixture = kernel_fixture.AuditFixture()
        fixture.addresses['_sgpu_session_start'] = 0x1a0000
        lines = fixture.code['_sgpu_kernel_thread']
        pos = lines.index('add x0, sp, #0x10')
        lines[pos:pos + 2] = ['cbz w19, @old', 'add x0, sp, #0x10',
            'bl @_sgpu_session_start', 'b @done', 'old:', 'add x0, sp, #0x10',
            'bl @_sgpu_probe', 'done:']
        return fixture

    def check_ops(self, fixture):
        symbol = '_sgpu_kernel_thread'
        code = e._Code(fixture.assembly(symbol), symbol, fixture.addresses[symbol])
        names = {name: {addr} for name, addr in fixture.addresses.items()}
        return e._ops_wiring(code, e._Image(fixture.kernel.read_bytes()), names, names)

    def test_both_worker_entries_require_the_actual_callback_table(self):
        callbacks, evidence = self.check_ops(self.ops_fixture())
        self.assertEqual(len(callbacks), 12)
        self.assertEqual(len(evidence['probe_calls']), 1)
        self.assertEqual(len(evidence['session_start_calls']), 1)

    def test_session_callback_pointer_or_missing_entry_cannot_reuse_old_proof(self):
        for change in ('offset', 'context', 'missing'):
            fixture = self.ops_fixture()
            lines = fixture.code['_sgpu_kernel_thread']
            pos = lines.index('bl @_sgpu_session_start')
            if change == 'offset':
                lines[pos - 1] = 'add x0, sp, #0x18'
            elif change == 'context':
                lines[pos:pos] = ['mov x8, #1', 'str x8, [sp, #0x10]']
            else:
                lines[pos] = 'nop'
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check_ops(fixture)

    def start_fixture(self):
        lines = ['cbz x0, @bad', 'cbz x4, @bad', 'cmp w1, #3', 'b.ne @bad']
        for offset in (116, 112, 108, 104):
            lines += [f'ldr w8, [x0, #{offset}]', 'cmp w8, #1', 'b.ne @bad']
        lines += ['mov x19, #0x8000', 'ldrb w8, [x19]', 'cbnz w8, @bad',
                  'mov w8, #1', 'strb w8, [x19]', 'mov x9, x0']
        for offset in range(0, 112, 16):
            lines += [f'ldr q0, [x9, #{offset}]', f'str q0, [x19, #{8 + offset}]']
        lines += ['ldr x8, [x9, #112]', 'str x8, [x19, #120]',
                  'add x0, x19, #8', 'add x4, x19, #1776', 'add x5, x19, #128',
                  'add x6, x19, #872', 'add x7, x19, #2236', 'bl 0x4000', 'ret',
                  'bad:', 'mov w0, #0', 'ret']
        return lines

    def check_start(self, lines, image=None):
        return session.session_start_storage(decoded(lines, '_sgpu_session_start'), image or Image(),
            {'_sgpu_bootstrap': {0x4000}, '_session_core': {0x8000}}, e)

    def test_start_opt_ins_once_only_and_final_storage(self):
        result = self.check_start(self.start_fixture())
        self.assertEqual(result['start_cases'], 1544)
        self.assertFalse(result['readiness_checked'])

    def test_start_storage_and_admission_mutants(self):
        changes = [('cbnz w8, @bad', 'nop'), ('strb w8, [x19]', 'nop'),
                   ('cmp w1, #3', 'cmp w1, #2'), ('cbz x0, @bad', 'nop'),
                   ('cbz x4, @bad', 'nop'), ('add x0, x19, #8', 'mov x0, x9'),
                   ('str x8, [x19, #120]', 'nop'), ('ldr q0, [x9, #0]', 'ldr q0, [x9, #16]')]
        changes += [(f'ldr w8, [x0, #{off}]', 'mov w8, #1') for off in (104, 108, 112, 116)]
        changes += [(f'add x{reg}, x19, #{off}', f'add x{reg}, sp, #0')
                    for reg, off in ((4, 1776), (5, 128), (6, 872), (7, 2236))]
        for old, new in changes:
            with self.subTest(change=old), self.assertRaises(ValueError):
                self.check_start([new if x == old else x for x in self.start_fixture()])

    def test_final_storage_must_fit_one_writable_nonexecuting_segment(self):
        for segment in ({'vmaddr': 0x8000, 'vmsize': 1024, 'initprot': 3},
                        {'vmaddr': 0x8000, 'vmsize': 4096, 'initprot': 5},
                        {'vmaddr': 0x8000, 'vmsize': 4096, 'initprot': 7}):
            image = Image()
            image.segs = [segment]
            with self.assertRaises(ValueError):
                self.check_start(self.start_fixture(), image)
        image.segs = [Image.segs[0], Image.segs[0]]
        with self.assertRaises(ValueError):
            self.check_start(self.start_fixture(), image)

    def test_segment_protections_are_read_from_load_commands(self):
        fixture = kernel_fixture.AuditFixture()
        for protection in (1, 3, 5, 7):
            data = bytearray(fixture.kernel.read_bytes())
            struct.pack_into('<I', data, 32 + 72 + 60, protection)
            image = e._Image(data)
            self.assertEqual(image.segs[1]['initprot'], protection)


if __name__ == '__main__':
    unittest.main()
