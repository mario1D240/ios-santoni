#!/usr/bin/env python3
"""Codex regressions of audit() itself; no kernel build or real artifact writes."""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'tests'))
import check_santoni_gpu_kernel as checker
import santoni_gpu_prepare as prep
from test_santoni_gpu_prepare import mdt32

COMMIT = 'a' * 40
CALLBACKS = ('_io_map', '_sgpu_io_read32', '_sgpu_io_read64',
             '_sgpu_io_write32', '_sgpu_io_write64', '_now_us',
             '_sgpu_kernel_wait_us', '_allocate', '_release', '_clean',
             '_sgpu_cache_invalidate', '_trace')
SYMBOLS = ('_IOKitBSDInit', '_santoni_gpu_start', '_sgpu_kernel_thread',
           '_sgpu_probe', '_sgpu_power', '_sgpu_restore_power',
            '_sgpu_smmu_start', '_sgpu_smmu_restore', '_sgpu_a505_init',
            '_sgpu_a505_resume', '_sgpu_a505_halt', '_sgpu_a505_sp_release',
           '_checked_write32', '_checked_write64', '_branch_state',
           '_sgpu_failure', '_sgpu_failure_summary', '_sgpu_tables_build',
           '_sgpu_firmware_validate', '_sgpu_blit_commands',
           '_kernel_thread_start', '_CleanPoC_DcacheRegion_Force', *CALLBACKS)
LITERALS = (b'santonigpu\0', b'santoni-gpu-firmware\0', b'SANTONI GPU: RESULT',
            b'SANTONI GPU: request', b'SANTONI GPU: worker entered',
            b'SANTONI GPU: worker awake', b'SANTONI GPU: worker queued',
            b'FIRST_FAIL\0', b'ROLLBACK_FAIL\0', b'FAIL offset/mask/want',
            b'FAIL old/written/got', b'FAIL elapsed/budget/saved', b'trust_read=%u',
            b'power_pending=%u', b'quiescent=%u', b'smmu_restored=%u', b'ROLLBACK_MORE',
            b'A505 CP halt site/old/got', b'A505 SP release old/written/got',
            b'partial A50x resume; power held until reboot')


class MemoryPath:
    """Only the filesystem operations used by the auditor/firmware validator."""
    def __init__(self, files, path='/audit'):
        self.files, self.path = files, PurePosixPath(path)

    def __truediv__(self, suffix):
        return MemoryPath(self.files, self.path / suffix)

    def __str__(self):
        return str(self.path)

    @property
    def name(self):
        return self.path.name

    def is_file(self):
        return str(self) in self.files

    def exists(self):
        return self.is_file()

    def read_bytes(self):
        try:
            return self.files[str(self)]
        except KeyError:
            raise FileNotFoundError(str(self)) from None

    def read_text(self):
        return self.read_bytes().decode()

    def write_text(self, text):
        self.files[str(self)] = text.encode()
        return len(text)

    def open(self, mode):
        if mode == 'x':
            if self.exists():
                raise FileExistsError(str(self))
            path = self
            class ExclusiveText(io.StringIO):
                def close(self):
                    if not self.closed:
                        path.write_text(self.getvalue())
                    super().close()
            self.files[str(self)] = b''
            return ExclusiveText()
        if mode != 'rb':
            raise AssertionError('unexpected filesystem operation')
        return io.BytesIO(self.read_bytes())


class AuditFixture:
    """Synthetic Mach-O, private intake and decoded llvm responses, all in memory."""
    def __init__(self):
        self.files = {}
        self.root = MemoryPath(self.files)
        self.folder = self.root / ('out/ci-' + COMMIT[:7])
        self.kernel = self.folder / 'kernel/kernel.development.santoni'
        self.bundle = self.root / 'out/santoni-gpu-msm49-fw-working'
        self.addresses = {name: 0x100000 + 0x1000 * i for i, name in enumerate(SYMBOLS)}
        self.table = 0x200080
        self.code = {name: ['ret'] for name in SYMBOLS}
        self.code['_IOKitBSDInit'] = ['bl @_santoni_gpu_start', 'ret']
        self.code['_santoni_gpu_start'] = [
            'adr x0, @_sgpu_kernel_thread', 'bl @_kernel_thread_start', 'ret']
        # Match the old compiler's vector/scalar constant-table copy, not a
        # filename or a stray list of callback addresses elsewhere in the file.
        self.code['_sgpu_kernel_thread'] = [
            'sub sp, sp, #0x100', 'adrp x8, 0x200000', 'add x8, x8, #0x80',
            'ldp q0, q1, [x8]', 'stp q0, q1, [sp, #0x10]',
            'ldp q2, q3, [x8, #0x20]', 'stp q2, q3, [sp, #0x30]',
            'ldp q4, q5, [x8, #0x40]', 'stp q4, q5, [sp, #0x50]',
            'ldr x9, [x8, #0x60]', 'str x9, [sp, #0x70]',
            'add x0, sp, #0x10', 'bl @_sgpu_probe',
            'bl @_sgpu_failure_summary', 'bl @_sgpu_failure_summary',
            'add sp, sp, #0x100', 'ret']
        self.code['_clean'] = ['mov x0, x1', 'mov w1, w2',
                               'b @_CleanPoC_DcacheRegion_Force']
        self.code['_sgpu_cache_invalidate'] = ['dc ivac, x1', 'ret']
        self.code['_sgpu_kernel_wait_us'] = ['mrs x8, CNTVCT_EL0', 'ret']
        for bits, reg in ((32, 'w'), (64, 'x')):
            self.code[f'_sgpu_io_write{bits}'] = [
                'dmb sy', f'str {reg}3, [x8]', 'dsb sy', 'ret']
            self.code[f'_sgpu_io_read{bits}'] = [f'ldr {reg}0, [x8]', 'dmb sy', 'ret']
        self.code['_sgpu_failure'] = [
            'ldr x8, [x0, #8]', 'ldr w9, [x8, #56]', 'cbnz w9, @done',
            'str w1, [x8, #56]', 'done:', 'ret']
        self.code['_checked_write32'] = self.checked_write(32)
        self.code['_checked_write64'] = self.checked_write(64)
        self.code['_branch_state'] = self.branch_state()
        for name in ('_sgpu_power', '_sgpu_restore_power'):
            self.code[name] = ['bl @_branch_state', 'cbz w0, @fail',
                               'mov w0, #1', 'ret', 'fail:', 'mov w0, #0', 'ret']
        for name in ('_sgpu_smmu_start', '_sgpu_smmu_restore'):
            self.code[name] = self.translation(name.endswith('restore'))
        self.code['_sgpu_a505_resume'] = ['mov x19, x0', 'strb wzr, [x19, #739]',
                                         'mov w8, #1', 'strb w8, [x19, #740]']
        for offset, value in ((0x19c, 0x55), (0x14cc, 0x182)):
            if offset == 0x14cc:
                self.code['_sgpu_a505_resume'] += self.callback(32, [
                    'mov w1, #4', 'mov w2, #412', f'mov w3, #{0xaaa8aa00}'])
            self.code['_sgpu_a505_resume'] += [
                'mov x0, x19', 'mov w1, #4', f'mov w2, #{offset}',
                'mov w3, #-1', f'mov w4, #{value}', 'bl @_checked_write32', 'cbz w0, @fail']
        self.code['_sgpu_a505_resume'] += ['mov x0, x19', 'bl @_sgpu_a505_sp_release', 'cbz w0, @fail']
        self.code['_sgpu_a505_resume'] += ['mov w0, #1', 'strb w0, [x19, #739]', 'ret', 'fail:', 'mov w0, #0', 'ret']
        self.code['_sgpu_a505_halt'] = self.a505_halt()
        self.code['_sgpu_a505_sp_release'] = self.sp_release()
        self.code['_sgpu_probe'] = [
            'mov x19, x0', 'sub sp, sp, #0x400', 'str x0, [sp]', 'mov x19, sp',
            'bl @_sgpu_power', 'cbz w0, @fail',
            'mov x0, x19', 'bl @_sgpu_a505_resume', 'cbz w0, @fail',
            'mov x0, x19', 'mov w1, #1', 'bl @_sgpu_a505_halt', 'cbz w0, @fail',
            *self.callback(32, ['mov w1, #4', 'mov w2, #268', 'mov w3, #0']),
            'mov x0, x19', 'bl @_sgpu_a505_resume', 'cbz w0, @fail',
            'mov x0, x19', 'mov w1, #2', 'bl @_sgpu_a505_halt', 'cbz w0, @fail',
            'add x1, sp, #0x320', 'bl @_sgpu_smmu_start', 'cbz w0, @fail', 'bl @_sgpu_a505_init',
            'mov w1, #4', 'mov w2, #8392', 'mov w3, #3', 'mov w4, #0',
            'bl @_checked_write32', 'cbz w0, @fail', 'mov w1, #3', 'bl @_sgpu_a505_halt',
            'cbz w0, @recovery', 'b @restore', 'recovery:',
            *self.callback(32, ['mov w1, #4', 'mov w2, #268', 'mov w3, #0']),
            'mov x0, x19', 'bl @_sgpu_a505_resume', 'cbz w0, @fail',
            'mov w1, #4', 'bl @_sgpu_a505_halt', 'cbz w0, @fail', 'restore:',
            'bl @_sgpu_smmu_restore', 'cbz w0, @fail',
            'bl @_sgpu_restore_power', 'cbz w0, @fail',
            'mov w0, #1', 'ret', 'fail:', 'mov w0, #0', 'ret']
        (self.folder / 'run.json').write_text(json.dumps({
            'headSha': COMMIT, 'status': 'completed', 'conclusion': 'success',
            'repository_private': True, 'databaseId': 123}))
        entries = []
        for i, name in enumerate(('a530_pm4.fw', 'a530_pfp.fw')):
            raw = struct.pack('<4I', 0, 0x12345674 + i, 0x55667788 + i, 0x99887766 + i)
            info, payload = prep.ucode(raw, name)
            self.files[str(self.bundle / 'firmware' / name)] = raw
            self.files[str(self.bundle / 'firmware' / (name + '.payload'))] = payload
            entries.append(info)
        (self.bundle / 'target.json').write_text(json.dumps({
            'chipid': 0x05000500, 'gmem_bytes': 139264, 'kernel_page_bytes': 4096}))
        (self.bundle / 'firmware-intake.json').write_text(json.dumps({'ucode': entries}))
        # Two bounded file-backed segments suffice for the constant Ops table.
        data = bytearray(0x3000)
        struct.pack_into('<8I', data, 0, 0xfeedfacf, 0x100000c, 0, 2, 2, 144, 0, 0)
        for i, (name, va, off) in enumerate((('__TEXT_EXEC', 0x100000, 0x1000),
                                            ('__DATA_CONST', 0x200000, 0x2000))):
            struct.pack_into('<II16s4Q4I', data, 32 + i * 72, 0x19, 72, name.encode(),
                             va, 0x1000, off, 0x1000, 7, 5, 0, 0)
        struct.pack_into('<13Q', data, 0x2080, 0, *(self.addresses[n] for n in CALLBACKS))
        data.extend(b'\0'.join(LITERALS))
        self.set_kernel(data)

    def add_pas(self):
        helpers = ('_sgpu_zap_allocation_preflight', '_sgpu_zap_prepare', '_sgpu_zap_layout',
                   '_sgpu_pas_allocate', '_sgpu_pas_release', '_PE_parse_boot_argn',
                   '_kmem_alloc_contig_guard', '_kmem_free_guard', '_pmap_find_phys')
        for i, name in enumerate(helpers):
            self.addresses[name] = 0x180000 + 0x1000 * i
            self.code[name] = ['ret']
        self.code['_sgpu_kernel_thread'].insert(1, 'bl @_sgpu_zap_allocation_preflight')
        self.code['_sgpu_zap_allocation_preflight'] = [
            'cmp w0, #3', 'b.ne @done', 'sub sp, sp, #0x40', 'str wzr, [sp]',
            'adrp x0, 0x200000', 'add x0, x0, #0x280', 'mov x1, sp', 'mov w2, #4',
            'bl @_PE_parse_boot_argn', 'ldr w8, [sp]', 'cmp w8, #1', 'b.ne @skip',
            'bl @_sgpu_zap_prepare', 'cbz w0, @skip', 'bl @_sgpu_pas_release',
            'bl @_sgpu_pas_release', 'skip:', 'add sp, sp, #0x40', 'done:', 'ret']
        self.code['_sgpu_zap_prepare'] = [
            'bl @_sgpu_zap_layout', 'cbz w0, @fail', 'bl @_sgpu_pas_allocate',
            'cbz w0, @fail', 'bl @_sgpu_pas_allocate', 'cbz w0, @cleanup',
            'mov w0, #1', 'ret', 'cleanup:', 'bl @_sgpu_pas_release',
            'fail:', 'mov w0, #0', 'ret']
        self.code['_sgpu_zap_layout'] = ['mov w0, #1', 'ret']
        self.code['_sgpu_pas_allocate'] = [
            'lsr w4, w2, #12', 'sub w4, w4, #1', 'mov x2, #4095',
            'mov x3, #1048575', 'mov x5, #32832', 'bl @_kmem_alloc_contig_guard',
            'bl @_pmap_find_phys', 'mov w0, #1', 'ret']
        self.code['_sgpu_pas_release'] = [
            'ldrb w8, [x0, #20]', 'cbnz w8, @done', 'bl @_kmem_free_guard', 'done:', 'ret']
        data = bytearray(self.kernel.read_bytes())
        literal = b'santonigpu_zap\0'
        data[0x2280:0x2280 + len(literal)] = literal
        data.extend(b'\0'.join((b'santoni-gpu-zap-mdt\0', b'santoni-gpu-zap-b02\0',
                              b'zap allocation-only preflight', b'NO PAS/SMC')))
        self.set_kernel(data)
        bundle = self.root / 'out/santoni-gpu-pas-fw-working'
        mdt = mdt32([(0, 0, 0, 0, 0, 0, 0, 0), (0, 0, 0, 0, 0, 0, 0, 0),
                     (1, 0, 0, 0x5000, 16, 16, 0x08000007, 0x100000)], machine=164)
        payload = bytes(range(16))
        # Install synthetic binary fixtures without text encoding.
        self.files[str(bundle / 'firmware/a506_zap.mdt')] = mdt
        self.files[str(bundle / 'firmware/a506_zap.b02')] = payload
        report, _ = prep.zap_segments(bundle / 'firmware', 'a506_zap')
        (bundle / 'target.json').write_text(json.dumps({'chipid': 0x05000500,
            'kernel_page_bytes': 4096, 'vendor_zap_subsystem': 'a506_zap'}))
        (bundle / 'firmware-intake.json').write_text(json.dumps({'zap': report}))

    def add_scm(self):
        self.add_pas()
        for i, name in enumerate((*checker._SCM_HELPERS, '_thread_terminate_self',
                                  '_printf', '_memcpy', '_bzero')):
            self.addresses[name] = 0x190000 + 0x1000 * i
            self.code[name] = ['ret']
        self.code['_sgpu_kernel_thread'][1:1] = [
            'mov w0, #3', 'bl @_sgpu_scm_capability_probe', 'cbz w0, @scm_skip',
            'bl @_thread_terminate_self', 'ret', 'scm_skip:']
        frame = ['mov x19, x2', 'mov w20, w1', 'cbnz w20, @wide']
        for i in range(7):
            frame += [f'ldr w8, [x19, #{i * 8}]', f'str x8, [x19, #{i * 8}]']
        frame += ['wide:', *(f'ldr x{i}, [x19, #{i * 8}]' for i in range(7)),
                  'mov x7, #0', 'dmb sy', 'smc #0', 'dsb sy']
        for i in range(0, 8, 2):
            frame += [f'stp x{i}, x{i + 1}, [x19, #{i * 8}]']
        frame += ['cbnz w20, @done']
        for i in range(7):
            frame += [f'ldr w8, [x19, #{i * 8}]', f'str x8, [x19, #{i * 8}]']
        self.code['_sgpu_smc_frame'] = frame + ['done:', 'mov w0, #1', 'ret']
        self.code['_sgpu_scm_capability_probe'] = [
            'cmp w0, #3', 'b.ne @off', 'sub sp, sp, #576', 'mov w19, w0',
            'str wzr, [sp]', 'str wzr, [sp, #4]',
            'adr x0, 0x200280', 'mov x1, sp', 'mov w2, #4', 'bl @_PE_parse_boot_argn',
            'adr x0, 0x200300', 'add x1, sp, #4', 'mov w2, #4', 'bl @_PE_parse_boot_argn',
            'ldr w8, [sp]', 'cmp w8, #1', 'b.ne @skip',
            'ldr w8, [sp, #4]', 'cmp w8, #1', 'b.ne @skip',
            'adr x8, 0x200400', 'ldp q0, q1, [x8]', 'stp q0, q1, [sp, #16]',
            'ldr x9, [x8, #32]', 'str x9, [sp, #48]',
            'add x0, sp, #16', 'mov w1, w19', 'ldr w2, [sp]', 'ldr w3, [sp, #4]',
            'add x4, sp, #64', 'bl @_sgpu_scm_probe', 'bl @_printf',
            'mov w0, #1', 'add sp, sp, #576', 'ret',
            'skip:', 'add sp, sp, #576', 'off:', 'mov w0, #0', 'ret']
        self.code['_sgpu_scm_query'] = [
            'sub sp, sp, #64', 'mov x24, x6', 'mov x25, x7',
            'str x4, [sp]', 'mov x8, #1', 'str x8, [sp, #8]', 'str x5, [sp, #16]',
            'str xzr, [sp, #24]', 'stp xzr, xzr, [sp, #32]', 'stp xzr, xzr, [sp, #48]',
            'mov x4, sp', 'mov x5, x24', 'mov x6, x25',
            'bl @_sgpu_scm_readonly_transport', 'add sp, sp, #64', 'ret']
        self.code['_sgpu_scm_failure'] = [
            'ldr w8, [x0, #4]', 'cbnz w8, @done', 'str w1, [x0, #4]',
            'mov x19, x0', 'mov w20, w3', 'add x0, x0, #400',
            'mov x1, x2', 'mov x2, #96', 'bl @_memcpy',
            'ldr w8, [x19, #400]', 'cbnz w8, @done', 'str w20, [x19, #400]', 'done:', 'ret']
        transport = [
            'sub sp, sp, #64', 'mov x19, x0', 'mov x20, x4', 'mov x21, x5', 'mov x22, x6',
            'mov w23, w1', 'mov w24, w2', 'mov w25, w3',
            'mov x0, x22', 'mov x1, #96', 'bl @_bzero', 'mov w8, #1', 'str w8, [x22]',
            'cmp w23, #3', 'b.ne @reject', 'cmp w24, #1', 'b.ne @reject',
            'cmp w25, #1', 'b.ne @reject', 'ldr x8, [x20]', 'and x8, x8, #0xffffffffbfffffff',
            'cmp x8, #0x82000601', 'b.eq @fast', 'cmp x8, #0x02000601', 'b.eq @info',
            'cmp x8, #0x02000207', 'b.ne @reject',
            'ldr x9, [x20, #16]', 'cmp x9, #13', 'b.ne @reject', 'b @scalar',
            'fast:', 'ldr x9, [x20, #16]', 'cmp x9, #0x82000601', 'b.ne @reject', 'b @scalar',
            'info:', 'ldr x9, [x20, #16]', 'cmp x9, #0x02000207', 'b.ne @reject',
            'scalar:', 'ldr x9, [x20, #8]', 'cmp x9, #1', 'b.ne @reject']
        for i in range(3, 8):
            transport += [f'ldr x9, [x20, #{i * 8}]', 'cbnz x9, @reject']
        transport += [
            'ldr x8, [x20]', 'ubfx w27, w8, #30, #1',
            'ldp q0, q1, [x20]', 'stp q0, q1, [sp]',
            'ldp q0, q1, [x20, #32]', 'stp q0, q1, [sp, #32]', 'loop:',
            'ldr x8, [x19, #16]', 'ldr x0, [x19]', 'blr x8',
            'ldr x8, [x21]', 'sub x9, x0, x8', 'str x9, [x22, #16]',
            'cmp x9, #1000000', 'b.hs @time',
            'ldr w8, [x21, #8]', 'cmp w8, #64', 'b.hs @calls',
            'add w8, w8, #1', 'str w8, [x21, #8]',
            'ldr w8, [x22, #4]', 'add w8, w8, #1', 'str w8, [x22, #4]',
            'ldr x8, [x19, #8]', 'ldr x0, [x19]', 'mov w1, w27', 'mov x2, sp',
            'blr x8', 'cbz w0, @transport',
            'ldp q0, q1, [sp]', 'stp q0, q1, [x22, #24]',
            'ldp q0, q1, [sp, #32]', 'stp q0, q1, [x22, #56]',
            'ldr x8, [x19, #16]', 'ldr x0, [x19]', 'blr x8',
            'ldr x8, [x21]', 'sub x9, x0, x8', 'str x9, [x22, #16]',
            'ldr x28, [sp]', 'sxtw x8, w28', 'cmp x28, x8', 'b.eq @classify',
            'mov w8, w28', 'cmp x28, x8', 'b.ne @transport',
            'classify:', 'cmp w28, #1', 'b.eq @interrupted',
            'cmp w28, #-12', 'b.eq @busy',
            'cmp x9, #1000000', 'b.hs @time', 'cmp w28, #0',
            'cset w0, eq', 'mov w8, #6', 'csel w8, wzr, w8, eq', 'str w8, [x22]',
            'add sp, sp, #64', 'ret',
            'interrupted:', 'ldr w8, [x22, #12]', 'add w8, w8, #1', 'str w8, [x22, #12]', 'b @loop',
            'busy:', 'ldr w8, [x21, #12]', 'cmp w8, #20', 'b.hs @busy_limit',
            'cmp x9, #970000', 'b.hs @time', 'add w8, w8, #1', 'str w8, [x21, #12]',
            'ldr w8, [x22, #8]', 'add w8, w8, #1', 'str w8, [x22, #8]',
            'ldr x8, [x19, #24]', 'ldr x0, [x19]', 'mov w1, #30000', 'blr x8',
            'ldp q0, q1, [x20]', 'stp q0, q1, [sp]',
            'ldp q0, q1, [x20, #32]', 'stp q0, q1, [sp, #32]', 'b @loop']
        for label, error in (('transport', 2), ('calls', 3), ('time', 4), ('busy_limit', 5)):
            transport += [label + ':', f'mov w8, #{error}', 'str w8, [x22]', 'b @reject']
        self.code['_sgpu_scm_readonly_transport'] = transport + [
            'reject:', 'mov w0, #0', 'add sp, sp, #64', 'ret']
        probe = [
            'mov x19, x0', 'mov w20, w1', 'mov w21, w2', 'mov w22, w3', 'mov x23, x4',
            'cmp w20, #3', 'b.ne @fail', 'cmp w21, #1', 'b.ne @fail',
            'cmp w22, #1', 'b.ne @fail', 'sub sp, sp, #16',
            'mov x0, x23', 'mov x1, #496', 'bl @_bzero',
            'mov w8, #1', 'strb w8, [x23, #8]',
            'ldr x8, [x19, #16]', 'ldr x0, [x19]', 'blr x8',
            'str x0, [sp]', 'str wzr, [sp, #8]', 'str wzr, [sp, #12]']

        def query(function, argument, offset, mask=False):
            return ['mov x0, x19', 'mov w1, w20', 'mov w2, w21', 'mov w3, w22',
                    f'mov w4, #{function}', *(['orr w4, w4, w24'] if mask else []),
                    f'mov w5, #{argument}', 'mov x6, sp', f'add x7, x23, #{offset}',
                    'bl @_sgpu_scm_query']

        probe += query(0xc2000601, 0x82000601, 16)
        probe += [
            'cbz w0, @maybe32', 'ldr x8, [x23, #48]', 'cmp x8, #1', 'b.eq @wide',
            'maybe32:', 'ldrb w8, [x23, #105]', 'cbnz w8, @fail64',
            'ldr w8, [x23, #16]', 'cmp w8, #6', 'b.eq @remote',
            'cbz w0, @fail64', 'ldr x8, [x23, #48]', 'cbnz x8, @fail64', 'b @probe32',
            'remote:', 'ldr w8, [x23, #40]', 'cmp w8, #-1', 'b.eq @probe32',
            'cmp w8, #-4', 'b.ne @fail64', 'probe32:']
        probe += query(0x82000601, 0x82000601, 112)
        probe += [
            'cbz w0, @fail32', 'ldr x8, [x23, #144]', 'cmp x8, #1', 'b.ne @fail32',
            'mov w8, #1', 'str w8, [x23]', 'mov w24, #0', 'b @availability',
            'wide:', 'mov w8, #2', 'str w8, [x23]', 'mov w24, #0x40000000', 'availability:']
        probe += query(0x02000601, 0x02000207, 208, mask=True)
        probe += ['cbz w0, @fail_avail', 'ldr x8, [x23, #240]', 'cmp x8, #1', 'b.ne @fail_avail']
        probe += query(0x02000207, 13, 304, mask=True)
        probe += ['cbz w0, @fail_support', 'ldr x8, [x23, #336]', 'cmp x8, #1', 'b.ne @fail_support',
                  'mov w8, #1', 'strb w8, [x23, #9]', 'mov w0, #1', 'add sp, sp, #16', 'ret']
        for label, phase, offset, error in (('fail64', 1, 16, 7), ('fail32', 2, 112, 7),
                                           ('fail_avail', 3, 208, 8), ('fail_support', 4, 304, 8)):
            probe += [label + ':', 'mov x0, x23', f'mov w1, #{phase}', f'add x2, x23, #{offset}',
                      f'mov w3, #{error}', 'bl @_sgpu_scm_failure', 'add sp, sp, #16', 'b @fail']
        self.code['_sgpu_scm_probe'] = probe + ['fail:', 'mov w0, #0', 'ret']
        data = bytearray(self.kernel.read_bytes())
        data[0x2300:0x2300 + 15] = b'santonigpu_scm\0'
        struct.pack_into('<5Q', data, 0x2400, 0, *(self.addresses[n] for n in checker._SCM_CALLBACKS.values()))
        data.extend(b'\0'.join((b'SCM capability-only opt-in; REAL SMC',
                               b'SCM LAST FRAME', b'SCM PROBE RESULT', b'NO PAS LOAD')))
        self.set_kernel(data)

    def compact_scm(self):
        """Model AppleClang's private parameter deletion, not deleted gates."""
        self.add_scm()
        entry = self.code['_sgpu_scm_capability_probe']
        changes = {'mov w1, w19': 'nop', 'ldr w2, [sp]': 'ldr w1, [sp]',
                   'ldr w3, [sp, #4]': 'ldr w2, [sp, #4]',
                   'add x4, sp, #64': 'add x3, sp, #64'}
        self.code['_sgpu_scm_capability_probe'] = [changes.get(line, line) for line in entry]
        probe = self.code['_sgpu_scm_probe']
        gate = probe.index('cmp w20, #3')
        del probe[gate:gate + 2]
        changes = {'mov w20, w1': 'nop', 'mov w21, w2': 'mov w21, w1',
                   'mov w22, w3': 'mov w22, w2', 'mov x23, x4': 'mov x23, x3'}
        probe = [changes.get(line, line) for line in probe
                 if line not in ('mov w1, w20', 'mov w2, w21', 'mov w3, w22')]
        registers = {'w4': 'w1', 'w5': 'w2', 'x6': 'x3', 'x7': 'x4'}
        self.code['_sgpu_scm_probe'] = [re.sub(r'\b(?:w4|w5|x6|x7)\b',
            lambda match: registers[match[0]], line) for line in probe]
        changes = {'mov x24, x6': 'mov x24, x3', 'mov x25, x7': 'mov x25, x4',
                   'str x4, [sp]': 'str x1, [sp]', 'str x5, [sp, #16]': 'str x2, [sp, #16]',
                   'mov x4, sp': 'mov x1, sp', 'mov x5, x24': 'mov x2, x24',
                   'mov x6, x25': 'mov x3, x25'}
        self.code['_sgpu_scm_query'] = [changes.get(line, line) for line in self.code['_sgpu_scm_query']]
        transport = self.code['_sgpu_scm_readonly_transport']
        gate = transport.index('cmp w23, #3')
        del transport[gate:gate + 6]
        changes = {'mov x20, x4': 'mov x20, x1', 'mov x21, x5': 'mov x21, x2',
                   'mov x22, x6': 'mov x22, x3'}
        transport = [changes.get(line, line) for line in transport
                     if line not in ('mov w23, w1', 'mov w24, w2', 'mov w25, w3')]
        transport[1:1] = ['cbz x1, @reject', 'cbz x2, @reject', 'cbz x3, @reject']
        self.code['_sgpu_scm_readonly_transport'] = transport

    def add_stack_failure(self):
        self.addresses['___stack_chk_fail'] = 0x1b0000
        self.addresses['_panic'] = 0x1b1000
        self.code['___stack_chk_fail'] = ['bl @_panic']
        self.code['_panic'] = ['brk #0']
        body = self.code['_sgpu_scm_query']
        body.insert(body.index('add sp, sp, #64'), 'cbnz w10, @stack_failed')
        body += ['stack_failed:', 'bl @___stack_chk_fail']

    @staticmethod
    def callback(slot, extra=()):
        return ['ldr x8, [x19]', f'ldr x9, [x8, #{slot}]',
                'ldr x0, [x8]', *extra, 'blr x9']

    @classmethod
    def checked_write(cls, bits):
        reg, read, write = ('w', 16, 32) if bits == 32 else ('x', 24, 40)
        code = ['mov x19, x0', 'mov w20, w1', 'mov w21, w2',
                f'mov {reg}23, {reg}{4 if bits == 32 else 3}']
        if bits == 32:
            code += ['mov w22, w3']
        args = ['mov w1, w20', 'mov w2, w21']
        code += cls.callback(read, args) + [f'mov {reg}24, {reg}0']
        code += cls.callback(write, [*args, f'mov {reg}3, {reg}23'])
        code += cls.callback(read, args)
        code += (['eor w8, w0, w23', 'tst w8, w22'] if bits == 32 else ['cmp x0, x23'])
        code += ['b.eq @success', 'mov x0, x19', 'mov w1, #2', 'mov w2, w20',
                 'mov w3, w21', 'bl @_sgpu_failure', 'mov w0, #0', 'ret',
                 'success:', 'mov w0, #1', 'ret']
        return code

    @classmethod
    def a505_halt(cls):
        args = ['mov w1, #4', 'mov w2, #8392']
        code = ['mov x19, x0', 'mov w20, w1']
        code += cls.callback(16, args) + ['mov w24, w0', 'orr w23, w0, #3']
        code += cls.callback(32, [*args, 'mov w3, w23'])
        code += cls.callback(16, args) + ['mov w25, w0']
        code += cls.callback(96, ['mov w2, w20', 'mov w3, w24', 'mov w4, w25'])
        code += ['and w8, w25, #3', 'cmp w8, #3', 'b.eq @success',
                 'mov x0, x19', 'mov w1, #2', 'bl @_sgpu_failure', 'mov w0, #0', 'ret',
                 'success:', 'mov w0, #1', 'ret']
        return code

    @classmethod
    def sp_release(cls):
        args = ['mov w1, #4', 'mov w2, #412']
        code = ['mov x19, x0']
        code += cls.callback(16, args) + ['mov w24, w0', 'and w23, w0, #0xffffff00']
        code += cls.callback(32, [*args, 'mov w3, w23'])
        code += cls.callback(16, args) + ['mov w25, w0']
        code += cls.callback(96, ['mov w2, w24', 'mov w3, w23', 'mov w4, w25'])
        code += ['cmp w25, w23', 'b.eq @success', 'mov x0, x19', 'mov w1, #2',
                 'bl @_sgpu_failure', 'mov w0, #0', 'ret', 'success:', 'mov w0, #1', 'ret']
        return code

    @classmethod
    def branch_state(cls):
        code = ['mov x19, x0', 'mov w20, w1']
        code += cls.callback(48) + ['mov x21, x0', 'mov w22, #0', 'loop:']
        code += cls.callback(16, ['mov w1, #0', 'mov w2, w20'])
        code += ['and w23, w0, #0xf0000000', 'cbz w23, @success']
        code += cls.callback(48)
        code += ['sub x8, x0, x21', 'cmp x8, #0x2710', 'b.hs @fail']
        code += cls.callback(56, ['mov w1, #100'])
        code += ['add w22, w22, #1', 'cmp w22, #101', 'b.lo @loop', 'fail:',
                 'mov x0, x19', 'mov w1, #3', 'mov w2, #0', 'mov w3, w20',
                 'mov w4, #0xf0000000', 'bl @_sgpu_failure', 'mov w0, #0', 'ret',
                 'success:', 'mov w0, #1', 'ret']
        return code

    @staticmethod
    def translation(restore):
        code = ['mov x19, x0']
        for name, offset in (('_checked_write32', 0xc00), ('_checked_write64', 0x8020)):
            code += ['mov x0, x19', 'mov w1, #5', f'mov w2, #{offset}',
                     f'bl @{name}', 'cbz w0, @fail']
        code += ['mov w0, #1', 'ret', 'fail:']
        if restore:
            # Legitimate last-route containment writes are deliberately unchecked
            # on an already-failed path that can only return false.
            code += ['bl @_checked_write32', 'bl @_checked_write32']
        return code + ['mov w0, #0', 'ret']

    def set_kernel(self, data):
        self.files[str(self.kernel)] = bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        (self.folder / 'kernel/SHA256SUMS').write_text(digest + '  ' + self.kernel.name + '\n')

    def assembly(self, symbol):
        base, pc = self.addresses[symbol], self.addresses[symbol]
        labels = {}
        for line in self.code[symbol]:
            if line.endswith(':'):
                labels[line[:-1]] = pc
            else:
                pc += 4
        text, pc = [f'{base:016x} <{symbol}>:'], base
        for line in self.code[symbol]:
            if line.endswith(':'):
                continue
            for ref in line.split('@')[1:]:
                name = ref.split()[0].rstrip(',')
                target = self.addresses.get(name, labels.get(name))
                if target is None:
                    raise AssertionError('unknown synthetic assembly label')
                annotated = name if name in self.addresses else symbol + '+' + hex(target - base)
                line = line.replace('@' + name, f'0x{target:x} <{annotated}>')
            text.append(f'{pc:016x}: d503201f\t{line}')
            pc += 4
        return '\n'.join(text) + '\n'

    def tool(self, args, **kwargs):
        if args[0] == 'llvm-nm':
            return '\n'.join(f'{address:016x} t {name}' for name, address in self.addresses.items())
        if args[0] != 'llvm-objdump':
            raise AssertionError('unexpected external command')
        symbol = next(arg.split('=', 1)[1] for arg in args if arg.startswith('--disassemble-symbols='))
        return self.assembly(symbol)

    def audit(self, commit=COMMIT):
        with patch.object(checker, 'ROOT', self.root), patch.object(
                checker.subprocess, 'check_output', side_effect=self.tool):
            return checker.audit(commit)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.fixture = AuditFixture()

    def reject(self, pattern=None):
        before = str(self.fixture.folder / 'gpu-binary-audit.json')
        self.assertNotIn(before, self.fixture.files)
        with self.assertRaisesRegex(ValueError, pattern or '.'):
            self.fixture.audit()
        self.assertNotIn(before, self.fixture.files, 'failed audit must not publish a certificate')

    def test_positive_mock_audit_preserves_identity_and_hardware_boundary(self):
        report = self.fixture.audit()
        self.assertEqual((report['commit'], report['ci_run']), (COMMIT, 123))
        self.assertEqual(report['kernel_sha256'], hashlib.sha256(self.fixture.kernel.read_bytes()).hexdigest())
        self.assertIs(report['hardware_verified'], False)
        self.assertIn('not hardware proof', report['review'])
        self.assertIs(report['target_clock_setup_and_restore_wiring_checked'], True)
        self.assertEqual(len(report['wiring_evidence']['Ops_callbacks']), 12)
        self.assertIn('checked_call_edges', report['wiring_evidence'])

    def test_only_nonexecuted_zero_alignment_padding_is_accepted(self):
        symbol = '_padding_fixture'
        assembly = lambda: self.fixture.assembly(symbol).replace('d503201f\tudf', '00000000\tudf')
        self.fixture.addresses[symbol] = 0x102000
        self.fixture.code[symbol] = ['ret', 'udf #0', 'udf #0', 'udf #0']
        code = checker._Code(assembly(), symbol, 0x102000)
        self.assertEqual(code.padding, (0x102004, 0x102008, 0x10200c))
        self.assertEqual(code.reachable, {0x102000})
        invalid = (
            ['nop', 'udf #0', 'udf #0', 'udf #0'],
            ['cbz w0, 0x102008', 'ret', 'udf #0', 'udf #0'],
            ['b 0x102004', 'udf #0', 'udf #0', 'udf #0'],
            ['udf #0', 'ret', 'udf #0', 'udf #0'],
            ['ret', 'udf #0'],
            ['ret', 'udf #0', 'udf #0', 'udf #1'],
            ['ret', 'udf #0', 'udf #0', 'unknown'],
        )
        for body in invalid:
            with self.subTest(body=body):
                self.fixture.code[symbol] = body
                with self.assertRaises(ValueError):
                    checker._Code(assembly(), symbol, 0x102000)
        self.fixture.addresses[symbol] = 0x101ffc
        self.fixture.code[symbol] = ['ret', *(['udf #0'] * 4)]
        with self.assertRaises(ValueError):
            checker._Code(assembly(), symbol, 0x101ffc)
        self.fixture.addresses[symbol] = 0x102000
        self.fixture.code[symbol] = ['ret', 'udf #0', 'udf #0', 'udf #0']
        text = assembly().replace('10200c: 00000000', '10200c: 00000001')
        with self.assertRaises(ValueError):
            checker._Code(text, symbol, 0x102000)

    def test_pas_positive_wiring_does_not_claim_authentication(self):
        self.fixture.add_pas()
        report = self.fixture.audit()
        self.assertTrue(report['PAS_allocation_preflight_wiring_checked'])
        evidence = report['wiring_evidence']['PAS_allocation_preflight']
        self.assertTrue(evidence['explicit_zap_one_required'])
        self.assertTrue(evidence['exposed_release_blocked'])
        self.assertFalse(evidence['private_firmware_reference']['signature_or_TZ_acceptance_verified'])

    def test_pas_negative_binary_contracts_do_not_publish_certificates(self):
        cases = (
            ('_sgpu_zap_allocation_preflight', 'cmp w0, #3', 'cmp w0, #2'),
            ('_sgpu_zap_allocation_preflight', 'cmp w8, #1', 'cmp w8, #2'),
            ('_sgpu_zap_allocation_preflight', 'add x0, x0, #0x280', 'add x0, x0, #0x281'),
            ('_sgpu_zap_allocation_preflight', 'mov w2, #4', 'mov w2, #8'),
            ('_sgpu_zap_prepare', 'cbz w0, @fail', 'nop'),
            ('_sgpu_pas_allocate', 'mov x2, #4095', 'mov x2, #0'),
            ('_sgpu_pas_allocate', 'mov x3, #1048575', 'mov x3, #0'),
            ('_sgpu_pas_allocate', 'mov x5, #32832', 'mov x5, #32768'),
            ('_sgpu_pas_allocate', 'lsr w4, w2, #12', 'mov w4, w2'),
            ('_sgpu_pas_allocate', 'bl @_pmap_find_phys', 'nop'),
            ('_sgpu_pas_release', 'cbnz w8, @done', 'nop'),
            ('_sgpu_pas_release', 'ldrb w8, [x0, #20]', 'ldrb w8, [x0, #21]'),
            ('_sgpu_zap_layout', 'mov w0, #1', 'smc #0'),
        )
        for symbol, old, new in cases:
            with self.subTest(symbol=symbol, change=new):
                self.fixture = AuditFixture(); self.fixture.add_pas()
                at = self.fixture.code[symbol].index(old)
                self.fixture.code[symbol][at] = new
                self.reject()

    def test_pas_embedded_firmware_is_rejected(self):
        self.fixture.add_pas()
        mdt = (self.fixture.root / 'out/santoni-gpu-pas-fw-working/firmware/a506_zap.mdt').read_bytes()
        self.fixture.set_kernel(self.fixture.kernel.read_bytes() + mdt)
        self.reject('embedded')

    def test_compact_SCM_ABI_keeps_guarded_caller_and_full_frame_proofs(self):
        self.fixture.compact_scm()
        self.fixture.add_stack_failure()
        report = self.fixture.audit()
        evidence = report['wiring_evidence']['SCM_capability_probe']
        self.assertEqual(evidence['private_ABI'], 'constant_parameters_removed')
        self.assertIs(evidence['explicit_mode3_zap1_SCM1'], True)
        self.assertIs(evidence['transport']['independent_transport_opt_ins'], False)
        self.assertIs(evidence['transport']['opt_ins_checked_at_guarded_entry_and_all_caller_edges'], True)
        self.assertIs(evidence['transport']['shared_calls_time_and_busy_budget_checked'], True)
        self.assertIs(evidence['frame']['returned_x0_through_x7_preserved'], True)
        self.assertIn('_sgpu_scm_query', report['wiring_evidence']['verified_noreturn_stack_failure_calls'])

    def test_compact_SCM_ABI_rejects_removed_gates_wrong_arguments_and_budget_changes(self):
        cases = (
            ('_sgpu_scm_capability_probe', 'cmp w0, #3', 'cmp w0, #2'),
            ('_sgpu_scm_capability_probe', 'cmp w8, #1', 'cmp w8, #2'),
            ('_sgpu_scm_capability_probe', 'mov w0, #1', 'mov w0, #0'),
            ('_sgpu_scm_capability_probe', 'add x3, sp, #64', 'mov x3, xzr'),
            ('_sgpu_scm_probe', 'cmp w21, #1', 'cmp w21, #2'),
            ('_sgpu_scm_probe', 'cmp w22, #1', 'cmp w22, #2'),
            ('_sgpu_scm_probe', 'cbz w0, @fail_avail', 'nop'),
            ('_sgpu_scm_probe', 'mov w2, #13', 'mov w2, #12'),
            ('_sgpu_scm_query', 'str x1, [sp]', 'str x2, [sp]'),
            ('_sgpu_scm_query', 'mov x2, x24', 'mov x2, x25'),
            ('_sgpu_scm_readonly_transport', 'cmp x8, #0x02000207', 'cmp x8, #0x02000201'),
            ('_sgpu_scm_readonly_transport', 'cmp w8, #64', 'cmp w8, #65'),
            ('_sgpu_scm_readonly_transport', 'cmp x9, #1000000', 'cmp x9, #1000001'),
            ('_sgpu_scm_readonly_transport', 'str w8, [x21, #12]', 'str wzr, [x21, #12]'),
        )
        for symbol, old, new in cases:
            with self.subTest(symbol=symbol, old=old):
                self.fixture = AuditFixture(); self.fixture.compact_scm()
                body = self.fixture.code[symbol]
                self.assertIn(old, body)
                body[body.index(old)] = new
                self.reject()
        for callee in checker._SCM_HELPERS:
            with self.subTest(unguarded_callee=callee):
                self.fixture = AuditFixture(); self.fixture.compact_scm()
                self.fixture.code['_sgpu_kernel_wait_us'].insert(1, 'bl @' + callee)
                self.reject('guarded SCM layer')

    def test_compact_SCM_calls_invalidate_actual_machine_result_and_budget_arguments(self):
        self.fixture.compact_scm()
        names = checker._SCMNames({name: {address} for name, address in self.fixture.addresses.items()}, True)
        image = checker._Image(self.fixture.kernel.read_bytes())
        for symbol, output, budget, size in (('_sgpu_scm_probe', 'x3', None, 496),
                ('_sgpu_scm_query', 'x4', 'x3', 96),
                ('_sgpu_scm_readonly_transport', 'x3', 'x2', 96)):
            with self.subTest(symbol=symbol):
                caller = '_compact_caller_fixture'
                self.fixture.addresses[caller] = 0x1c0000
                self.fixture.code[caller] = ['bl @' + symbol, 'ret']
                state = checker._initial(caller)
                result = checker._Value(64, ('probe', 0x7000))
                state.put(output, result); state.store(result, size, checker._Value(size * 8, 0))
                span = checker._Value(64, ('probe', 0x6000))
                if budget:
                    state.put(budget, span); state.store(span, 16, checker._Value(128, 123))
                code = checker._Code(self.fixture.assembly(caller), caller, 0x1c0000)
                flow = checker._Flow(code, image, names, initial=state)
                after = flow.before[code.entry + 4]
                self.assertIsNone(after.load(result, size, image))
                if budget:
                    self.assertEqual(after.load(span, 8, image), checker._Value(64, 123))
                    self.assertIsNone(after.load(checker._scm_at(span, 8), 8, image))

    def test_stack_failure_requires_numeric_verified_noreturn_target(self):
        for change in ('returning_stub', 'other_call', 'misleading_annotation', 'bad_caller', 'unknown'):
            with self.subTest(change=change):
                self.fixture = AuditFixture(); self.fixture.compact_scm(); self.fixture.add_stack_failure()
                if change == 'returning_stub':
                    self.fixture.code['___stack_chk_fail'] = ['ret']
                elif change == 'other_call':
                    self.fixture.code['___stack_chk_fail'] = ['bl @_printf']
                elif change == 'misleading_annotation':
                    original = self.fixture.assembly
                    def misleading(symbol):
                        text = original(symbol)
                        if symbol == '___stack_chk_fail':
                            text = text.replace(f'0x{self.fixture.addresses["_panic"]:x} <_panic>',
                                                f'0x{self.fixture.addresses["_printf"]:x} <_panic>')
                        return text
                    self.fixture.assembly = misleading
                elif change == 'bad_caller':
                    self.fixture.code['_sgpu_scm_query'][-1] = 'bl @_printf'
                else:
                    self.fixture.code['_sgpu_scm_query'].append('unknown')
                self.reject()

    def test_noreturn_terminal_cannot_hide_reachable_truncation_or_a_hole(self):
        self.fixture.add_scm(); self.fixture.add_stack_failure()
        symbol = '_sgpu_scm_query'
        text = self.fixture.assembly(symbol)
        target = self.fixture.addresses['___stack_chk_fail']
        with self.assertRaisesRegex(ValueError, 'truncated'):
            checker._Code(text, symbol, self.fixture.addresses[symbol])
        checker._Code(text, symbol, self.fixture.addresses[symbol], noreturn=(target,))
        with self.assertRaisesRegex(ValueError, 'elided'):
            checker._Code(text + '\t...\n', symbol, self.fixture.addresses[symbol], noreturn=(target,))
        self.fixture.code[symbol].insert(0, 'b @live_tail')
        self.fixture.code[symbol] += ['live_tail:', 'nop']
        with self.assertRaisesRegex(ValueError, 'truncated'):
            checker._Code(self.fixture.assembly(symbol), symbol, self.fixture.addresses[symbol], noreturn=(target,))
        lines = text.splitlines()
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            checker._Code('\n'.join(lines[:2] + lines[3:]), symbol,
                          self.fixture.addresses[symbol], noreturn=(target,))

        self.fixture.addresses[symbol] = 0x1c0000
        self.fixture.code[symbol] = ['bl @___stack_chk_fail', 'udf #0', 'udf #0', 'udf #0']
        padded = self.fixture.assembly(symbol).replace('d503201f\tudf', '00000000\tudf')
        code = checker._Code(padded, symbol, 0x1c0000, noreturn=(target,))
        self.assertEqual(len(code.padding), 3)
        with self.assertRaises(ValueError):
            checker._Code(padded, symbol, 0x1c0000, noreturn=(target + 4,))

    def test_only_bound_64bit_objects_are_known_nonnull(self):
        state = checker._State()
        for tag in ('stack', 'probe', 'ops', 'report'):
            pointer = checker._Value(64, (tag, 0))
            self.assertIs(state.truth(checker._eq(pointer, checker._Value(64, 0))), False)
            self.assertIsNone(state.truth(checker._eq(checker._cast(pointer, 32), checker._Value(32, 0))))
        for pointer in (None, checker._Value(64, ('arg', 1)), checker._Value(64, ('read', 0x1000))):
            self.assertIsNone(state.truth(checker._eq(pointer, checker._Value(64, 0))))

    def test_scm_positive_binary_wiring_is_capability_only(self):
        self.fixture.add_scm()
        report = self.fixture.audit()
        self.assertIs(report['SCM_capability_probe_wiring_checked'], True)
        self.assertIs(report['hardware_verified'], False)
        evidence = report['wiring_evidence']['SCM_capability_probe']
        self.assertIs(evidence['worker_terminates_after_both_handled_results'], True)
        self.assertIs(evidence['PAS_authentication_or_pixels_verified'], False)
        self.assertEqual(len(evidence['Ops_callbacks']), 4)
        self.assertIs(evidence['frame']['SMC32_truncation_checked'], True)
        self.assertIs(evidence['transport']['shared_calls_time_and_busy_budget_checked'], True)
        self.assertIs(evidence['negotiation']['availability_before_PAS_ID13_support'], True)

    def reject_scm_mutants(self, cases):
        for symbol, old, new in cases:
            with self.subTest(symbol=symbol, change=new):
                self.fixture = AuditFixture(); self.fixture.add_scm()
                self.assertIn(old, self.fixture.code[symbol])
                at = self.fixture.code[symbol].index(old)
                self.fixture.code[symbol][at] = new
                self.reject()

    def test_scm_entry_and_worker_binary_negatives_fail_without_certificates(self):
        self.reject_scm_mutants((
            ('_sgpu_scm_capability_probe', 'cmp w0, #3', 'cmp w0, #2'),
            ('_sgpu_scm_capability_probe', 'cmp w8, #1', 'cmp w8, #2'),
            ('_sgpu_scm_capability_probe', 'adr x0, 0x200300', 'adr x0, 0x200280'),
            ('_sgpu_scm_capability_probe', 'mov w2, #4', 'mov w2, #8'),
            ('_sgpu_scm_capability_probe', 'add x1, sp, #4', 'mov x1, sp'),
            ('_sgpu_scm_capability_probe', 'str x9, [sp, #48]', 'nop'),
            ('_sgpu_scm_capability_probe', 'add x0, sp, #16', 'add x0, sp, #24'),
            ('_sgpu_scm_capability_probe', 'mov w0, #1', 'mov w0, #0'),
            ('_sgpu_scm_capability_probe', 'bl @_sgpu_scm_probe', 'nop'),
            ('_sgpu_kernel_thread', 'cbz w0, @scm_skip', 'b @scm_skip'),
            ('_sgpu_kernel_thread', 'bl @_thread_terminate_self', 'nop'),
            ('_sgpu_kernel_thread', 'ret', 'b @scm_skip'),
        ))

    def test_scm_each_actual_frame_register_and_barrier_is_checked(self):
        self.reject_scm_mutants((
            ('_sgpu_smc_frame', 'dmb sy', 'nop'),
            ('_sgpu_smc_frame', 'dsb sy', 'isb'),
            ('_sgpu_smc_frame', 'smc #0', 'nop'),
            ('_sgpu_smc_frame', 'mov x7, #0', 'mov x7, #1'),
            ('_sgpu_smc_frame', 'ldr x6, [x19, #48]', 'ldr x6, [x19, #40]'),
            ('_sgpu_smc_frame', 'stp x6, x7, [x19, #48]', 'stp x5, x7, [x19, #48]'),
            ('_sgpu_smc_frame', 'ldr w8, [x19, #0]', 'ldr x8, [x19, #0]'),
            ('_sgpu_smc_frame', 'mov w0, #1', 'mov w0, #0'),
        ))
        self.fixture = AuditFixture(); self.fixture.add_scm()
        body = self.fixture.code['_sgpu_smc_frame']
        body.insert(body.index('smc #0'), 'interior:')
        body[body.index('mov x7, #0')] = 'cbnz w20, @interior'
        self.reject('interior entry')
        self.fixture = AuditFixture(); self.fixture.add_scm()
        body = self.fixture.code['_sgpu_smc_frame']
        at = body.index('ldr w8, [x19, #0]', body.index('ldr w8, [x19, #0]') + 1)
        body[at] = 'ldr x8, [x19, #0]'
        self.reject('returned')

    def test_scm_scalar_transport_whitelist_budgets_and_resume_are_checked(self):
        self.reject_scm_mutants((
            ('_sgpu_scm_readonly_transport', 'cmp w23, #3', 'cmp w23, #2'),
            ('_sgpu_scm_readonly_transport', 'cmp w24, #1', 'cmp w24, #2'),
            ('_sgpu_scm_readonly_transport', 'cmp w25, #1', 'cmp w25, #2'),
            ('_sgpu_scm_readonly_transport', 'cmp x9, #1', 'cmp x9, #2'),
            ('_sgpu_scm_readonly_transport', 'cmp x8, #0x02000207', 'cmp x8, #0x02000201'),
            ('_sgpu_scm_readonly_transport', 'and x8, x8, #0xffffffffbfffffff', 'and w8, w8, #0xbfffffff'),
            ('_sgpu_scm_readonly_transport', 'cmp w8, #64', 'cmp w8, #65'),
            ('_sgpu_scm_readonly_transport', 'cmp x9, #1000000', 'cmp x9, #1000001'),
            ('_sgpu_scm_readonly_transport', 'str w8, [x21, #8]', 'str wzr, [x21, #8]'),
            ('_sgpu_scm_readonly_transport', 'cmp w8, #20', 'cmp w8, #21'),
            ('_sgpu_scm_readonly_transport', 'str w8, [x21, #12]', 'str wzr, [x21, #12]'),
            ('_sgpu_scm_readonly_transport', 'mov w1, #30000', 'mov w1, #1'),
            ('_sgpu_scm_readonly_transport', 'str w8, [x22, #12]', 'stp xzr, xzr, [sp]'),
            ('_sgpu_scm_readonly_transport', 'cset w0, eq', 'mov w0, #1'),
        ))
        self.fixture = AuditFixture(); self.fixture.add_scm()
        body = self.fixture.code['_sgpu_scm_readonly_transport']
        start = body.index('ldp q0, q1, [x20]', body.index('busy:'))
        body[start:start + 4] = ['nop'] * 4
        self.reject('original frame')

    def test_scm_complementary_frames_reject_bits_hidden_by_one_sentinel(self):
        for line, added in (('dmb sy', 'and x6, x6, #0xfffffffffffffeff'),
                            ('stp x6, x7, [x19, #48]', 'orr x6, x6, #0x200')):
            with self.subTest(change=added):
                self.fixture = AuditFixture(); self.fixture.add_scm()
                body = self.fixture.code['_sgpu_smc_frame']
                body.insert(body.index(line), added)
                self.reject()

    def test_scm_query_probe_negotiation_and_first_failure_are_checked(self):
        self.reject_scm_mutants((
            ('_sgpu_scm_query', 'str x4, [sp]', 'str x5, [sp]'),
            ('_sgpu_scm_query', 'mov x8, #1', 'mov x8, #2'),
            ('_sgpu_scm_query', 'str xzr, [sp, #24]', 'str x6, [sp, #24]'),
            ('_sgpu_scm_query', 'mov x5, x24', 'mov x5, x25'),
            ('_sgpu_scm_query', 'add sp, sp, #64', 'mov w0, #1'),
            ('_sgpu_scm_probe', 'mov w4, #3254781441', 'mov w4, #2181039617'),
            ('_sgpu_scm_probe', 'cmp w8, #-4', 'cmp w8, #-2'),
            ('_sgpu_scm_probe', 'b.ne @fail64', 'nop'),
            ('_sgpu_scm_probe', 'cbz w0, @fail_avail', 'nop'),
            ('_sgpu_scm_probe', 'cbz w0, @fail_support', 'nop'),
            ('_sgpu_scm_probe', 'ldr x8, [x23, #240]', 'ldr x8, [x23, #248]'),
            ('_sgpu_scm_probe', 'str x0, [sp]', 'str xzr, [sp]'),
            ('_sgpu_scm_failure', 'cbnz w8, @done', 'nop'),
            ('_sgpu_scm_failure', 'mov x2, #96', 'mov x2, #64'),
        ))
        for offset in (0, 8, 12):
            with self.subTest(reset_offset=offset):
                self.fixture = AuditFixture(); self.fixture.add_scm()
                body = self.fixture.code['_sgpu_scm_probe']
                queries = [i for i, line in enumerate(body) if line == 'bl @_sgpu_scm_query']
                body.insert(queries[2], f'str {"xzr" if offset == 0 else "wzr"}, [sp, #{offset}]')
                self.reject('budget')

    def test_scm_real_passed_Ops_table_cannot_be_missing_corrupt_or_only_named(self):
        for offset, value in ((0, 1), (8, self.fixture.addresses['_sgpu_io_write32']),
                              (16, 0), (24, 0), (32, 0)):
            with self.subTest(offset=offset):
                self.fixture = AuditFixture(); self.fixture.add_scm()
                data = bytearray(self.fixture.kernel.read_bytes())
                struct.pack_into('<Q', data, 0x2400 + offset, value)
                self.fixture.set_kernel(data)
                self.reject()
        self.fixture = AuditFixture(); self.fixture.add_scm()
        del self.fixture.addresses['_sgpu_scm_failure']
        self.reject('boundaries')

    def test_scm_cannot_hide_SMC_or_bypass_a_policy_layer(self):
        for symbol in ('_sgpu_probe', '_sgpu_scm_query', '_sgpu_scm_probe'):
            with self.subTest(symbol=symbol):
                self.fixture = AuditFixture(); self.fixture.add_scm()
                self.fixture.code[symbol].insert(0, 'smc #0')
                self.reject('outside')
        self.fixture = AuditFixture(); self.fixture.add_scm()
        self.fixture.code['_sgpu_scm_probe'].insert(0, 'bl @_sgpu_smc_frame')
        self.reject('layer')
        self.fixture = AuditFixture(); self.fixture.add_scm()
        self.fixture.code['_sgpu_scm_capability_probe'].insert(0, 'bl @_sgpu_zap_allocation_preflight')
        self.reject('layer')

    def test_historical_kernel_never_earns_the_new_SCM_gate(self):
        report = self.fixture.audit()
        self.assertIs(report['SCM_capability_probe_wiring_checked'], False)

    def test_known_scalar_fragments_form_vectors_only_with_full_byte_coverage(self):
        state = checker._State()
        base = checker._Value(64, ('probe', 0x6000))
        state.store(base, 8, checker._Value(64, 0x1122334455667788))
        upper = checker._scm_at(base, 8)
        self.assertIsNone(state.load(base, 16, None))
        state.store(upper, 8, checker._Value(64, 0xaabbccddeeff0011))
        self.assertEqual(state.load(base, 16, None),
                         checker._Value(128, 0xaabbccddeeff00111122334455667788))
        state.store(checker._scm_at(base, 9), 1, None)
        self.assertIsNone(state.load(base, 16, None))

    def test_partial_vector_copies_preserve_only_known_snapshot_bytes(self):
        V, at = checker._Value, checker._scm_at
        for size in (8, 16):
            for known in (0, 4):
                state=checker._State(); source=V(64,('probe',0x600c)); dest=V(64,('stack',-0x44))
                state.store(at(source,known),4,V(32,0x12345678))
                self.assertIsNone(state.load(source,size,None))
                snapshot=state.load_copy(source,size,None)
                self.assertIsNotNone(snapshot)
                state.store(at(source,known),4,V(32,0x99999999))
                state.store(dest,size,V(size*8,0))
                state.store(dest,size,snapshot)
                self.assertEqual(state.load(at(dest,known),4,None),V(32,0x12345678))
                self.assertIsNone(state.load(at(dest,4 if known==0 else 0),4,None))
                self.assertIsNone(state.load(dest,size,None))
                self.assertIsNone(state.truth(checker._eq(snapshot,V(size*8,0))))
                if known==0:self.assertEqual(checker._cast(snapshot,32),V(32,0x12345678))

    def test_partial_vector_unknown_bytes_do_not_keep_destination_zeroes(self):
        V, at = checker._Value, checker._scm_at
        state=checker._State(); source=V(64,('probe',100)); dest=V(64,('stack',20))
        state.store(at(source,3),1,V(8,0xaa))
        state.store(dest,16,V(128,0))
        state.store(dest,8,state.load_copy(source,8,None))
        for offset in range(8):
            self.assertEqual(state.load(at(dest,offset),1,None),V(8,0xaa) if offset==3 else None)
        self.assertEqual(state.load(at(dest,8),8,None),V(64,0))
        state.store(at(source,3),1,None)
        self.assertIsNone(state.load_copy(source,8,None))

    def test_actual_00b783c_combined_option_copy_when_available(self):
        import copy
        folder=ROOT/'out/ci-00b783c'; kernel=folder/'kernel/kernel.development.santoni'
        if not kernel.exists(): self.skipTest('local 00b783c CI artifact absent')
        self.assertEqual(hashlib.sha256(kernel.read_bytes()).hexdigest(),
                         '19c9646392a9c0981c21bafb6f2bbd88226124804b2537720593481679b249b3')
        names=checker._symbols(checker.subprocess.check_output(['llvm-nm','--defined-only',str(kernel)],text=True))
        image=checker._Image(kernel.read_bytes())
        noreturn={address for name in ('_panic','_Assert','___stack_chk_fail') for address in names.get(name,())}
        symbols=set((*checker.PIXEL_HELPERS,*checker.G3_HELPERS,'_sgpu_probe','_sgpu_kernel_thread','_render_test','_consume'))
        codes={name:checker._Code((folder/(name[1:]+'.asm')).read_text(),name,next(iter(names[name])),noreturn=noreturn)
               for name in symbols}
        self.assertTrue(checker.audit_pixels(codes,image,names,checker))
        self.assertTrue(checker.audit_g3(codes,image,names,checker))
        worker=codes['_sgpu_kernel_thread']
        loads=[pc for pc,(op,args) in worker.ins.items() if op=='ldur' and args[0]=='d1']
        stores=[pc for pc,(op,args) in worker.ins.items() if op=='stur' and args[0]=='d1']
        self.assertEqual(len(loads),1);self.assertEqual(len(stores),1)
        changes=((loads[0],('ldur',('d1','[x21, #0x8]'))),
                 (stores[0],('stur',('d1','[x29, #-0x40]'))),
                 (stores[0],('stur',('s1','[x29, #-0x44]'))))
        for pc,instruction in changes:
            altered=copy.deepcopy(worker);altered.ins[pc]=instruction
            variant={**codes,'_sgpu_kernel_thread':altered}
            with self.subTest(instruction=instruction),self.assertRaises(ValueError):
                checker.audit_pixels(variant,image,names,checker)
                checker.audit_g3(variant,image,names,checker)

    def test_SCM_mutating_calls_invalidate_old_frame_and_report_zeroes(self):
        self.fixture.add_scm()
        image = checker._Image(self.fixture.kernel.read_bytes())
        names = {name: {address} for name, address in self.fixture.addresses.items()}
        for symbol, output_reg, size in (('_sgpu_smc_frame', 'x2', 64),
                                        ('_sgpu_scm_readonly_transport', 'x6', 96),
                                        ('_sgpu_scm_query', 'x7', 96),
                                        ('_sgpu_scm_probe', 'x4', 496)):
            with self.subTest(symbol=symbol):
                name = '_SCM_mutation_fixture'
                self.fixture.addresses[name] = 0x1a0000
                self.fixture.code[name] = ['bl @' + symbol, 'ret']
                code = checker._Code(self.fixture.assembly(name), name, 0x1a0000)
                state = checker._initial(name)
                base = checker._Value(64, ('probe', 0x6000))
                state.put(output_reg, base); state.store(base, size, checker._Value(size * 8, 0))
                flow = checker._Flow(code, image, names, initial=state)
                self.assertIsNone(flow.before[code.entry + 4].load(base, size, image))

    def test_cr02_constant_success_helpers_and_disconnected_worker_are_rejected(self):
        for symbol in ('_checked_write32', '_checked_write64', '_branch_state'):
            self.fixture.code[symbol] = ['mov w0, #1', 'ret']
        self.fixture.code['_sgpu_kernel_thread'] = [
            'bl @_sgpu_failure_summary', 'bl @_sgpu_failure_summary', 'ret']
        self.reject()

    def test_cr03_ldclr_is_rejected(self):
        self.fixture.code['_sgpu_probe'].insert(0, 'ldclr w0, w1, [x2]')
        self.reject('Cortex-A53')

    def test_cr04_swapped_32_bit_mmio_widths_are_rejected(self):
        self.fixture.code['_sgpu_io_write32'] = ['dmb sy', 'str x3, [x8]', 'dsb sy', 'ret']
        self.fixture.code['_sgpu_io_read32'] = ['ldr x0, [x8]', 'dmb sy', 'ret']
        self.reject('MMIO')

    def test_cr05_stripped_payload_is_rejected(self):
        payload = (self.fixture.bundle / 'firmware/a530_pm4.fw.payload').read_bytes()
        self.fixture.set_kernel(self.fixture.kernel.read_bytes() + payload)
        self.reject('firmware')

    def test_cr05_missing_reference_corpus_is_rejected(self):
        for name in ('a530_pm4.fw', 'a530_pfp.fw'):
            del self.fixture.files[str(self.fixture.bundle / 'firmware' / name)]
        self.reject('firmware')

    def test_each_required_execution_edge_is_checked_independently(self):
        edges = [(caller, callee) for caller in ('_sgpu_power', '_sgpu_restore_power')
                 for callee in ('_branch_state',)]
        edges += [(caller, callee) for caller in ('_sgpu_smmu_start', '_sgpu_smmu_restore')
                  for callee in ('_checked_write32', '_checked_write64')]
        edges += [('_sgpu_probe', callee) for callee in (
            '_sgpu_power', '_sgpu_smmu_start', '_sgpu_smmu_restore',
            '_sgpu_restore_power', '_sgpu_a505_init', '_sgpu_a505_resume', '_sgpu_a505_halt', '_checked_write32')]
        edges += [('_sgpu_kernel_thread', '_sgpu_probe'), ('_IOKitBSDInit', '_santoni_gpu_start')]
        edges += [('_sgpu_a505_resume', '_sgpu_a505_sp_release')]
        for caller, callee in edges:
            with self.subTest(caller=caller, callee=callee):
                self.fixture = AuditFixture()
                self.fixture.code[caller] = ['nop' if line == 'bl @' + callee else line
                                            for line in self.fixture.code[caller]]
                self.reject()

    def test_helper_results_cannot_be_ignored_or_test_an_unrelated_register(self):
        for caller in ('_sgpu_power', '_sgpu_restore_power', '_sgpu_smmu_start', '_sgpu_a505_resume',
                       '_sgpu_smmu_restore', '_sgpu_probe'):
            for replacement in ('nop', 'cbz w8, @fail', 'cmp w0, #2'):
                with self.subTest(caller=caller, replacement=replacement):
                    self.fixture = AuditFixture()
                    at = self.fixture.code[caller].index('cbz w0, @fail')
                    self.fixture.code[caller][at] = replacement
                    self.reject()

    def test_power_and_translation_failures_cannot_reach_a505_init(self):
        for callee in ('_sgpu_power', '_sgpu_smmu_start'):
            with self.subTest(callee=callee):
                self.fixture = AuditFixture()
                code = self.fixture.code['_sgpu_probe']
                code[code.index('fail:') + 1:code.index('fail:') + 1] = ['bl @_sgpu_a505_init']
                self.reject('unsafe continuation')

    def test_failed_smmu_restore_cannot_drop_power_prerequisites(self):
        code = self.fixture.code['_sgpu_probe']
        at = code.index('bl @_sgpu_smmu_restore')
        code[at + 1] = 'cbz w0, @bad_restore'
        code += ['bad_restore:', 'bl @_sgpu_restore_power', 'mov w0, #0', 'ret']
        self.reject('unsafe continuation')

    def test_constant_success_helpers_are_rejected_one_at_a_time(self):
        for symbol in ('_checked_write32', '_checked_write64', '_branch_state'):
            with self.subTest(symbol=symbol):
                self.fixture = AuditFixture()
                self.fixture.code[symbol] = ['mov w0, #1', 'ret']
                self.reject()

    def test_unreachable_good_helper_body_is_not_a_checked_helper(self):
        for symbol in ('_checked_write32', '_checked_write64', '_branch_state'):
            with self.subTest(symbol=symbol):
                self.fixture = AuditFixture()
                self.fixture.code[symbol][:0] = ['mov w0, #1', 'ret']
                self.reject()

    def test_checked_helpers_require_each_read_write_read_operation(self):
        for bits in (32, 64):
            for occurrence in range(3):
                with self.subTest(bits=bits, operation=occurrence):
                    self.fixture = AuditFixture()
                    code = self.fixture.code[f'_checked_write{bits}']
                    at = [i for i, line in enumerate(code) if line == 'blr x9'][occurrence]
                    code[at] = 'nop'
                    self.reject('read/write/read')

    def test_checked_helpers_use_correct_ops_slots_context_and_register(self):
        for symbol, old, new in (
                ('_checked_write32', 'ldr x9, [x8, #16]', 'ldr x9, [x8, #24]'),
                ('_checked_write64', 'ldr x9, [x8, #40]', 'ldr x9, [x8, #32]'),
                ('_checked_write32', 'ldr x0, [x8]', 'mov x0, xzr'),
                ('_checked_write64', 'mov w2, w21', 'mov w2, #0'),
                ('_checked_write32', 'mov w3, w23', 'mov w3, wzr')):
            with self.subTest(symbol=symbol, replacement=new):
                self.fixture = AuditFixture()
                self.fixture.code[symbol] = [new if line == old else line for line in self.fixture.code[symbol]]
                self.reject()

    def test_readback_comparison_requires_actual_read_expected_value_and_mask(self):
        for symbol, old, new in (
                ('_checked_write32', 'eor w8, w0, w23', 'eor w8, w24, w23'),
                ('_checked_write32', 'mov w22, w3', 'mov w22, w1'),
                ('_checked_write64', 'cmp x0, x23', 'cmp w0, w23'),
                ('_checked_write64', 'cmp x0, x23', 'cmp x0, x24'),
                ('_checked_write32', 'b.eq @success', 'b.ne @success')):
            with self.subTest(symbol=symbol, replacement=new):
                self.fixture = AuditFixture()
                self.fixture.code[symbol] = [new if line == old else line for line in self.fixture.code[symbol]]
                self.reject('readback')

    def test_readback_mismatch_must_call_failure_and_return_false(self):
        for bits in (32, 64):
            for old, new in (('bl @_sgpu_failure', 'nop'), ('mov w0, #0', 'mov w0, #1'),
                             ('mov w1, #2', 'mov w1, #3')):
                with self.subTest(bits=bits, replacement=new):
                    self.fixture = AuditFixture()
                    code = self.fixture.code[f'_checked_write{bits}']
                    self.fixture.code[f'_checked_write{bits}'] = [new if line == old else line for line in code]
                    self.reject('readback')

    def test_checked_write_pre_store_guard_must_fail_without_any_write(self):
        def guarded():
            body = AuditFixture.checked_write(32)
            where = body.index('mov w24, w0') + 1
            body[where:where] = ['cbz w24, @prewrite_guard']
            body += ['prewrite_guard:', 'mov x0, x19', 'mov w1, #4',
                     'bl @_sgpu_failure', 'mov w0, #0', 'ret']
            return body
        self.fixture.code['_checked_write32'] = guarded()
        self.assertTrue(self.fixture.audit()['target_clock_setup_and_restore_wiring_checked'])
        for change in ('success', 'missing-record', 'wrong-kind', 'after-write'):
            self.fixture = AuditFixture()
            body = guarded(); boundary = body.index('prewrite_guard:')
            if change == 'success': body[boundary + 4] = 'mov w0, #1'
            if change == 'missing-record': body[boundary + 3] = 'nop'
            if change == 'wrong-kind': body[boundary + 2] = 'mov w1, #2'
            if change == 'after-write':
                at = [i for i, line in enumerate(body) if line == 'blr x9'][1] + 1
                body[at:at] = ['cbz w24, @prewrite_guard']
            self.fixture.code['_checked_write32'] = body
            with self.subTest(change=change): self.reject('readback')

    def test_cset_and_stack_spilled_boolean_results_are_supported(self):
        code = self.fixture.code['_checked_write64']
        code[code.index('b.eq @success'):code.index('b.eq @success')] = ['cset w25, eq']
        code[code.index('mov w0, #0')] = 'mov w0, w25'
        code[code.index('mov w0, #1')] = 'mov w0, w25'
        probe = self.fixture.code['_sgpu_probe']
        at = probe.index('bl @_sgpu_restore_power') + 1
        probe[at:at] = ['strb w0, [sp, #0x10]', 'ldrb w8, [sp, #0x10]']
        probe[at + 2] = 'tbz w8, #0, @fail'
        self.assertIs(self.fixture.audit()['target_clock_setup_and_restore_wiring_checked'], True)

    def test_smmu_only_private_64_bit_argument_promotion_is_full_width(self):
        code = self.fixture.code['_checked_write64']
        replacements = {'mov w20, w1': 'mov w20, #5',
                        'mov w21, w2': 'mov w21, w1',
                        'mov x23, x3': 'mov x23, x2'}
        self.fixture.code['_checked_write64'] = [replacements.get(line, line) for line in code]
        report = self.fixture.audit()['wiring_evidence']['checked_write64']
        self.assertEqual((report['block'], report['offset_argument'], report['value_argument']), (5, 1, 2))
        self.fixture.code['_checked_write64'] = [
            'cmp w0, w23' if line == 'cmp x0, x23' else line
            for line in self.fixture.code['_checked_write64']]
        self.fixture.files.pop(str(self.fixture.folder / 'gpu-binary-audit.json'))
        self.reject('readback')

    def test_zero_extended_enum_and_offset_copies_preserve_the_32_bit_ABI(self):
        code = self.fixture.code['_checked_write64']
        self.fixture.code['_checked_write64'] = [
            {'mov w1, w20': 'mov x1, x20', 'mov w2, w21': 'mov x2, x21'}.get(line, line)
            for line in code]
        self.assertIs(self.fixture.audit()['target_clock_setup_and_restore_wiring_checked'], True)

    def test_exact_shifted_elapsed_deadline_is_not_a_weaker_timeout(self):
        code = self.fixture.code['_branch_state']
        at = code.index('cmp x8, #0x2710')
        code[at:at + 2] = ['lsr x8, x8, #4', 'cmp x8, #624', 'b.hi @fail']
        good = list(code)
        self.assertIs(self.fixture.audit()['target_clock_setup_and_restore_wiring_checked'], True)
        for old, new in (('cmp x8, #624', 'cmp x8, #625'),
                         ('cmp x8, #624', 'cmp x8, #623'),
                         ('lsr x8, x8, #4', 'lsr x8, x8, #5'),
                         ('sub x8, x0, x21', 'mov x8, x0'),
                         ('sub x8, x0, x21', 'sub x8, x21, x0')):
            with self.subTest(replacement=new):
                self.fixture = AuditFixture()
                self.fixture.code['_branch_state'] = [new if line == old else line for line in good]
                self.reject('branch_state')

    def test_smmu_saved_state_zero_initializers_do_not_survive_mutating_calls(self):
        code = self.fixture.code['_sgpu_probe']
        at = code.index('bl @_sgpu_smmu_start')
        code[at:at] = ['movi.2d v0, #0', 'stp q0, q0, [sp, #0x320]',
                      'stp q0, q0, [sp, #0x340]', 'add x1, sp, #0x320']
        at = code.index('bl @_sgpu_smmu_restore')
        code[at:at] = ['ldrb w8, [sp, #857]', 'cbz w8, @skip_restore', 'add x1, sp, #0x320']
        at = code.index('bl @_sgpu_restore_power')
        code.insert(at, 'skip_restore:')
        self.assertIs(self.fixture.audit()['target_clock_setup_and_restore_wiring_checked'], True)

    def test_only_already_failed_restore_containment_writes_may_ignore_results(self):
        code = self.fixture.code['_sgpu_smmu_restore']
        at = code.index('mov w0, #1')
        code[at:at] = ['bl @_checked_write32']
        self.reject('unchecked helper result')

    def test_branch_state_requires_read_time_wait_loop_and_failure(self):
        for old, new in (('ldr x9, [x8, #16]', 'ldr x9, [x8, #24]'),
                         ('ldr x9, [x8, #48]', 'ldr x9, [x8, #56]'),
                         ('ldr x9, [x8, #56]', 'ldr x9, [x8, #48]'),
                         ('b.lo @loop', 'nop'), ('cmp x8, #0x2710', 'cmp x8, #0'),
                         ('cbz w23, @success', 'cbz w24, @success'),
                         ('bl @_sgpu_failure', 'nop'), ('mov w0, #0', 'mov w0, #1')):
            with self.subTest(replacement=new):
                self.fixture = AuditFixture()
                self.fixture.code['_branch_state'] = [new if line == old else line
                                                      for line in self.fixture.code['_branch_state']]
                self.reject('branch_state')

    def test_every_ops_callback_and_context_must_match_the_table_actually_passed(self):
        for slot in range(0, 104, 8):
            with self.subTest(slot=slot):
                self.fixture = AuditFixture()
                data = bytearray(self.fixture.kernel.read_bytes())
                struct.pack_into('<Q', data, 0x2080 + slot, 1 if slot == 0 else 0)
                self.fixture.set_kernel(data)
                self.reject('Ops')

    def test_ops_table_cannot_be_only_present_unpassed_in_the_binary(self):
        code = self.fixture.code['_sgpu_kernel_thread']
        code[code.index('add x0, sp, #0x10')] = 'add x0, sp, #0x20'
        self.reject('Ops')

    def test_ops_vector_copy_must_include_the_clean_callback_and_last_trace_pointer(self):
        for removed in ('stp q4, q5, [sp, #0x50]', 'str x9, [sp, #0x70]'):
            with self.subTest(removed=removed):
                self.fixture = AuditFixture()
                self.fixture.code['_sgpu_kernel_thread'].remove(removed)
                self.reject('Ops')

    def test_ops_cannot_be_corrupted_after_copy(self):
        code = self.fixture.code['_sgpu_kernel_thread']
        code.insert(code.index('add x0, sp, #0x10'), 'str xzr, [sp, #0x60]')
        self.reject('Ops')

    def test_direct_constant_ops_pointer_is_also_supported(self):
        self.fixture.code['_sgpu_kernel_thread'] = [
            'adrp x0, 0x200000', 'add x0, x0, #0x80', 'bl @_sgpu_probe',
            'bl @_sgpu_failure_summary', 'bl @_sgpu_failure_summary', 'ret']
        self.assertIs(self.fixture.audit()['target_clock_setup_and_restore_wiring_checked'], True)

    def test_known_constant_branch_cannot_make_an_uninitialized_ops_table_reachable(self):
        code = self.fixture.code['_sgpu_kernel_thread']
        code[:0] = ['mov w8, #1', 'cbnz w8, @uncopied']
        code.insert(code.index('add x0, sp, #0x10'), 'uncopied:')
        self.reject('Ops')

    def test_cache_clean_callback_requires_actual_force_clean_call_and_arguments(self):
        for code in (['ret'], ['mov x0, xzr', 'mov w1, w2', 'b @_CleanPoC_DcacheRegion_Force'],
                     ['mov x0, x1', 'mov w1, wzr', 'b @_CleanPoC_DcacheRegion_Force']):
            with self.subTest(code=code):
                self.fixture = AuditFixture()
                self.fixture.code['_clean'] = code
                self.reject('cache-clean')

    def test_worker_must_be_the_function_passed_to_kernel_thread_start(self):
        self.fixture.code['_santoni_gpu_start'][0] = 'adr x0, @_sgpu_probe'
        self.reject('inspected GPU worker')

    def test_numeric_call_target_not_annotation_controls_the_gate(self):
        original = self.fixture.assembly
        def misleading(symbol):
            text = original(symbol)
            if symbol == '_sgpu_probe':
                text = text.replace(f'0x{self.fixture.addresses["_sgpu_power"]:x} <_sgpu_power>',
                                    '0xdead000 <_sgpu_power>')
            return text
        self.fixture.assembly = misleading
        self.reject()

    def test_cannot_inspect_empty_unknown_or_gapped_actual_instructions(self):
        for change in ('empty', 'unknown', 'gap', 'indirect'):
            with self.subTest(change=change):
                self.fixture = AuditFixture()
                original = self.fixture.assembly
                def malformed(symbol):
                    text = original(symbol)
                    if symbol == '_sgpu_probe':
                        if change == 'empty':
                            text = text.splitlines()[0] + '\n'
                        elif change == 'unknown':
                            text = text.replace('d503201f\tmov x19, x0', '00000000\t<unknown>')
                        elif change == 'gap':
                            text = '\n'.join(text.splitlines()[:1] + text.splitlines()[2:]) + '\n'
                    return text
                self.fixture.assembly = malformed
                if change == 'indirect':
                    self.fixture.code['_sgpu_probe'][0] = 'br x17'
                self.reject()

    def test_all_lse_ld_st_families_and_suffixes_are_rejected(self):
        for family in ('add', 'clr', 'eor', 'set', 'smax', 'smin', 'umax', 'umin'):
            for prefix, suffixes in (('ld', ('', 'a', 'l', 'al', 'b', 'h', 'ab', 'ah', 'lb', 'lh', 'alb', 'alh')),
                                     ('st', ('', 'l', 'b', 'h', 'lb', 'lh'))):
                for suffix in suffixes:
                    op = prefix + family + suffix
                    with self.subTest(op=op):
                        self.fixture = AuditFixture()
                        args = 'w0, w1, [x2]' if prefix == 'ld' else 'w0, [x2]'
                        self.fixture.code['_sgpu_probe'].insert(0, op + ' ' + args)
                        self.reject('Cortex-A53')

    def test_cas_swp_rcpc_pac_and_other_post_a53_instructions_are_rejected(self):
        instructions = ('cas casal casb cash casalb casalh casp caspal '
                        'swp swpal swpb swph swpalb swpalh '
                        'ldapr ldaprb ldaprh ldapur ldapurh ldapursb ldapursh ldapursw stlur stlurb stlurh '
                        'paciasp pacibsp pacia pacib pacda pacdb pacga autiasp autibsp autia autib autda autdb '
                        'xpaci xpacd xpaclri braa brab braaz brabz blraa blrab blraaz blrabz '
                        'retaa retab eretaa eretab ldraa ldrab bti sb sdot udot ld64b st64b').split()
        for op in instructions:
            with self.subTest(op=op):
                self.fixture = AuditFixture()
                self.fixture.code['_sgpu_probe'].insert(0, op + ' w0, w1, [x2]')
                self.reject('Cortex-A53')

    def test_lse_in_adapter_callbacks_and_outlined_gpu_callees_is_also_rejected(self):
        for symbol in ('_clean', '_sgpu_a505_init', '_sgpu_smmu_restore'):
            with self.subTest(symbol=symbol):
                self.fixture = AuditFixture()
                self.fixture.code[symbol].insert(0, 'ldset w0, w1, [x2]')
                self.reject('Cortex-A53')
        self.fixture = AuditFixture()
        self.fixture.addresses['_sgpu_marker_test'] = 0x140000
        self.fixture.code['_sgpu_marker_test'] = ['ldumin w0, w1, [x2]', 'ret']
        self.fixture.code['_sgpu_probe'].insert(0, 'bl @_sgpu_marker_test')
        self.reject('Cortex-A53')

    def test_supported_a53_exclusives_and_unsupported_words_in_prose_are_not_rejected(self):
        self.fixture.code['_sgpu_probe'][:0] = [
            'ldaxr w8, [x2]', 'stlxr w8, w9, [x2]', 'yield ; paciasp ldclr retaa']
        original = self.fixture.assembly
        self.fixture.assembly = lambda symbol: original(symbol) + 'Review prose: ldclr and paciasp are forbidden.\n'
        self.assertIs(self.fixture.audit()['checked_changed_code_is_Cortex_A53_compatible'], True)

    def test_mmio_access_width_is_checked_for_each_callback_independently(self):
        for bits in (32, 64):
            for role in ('read', 'write'):
                with self.subTest(bits=bits, role=role):
                    self.fixture = AuditFixture()
                    symbol, reg = f'_sgpu_io_{role}{bits}', 'x' if bits == 32 else 'w'
                    self.fixture.code[symbol] = (['dmb sy', f'str {reg}3, [x8]', 'dsb sy', 'ret'] if role == 'write'
                                                 else [f'ldr {reg}0, [x8]', 'dmb sy', 'ret'])
                    self.reject('MMIO')

    def test_mmio_write_zero_register_and_all_bad_barrier_paths_are_rejected(self):
        for bits, reg in ((32, 'w'), (64, 'x')):
            store = f'str {reg}3, [x8]'
            cases = ([f'str {reg}zr, [x8]', 'dsb sy', 'ret'],
                     [store, 'dsb sy', 'ret'], ['dmb sy', store, 'ret'],
                     ['dsb sy', store, 'dmb sy', 'ret'],
                     ['dmb oshst', store, 'dsb sy', 'ret'],
                     ['b @store', 'dmb sy', 'store:', store, 'dsb sy', 'ret'],
                     ['cbz w9, @store', 'dmb sy', 'store:', store, 'dsb sy', 'ret'],
                     ['dmb sy', store, 'ret', 'dsb sy', 'ret'],
                     ['ret', 'dmb sy', store, 'dsb sy', 'ret'],
                     ['mov w9, #1', 'cbz w9, @stub', 'ret', 'stub:', 'dmb sy', store, 'dsb sy', 'ret'])
            for code in cases:
                with self.subTest(bits=bits, code=code):
                    self.fixture = AuditFixture()
                    self.fixture.code[f'_sgpu_io_write{bits}'] = code
                    self.reject('MMIO')

    def test_mmio_read_missing_reordered_and_unreachable_barriers_are_rejected(self):
        for bits, reg in ((32, 'w'), (64, 'x')):
            load = f'ldr {reg}0, [x8]'
            cases = ([load, 'ret'], ['dmb sy', load, 'ret'], [load, 'dmb ish', 'ret'],
                     [load, 'ret', 'dmb sy', 'ret'], ['ret', load, 'dmb sy', 'ret'],
                     ['mov w9, #1', 'cbz w9, @stub', 'ret', 'stub:', load, 'dmb sy', 'ret'])
            for code in cases:
                with self.subTest(bits=bits, code=code):
                    self.fixture = AuditFixture()
                    self.fixture.code[f'_sgpu_io_read{bits}'] = code
                    self.reject('MMIO')

    def test_private_original_and_stripped_payload_for_both_firmware_files_are_rejected(self):
        for name in ('a530_pm4.fw', 'a530_pfp.fw'):
            for stripped in (False, True):
                with self.subTest(name=name, stripped=stripped):
                    self.fixture = AuditFixture()
                    raw = (self.fixture.bundle / 'firmware' / name).read_bytes()
                    self.fixture.set_kernel(self.fixture.kernel.read_bytes() + (raw[4:] if stripped else raw))
                    self.reject('embedded')

    def test_missing_private_original_payload_or_metadata_is_not_absence(self):
        for name in ('target.json', 'firmware-intake.json', 'firmware/a530_pm4.fw',
                     'firmware/a530_pfp.fw', 'firmware/a530_pm4.fw.payload', 'firmware/a530_pfp.fw.payload'):
            with self.subTest(name=name):
                self.fixture = AuditFixture()
                del self.fixture.files[str(self.fixture.bundle / name)]
                self.reject('validated private firmware corpus')

    def test_changed_private_original_payload_and_metadata_are_rejected(self):
        for name in ('firmware/a530_pm4.fw', 'firmware/a530_pfp.fw.payload',
                     'firmware-intake.json', 'target.json'):
            with self.subTest(name=name):
                self.fixture = AuditFixture()
                source = self.fixture.bundle / name
                data = bytearray(source.read_bytes())
                data[8] ^= 1
                self.fixture.files[str(source)] = bytes(data)
                self.reject('validated private firmware corpus')

    def test_invalid_empty_truncated_oversized_or_unaligned_firmware_is_rejected(self):
        for raw in (b'', bytes(12), bytes(32772), bytes(17), struct.pack('<4I', 1, 1, 2, 3)):
            with self.subTest(size=len(raw)):
                self.fixture = AuditFixture()
                self.fixture.files[str(self.fixture.bundle / 'firmware/a530_pm4.fw')] = raw
                self.reject('validated private firmware corpus')

    def test_reports_never_include_raw_private_firmware(self):
        report = json.dumps(self.fixture.audit()).encode()
        for name in ('a530_pm4.fw', 'a530_pfp.fw'):
            raw = (self.fixture.bundle / 'firmware' / name).read_bytes()
            self.assertNotIn(raw, report)
            self.assertNotIn(raw[4:], report)

    def test_A505_clock_completion_checks_each_call_arguments_and_result(self):
        for old, new in (('mov w4, #85', 'mov w4, #0'),
                         ('mov w4, #386', 'mov w4, #384'),
                         ('mov w2, #5324', 'mov w2, #5328'),
                         ('mov w3, #-1', 'mov w3, #255'),
                         ('cbz w0, @fail', 'nop')):
            with self.subTest(replacement=new):
                self.fixture = AuditFixture()
                code = self.fixture.code['_sgpu_a505_resume']
                self.assertIn(old, code)
                self.fixture.code['_sgpu_a505_resume'] = [new if line == old else line for line in code]
                self.reject()
        self.fixture = AuditFixture()
        at = self.fixture.code['_sgpu_probe'].index('bl @_sgpu_a505_resume')
        self.fixture.code['_sgpu_probe'][at + 1] = 'nop'
        self.reject('unchecked helper result')

    def test_SP_RMW_preserves_all_upper_bits_and_does_not_ignore_observed_bit15(self):
        for old, new in (('and w23, w0, #0xffffff00', 'mov w23, #0xaaa82a00'),
                         ('and w23, w0, #0xffffff00', 'and w23, w0, #0xffff7f00'),
                         ('and w23, w0, #0xffffff00', 'and w23, w0, #0xff'),
                         ('cmp w25, w23', 'tst w25, #0xff'),
                         ('cmp w25, w23', 'cmp w24, w23'),
                         ('bl @_sgpu_failure', 'nop'), ('mov w0, #0', 'mov w0, #1')):
            with self.subTest(replacement=new):
                self.fixture = AuditFixture()
                self.fixture.code['_sgpu_a505_sp_release'] = [new if line == old else line
                                                             for line in self.fixture.code['_sgpu_a505_sp_release']]
                self.reject('readback|callback')

    def test_SP_CCMP_requires_both_full_echo_and_low_byte_release(self):
        code = self.fixture.code['_sgpu_a505_sp_release']
        at = code.index('cmp w25, w23')
        code[at:at + 2] = ['tst w25, #0xff', 'ccmp w25, w23, #0, eq',
                          'cset w26, eq', 'b.eq @success']
        code[code.index('mov w0, #0')] = 'mov w0, w26'
        code[code.index('mov w0, #1')] = 'mov w0, w26'
        self.assertTrue(self.fixture.audit()['a505_vendor_SP_RMW_release_and_partial_failure_hold_checked'])
        good = list(code)
        for old, new in (('tst w25, #0xff', 'tst w24, #0xff'),
                         ('tst w25, #0xff', 'tst w25, #1'),
                         ('ccmp w25, w23, #0, eq', 'ccmp w24, w23, #0, eq'),
                         ('ccmp w25, w23, #0, eq', 'ccmp w25, w23, #4, eq'),
                         ('ccmp w25, w23, #0, eq', 'ccmp w25, w23, #0, ne'),
                         ('ccmp w25, w23, #0, eq', 'nop')):
            with self.subTest(replacement=new):
                self.fixture = AuditFixture()
                self.fixture.code['_sgpu_a505_sp_release'] = [new if line == old else line for line in good]
                self.reject('readback')

    def test_SP_vendor_policy_and_ISDB_cannot_be_skipped_or_replaced(self):
        for old, new in ((f'mov w3, #{0xaaa8aa00}', 'mov w3, #0xaaa82a00'),
                         (f'mov w3, #{0xaaa8aa00}', 'mov w3, #0'),
                         ('bl @_sgpu_a505_sp_release', 'mov w0, #1'),
                         ('strb w8, [x19, #740]', 'nop')):
            with self.subTest(replacement=new):
                self.fixture = AuditFixture()
                self.fixture.code['_sgpu_a505_resume'] = [new if line == old else line
                                                        for line in self.fixture.code['_sgpu_a505_resume']]
                self.reject()

    def test_packed_false_ready_true_touched_store_is_checked_byte_for_byte(self):
        code = self.fixture.code['_sgpu_a505_resume']
        code[1:4] = ['mov w8, #0x100', 'add x9, x19, #739', 'strh w8, [x9]']
        self.assertTrue(self.fixture.audit()['a505_vendor_SP_RMW_release_and_partial_failure_hold_checked'])
        good = list(code)
        for value in ('#0', '#0x101', '#0x200'):
            with self.subTest(value=value):
                self.fixture = AuditFixture()
                self.fixture.code['_sgpu_a505_resume'] = [
                    'mov w8, ' + value if line == 'mov w8, #0x100' else line for line in good]
                self.reject('readiness|partial-resume')

    def test_A505_stop_requires_vendor_RMW_both_bits_and_checked_failure(self):
        for old, new in (('orr w23, w0, #3', 'mov w23, #0x10000000'),
                         ('orr w23, w0, #3', 'mov w23, #3'),
                         ('orr w23, w0, #3', 'orr w23, w0, #1'),
                         ('and w8, w25, #3', 'and w8, w25, #1'),
                         ('cmp w8, #3', 'cmp w8, #1'),
                         ('mov w3, w24', 'mov w3, wzr'),
                         ('bl @_sgpu_failure', 'nop'), ('mov w0, #0', 'mov w0, #1')):
            with self.subTest(replacement=new):
                self.fixture = AuditFixture()
                code = self.fixture.code['_sgpu_a505_halt']
                self.assertIn(old, code)
                self.fixture.code['_sgpu_a505_halt'] = [new if line == old else line for line in code]
                self.reject()

    def test_A505_resume_readiness_and_distinct_halt_sites_cannot_be_dropped(self):
        for old, new in (('strb wzr, [x19, #739]', 'nop'),
                         ('strb w0, [x19, #739]', 'strb w0, [x19, #738]')):
            self.fixture = AuditFixture()
            self.fixture.code['_sgpu_a505_resume'] = [new if line == old else line
                                                    for line in self.fixture.code['_sgpu_a505_resume']]
            self.reject('readiness')
        for old, new in (('mov w1, #2', 'mov w1, #1'), ('mov w3, #3', 'mov w3, #0x10000000')):
            self.fixture = AuditFixture()
            self.fixture.code['_sgpu_probe'] = [new if line == old else line for line in self.fixture.code['_sgpu_probe']]
            self.reject('A505')

    def test_A505_reset_cannot_skip_its_resume(self):
        for occurrence in range(3):
            self.fixture = AuditFixture()
            code = self.fixture.code['_sgpu_probe']
            at = [i for i, line in enumerate(code) if line == 'bl @_sgpu_a505_resume'][occurrence]
            code[at] = 'mov w0, #1'
            self.reject('resume')

    def test_failed_A505_resume_flag_is_false_at_the_cleanup_branch(self):
        self.fixture.code['_sgpu_probe'] = [
            'sub sp, sp, #0x400', 'mov x19, sp', 'str x0, [sp]', 'strb wzr, [x19, #739]',
            'mov x0, x19', 'bl @_sgpu_a505_resume', 'cbz w0, @cleanup',
            'mov w0, #1', 'ret', 'cleanup:', 'ldrb w8, [x19, #739]', 'cbz w8, @failed',
            'bl @_sgpu_a505_halt', 'failed:', 'mov w0, #0', 'ret']
        symbol = '_sgpu_probe'
        code = checker._Code(self.fixture.assembly(symbol), symbol, self.fixture.addresses[symbol])
        evidence = checker._controlled_calls(code, checker._Image(self.fixture.kernel.read_bytes()),
                                            {name: {value} for name, value in self.fixture.addresses.items()},
                                            '_sgpu_a505_resume', forbidden=('_sgpu_a505_halt',))
        self.assertEqual(len(evidence), 1)

    def test_A505_resume_readiness_cannot_return_false_after_becoming_true(self):
        code = self.fixture.code['_sgpu_a505_resume']
        code.insert(code.index('strb w0, [x19, #739]') + 1, 'mov w0, #0')
        self.reject('readiness')

    def test_A505_readiness_byte_keeps_adjacent_known_ownership_flags(self):
        state = checker._State(memory={(('probe', 732), 8): checker._Value(64, 0)})
        state.store(checker._Value(64, ('probe', 739)), 1, checker._Value(32, ('result', 123)))
        image = checker._Image(self.fixture.kernel.read_bytes())
        for offset in range(732, 739):
            self.assertEqual(state.load(checker._Value(64, ('probe', offset)), 1, image), checker._Value(8, 0))
        self.assertEqual(state.load(checker._Value(64, ('probe', 739)), 1, image),
                         checker._Value(8, ('result', 123)))

    def test_symbolic_memory_partial_stores_preserve_only_exact_constant_fragments(self):
        image = checker._Image(self.fixture.kernel.read_bytes())
        state = checker._State(memory={(('stack', 0), 8): checker._Value(64, 0x0807060504030201)})
        state.store(checker._Value(64, ('stack', 2)), 2, None)
        self.assertEqual(state.load(checker._Value(64, ('stack', 0)), 2, image), checker._Value(16, 0x0201))
        self.assertIsNone(state.load(checker._Value(64, ('stack', 2)), 2, image))
        self.assertEqual(state.load(checker._Value(64, ('stack', 4)), 4, image), checker._Value(32, 0x08070605))

    def test_bzero_outlined_probe_initializer_has_an_exact_bounded_extent(self):
        self.fixture.addresses['_bzero'] = 0x140000
        self.fixture.code['_sgpu_probe'] = [
            'sub sp, sp, #0x400', 'mov x19, sp', 'str x0, [sp]',
            'add x0, x19, #16', 'mov w1, #728', 'bl @_bzero',
            'ldrb w0, [x19, #738]', 'ret']
        symbol = '_sgpu_probe'
        code = checker._Code(self.fixture.assembly(symbol), symbol, self.fixture.addresses[symbol])
        names = {name: {value} for name, value in self.fixture.addresses.items()}
        flow = checker._Flow(code, checker._Image(self.fixture.kernel.read_bytes()), names)
        self.assertTrue(flow.returns(0))
        for length in ('#722', '#4097'):
            code_text = self.fixture.assembly(symbol).replace('#728', length)
            bad = checker._Code(code_text, symbol, self.fixture.addresses[symbol])
            self.assertFalse(checker._Flow(bad, checker._Image(self.fixture.kernel.read_bytes()), names).returns(0))

    def test_file_only_CTF_metadata_is_never_a_mapped_pointer_source(self):
        data = bytearray(self.fixture.kernel.read_bytes())
        struct.pack_into('<II', data, 16, 3, 216)
        struct.pack_into('<II16s4Q4I', data, 32 + 144, 0x19, 72, b'__CTF',
                         self.fixture.table, 0, 0x2100, 32, 7, 5, 0, 0)
        self.fixture.set_kernel(data)
        self.assertIs(self.fixture.audit()['target_clock_setup_and_restore_wiring_checked'], True)
        struct.pack_into('<Q', data, 32 + 72 + 32, 0)  # DATA_CONST also becomes file-only
        self.fixture.set_kernel(data)
        self.fixture.files.pop(str(self.fixture.folder / 'gpu-binary-audit.json'))
        self.reject('Ops')

    def test_original_exact_sha_success_private_checksum_and_diagnostics_gates_remain(self):
        for key, bad in (('headSha', 'b' * 40), ('status', 'in_progress'),
                         ('conclusion', 'failure'), ('repository_private', False)):
            with self.subTest(key=key):
                self.fixture = AuditFixture()
                run = self.fixture.folder / 'run.json'
                metadata = json.loads(run.read_text())
                metadata[key] = bad
                run.write_text(json.dumps(metadata))
                self.reject('exact CI')
        self.fixture = AuditFixture()
        self.fixture.files[str(self.fixture.kernel)] += b'changed'
        self.reject('checksum')
        for literal in LITERALS:
            with self.subTest(literal=literal):
                self.fixture = AuditFixture()
                self.fixture.set_kernel(self.fixture.kernel.read_bytes().replace(literal, b'X' * len(literal)))
                self.reject('contract')

    def test_failure_records_counter_reads_and_explicit_invalidation_cannot_be_dead_stubs(self):
        for symbol in ('_sgpu_failure', '_sgpu_kernel_wait_us', '_sgpu_cache_invalidate'):
            with self.subTest(symbol=symbol):
                self.fixture = AuditFixture()
                self.fixture.code[symbol].insert(0, 'ret')
                self.reject()

    def test_real_af863f9_mmio_blocks_when_local_artifacts_exist(self):
        folder = ROOT / 'out/ci-af863f9'
        if not (folder / 'sgpu_io_write32.asm').is_file():
            self.skipTest('optional private CI assembly absent; synthetic audit tests always run')
        for bits in (32, 64):
            for role in ('read', 'write'):
                symbol = f'_sgpu_io_{role}{bits}'
                text = (folder / (symbol[1:] + '.asm')).read_text()
                address = int(text.split(f' <{symbol}>:')[0].splitlines()[-1], 16)
                code = checker._Code(text, symbol, address)
                self.assertEqual(len(checker._mmio(code, bits, role == 'write')), 1)

    def test_real_af863f9_worker_vector_copy_startup_and_force_clean_link_when_available(self):
        folder = ROOT / 'out/ci-af863f9'
        kernel = folder / 'kernel/kernel.development.santoni'
        if not kernel.is_file():
            self.skipTest('optional private CI kernel absent; synthetic audit tests always run')
        image = checker._Image(kernel.read_bytes())
        nm = checker.subprocess.check_output(['llvm-nm', '--defined-only', str(kernel)], text=True, timeout=30)
        names, local = checker._symbols(nm), checker._symbols(nm, local=True)
        symbol = '_sgpu_kernel_thread'
        code = checker._Code((folder / 'sgpu_kernel_thread.asm').read_text(), symbol, next(iter(names[symbol])))
        callbacks, evidence = checker._ops_wiring(code, image, names, local)
        self.assertEqual(len(evidence['Ops_callbacks']), 12)
        self.assertIn(callbacks['_io_map'], local['_io_map'])  # The old kernel also has a global homonym.
        text = checker.subprocess.check_output([
            'llvm-objdump', '--disassemble', '--disassemble-symbols=_clean', str(kernel)], text=True, timeout=30)
        clean = checker._Code(text, '_clean', callbacks['_clean'])
        self.assertTrue(clean.calls_to(names['_CleanPoC_DcacheRegion_Force'], checker._Flow(clean, image, names).before))
        launch = checker._Code((folder / 'santoni_gpu_start.asm').read_text(), '_santoni_gpu_start',
                               next(iter(names['_santoni_gpu_start'])))
        flow = checker._Flow(launch, image, names)
        sites = launch.calls_to(names['_kernel_thread_start'], flow.before)
        self.assertTrue(sites)
        self.assertTrue(all(flow.before[pc].get('x0') == checker._Value(64, code.entry) for pc in sites))

    def test_real_022ef39_optimized_helpers_and_mutable_restore_edge_when_available(self):
        folder = ROOT / 'out/ci-022ef39'
        kernel = folder / 'kernel/kernel.development.santoni'
        if not (folder / 'gpu-binary-audit.json').is_file():
            self.skipTest('optional audited CI kernel absent; portable compiler-form regressions always run')
        image = checker._Image(kernel.read_bytes())
        names = checker._symbols(checker.subprocess.check_output(
            ['llvm-nm', '--defined-only', str(kernel)], text=True, timeout=30))
        for symbol in ('_checked_write32', '_checked_write64', '_branch_state', '_sgpu_probe'):
            code = checker._Code((folder / (symbol[1:] + '.asm')).read_text(), symbol, next(iter(names[symbol])))
            if symbol.startswith('_checked_write'):
                checker._helper_readback(code, image, names, int(symbol[-2:]))
            elif symbol == '_branch_state':
                checker._branch_poll(code, image, names)
            else:
                flow = checker._Flow(code, image, names)
                self.assertTrue(code.calls_to(names['_sgpu_smmu_restore'], flow.before))


class CacheAuditTests(unittest.TestCase):
    """Exercise the decoded cache gate without claiming hardware/VM emulation."""
    def setUp(self):
        self.fixture = f = AuditFixture()
        f.add_scm()
        extra = (*checker.CACHE_HELPERS, '_ml_set_interrupts_enabled', '_phystokv',
                 '_pmap_update_cache_attributes_locked', '_flush_mmu_tlb_region_asid_async',
                 '_arm_vm_physmap_slide', '_arm_vm_init', '_arm_vm_page_granular_prot')
        for i, name in enumerate(extra):
            f.addresses[name] = 0x1c0000 + 0x1000 * i
            f.code[name] = ['ret']
        data = bytearray(f.kernel.read_bytes())
        for offset, literal in ((0x2600, b'santonigpu_cache\0'),
                                (0x2620, b'santonigpu_zap\0'),
                                (0x2640, b'santonigpu_scm\0')):
            data[offset:offset + len(literal)] = literal
        data.extend(b'PAS CACHE RESULT\0NO SCM, NO GPU CONTINUATION\0')
        f.set_kernel(data)
        f.code['_sgpu_kernel_thread'][1:1] = [
            'mov w0, #3', 'bl @_sgpu_pas_cache_preflight', 'cbz w0, @cache_skip',
            'bl @_thread_terminate_self', 'ret', 'cache_skip:']
        f.code['_sgpu_pas_cache_preflight'] = [
            'cmp w0, #3', 'b.ne @off', 'sub sp, sp, #32',
            'str wzr, [sp]', 'str wzr, [sp, #4]', 'str wzr, [sp, #8]',
            'adr x0, 0x200600', 'mov x1, sp', 'mov w2, #4', 'bl @_PE_parse_boot_argn',
            'ldr w8, [sp]', 'cmp w8, #1', 'b.ne @skip',
            'adr x0, 0x200620', 'add x1, sp, #4', 'mov w2, #4', 'bl @_PE_parse_boot_argn',
            'adr x0, 0x200640', 'add x1, sp, #8', 'mov w2, #4', 'bl @_PE_parse_boot_argn',
            'ldr w8, [sp, #4]', 'cmp w8, #1', 'b.ne @handled',
            'ldr w8, [sp, #8]', 'cbnz w8, @handled', 'bl @_sgpu_pas_cache_trial_run',
            'handled:', 'add sp, sp, #32', 'mov w0, #1', 'ret',
            'skip:', 'add sp, sp, #32', 'off:', 'mov w0, #0', 'ret']
        f.code['_sgpu_pas_cached_release'] = [
            'ldrb w8, [x0, #20]', 'cbnz w8, @fail',
            'ldrb w8, [x0, #28]', 'cbnz w8, @fail',
            'bl @_sgpu_pas_cached_views', 'cbz w0, @fail',
            'bl @_pmap_santoni_pas_cache_control', 'cbz w0, @fail',
            'bl @_sgpu_pas_cached_views', 'cbz w0, @fail',
            'bl @_sgpu_pas_release', 'ret', 'fail:', 'mov w0, #0', 'ret']
        f.code['_sgpu_pas_cache_trial_run'] = [
            'bl @_sgpu_pas_allocate', 'cbz w0, @cleanup',
            'bl @_sgpu_pas_allocate', 'cbz w0, @cleanup',
            'bl @_sgpu_pas_cached_prepare', 'cbz w0, @cleanup',
            'bl @_sgpu_pas_cached_prepare', 'cbz w0, @cleanup',
            'cleanup:', 'bl @_sgpu_pas_cached_release', 'cbnz w0, @second',
            'mov w8, #1', 'second:', 'bl @_sgpu_pas_cached_release',
            'cbnz w0, @done', 'mov w8, #2', 'done:', 'ret']
        f.code['_sgpu_pas_cached_prepare'] = [
            'bl @_sgpu_pas_cached_views', 'cbz w0, @fail',
            'bl @_pmap_santoni_pas_cache_control', 'cbz w0, @fail',
            'bl @_CleanPoC_DcacheRegion_Force',
            'bl @_pmap_santoni_pas_cache_control', 'cbz w0, @fail',
            'bl @_sgpu_pas_cached_views', 'cbz w0, @fail',
            'mov w0, #1', 'ret', 'fail:', 'mov w0, #0', 'ret']
        f.code['_sgpu_pas_cached_views'] = [
            'bl @_pmap_find_phys', 'bl @_phystokv', 'bl @_sgpu_pas_cache_view',
            'cbz w0, @fail', 'b @_sgpu_pas_cache_view', 'fail:', 'mov w0, #0', 'ret']
        f.code['_sgpu_pas_cache_view'] = [
            'mov x19, x0', 'mov x20, x1', 'mov w21, w2', 'mov w0, #0',
            'bl @_ml_set_interrupts_enabled', 'mov w22, w0',
            'dsb ish', 'at s1e1r, x19', 'isb', 'mrs x23, PAR_EL1',
            'mov w0, w22', 'bl @_ml_set_interrupts_enabled',
            'tbnz x23, #0, @fail', 'and x8, x23, #0x0000fffffffff000',
            'cmp x8, x20', 'b.ne @fail', 'lsr x8, x23, #56',
            'cmp w8, w21', 'cset w0, eq', 'ret', 'fail:', 'mov w0, #0', 'ret']
        f.code['_pmap_santoni_pas_cache_control'] = [
            'str x8, [x19]', 'dsb ishst', 'bl @_flush_mmu_tlb_region_asid_async',
            'bl @_pmap_update_cache_attributes_locked', 'dsb ish', 'isb', 'ret']
        f.code['_arm_vm_init'] = [
            'mov w3, #0', 'mov w4, #3', 'bl @_arm_vm_physmap_slide',
            'mov w3, #0', 'mov w4, #0', 'bl @_arm_vm_physmap_slide', 'ret']
        f.code['_arm_vm_physmap_slide'] = [
            'mov w6, w4', 'mov w4, w3', 'mov w3, #1', 'mov w5, #1',
            'bl @_arm_vm_page_granular_prot', 'ret']

    def audit(self):
        f = self.fixture
        names = {name: {address} for name, address in f.addresses.items()}
        codes = {name: checker._Code(f.assembly(name), name, f.addresses[name])
                 for name in (*checker.CACHE_HELPERS, '_sgpu_kernel_thread')}
        return checker.audit_cache(codes, checker._Image(f.kernel.read_bytes()), names,
                                   checker, f.assembly('_arm_vm_init'), slide=f.assembly('_arm_vm_physmap_slide'))

    def test_cache_wiring_positive_is_not_hardware_or_authentication(self):
        report = self.audit()
        self.assertTrue(report['mode3_cache1_zap1_scm0'])
        self.assertIn('hardware unproven', report['scope'])
        self.assertEqual(report['bootstrap_physmap_granules'], [3, 0])

    def test_full_audit_publishes_cache_gate_only_after_all_checks(self):
        self.assertTrue(self.fixture.audit()['PAS_cache_preflight_wiring_checked'])
        self.setUp()
        self.fixture.code['_sgpu_pas_cache_view'][6] = 'nop'
        with self.assertRaises(ValueError):
            self.fixture.audit()
        self.assertNotIn(str(self.fixture.folder / 'gpu-binary-audit.json'), self.fixture.files)

    def test_cache_caller_graph_cannot_bypass_the_independent_entry(self):
        for callee in checker.CACHE_HELPERS[1:]:
            with self.subTest(callee=callee):
                self.setUp()
                self.fixture.code['_sgpu_kernel_thread'].insert(1, 'bl @' + callee)
                with self.assertRaisesRegex(ValueError, 'bypasses'):
                    self.audit()

    def test_bootstrap_decoder_and_interior_entry_are_fail_closed(self):
        for body in (
                ['unknown', 'mov w4, #3', 'bl @_arm_vm_physmap_slide',
                 'mov w4, #0', 'bl @_arm_vm_physmap_slide', 'ret'],
                ['cbz w0, @bypass', 'mov w4, #3', 'bypass:', 'bl @_arm_vm_physmap_slide',
                 'mov w4, #0', 'bl @_arm_vm_physmap_slide', 'ret'],
                ['mov w4, #3', 'bl @_arm_vm_physmap_slide',
                 'mov w4, #0', 'bl @_arm_vm_physmap_slide', 'udf #0', 'ret']):
            with self.subTest(body=body):
                self.setUp()
                self.fixture.code['_arm_vm_init'] = body
                with self.assertRaises(ValueError):
                    self.audit()

    def test_private_physmap_ABI_requires_proven_granule_and_fixed_permissions(self):
        f = self.fixture
        f.code['_arm_vm_init'] = [line.replace('w4', 'w3') for line in f.code['_arm_vm_init']]
        f.code['_arm_vm_physmap_slide'] = [
            'mov w6, w3', 'mov w4, #0', 'mov w3, #1', 'mov w5, #1',
            'bl @_arm_vm_page_granular_prot', 'ret']
        self.assertEqual(self.audit()['bootstrap_physmap_ABI'], 'private AP_RWNA=0 specialization')
        valid = list(f.code['_arm_vm_physmap_slide'])
        for old, new in (('mov w6, w3', 'mov w6, w2'), ('mov w4, #0', 'mov w4, #2'),
                         ('mov w3, #1', 'mov w3, #0'), ('mov w5, #1', 'mov w5, #0')):
            with self.subTest(mutation=new):
                f.code['_arm_vm_physmap_slide'] = [new if line == old else line for line in valid]
                with self.assertRaises(ValueError):
                    self.audit()

    def test_inlined_leaf_TLBI_and_common_store_barrier_are_inspected(self):
        f = self.fixture
        provider = '_pmap_santoni_pas_cache_control'
        valid = ['str x8, [x19]', 'b @barrier', 'barrier:', 'dsb ishst',
                 'tlbi vale1is, x20', 'bl @_pmap_update_cache_attributes_locked',
                 'dsb ish', 'isb', 'ret']
        f.code[provider] = valid
        self.assertEqual(len(self.audit()['pmap_inline_leaf_TLBI']), 1)
        for old, new in (('tlbi vale1is, x20', 'nop'), ('tlbi vale1is, x20', 'tlbi vale1is, xzr'),
                         ('dsb ishst', 'nop'), ('str x8, [x19]', 'str xzr, [x19]')):
            with self.subTest(mutation=new):
                f.code[provider] = [new if line == old else line for line in valid]
                with self.assertRaises(ValueError):
                    self.audit()

    def test_bootstrap_outlined_terminal_chain_is_verified_not_named(self):
        f = self.fixture
        for i, symbol in enumerate(('_arm_vm_init.cold.1', '_OUTLINED_FUNCTION_7', '_panic')):
            f.addresses[symbol] = 0x310000 + i * 0x1000
            f.code[symbol] = ['ret']
        f.code['_arm_vm_init.cold.1'] = ['bl @_OUTLINED_FUNCTION_7']
        f.code['_OUTLINED_FUNCTION_7'] = ['str x8, [sp]', 'b @_panic']
        f.code['_arm_vm_init'] += ['bl @_arm_vm_init.cold.1']
        self.assertTrue(f.audit()['PAS_cache_preflight_wiring_checked'])
        for body in (['ret'], ['bl @_printf', 'b @_panic'], ['b @_OUTLINED_FUNCTION_7'],
                     ['unknown', 'b @_panic']):
            with self.subTest(body=body):
                f.code['_OUTLINED_FUNCTION_7'] = body
                with self.assertRaises(ValueError):
                    f.audit()

    def test_cache_gate_rejects_each_unsafe_decoded_change(self):
        changes = [
            ('_sgpu_pas_cache_preflight', 'cmp w0, #3', 'cmp w0, #2'),
            ('_sgpu_pas_cache_preflight', 'cmp w8, #1', 'cmp w8, #2'),
            ('_sgpu_pas_cache_preflight', 'adr x0, 0x200600', 'adr x0, 0x200620'),
            ('_sgpu_pas_cache_preflight', 'add x1, sp, #8', 'add x1, sp, #4'),
            ('_sgpu_pas_cache_preflight', 'cbnz w8, @handled', 'nop'),
            ('_sgpu_pas_cached_release', 'ldrb w8, [x0, #20]', 'mov w8, #0'),
            ('_sgpu_pas_cached_release', 'ldrb w8, [x0, #28]', 'mov w8, #0'),
            ('_sgpu_pas_cache_trial_run', 'cbz w0, @cleanup', 'nop'),
            ('_sgpu_pas_cached_prepare', 'cbz w0, @fail', 'nop'),
            ('_sgpu_pas_cached_release', 'cbz w0, @fail', 'nop'),
            ('_sgpu_kernel_thread', 'cbz w0, @cache_skip', 'b @cache_skip'),
            ('_sgpu_pas_cache_view', 'dsb ish', 'nop'),
            ('_sgpu_pas_cache_view', 'at s1e1r, x19', 'at s1e1w, x19'),
            ('_sgpu_pas_cache_view', 'mov w0, w22', 'mov w0, #1'),
            ('_sgpu_pas_cache_view', 'tbnz x23, #0, @fail', 'nop'),
            ('_sgpu_pas_cache_view', 'cmp x8, x20', 'cmp x8, x8'),
            ('_sgpu_pas_cache_view', 'cmp w8, w21', 'cmp w8, w8'),
            ('_pmap_santoni_pas_cache_control', 'str x8, [x19]', 'str xzr, [x19]'),
            ('_pmap_santoni_pas_cache_control', 'dsb ishst', 'nop'),
            ('_pmap_santoni_pas_cache_control', 'bl @_pmap_update_cache_attributes_locked', 'nop'),
            ('_pmap_santoni_pas_cache_control', 'bl @_flush_mmu_tlb_region_asid_async', 'nop'),
            ('_pmap_santoni_pas_cache_control', 'isb', 'nop'),
            ('_arm_vm_init', 'mov w4, #0', 'mov w4, #3'),
            ('_arm_vm_init', 'mov w3, #0', 'mov w3, #2'),
        ]
        for symbol, old, new in changes:
            with self.subTest(symbol=symbol, mutation=new):
                self.setUp()
                body = self.fixture.code[symbol]
                body[body.index(old)] = new
                with self.assertRaises(ValueError):
                    self.audit()

    def test_cache_only_layer_rejects_SMC_unknowns_and_unreviewed_calls(self):
        for symbol in checker.CACHE_HELPERS:
            for op in ('smc #0', 'unknown', 'bl @_sgpu_scm_probe'):
                with self.subTest(symbol=symbol, instruction=op):
                    self.setUp()
                    self.fixture.code[symbol].insert(0, op)
                    with self.assertRaises(ValueError):
                        self.audit()

    def test_old_kernel_cannot_earn_cache_certificate(self):
        f = AuditFixture()
        self.assertFalse(f.audit()['PAS_cache_preflight_wiring_checked'])

    def test_each_cache_helper_cannot_become_a_constant_success_stub(self):
        for symbol in checker.CACHE_HELPERS:
            with self.subTest(symbol=symbol):
                self.setUp()
                self.fixture.code[symbol] = ['mov w0, #1', 'ret']
                with self.assertRaises(ValueError):
                    self.audit()

    def test_mutating_cache_helpers_forget_previous_object_state(self):
        f = self.fixture
        names = {name: {address} for name, address in f.addresses.items()}
        for symbol, size in (('_sgpu_pas_allocate', 24), ('_sgpu_pas_release', 24),
                             ('_sgpu_pas_cached_prepare', 32), ('_sgpu_pas_cached_release', 32)):
            with self.subTest(symbol=symbol):
                caller = '_cache_mutation_caller'
                f.addresses[caller] = 0x300000
                f.code[caller] = ['bl @' + symbol, 'ret']
                code = checker._Code(f.assembly(caller), caller, f.addresses[caller])
                state = checker._initial(caller)
                base = checker._Value(64, ('probe', 0x6000))
                state.put('x0', base)
                state.store(base, size, checker._Value(size * 8, 0))
                flow = checker._Flow(code, checker._Image(f.kernel.read_bytes()), names, initial=state)
                self.assertIsNone(flow.before[code.entry + 4].load(base, size, flow.image))


if __name__ == '__main__':
    unittest.main(verbosity=2)
