#!/usr/bin/env python3
"""Own-kernel live worker/copy proof; GPU/MMIO responses remain modeled.

Large pure CPU helpers execute their identical inspected A53 words in a
private EL0 image copy. All live ownership, table linking, register checks,
publication, fences and failure paths execute in the bounded interpreter.
The retained legacy bootstrap result uses the existing, explicit stable-
storage model boundary; this is never an actual phone/GPU result.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import ast
import types

from santoni_gpu_binary_model import integer
from santoni_gpu_launcher_replay import require
from santoni_gpu_launcher_replay import LauncherMachine
from santoni_gpu_native_cpu import PureCPU, PURE
from santoni_gpu_scalar_certificate import load_inputs, identity_of
from santoni_gpu_session_replay import SessionModel, OFF
from santoni_gpu_render_audit import HELPERS, LIVE_HELPERS, CP_HELPER
from santoni_gpu_render_audit import LIVE_STORAGE
from santoni_gpu_binary_model import Machine, vector_step

TABLES, PIXELS, PAGES, INPUT, OUTPUT = 0x62000000, 0x63000000, 0x64002000, 0x64000000, 0x64001000
BYTES, GVA = 3932160, 0x01200000
WRITES = ((4, 0x20c8, 3), (5, 0xc00, 0x20000), (5, 0x8000, 0x1126),
          (5, 0x8610, 1), (5, 0x87f0, 0), (5, 0x8000, 0x1127),
          (5, 0xc00, 0), (4, 0x20c8, 0), (4, 0x201c, 243), (4, 0x201c, 316))
CP_CASES = ('halt-echo', 'halt-response-bit2', 'halt-response-bit3', 'resume-response',
            'halt-unknown', 'halt-one-request', 'halt-other-request', 'halt-response-only',
            'resume-denied', 'resume-unknown', 'resume-one-request', 'lost-stop-after-cb',
            'unknown-stop-after-tlbi', 'halt-busy')
CP_PASSES = ('success', 'halt-echo', 'halt-response-bit2', 'halt-response-bit3', 'resume-response')


def live_vector_step(op,args,state,memory,e):
    if op in ('uzp1.8h','uzp1.4s') and len(args)==3:
        bits,lanes=(16,8) if op=='uzp1.8h' else (32,4)
        mask=(1<<bits)-1;a=integer(state,args[1]);b=integer(state,args[2])
        values=[(a>>(bits*i))&mask for i in range(0,lanes,2)] + [(b>>(bits*i))&mask for i in range(0,lanes,2)]
        state.put(args[0],e._Value(128,sum(v<<(bits*i) for i,v in enumerate(values))));return True
    if op in ('cmeq.2s','cmeq.4s') and len(args)==3 and args[2]=='#0':
        lanes=2 if op=='cmeq.2s' else 4;value=integer(state,args[1])
        result=sum((0xffffffff if (value>>(32*i))&0xffffffff==0 else 0)<<(32*i) for i in range(lanes))
        state.put(args[0],e._Value(lanes*32,result));return True
    return vector_step(op,args,state,memory,e)


class LiveMachine(LauncherMachine):
    pass


LiveMachine.run=types.FunctionType(LauncherMachine.run.__code__,
    {**LauncherMachine.run.__globals__,'vector_step':live_vector_step},
    LauncherMachine.run.__name__,LauncherMachine.run.__defaults__,LauncherMachine.run.__closure__)


def incoming_argument_used(code, index):
    """Conservative CFG def/use check for LLVM's eliminated integer arguments."""
    register = 'x' + str(index)
    pending, seen = [(code.entry, False)], set()
    while pending:
        pc, defined = pending.pop()
        if (pc, defined) in seen: continue
        seen.add((pc, defined)); op, args = code.ins[pc]
        normalized = lambda text: set('x' + n for n in re.findall(r'\b[wx]([0-9]+)\b', text))
        writes = set()
        first = 2 if op == 'ldp' else 1
        if op not in ('cmp','cmn','tst','str','stur','stp','cbz','cbnz','tbz','tbnz','ret','b','bl') and not op.startswith('b.'):
            writes = normalized(','.join(args[:first]))
            reads = normalized(','.join(args[first:]))
        else: reads = normalized(','.join(args))
        if register in reads and not defined: return True
        defined = defined or register in writes
        pending += [(target, defined) for target in code.succ[pc]]
    return False


class LiveAdapter:
    """Actual option/allocation/worker code; core result consumed at its proven ABI."""
    OPS, FW, REPORT = 0x65000000, 0x65001000, 0x65002000

    def __init__(self, codes, image, names, e, native, case):
        self.e, self.names, self.native, self.case = e, names, native, case
        selected = (*HELPERS, *LIVE_HELPERS, '_sgpu_kernel_thread', '_sgpu_stock_options',
                    '_sgpu_pixel_options', '_sgpu_g3_options', '_sgpu_session_options',
                    '_sgpu_user_options', '_sgpu_user_test_options', '_sgpu_failure_summary',
                    '_sgpu_ui_options', '_sgpu_ui_publish','_sgpu_graphics_options')
        self.vm = LiveMachine({n: codes[n] for n in selected if n in codes}, image, names, e)
        self.m = self.vm.memory
        sizes = {n: 4 for n in LIVE_STORAGE}  # source uint32 flags; LLVM may narrow them
        sizes.update({'_sgpu_render_live': 9024, '_sgpu_render_tables_kva': 8,
                      '_sgpu_render_pixels_kva': 8, '_sgpu_render_page_pas': 15360,
                      '_sgpu_render_owned': 88, '_sg': 120, '_page_shift': 4,
                      '_page_size': 8, '_kernel_map': 8, '_kernel_pmap': 8})
        for n in ('_sgpu_ui_enabled', '_sgpu_ui_published','_sgpu_graphics_enabled','_sgpu_graphics_published'):
            if n in names:
                sizes[n] = 4
        spans = []
        for name, size in sizes.items():
            require(len(names.get(name, ())) == 1, 'adapter global identity missing: ' + name)
            address = next(iter(names[name])); spans.append((address, address + size))
        merged = []
        for start, end in sorted(spans):
            if merged and start <= merged[-1][1]: merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else: merged.append((start, end))
        for start, end in merged: self.m.map(start, end - start)
        self.sg = next(iter(names['_sg']))
        self.m.put(next(iter(names['_page_shift'])), 12)
        self.m.put(next(iter(names['_page_size'])), 4096, 8)
        self.m.put(next(iter(names['_kernel_map'])), 0x71000000, 8)
        self.m.put(next(iter(names['_kernel_pmap'])), 0x72000000, 8)
        mode = 1 if case == 'mode1' else 2 if case == 'mode2' else 3
        self.m.put(self.sg + 84, mode)
        self.options = {'santonigpu_stock': int(mode == 3), 'santonigpu_pixels': int(mode == 3),
            'santonigpu_submit': int(mode == 3), 'santonigpu_session': int(mode == 3),
            'santonigpu_user': 0, 'santonigpu_user_test': 0, 'santonigpu_user_exec': 0,
            'santonigpu_zap': 0, 'santonigpu_scm': 0, 'santonigpu_cache': 0,
            'santonigpu_render': 0 if case == 'off' else 2 if case == 'bad-enable' else 1,
            'santonigpu_ui': 0,'santonigpu_graphics':0}
        if case == 'foreign-client': self.options['santonigpu_user'] = 1
        if case == 'scm': self.options['santonigpu_scm'] = 1
        for address, size in ((self.OPS, 120), (self.FW, 64), (self.REPORT, 192)):
            self.m.map(address, size)
        self.allocations, self.frees, self.pmaps, self.core_calls, self.other_entries, self.terminated = [], [], 0, 0, 0, 0
        self.parses = []
        self.vm.external = self.external

    def address(self, name): return next(iter(self.names[name]))

    def text(self, address):
        data = bytearray()
        for i in range(256):
            value = self.m.get(address + i, 1)
            if value == 0: return data.decode()
            data.append(value)
        raise ValueError('adapter string is not bounded/terminated')

    def external(self, target, state, probe=False, before=None):
        name = self.vm.by_address.get(target)
        handled = ('_PE_parse_boot_argn', '_kmem_alloc', '_kmem_free', '_kmem_alloc_guard', '_kmem_free_guard', '_pmap_find_phys',
            '_printf', '_santoni_gpu_user_launch_options_ok', '_santoni_gpu_user_launch_worker_ready',
            '_sgpu_kernel_wait_us', '_sgpu_pas_cache_preflight', '_sgpu_scm_capability_probe',
            '_sgpu_zap_allocation_preflight', '_SecureDTLookupEntry', '_SecureDTGetProperty',
            '_sgpu_render_live_start', '_sgpu_probe', '_sgpu_session_start', '_sgpu_session_loop',
            '_sgpu_session_failure_result', '_thread_terminate_self', '_memcpy', '_memmove', '_bzero',
            '_sgpu_render_memory_valid', '_clock_interval_to_deadline', '_assert_wait_deadline', '_thread_block')
        if name not in handled: return False
        if probe: return True
        a = lambda i: integer(before, 'x' + str(i))
        value = 0
        if name == '_sgpu_render_memory_valid':
            value = self.native.run(name, self.m, (a(0),))
        elif name == '_PE_parse_boot_argn':
            option = self.text(a(0)); require(option in self.options and a(2) == 4, 'adapter option ABI differs')
            self.parses.append(option); self.m.put(a(1), self.options[option]); value = 1
        elif name in ('_kmem_alloc','_kmem_alloc_guard'):
            expected = 28672 if not self.allocations else 7864320
            size = a(1) if name=='_kmem_alloc_guard' else a(2)
            require(a(0) == 0x71000000 and size == expected and len(self.allocations) < 2,
                    'allocator extent/map differs')
            if name=='_kmem_alloc_guard':
                require((a(2),a(3),a(4))==(0,0x8040,3),'allocator alignment/zero/data/tag ABI differs')
            if self.case == 'alloc-fail' and self.allocations:
                value = 3
                if name=='_kmem_alloc_guard':state.put('x1',self.e._Value(64,0))
            else:
                address = TABLES if not self.allocations else PIXELS
                self.m.map(address, expected)
                if name=='_kmem_alloc_guard':state.put('x1',self.e._Value(64,address))
                else:self.m.put(a(1),address,8)
                self.allocations.append((address, expected))
        elif name in ('_kmem_free','_kmem_free_guard'):
            require(a(0) == 0x71000000 and (a(1), a(2)) in self.allocations and a(1) not in self.frees,
                    'free does not match a fresh owned span')
            if name=='_kmem_free_guard':require((a(3),a(4))==(0,0),'free guard flags/identity ABI differs')
            self.frees.append(a(1))
        elif name == '_pmap_find_phys':
            require(a(0) == 0x72000000, 'pmap identity differs')
            self.pmaps += 1
            for base, size in self.allocations:
                if base <= a(1) < base + size:
                    index = (a(1) - base) // 4096
                    value = ((0xa0000000 if base == TABLES else 0xa1000000) + index * 8192) >> 12
                    if self.case == 'last-page' and base == PIXELS and index == 1919: value = 0
                    break
            else: raise ValueError('pmap touched a page outside owned spans')
        elif name == '_sgpu_render_live_start':
            require((a(1), a(2), a(3), a(4), a(5)) == (3, 1, self.FW, 64, self.address('_sgpu_render_owned')),
                    'adapter/core opt-in/firmware/owned descriptor ABI differs')
            require(self.pmaps == 1927 and len(self.allocations) == 2, 'core called without complete per-page allocation')
            self.core_calls += 1
            self.m.put(a(6) + 56, 1, 1)  # exact kernel core proof: held legacy allocation
            self.m.write(a(7), bytes(84))
            for off, datum in ((0, 12), (8, 2), (12, 2), (16, 2), (20, 316), (24, 1843200)):
                self.m.put(a(7) + off, datum)
            for off in (28, 29, 30, 31, 32): self.m.put(a(7) + off, 1, 1)
            value = 1
        elif name in ('_sgpu_probe', '_sgpu_session_start', '_sgpu_session_loop'):
            self.other_entries += 1
        elif name == '_sgpu_session_failure_result': self.m.write(a(0), bytes(76))
        elif name == '_SecureDTLookupEntry':
            require(a(0) == 0 and self.text(a(1)) == '/chosen', 'firmware entry lookup differs')
            self.m.put(a(2), 0x73000000, 8)
            value = 1  # actual XNU kSuccess value, checked at the compiled callsite
        elif name == '_SecureDTGetProperty':
            require(a(0) == 0x73000000 and self.text(a(1)) == 'santoni-gpu-firmware', 'firmware property differs')
            self.m.put(a(2), self.FW, 8); self.m.put(a(3), 64)
            value = 1
        elif name in ('_santoni_gpu_user_launch_options_ok', '_santoni_gpu_user_launch_worker_ready'): value = 1
        elif name == '_sgpu_kernel_wait_us': require(a(1) == 40000000, 'normal input/storage delay changed')
        elif name == '_clock_interval_to_deadline':
            require((a(0),a(1))==(40000000,1000) and self.m.locate(a(2),8) is not None,
                    'worker delay duration/unit/stack storage differs')
            self.m.put(a(2),12345678,8)
        elif name == '_assert_wait_deadline':
            require((a(0),a(1),a(2))==(self.sg+92,0,12345678), 'worker delay event/deadline ABI differs')
        elif name == '_thread_block': require(a(0)==0,'worker delay continuation differs')
        elif name == '_thread_terminate_self': self.terminated += 1
        elif name in ('_memcpy', '_memmove', '_bzero'):
            length = a(1) if name == '_bzero' else a(2)
            require(length <= 28672 and self.m.locate(a(0), length) is not None, 'adapter memory primitive exceeds object')
            self.m.write(a(0), bytes(length) if name == '_bzero' else self.m.bytes(a(1), length, partial=True)); value = a(0)
        # printf and disabled PAS/SCM preflight calls are modeled CPU-only boundaries.
        state.put('x0', self.e._Value(64, value)); return True

    def run(self):
        self.vm.run('_sgpu_kernel_thread', (0, 0), budget=1500000)
        require(self.terminated == 1, 'worker does not terminate exactly once')
        if self.case == 'success':
            require(self.core_calls == 1 and self.other_entries == 0 and self.frees == [] and self.pmaps == 1927,
                    'live worker allocation/dispatch/retention differs')
        elif self.case == 'off':
            require(not self.allocations and self.core_calls == 0 and self.other_entries == 1, 'disabled render changed existing route')
        elif self.case in ('alloc-fail', 'last-page'):
            require(self.core_calls == 0 and self.other_entries == 0 and len(self.frees) == len(self.allocations),
                    'failed owned allocation reached GPU or leaked unexposed spans')
        else:
            require(not self.allocations and self.core_calls == 0 and self.other_entries == 0,
                    'invalid render role reached hardware/allocator')
        return {'success': True, 'case': self.case, 'per_page_queries': self.pmaps,
                'allocations': self.allocations, 'frees': self.frees, 'core_calls': self.core_calls,
                'hardware_verified': False}


class LiveModel(SessionModel):
    def __init__(self, codes, image, names, e, native, scenario):
        extra = (*HELPERS, *LIVE_HELPERS, CP_HELPER, '_consume', '_poll', '_read32', '_write32', '_wait_us',
                 '_sgpu_pixel_fence', '_sgpu_failure', '_faults', '_has_fault')
        super().__init__(codes, image, names, e, extra=extra)
        self.vm.__class__ = LauncherMachine
        self.vm.atomic_events = []
        self.native, self.scenario = native, scenario
        self.cp_readback_v2 = CP_HELPER in codes
        self.cp_reads = 0
        self.live = next(iter(names['_sgpu_render_live']))
        self.m.map(self.live, 9024)
        self.m.map(INPUT, 88); self.m.map(OUTPUT, 84)
        self.m.map(TABLES, 28672); self.m.map(PIXELS, 2 * BYTES, fill=0xa5); self.m.map(PAGES, 1920 * 8)
        for off, value in ((0, TABLES), (8, PIXELS), (16, PAGES)):
            self.m.put(INPUT + off, value, 8)
        for i in range(7): self.m.put(INPUT + 24 + i * 8, 0xa0000000 + i * 8192, 8)
        for i in range(1920): self.m.put(PAGES + i * 8, 0xa1000000 + i * 8192, 8)
        self.m.put(INPUT + 80, 1920)
        self.regs.update({(5, 0x20): (1 << 30) | (1 << 27) | 4, (5, 0x800): 1 << 31,
                          (5, 0x8610): 0, (5, 0x87f0): 0, (5, 0x87f4): 0})
        self.regs[5, 0x8058] = 0x400
        self.write_index, self.frame = 0, 0
        self.old_dma = bytearray(98304); self.tables_dma = bytearray(28672); self.pixels_dma = bytearray(2 * BYTES)
        self.pure_calls = []
        self.after_bootstrap = self.seed_legacy
        self.vm.external = self.external_live
        self.vm.observe = None

    def seed_legacy(self, model):
        m = self.m
        m.put(self.POOL, 0x98002003, 8)
        m.put(self.POOL + 4096 + 8 * 8, 0x98004003, 8)
        for slot, physical, rw in ((0, 7, False), (16, 8, False), (32, 3, False),
                                   (48, 4, True), (64, 5, False), (80, 6, True)):
            m.put(self.POOL + 8192 + slot * 8, (0x98000000 + physical * 8192) |
                  self.PTE | ((1 if rw else 3) << 6), 8)
        m.put(self.POOL + 4 * 4096 + 768, 0xa5052d01)
        self.old_dma[:] = self.bytes(self.POOL, 98304)

    def bytes(self, address, length):
        return b''.join(self.m.bytes(address + i, min(65536, length - i)) for i in range(0, length, 65536))

    def physical(self, pa):
        for start, count, data in ((0x98000000, 24, self.old_dma),
                                   (0xa0000000, 7, self.tables_dma), (0xa1000000, 1920, self.pixels_dma)):
            offset = pa - start
            if 0 <= offset < count * 8192 and offset % 8192 < 4096:
                return data, (offset // 8192) * 4096 + offset % 8192
        raise ValueError('modeled GPU addressed an unowned physical page')

    def gpu(self, address, write=False):
        require(self.regs[5, 0x8000] == 0x1127 and self.regs[5, 0xc00] == 0, 'modeled GPU lost translated CB0')
        table, base = self.physical(0x98000000)
        for level, shift in enumerate((30, 21, 12)):
            pte = int.from_bytes(table[base + ((address >> shift) & 511) * 8:
                                       base + ((address >> shift) & 511) * 8 + 8], 'little')
            require(pte & 3 == 3 and (not write or level != 2 or not pte & 128), 'modeled GPU guard/permission failure')
            pa = pte & 0x0000fffffffff000
            table, base = self.physical(pa + (address & 4095 if level == 2 else 0))
        return table, base

    def gpu_word(self, address, value):
        data, off = self.gpu(address, True); data[off:off + 4] = value.to_bytes(4, 'little')

    def render(self, end):
        start = end - 73
        words = [int.from_bytes(self.old_dma[12288 + (start + i) * 4:12288 + (start + i + 1) * 4], 'little')
                 for i in range(73)]
        source = destination = 0
        i = 0
        while i < len(words):
            header = words[i]; i += 1
            count = header & (127 if header >> 28 == 4 else 0x3fff)
            require(i + count <= len(words), 'modeled command count exceeds immutable snapshot')
            if header >> 28 == 4:
                reg = header >> 8 & 0x3ffff
                if reg in (0x2107, 0x2110):
                    require(count == 9 and words[i] == 0x30 and words[i + 2] == 0 and words[i + 3] == 0xf0000030,
                            'full BGRA format/pitch/address-high differs')
                    if reg == 0x2107: source = words[i + 1]
                    else: destination = words[i + 1]
            else:
                require(header >> 28 == 7, 'unknown modeled GPU packet type')
                op = header >> 16 & 127
                if op == 0x2c:
                    require(words[i:i + 5] == [1, 0, 0x04ff02cf, 0, 0x04ff02cf] and
                            source == GVA + 4096 and destination == GVA + 962 * 4096,
                            'full owned copy bounds/rectangle differ')
                    for y in range(1280):
                        offset = 0
                        while offset < 2880:
                            a, b = source + y * 3072 + offset, destination + y * 3072 + offset
                            n = min(4096 - (a & 4095), 4096 - (b & 4095), 2880 - offset)
                            s, so = self.gpu(a); d, do = self.gpu(b, True)
                            d[do:do + n] = s[so:so + n]; offset += n
                    self.frame += 1
                    if self.scenario == 'bad-pixel': self.pixels_dma[BYTES] ^= 1
                    if self.scenario == 'bad-padding': self.pixels_dma[BYTES + 2880] ^= 1
                elif op == 0x46:
                    require(count == 4 and words[i + 1] == GVA and words[i + 2] == 0, 'private fence address differs')
                    if words[i] == 0x1d: self.gpu_word(GVA, 0)
                    else:
                        require(words[i] == 4 and words[i + 3] == self.frame, 'private fence sequence differs')
                        if self.scenario != 'no-fence': self.gpu_word(GVA, self.frame + int(self.scenario == 'wrong-fence'))
                else: require(op in (0x26, 0x6c), 'unknown modeled GPU opcode')
            i += count
        self.regs[4, 0x2018] = end
        self.regs[4, 0x13d4] = 0
        if self.scenario == 'cb-fault': self.regs[5, 0x8058] = 2
        if self.scenario == 'global-fault': self.regs[5, 0x48] = 8

    def external_live(self, target, state, probe=False, before=None):
        name = self.vm.by_address.get(target)
        if name in PURE and name != '_sgpu_render_overlap':
            if probe: return True
            count = {'_sgpu_render_memory_valid': 1, '_sgpu_render_tables_valid': 1,
                     '_sgpu_render_plane_valid': 2, '_sgpu_render_live_pattern': 6,
                     '_sgpu_render_live_compare': 5, '_sgpu_render_live_tables':1,
                     '_sgpu_memory_validate':1}[name]
            arguments = []
            constants = {3:720,4:1280,5:3072} if name == '_sgpu_render_live_pattern' else (
                {2:720,3:1280,4:3072} if name == '_sgpu_render_live_compare' else {})
            for i in range(count):
                if i in constants and not incoming_argument_used(self.vm.codes[name],i):
                    arguments.append(constants[i])  # source geometry is frozen in actual inspected words
                else:
                    value = integer(before,'x'+str(i))
                    if i in constants: require(value == constants[i], 'live helper geometry ABI differs')
                    arguments.append(value)
            arguments = tuple(arguments)
            result = self.native.run(name, self.m, arguments)
            if name == '_sgpu_render_live_pattern' and result:
                expected = bytearray(BYTES); passno = arguments[2]
                for y in range(1280):
                    start = y * 3072
                    for x in range(720):
                        at = start + x * 4
                        expected[at:at+4] = bytes(((x*13+passno*17)&255,(y*11+passno*23)&255,
                                                   ((x+y)*7+passno*31)&255,255))
                    expected[start+2880:start+3072] = bytes([0x3c])*192
                require(self.bytes(arguments[0],BYTES) == expected and
                        self.bytes(arguments[1],BYTES) == bytes([0xa5])*BYTES,
                        'actual native pattern does not match independent full-frame oracle')
            self.pure_calls.append({'helper': name, 'arguments': list(arguments), 'result': result})
            state.put('w0', self.e._Value(32, result)); return True
        if name in ('_bzero', '_memcpy', '_memmove', '_memset'):
            if probe: return True
            a = lambda i: integer(before, 'x' + str(i))
            n = a(1) if name == '_bzero' else a(2)
            require(0 <= n <= 4194304 and self.m.locate(a(0), n) is not None, 'libc write exceeds owned object')
            data = self.bytes(a(1), n) if name in ('_memcpy', '_memmove') else bytes([a(1) & 255 if name == '_memset' else 0]) * n
            self.m.write(a(0), data); state.put('x0', self.e._Value(64, a(0))); return True
        if name == '_sgpu_bootstrap':
            return super().external(target, state, probe, before)
        if name not in ('_now_us', '_sgpu_kernel_wait_us', '_sgpu_io_read32', '_sgpu_io_read64',
                        '_sgpu_io_write32', '_clean', '_sgpu_cache_invalidate', '_trace'):
            return False
        if probe: return True
        a = lambda i: integer(before, 'x' + str(i))
        require(a(0) == 0, 'live callback context differs from retained adapter Ops')
        result = 0
        if name == '_now_us': result = self.clock
        elif name == '_sgpu_kernel_wait_us':
            require(0 < a(1) <= 100, 'live wait exceeded bounded polling slice'); self.clock += a(1)
        elif name == '_sgpu_io_read32':
            key = (a(1), a(2)); require(key in self.regs, 'unreviewed live register read'); result = self.regs[key]
            if key == (4, 0x20c8): self.cp_reads += 1
        elif name == '_sgpu_io_read64':
            key = (a(1), a(2)); require(key == (5, 0x8020), 'unreviewed wide live register read')
            result = self.regs[key] | (self.regs[5, 0x8024] << 32)
        elif name == '_sgpu_io_write32':
            write = (a(1), a(2), a(3))
            require(self.write_index < len(WRITES) and write == WRITES[self.write_index], 'live MMIO delta/order differs')
            self.write_index += 1
            if self.scenario == 'halt-denied' and write == WRITES[0]: return True
            if self.scenario == 'cb-enable-denied' and write == WRITES[5]: return True
            self.regs[write[:2]] = write[2]
            if self.cp_readback_v2 and write == WRITES[0]:
                self.regs[4, 0x20c8] = {'halt-echo':3, 'halt-response-bit2':7, 'halt-response-bit3':11,
                    'halt-unknown':19, 'halt-one-request':13, 'halt-other-request':14,
                    'halt-response-only':12}.get(self.scenario,15)
                if self.scenario == 'halt-busy': self.regs[4, 0x13d4] = 2
            if self.cp_readback_v2 and write == WRITES[7]:
                self.regs[4, 0x20c8] = {'resume-response':12,'resume-denied':15,
                    'resume-unknown':16,'resume-one-request':1}.get(self.scenario,0)
            if self.scenario == 'lost-stop-after-cb' and write == WRITES[2]: self.regs[4, 0x20c8] = 14
            if self.scenario == 'unknown-stop-after-tlbi' and write == WRITES[3]: self.regs[4, 0x20c8] = 19
            if write == WRITES[4] and self.scenario == 'tlb-timeout': self.regs[5, 0x87f4] = 1
            if write[1] == 0x201c:
                if self.scenario == 'rptr-timeout' or self.scenario == 'second-timeout' and self.frame == 1: return True
                self.render(write[2])
        elif name == '_clean':
            address, n = a(1), a(2)
            if self.POOL <= address < self.POOL + 98304:
                require(n == 4096, 'legacy live clean extent differs'); self.old_dma[address - self.POOL:address - self.POOL + n] = self.bytes(address, n)
            elif TABLES <= address < TABLES + 28672:
                require(address == TABLES and n == 28672, 'prepared table clean extent differs'); self.tables_dma[:] = self.bytes(address, n)
            elif PIXELS <= address < PIXELS + 2 * BYTES:
                require(n == BYTES and address in (PIXELS, PIXELS + BYTES), 'pixel clean escapes BO')
                self.pixels_dma[address - PIXELS:address - PIXELS + n] = self.bytes(address, n)
            else:
                require(n == 292 and address == self.live + 4524, 'immutable command snapshot clean differs')
                if self.scenario == 'late-root': self.m.put(self.POOL + 4096 + 9 * 8, 0, 8)
        elif name == '_sgpu_cache_invalidate':
            address, n = a(1), a(2)
            if address == TABLES + 24576:
                require(n == 64, 'private fence invalidation differs'); self.m.write(address, self.tables_dma[24576:24640])
            elif address == PIXELS + BYTES:
                require(n == BYTES, 'destination invalidation differs')
                if self.scenario != 'lost-invalidate': self.m.write(address, self.pixels_dma[BYTES:])
            else: require((address, n) == (self.POOL + 4 * 4096 + 768, 64), 'unreviewed old fence invalidation')
        else:
            text = bytearray()
            for i in range(160):
                ch = self.m.get(a(1) + i, 1)
                if not ch: break
                text.append(ch)
            require(not text.startswith(b'before '), 'new live path introduces startup trace waits')
        state.put('x0', self.e._Value(64, result)); return True

    def run_live(self):
        value = self.vm.run('_sgpu_render_live_start', (self.OPS, 3, 1, 0, 0, INPUT, self.REPORT, OUTPUT), budget=3000000)
        successful = self.scenario in CP_PASSES
        require(value is not None and value.expr == int(successful), 'live terminal return differs')
        passed = self.m.get(OUTPUT + 32, 1)
        require(passed == int(successful), 'live passed field differs')
        if successful:
            require([self.m.get(OUTPUT + i * 4) for i in range(7)] == [12, 0, 2, 2, 2, 316, 1843200] and
                    self.write_index == 10 and self.m.get(OUTPUT + 30, 1) == 1, 'full live counters/retention differ')
        else:
            require(self.m.get(OUTPUT + 4) != 0 and self.m.get(OUTPUT + 30, 1) == 1, 'live failure lost first error/exposure')
            if self.scenario == 'late-root': require(self.m.get(OUTPUT + 8) == 0 and self.m.get(OUTPUT + 31, 1) == 0,
                                                      'late root mutation reached publication')
            if self.scenario == 'second-timeout': require(self.m.get(OUTPUT + 12) == 1, 'earlier completion lost')
            if self.scenario in CP_CASES:
                require(self.m.get(OUTPUT+8)==0 and self.m.get(OUTPUT+12)==0 and self.m.get(OUTPUT+31,1)==0,
                        'invalid CP handoff reached render publication')
                require(self.m.get(OUTPUT+44)==4, 'CP first failure attributed to another block')
                if self.scenario != 'halt-busy':
                    require(self.m.get(OUTPUT+48)==0x20c8 and self.m.get(OUTPUT+52)==0xfffffff3,
                            'CP readback failure lost the exact controlled-bit mask')
                if self.scenario in ('halt-unknown','halt-one-request','halt-other-request','halt-response-only','halt-busy'):
                    require(self.write_index==1 and self.m.get(OUTPUT)==5,
                            'unaccepted CP halt touched SID0/CB/new tables')
                    for i in range(4): require(self.m.get(self.POOL+4096+(9+i)*8,8)==0,'unaccepted stop published L2')
                if self.scenario in ('lost-stop-after-cb','unknown-stop-after-tlbi'):
                    require(self.m.get(OUTPUT+36)==3 and self.m.get(OUTPUT+72)==10000 and
                            self.m.get(OUTPUT+76)==10000 and self.cp_reads<=130,
                            'lost CP stop does not terminate on the hard poll budget')
                elif self.scenario != 'halt-busy':
                    require(self.m.get(OUTPUT+36)==2 and self.m.get(OUTPUT+72)==0 and self.m.get(OUTPUT+76)==0,
                            'first CP write readback failure was delayed or replaced')
        return {'success': True, 'visited_words': len(self.vm.visited), 'modeled_register_writes': self.write_index,
                'CP_readback_revision':2 if self.cp_readback_v2 else 1, 'CP_register_reads':self.cp_reads,
                'native_pure_helper_calls': self.pure_calls, 'hardware_verified': False}


def compatible_model_extension(old_path):
    """Only the already reviewed dispatcher extension may differ in model setup."""
    old = Path(old_path).read_text(); new = Path(__file__).read_text()
    def models(source):
        tree = ast.parse(source); kept = []
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name in ('LiveModel','LiveAdapter'):
                for method in node.body:
                    if isinstance(method, ast.FunctionDef) and method.name == '__init__':
                        exact = [ast.dump(n) for n in ast.parse(
                            'self.vm.__class__ = LauncherMachine\nself.vm.atomic_events = []').body]
                        method.body = [n for n in method.body if ast.dump(n) not in exact]
                        for part in ast.walk(method):
                            if isinstance(part, ast.Call) and isinstance(part.func, ast.Name) and part.func.id == 'LauncherMachine':
                                part.func.id = 'Machine'
                kept.append(node)
            elif isinstance(node, ast.FunctionDef) and node.name == 'incoming_argument_used': kept.append(node)
            elif isinstance(node, ast.Assign): kept.append(node)
        return ast.dump(ast.Module(body=kept,type_ignores=[]))
    require(models(old) == models(new), 'CINC compatibility path changed model semantics beyond dispatcher setup')
    return hashlib.sha256(old.encode()).hexdigest()


def compatible_core_only(old_path):
    old=Path(old_path).read_text();new=Path(__file__).read_text()
    def core(source):
        nodes=[n for n in ast.parse(source).body if isinstance(n,ast.Assign) and all(isinstance(t,ast.Name) for t in n.targets) or
               isinstance(n,ast.ClassDef) and n.name=='LiveModel' or
               isinstance(n,ast.FunctionDef) and n.name=='incoming_argument_used']
        return ast.dump(ast.Module(body=nodes,type_ignores=[]))
    require(core(old)==core(new),'adapter-only resume changed the passed live-core model')
    return hashlib.sha256(old.encode()).hexdigest()


def audit(ci, compatible_baseline=None, adapter_baseline=None):
    ci = Path(ci).resolve()
    base, codes, image, names, e = load_inputs(ci)
    require(all(n in codes for n in (*HELPERS, *LIVE_HELPERS)), 'live own-kernel helper decode missing')
    raw = (ci / 'kernel/kernel.development.santoni').read_bytes()
    native = PureCPU(codes, image, names, raw)
    old_hash = compatible_model_extension(compatible_baseline) if compatible_baseline else None
    core_hash = compatible_core_only(adapter_baseline) if adapter_baseline else None
    identity = {**identity_of(base), 'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'native_cpu_sha256': hashlib.sha256(Path(__file__).with_name('santoni_gpu_native_cpu.py').read_bytes()).hexdigest()}
    directory = ci / ('live-components-adapter-'+identity['tool_sha256'][:12] if core_hash else 'live-components-cinc' if old_hash else 'live-components'); directory.mkdir(exist_ok=True)
    results = {}
    cases = ('success', 'halt-denied', 'cb-enable-denied', 'tlb-timeout', 'rptr-timeout',
             'second-timeout', 'no-fence', 'wrong-fence', 'bad-pixel', 'bad-padding',
             'lost-invalidate', 'late-root', 'cb-fault', 'global-fault')
    if CP_HELPER in codes:
        cases += CP_CASES
    for case in cases:
        path = directory / (case + '.json')
        if path.exists():
            result = json.loads(path.read_text()); require(result.get('identity') == identity and result.get('success') is True,
                                                         'live component identity differs')
        elif (core_hash or old_hash) and (ci/('live-components-cinc' if core_hash else 'live-components')/path.name).exists():
            prior = ci/('live-components-cinc' if core_hash else 'live-components')/path.name; result = json.loads(prior.read_text())
            require(result.get('success') is True and result.get('identity') == {**identity,'tool_sha256':core_hash or old_hash},
                    'completed pre-extension live component differs')
            result = {**result,'identity':identity,'completed_receipt_consumed':str(prior.relative_to(ci)),
                      'completed_receipt_sha256':hashlib.sha256(prior.read_bytes()).hexdigest(),
                      'unchanged_supported_instruction_semantics_checked':True}
            with path.open('x') as stream:stream.write(json.dumps(result,indent=2)+'\n')
            print('Consumed completed live case without replay:',case,flush=True)
        else:
            result = LiveModel(codes, image, names, e, native, case).run_live()
            result['identity'] = identity
            with path.open('x') as stream: stream.write(json.dumps(result, indent=2) + '\n')
            print('Actual live worker/copy contract passed:', case, flush=True)
        results[case] = result
    adapter_cases = ('success', 'off', 'mode1', 'mode2', 'bad-enable', 'foreign-client', 'scm', 'alloc-fail', 'last-page')
    for case in adapter_cases:
        label = 'adapter-' + case; path = directory / (label + '.json')
        if path.exists():
            result = json.loads(path.read_text()); require(result.get('identity') == identity and result.get('success') is True,
                                                         'adapter component identity differs')
        else:
            result = LiveAdapter(codes, image, names, e, native, case).run(); result['identity'] = identity
            with path.open('x') as stream: stream.write(json.dumps(result, indent=2) + '\n')
            print('Actual live allocator/role/dispatch passed:', case, flush=True)
        results[label] = result
    native.close()
    record = {**identity, 'success': True, 'hardware_verified': False, 'cases': len(results), 'results': results,
              'actual_live_core_checked': True, 'full_native_A53_helper_words_checked': True,
              'actual_allocator_role_and_dispatch_checked': True,
              'retained_TTBR_legacy_mapping_and_SID0_fault_routing_checked': True,
              'two_full_BGRA_jobs_cache_fence_readback_quarantine_checked': True,
              'scope': 'actual instructions/CPU helper words; bootstrap and GPU/MMIO responses modeled; no phone boot'}
    if CP_HELPER in codes:
        require(all(case in results for case in CP_CASES), 'CP observed-response proof incomplete')
        record.update(A505_CP_observed_response_bits_and_bounded_requests_checked=True,
                      A505_CP_unknown_bits_missing_requests_and_busy_stop_rejected=True,
                      CP_readback_mask='0xfffffff3', CP_response_bits='0x0000000c')
    with (ci / 'live-binary-audit.json').open('x') as stream: stream.write(json.dumps(record, indent=2) + '\n')
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('ci', type=Path)
    parser.add_argument('--compatible-cinc-baseline',type=Path)
    parser.add_argument('--compatible-adapter-baseline',type=Path)
    args=parser.parse_args()
    print(json.dumps(audit(args.ci,args.compatible_cinc_baseline,args.compatible_adapter_baseline), indent=2))
