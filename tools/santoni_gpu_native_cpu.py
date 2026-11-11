"""Run only inspected pure A53 helpers from a private CI-kernel COPY at EL0.

No kernel is built/booted, no MMIO/SMC is executed, and the delivered kernel
file is never modified. PC-relative image layout is retained in private mmap
storage. Standard memory/abort callees are redirected to the host libc; every
word of each helper under test remains identical to the audited CI image.
Use this for full-size CPU validation/pattern loops; GPU/worker/ownership calls
remain in the bounded instruction interpreter with modeled hardware responses.
"""
import ctypes
import mmap
import platform
from pathlib import Path
import struct
import subprocess
import tempfile

PURE = ('_sgpu_render_overlap', '_sgpu_render_memory_valid', '_sgpu_render_tables_valid',
        '_sgpu_render_plane_valid', '_sgpu_render_live_pattern', '_sgpu_render_live_compare',
        '_sgpu_render_live_tables', '_sgpu_memory_validate')
LIBC = {'_bzero': 'bzero', '_memcpy': 'memcpy', '_memmove': 'memmove', '_memset': 'memset',
        '___stack_chk_fail': 'abort'}
PAGE = 4096


def round_page(size):
    return (size + PAGE - 1) & -PAGE


class PureCPU:
    def __init__(self, codes, image, names, raw_kernel):
        if platform.machine().lower() not in ('aarch64', 'arm64'):
            raise ValueError('native pure-helper replay requires an ARM64 host')
        self.codes, self.names = codes, names
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.mprotect.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
        self.libc.mprotect.restype = ctypes.c_int
        segments = [s for s in image.segs if s['vmaddr'] and s['vmsize']]
        self.image_segments = segments
        self._segments = segments
        self.origin = min(s['vmaddr'] for s in segments)
        self.span = round_page(max(s['vmaddr'] + s['vmsize'] for s in segments) - self.origin)
        if self.origin % PAGE or self.span > 128 * 1024 * 1024:
            raise ValueError('pure-helper image extent is unreviewed')
        self.mapping = mmap.mmap(-1, self.span, prot=mmap.PROT_READ | mmap.PROT_WRITE)
        self.base = ctypes.addressof(ctypes.c_char.from_buffer(self.mapping))
        for seg in segments:
            begin = seg['vmaddr'] - self.origin
            data = raw_kernel[seg['fileoff']:seg['fileoff'] + seg['filesize']]
            if len(data) != seg['filesize']:
                raise ValueError('pure-helper segment is not completely file-backed')
            self.mapping[begin:begin + len(data)] = data
        allowed = {next(iter(names[n])) for n in PURE if n in codes}
        allowed |= {next(iter(names[n])) for n in LIBC if len(names.get(n, ())) == 1}
        for name in PURE:
            if name not in codes:
                continue
            code = codes[name]
            for pc in code.reachable:
                op, args = code.ins[pc]
                if op in ('mrs', 'msr', 'smc', 'hvc', 'svc', 'sys', 'dc', 'ic', 'blr', 'br'):
                    raise ValueError('pure helper reaches system/indirect instructions: ' + name)
                if op in ('bl', 'b'):
                    target = int(args[-1].lstrip('#'), 0)
                    if target not in code.ins and target not in allowed:
                        raise ValueError('pure helper reaches an unreviewed callee: ' + name)
                if image.read(pc, 4) != int.from_bytes(raw_kernel[self.offset(pc):self.offset(pc) + 4], 'little'):
                    raise ValueError('pure helper words differ from the delivered kernel')
        for name, host in LIBC.items():
            if len(names.get(name, ())) != 1:
                continue
            address = next(iter(names[name]))
            try:
                symbol = getattr(self.libc, host)
            except AttributeError:
                if host != 'bzero': raise
                self.load_support()
                symbol = self.cache_library.sgpu_cpu_bzero
            target = ctypes.cast(symbol, ctypes.c_void_p).value
            # ldr x16, [pc,#8]; br x16; host address. Callee copy only.
            stub = struct.pack('<IIQ', 0x58000050, 0xd61f0200, target)
            offset = address - self.origin
            if not 0 <= offset <= self.span - len(stub):
                raise ValueError('pure helper callee lies outside the private image')
            if any(c.entry <= address < max(c.ins) + 4 for n, c in codes.items() if n in PURE):
                raise ValueError('libc stub would overwrite a helper under test')
            self.mapping[offset:offset + len(stub)] = stub
        # Clean the newly copied instruction bytes before their first EL0 call.
        clear = getattr(self.libc, '__clear_cache', None)
        if clear is None:
            self.load_support()
            clear = self.cache_library.sgpu_cpu_cache_publish
        clear.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
        clear(self.base, self.base + self.span)
        self.protect(self.base, self.span, mmap.PROT_READ | mmap.PROT_EXEC)
        self.regions = []

    def load_support(self):
        if hasattr(self, 'cache_library'): return
        self.support = tempfile.TemporaryDirectory(prefix='sgpu-el0-cache-')
        library = Path(self.support.name) / 'cache.so'
        subprocess.run(['clang', '-O2', '-shared', '-fPIC',
            str(Path(__file__).with_name('santoni_gpu_native_cpu_support.c')),
            '-o', str(library)], check=True, capture_output=True, timeout=30)
        self.cache_library = ctypes.CDLL(str(library))

    def offset(self, address):
        # Raw file offset, not the relocated private-image offset.
        for seg in self._segments:
            if seg['vmaddr'] <= address < seg['vmaddr'] + seg['filesize']:
                return seg['fileoff'] + address - seg['vmaddr']
        raise ValueError('pure-helper word lies outside file bytes')

    @property
    def _segments(self):
        return self.__segments

    @_segments.setter
    def _segments(self, value):
        self.__segments = value

    def protect(self, address, size, protection):
        if address % PAGE or size % PAGE or self.libc.mprotect(address, size, protection):
            raise ValueError('pure-helper memory protection failed')

    def synchronize(self, memory):
        for mapping, address, size, model in self.regions:
            mapping.close()
        self.regions = []
        self.protect(self.base, self.span, mmap.PROT_READ | mmap.PROT_WRITE)
        for model, data, known in memory.regions:
            if self.origin <= model and model + len(data) <= self.origin + self.span:
                address = self.base + model - self.origin
                ctypes.memmove(address, bytes(data), len(data))
            else:
                size = round_page(len(data))
                mapping = mmap.mmap(-1, size + 2 * PAGE, prot=mmap.PROT_READ | mmap.PROT_WRITE)
                start = ctypes.addressof(ctypes.c_char.from_buffer(mapping))
                self.protect(start, PAGE, 0); self.protect(start + PAGE + size, PAGE, 0)
                address = start + PAGE
                ctypes.memmove(address, bytes(data), len(data))
                self.regions.append((mapping, address, size, model))
        return memory

    def translate(self, address):
        if address == 0:
            return 0
        if self.origin <= address < self.origin + self.span:
            return self.base + address - self.origin
        for mapping, native, size, model in self.regions:
            if model <= address < model + size:
                return native + address - model
        return address  # deliberately malformed scalar pointers stay malformed

    def run(self, name, memory, arguments):
        if name not in PURE or name not in self.codes:
            raise ValueError('unreviewed native pure-helper entry')
        # Verify the typed read set before copying any partially known stack
        # region. Padding/unused stack bytes do not become valid inputs.
        if name == '_sgpu_render_memory_valid' and arguments[0]:
            memory.bytes(arguments[0], 88)
            count = memory.get(arguments[0] + 80)
            pa = memory.get(arguments[0] + 16, 8)
            if pa and count <= 2048: memory.bytes(pa, count * 8)
        elif name == '_sgpu_render_tables_valid' and arguments[0]:
            memory.bytes(arguments[0], 4384)
            count = memory.get(arguments[0] + 80)
            pa = memory.get(arguments[0] + 16, 8)
            tables = memory.get(arguments[0], 8)
            if pa and count <= 2048: memory.bytes(pa, count * 8)
            if tables: memory.bytes(tables, 7 * 4096)
        elif name == '_sgpu_render_plane_valid':
            if arguments[0]: memory.bytes(arguments[0], 24)
            if arguments[1]: memory.bytes(arguments[1], 40)
        elif name == '_sgpu_memory_validate' and arguments[0]: memory.bytes(arguments[0],200)
        elif name == '_sgpu_render_live_tables':
            old = next(iter(self.names['_session_core'])) + 144
            live = next(iter(self.names['_sgpu_render_live']))
            memory.bytes(old,200); memory.bytes(memory.get(old,8),98304)
            memory.bytes(live+8,4384); memory.bytes(live+4928,4096)
            memory.bytes(memory.get(live+8,8),28672)
            memory.bytes(memory.get(live+24,8),memory.get(live+88)*8)
        elif name == '_sgpu_render_live_compare':
            length = arguments[3] * arguments[4]
            for arg in arguments[:2]:
                if length <= 4194304:
                    for off in range(0, length, 65536): memory.bytes(arg + off, min(65536, length - off))
        self._segments = self.image_segments
        self.synchronize(memory)
        args = list(arguments)
        pointer_slots = {'_sgpu_render_memory_valid': (0,), '_sgpu_render_tables_valid': (0,),
            '_sgpu_render_plane_valid': (0, 1), '_sgpu_render_live_pattern': (0, 1),
            '_sgpu_render_live_compare': (0, 1), '_sgpu_render_overlap': (0, 2),
            '_sgpu_memory_validate':(0,), '_sgpu_render_live_tables':()}[name]
        for index in pointer_slots:
            args[index] = self.translate(args[index])
        if name in ('_sgpu_render_memory_valid', '_sgpu_render_tables_valid') and arguments[0]:
            # Only the three pointer fields of sgpu_render_memory are rebased.
            for offset in (0, 8, 16):
                ctypes.c_uint64.from_address(args[0] + offset).value = self.translate(memory.get(arguments[0] + offset, 8))
        if name == '_sgpu_memory_validate' and arguments[0]:
            ctypes.c_uint64.from_address(args[0]).value = self.translate(memory.get(arguments[0],8))
        if name == '_sgpu_render_live_tables':
            old = next(iter(self.names['_session_core'])) + 144
            live = next(iter(self.names['_sgpu_render_live'])) + 8
            ctypes.c_uint64.from_address(self.translate(old)).value = self.translate(memory.get(old,8))
            for offset in (0,8,16):
                ctypes.c_uint64.from_address(self.translate(live)+offset).value = self.translate(memory.get(live+offset,8))
        for mapping, native, size, model in self.regions:
            self.protect(native, size, mmap.PROT_READ)
        self.protect(self.base, self.span, mmap.PROT_READ | mmap.PROT_EXEC)
        if name == '_sgpu_render_live_pattern':
            length = arguments[4] * arguments[5]
            for arg in arguments[:2]:
                if length and memory.locate(arg, length) is None:
                    raise ValueError('native pattern output exceeds owned buffer')
                if length:
                    native = self.translate(arg)
                    begin, end = native & -PAGE, round_page(native + length)
                    self.protect(begin, end - begin, mmap.PROT_READ | mmap.PROT_WRITE)
        call = ctypes.CFUNCTYPE(ctypes.c_uint32, *(ctypes.c_uint64 for _ in args))(
            self.base + self.codes[name].entry - self.origin)
        result = int(call(*args))
        if result not in (0, 1):
            raise ValueError('native pure helper returned a noncanonical boolean')
        if name == '_sgpu_render_live_pattern' and result:
            length = arguments[4] * arguments[5]
            for arg in arguments[:2]:
                memory.write(arg, ctypes.string_at(self.translate(arg), length))
        return result

    def close(self):
        for mapping, address, size, model in self.regions: mapping.close()
        self.regions = []
        self.mapping.close()
        if hasattr(self, 'support'): self.support.cleanup()
