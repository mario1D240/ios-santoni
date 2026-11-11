"""Run inspected, read-only UI validators from a private copy of the CI image.

Extends the existing pure A53 helper runner only for the closed UI validator
set. The delivered kernel and helper instructions are never rewritten. MMIO,
submission, ownership changes and waits remain in the bounded interpreter.
"""
import ctypes
import mmap
import types

import santoni_gpu_native_cpu as cpu

UI_PURE = tuple('_sgpu_ui_' + n for n in
                ('memory_valid', 'reserved', 'image_valid', 'pixel_tables', 'tables'))
UI_BYTES = 46632
UI_OWNED = 15560


class UIPureCPU(cpu.PureCPU):
    pass


# Keep the legacy runner/its tested default set unchanged. Its complete native
# call/ISA/word checks apply to the five explicitly admitted new validators.
UIPureCPU.__init__ = types.FunctionType(cpu.PureCPU.__init__.__code__,
    {**cpu.PureCPU.__init__.__globals__, 'PURE': cpu.PURE + UI_PURE},
    cpu.PureCPU.__init__.__name__, cpu.PureCPU.__init__.__defaults__,
    cpu.PureCPU.__init__.__closure__)


def run_ui(self, name, memory, arguments):
    if name not in UI_PURE:
        return cpu.PureCPU.run(self, name, memory, arguments)
    if name not in self.codes:
        raise ValueError('UI validator was not decoded from this kernel')
    ui = next(iter(self.names['_sgpu_ui']))
    live = next(iter(self.names['_sgpu_render_live'])) + 8
    old = next(iter(self.names['_session_core'])) + 144
    for addr, length in ((ui, UI_BYTES), (live, 4384), (old, 200)):
        memory.bytes(addr, length)
    for addr in (live, ui + UI_OWNED):
        count = memory.get(addr + 80)
        if count > 1920:
            raise ValueError('UI owned PA snapshot extent differs')
        memory.bytes(memory.get(addr + 16, 8), count * 8)
        memory.bytes(memory.get(addr, 8), 7 * 4096)
    memory.bytes(memory.get(old, 8), 98304)
    if name == '_sgpu_ui_image_valid' and arguments[0]:
        memory.bytes(arguments[0], 40)
        count = memory.get(arguments[0] + 16)
        pa = memory.get(arguments[0] + 8, 8)
        if pa and count <= 960:
            memory.bytes(pa, count * 8)
    self._segments = self.image_segments
    self.synchronize(memory)
    args = list(arguments)
    # Rebase only C pointer fields; physical addresses and encoded PTEs retain
    # their exact model values. Both sides of pointer-equality checks rebase.
    fields = [old, *(a + o for a in (live, ui + UI_OWNED) for o in (0, 8, 16))]
    if name != '_sgpu_ui_reserved' and args:
        args[0] = self.translate(args[0])
    if name == '_sgpu_ui_image_valid' and arguments[0]:
        fields += [arguments[0], arguments[0] + 8]
    for field in fields:
        ctypes.c_uint64.from_address(self.translate(field)).value = self.translate(memory.get(field, 8))
    for mapping, native, size, model in self.regions:
        self.protect(native, size, mmap.PROT_READ)
    self.protect(self.base, self.span, mmap.PROT_READ | mmap.PROT_EXEC)
    call = ctypes.CFUNCTYPE(ctypes.c_uint32, *(ctypes.c_uint64 for _ in args))(
        self.base + self.codes[name].entry - self.origin)
    value = int(call(*args))
    if value not in (0, 1):
        raise ValueError('native UI validator returned a noncanonical boolean')
    return value


UIPureCPU.run = run_ui
