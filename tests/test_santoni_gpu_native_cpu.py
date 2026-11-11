"""Private EL0 code mapping only; synthetic words are not kernel evidence."""
import platform
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import check_santoni_gpu_kernel as e
from santoni_gpu_binary_model import Memory
from santoni_gpu_native_cpu import PureCPU


class Image:
    def __init__(self, raw):
        self.raw = raw
        self.segs = [{'vmaddr': 0x10000000, 'vmsize': 4096, 'filesize': 4096, 'fileoff': 0, 'initprot': 5}]

    def read(self, address, length):
        return int.from_bytes(self.raw[address - 0x10000000:address - 0x10000000 + length], 'little')


@unittest.skipUnless(platform.machine().lower() in ('aarch64', 'arm64'), 'ARM64 EL0 fixture only')
class NativeCPU(unittest.TestCase):
    def test_helper_words_rebased_without_modification(self):
        raw = struct.pack('<II', 0x52800020, 0xd65f03c0) + bytes(4088)
        code = e._Code('10000000 <_sgpu_render_memory_valid>:\n10000000: 52800020 mov w0, #1\n10000004: d65f03c0 ret\n',
                       '_sgpu_render_memory_valid', 0x10000000)
        image = Image(raw)
        native = PureCPU({'_sgpu_render_memory_valid': code}, image,
                         {'_sgpu_render_memory_valid': {0x10000000}}, raw)
        self.assertEqual(native.run('_sgpu_render_memory_valid', Memory(image), (0,)), 1)
        self.assertEqual(native.mapping[:8], raw[:8])
        native.close()

    def test_system_instruction_is_rejected_before_execution(self):
        raw = struct.pack('<II', 0xd53bd040, 0xd65f03c0) + bytes(4088)
        code = e._Code('10000000 <_sgpu_render_memory_valid>:\n10000000: d53bd040 mrs x0, tpidr_el1\n10000004: d65f03c0 ret\n',
                       '_sgpu_render_memory_valid', 0x10000000)
        with self.assertRaisesRegex(ValueError, 'system/indirect'):
            PureCPU({'_sgpu_render_memory_valid': code}, Image(raw),
                    {'_sgpu_render_memory_valid': {0x10000000}}, raw)


if __name__ == '__main__':
    unittest.main()
