"""Bounded memmove ABI emitted for actual XNU render-state initialization."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import check_santoni_gpu_kernel as e
from check_santoni_gpu_render_kernel import RenderModel
from santoni_gpu_binary_model import Memory


class Image:
    segs = ()

    def read(self, address, size):
        raise AssertionError('fixture must stay inside owned model objects')


class VM:
    by_address = {0x1000: '_memmove'}


class RenderMemoryABI(unittest.TestCase):
    def model(self):
        model = object.__new__(RenderModel)
        model.vm, model.e, model.m = VM(), e, Memory(Image())
        model.m.map(0x8000, 16)
        model.m.write(0x8000, b'abcdefghijklmnop')
        return model

    def move(self, model, dest, source, length):
        before, after = e._State(), e._State()
        for i, value in enumerate((dest, source, length)):
            before.put('x' + str(i), e._Value(64, value))
        self.assertTrue(model.external(0x1000, after, before=before))
        self.assertEqual(after.get('x0'), e._Value(64, dest))

    def test_forward_and_backward_overlap_use_snapshot(self):
        model = self.model(); self.move(model, 0x8002, 0x8000, 6)
        self.assertEqual(model.m.bytes(0x8000, 8), b'ababcdef')
        model = self.model(); self.move(model, 0x8000, 0x8002, 6)
        self.assertEqual(model.m.bytes(0x8000, 8), b'cdefghgh')

    def test_external_copy_cannot_escape_or_modify_readonly_objects(self):
        model = self.model()
        with self.assertRaises(ValueError): self.move(model, 0x800f, 0x8000, 6)
        model.m.readonly.append((0x8000, 0x8010))
        with self.assertRaises(ValueError): self.move(model, 0x8000, 0x8008, 4)
        self.assertFalse(model.external(0x9999, e._State(), probe=True))


if __name__ == '__main__':
    unittest.main()
