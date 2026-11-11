"""Real VM link dependency, historical bytes and late-header rejection."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(os.environ.get('SANTONI_NATIVE_CORE_PROJECT',str(Path(__file__).resolve().parents[1])))
sys.path.insert(0,str(ROOT))
from tests import native_santoni_gpu_core as native
from tests.reconstruct_santoni_touch import reconstruct as base
FILES=('bsd/dev/santoni_gpu_core.c','bsd/dev/santoni_gpu_core.h','bsd/dev/santoni_gpu.c')

class NativeCoreLink(unittest.TestCase):
    def temporary(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        return tempfile.TemporaryDirectory(prefix='native-core-link-test-',dir=preferred if preferred.is_dir() else None)

    def test_current_VM_is_reconstructed_from_the_same_patch_chain(self):
        with self.temporary() as temporary:
            work=Path(temporary);result=native.reconstruct(work/'core',targets=FILES)
            vm=base(work/'vm',targets=(native.VM,))
            self.assertEqual(result['native_link_dependencies'],vm['sha256'])
            self.assertEqual(native.core_link_dependencies(work/'core/bsd/dev'),[str(work/'core'/native.VM)])
            self.assertEqual(native.core_source_hashes(result),{**result['sha256'],**vm['sha256']})

    def test_225_and_201_primary_bytes_and_link_recipes_are_unchanged(self):
        with self.temporary() as temporary:
            work=Path(temporary)
            for through in (201,225):
                with self.subTest(through=through):
                    result=native.reconstruct(work/('new'+str(through)),through=through,targets=FILES)
                    old=base(work/('old'+str(through)),through=through,targets=FILES)
                    self.assertEqual(result['sha256'],old['sha256'])
                    self.assertEqual(result['native_link_dependencies'],{})
                    self.assertEqual(native.core_link_dependencies(work/('new'+str(through))/'bsd/dev'),[])

    def test_missing_real_VM_module_refused(self):
        with self.temporary() as temporary:
            work=Path(temporary);(work/'santoni_gpu_vm.h').write_text('/* generated negative fixture */\n')
            with self.assertRaises(ValueError):native.core_link_dependencies(work)

    def test_header_changed_between_primary_and_auxiliary_reconstruction_refused(self):
        with self.temporary() as temporary:
            work=Path(temporary)
            def interrupted(output,through=None,targets=None):
                result=base(output,through=through,targets=targets)
                if tuple(targets)==FILES:
                    path=Path(output)/'bsd/dev/santoni_gpu_core.h'
                    path.write_bytes(path.read_bytes()+b'/* late change */\n')
                return result
            with patch.object(native,'reconstruct_base',side_effect=interrupted):
                with self.assertRaises(ValueError):native.reconstruct(work/'source',targets=FILES)

if __name__=='__main__':unittest.main()
