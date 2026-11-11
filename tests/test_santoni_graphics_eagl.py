"""Execute actual EAGL callbacks, including ABI refusal and partial-swap rollback."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from tests.reconstruct_santoni_touch import reconstruct
from tests.test_santoni_graphics_msm import ROOT,MESA
DRAFT=ROOT/'tools/santoni-graphics'
class EAGLTests(unittest.TestCase):
    def test_actual_callbacks(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='ui-eagl-',dir=preferred if preferred.is_dir() else None) as temporary:
            reconstruct(Path(temporary)/'source',targets=('bsd/dev/santoni_gpu_graphics_uapi.h',))
            for label,flags in [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:
                binary=Path(temporary)/label
                run=subprocess.run(['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-pthread',
                    '-I',str(ROOT/'tests/ui_eagl_stubs'),'-I',str(DRAFT),'-I',str(ROOT/'tools/santoni-graphics'),'-I',str(MESA/'include'),
                    '-I',str(Path(temporary)/'source/bsd/dev'),
                    str(ROOT/'tests/test_santoni_graphics_eagl.c'),str(DRAFT/'ui_eagl.c'),
                    str(DRAFT/'ui_context.c'),str(DRAFT/'ui_surface.c'),'-o',str(binary)],capture_output=True,text=True)
                self.assertEqual(run.returncode,0,run.stderr)
                for case in range(63):
                    run=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=15)
                    self.assertEqual(run.returncode,0,label+' case='+str(case)+'\n'+run.stdout+run.stderr)
if __name__=='__main__':unittest.main()
