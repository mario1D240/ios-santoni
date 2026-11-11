"""Exercise actual FBO selection/restoration and terminal readback failures."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from tests.test_santoni_graphics_msm import ROOT,MESA
class UIBackendTests(unittest.TestCase):
    def test_actual_backend(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='ui-backend-',dir=preferred if preferred.is_dir() else None) as temporary:
            for label,flags in [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:
                binary=Path(temporary)/label
                run=subprocess.run(['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror',
                    '-I',str(ROOT/'tools/santoni-graphics'),'-I',str(MESA/'include'),
                    str(ROOT/'tests/test_santoni_graphics_ui_backend.c'),
                    *[str(ROOT/'tools/santoni-graphics'/(name+'.c')) for name in ('ui_backend','ui_gl','ui_surface')],
                    '-o',str(binary)],capture_output=True,text=True)
                self.assertEqual(run.returncode,0,run.stderr)
                for case in range(8):
                    run=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=15)
                    self.assertEqual(run.returncode,0,run.stdout+run.stderr)
if __name__=='__main__':unittest.main()
