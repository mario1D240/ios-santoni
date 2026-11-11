from pathlib import Path
import subprocess,tempfile,unittest
from tests.test_santoni_graphics_msm import ROOT,MESA
class UIGLTests(unittest.TestCase):
    def test_actual_GLES_binding(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='ui-gl-',dir=preferred if preferred.is_dir() else None) as t:
            for label,flags in [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:
                binary=Path(t)/label
                r=subprocess.run(['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-I',str(ROOT/'tools/santoni-graphics'),
                    '-I',str(MESA/'include'),str(ROOT/'tests/test_santoni_graphics_ui_gl.c'),
                    str(ROOT/'tools/santoni-graphics/ui_surface.c'),str(ROOT/'tools/santoni-graphics/ui_gl.c'),'-o',str(binary)],capture_output=True,text=True)
                self.assertEqual(r.returncode,0,r.stderr)
                for case in range(12):
                    r=subprocess.run([str(binary),str(case)],capture_output=True,text=True)
                    self.assertEqual(r.returncode,0,r.stdout+r.stderr)
if __name__=='__main__':unittest.main()
