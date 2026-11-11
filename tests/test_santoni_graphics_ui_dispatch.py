"""Run actual shader/texture/draw adapters against exact Khronos declarations."""
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest
from tests.test_santoni_graphics_msm import ROOT,MESA
class UIDispatchTests(unittest.TestCase):
    def test_actual_manual_adapters(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='ui-manual-',dir=preferred if preferred.is_dir() else None) as temporary:
            for label,flags in [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:
                binary=Path(temporary)/label
                strip=['-Wl,-dead_strip'] if platform.system()=='Darwin' else ['-Wl,--gc-sections']
                run=subprocess.run(['clang','-std=c11',*flags,'-D__APPLE__','-Wall','-Wextra','-Werror',
                    '-ffunction-sections','-fdata-sections',*strip,
                    '-I',str(ROOT/'tools/santoni-graphics'),'-I',str(MESA/'include'),
                    str(ROOT/'tests/test_santoni_graphics_ui_dispatch.c'),str(ROOT/'tools/santoni-graphics/ui_dispatch.c'),
                    str(ROOT/'tools/santoni-graphics/ui_shader.c'),'-o',str(binary)],capture_output=True,text=True)
                self.assertEqual(run.returncode,0,run.stderr)
                for case in range(19):
                    run=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=15)
                    self.assertEqual(run.returncode,0,run.stdout+run.stderr)
if __name__=='__main__':unittest.main()
