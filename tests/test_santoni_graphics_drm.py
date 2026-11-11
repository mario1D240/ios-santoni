"""Exercise serialized libdrm tokens against actual command/kernel validation."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from tests.test_santoni_graphics_msm import ROOT, MESA
from tests.reconstruct_santoni_touch import reconstruct


class DRMTests(unittest.TestCase):
    def test_actual_facade(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='graphics-drm-',dir=preferred if preferred.is_dir() else None) as t:
            work=Path(t)
            reconstruct(work/'source',targets=('bsd/dev/santoni_gpu_pm4.c','bsd/dev/santoni_gpu_pm4.h',
                'bsd/dev/santoni_gpu_graphics_uapi.h'))
            for label,flags in [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:
                binary=work/label
                command=['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-pthread','-DARM64_BOARD_CONFIG_SANTONI',
                    '-I',str(work/'source/bsd/dev'),'-I',str(MESA/'include'),'-I',str(MESA/'include/drm-uapi'),
                    '-I',str(ROOT/'tools/santoni-graphics/include'),'-I',str(ROOT/'tools/santoni-graphics'),'-I',str(ROOT/'tests'),
                    str(ROOT/'tests/test_santoni_graphics_drm.c'),
                    *[str(ROOT/'tools/santoni-graphics'/(name+'.c')) for name in ('client','commands','msm','drm')],
                    str(work/'source/bsd/dev/santoni_gpu_pm4.c'),'-o',str(binary)]
                build=subprocess.run(command,capture_output=True,text=True,timeout=60)
                self.assertEqual(build.returncode,0,build.stderr)
                for case in range(19):
                    run=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=30)
                    self.assertEqual(run.returncode,0,run.stdout+run.stderr)


if __name__=='__main__':unittest.main()
