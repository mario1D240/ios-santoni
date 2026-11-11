"""Actual nested command packaging with the reconstructed kernel PM4 parser."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from tests.reconstruct_santoni_touch import reconstruct

ROOT=Path(__file__).resolve().parents[1]


class CommandTests(unittest.TestCase):
    def test_actual_command_packaging(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='graphics-commands-',dir=preferred if preferred.is_dir() else None) as t:
            w=Path(t);targets=('bsd/dev/santoni_gpu_core.h','bsd/dev/santoni_gpu_graphics.h','bsd/dev/santoni_gpu_pm4.h',
                             'bsd/dev/santoni_gpu_pm4.c','bsd/dev/santoni_gpu_graphics_uapi.h')
            reconstruct(w/'source',targets=targets)
            for label,flags in [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:
                binary=w/label
                r=subprocess.run(['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-DARM64_BOARD_CONFIG_SANTONI',
                    '-I',str(w/'source/bsd/dev'),'-I',str(ROOT/'tools/santoni-graphics'),
                    str(ROOT/'tests/test_santoni_graphics_commands.c'),str(ROOT/'tools/santoni-graphics/client.c'),
                    str(ROOT/'tools/santoni-graphics/commands.c'),str(w/'source/bsd/dev/santoni_gpu_pm4.c'),
                    '-o',str(binary)],capture_output=True,text=True,timeout=60)
                self.assertEqual(r.returncode,0,r.stderr)
                for case in range(20):
                    run=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=20)
                    self.assertEqual(run.returncode,0,run.stdout+run.stderr)


if __name__=='__main__':unittest.main()
