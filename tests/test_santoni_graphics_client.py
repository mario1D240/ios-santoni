"""Actual userspace protocol bounds, failed replies and timeout lifetimes."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from tests.reconstruct_santoni_touch import reconstruct

ROOT=Path(__file__).resolve().parents[1]


class ClientTests(unittest.TestCase):
    def test_actual_client(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='graphics-user-client-',dir=preferred if preferred.is_dir() else None) as t:
            work=Path(t);reconstruct(work/'source',targets=('bsd/dev/santoni_gpu_graphics_uapi.h',))
            for label,flags in [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:
                binary=work/label
                r=subprocess.run(['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-I',str(work/'source/bsd/dev'),
                    '-I',str(ROOT/'tools/santoni-graphics'),str(ROOT/'tools/santoni-graphics/client.c'),
                    str(ROOT/'tests/test_santoni_graphics_client.c'),'-o',str(binary)],capture_output=True,text=True,timeout=60)
                self.assertEqual(r.returncode,0,r.stderr)
                for case in range(15):
                    run=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=20)
                    self.assertEqual(run.returncode,0,run.stdout+run.stderr)


if __name__=='__main__':unittest.main()
