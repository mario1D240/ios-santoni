"""Pinned Mesa UAPI conversion and nested-command/kernel-policy boundaries."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from tests.reconstruct_santoni_touch import reconstruct

ROOT=Path(__file__).resolve().parents[1]
MESA=Path(os.environ.get('SANTONI_MESA_SOURCE',str(ROOT/'out/mesa-a505-25.0.7-reference')))


class MSMTests(unittest.TestCase):
    def test_actual_msm_bridge(self):
        self.assertTrue((MESA/'include/drm-uapi/msm_drm.h').is_file(),'pinned Mesa25.0.7 reference is required')
        lock=json.loads((ROOT/'tools/santoni-graphics/mesa-reference.json').read_text())
        for name in ('include/drm-uapi/msm_drm.h','include/drm-uapi/drm.h'):
            self.assertEqual(hashlib.sha256((MESA/name).read_bytes()).hexdigest(),lock['source_sha256'][name],name)
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='graphics-msm-',dir=preferred if preferred.is_dir() else None) as t:
            w=Path(t);reconstruct(w/'source',targets=('bsd/dev/santoni_gpu_core.h','bsd/dev/santoni_gpu_graphics.h',
                'bsd/dev/santoni_gpu_pm4.h','bsd/dev/santoni_gpu_pm4.c','bsd/dev/santoni_gpu_graphics_uapi.h'))
            for label,flags in [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:
                binary=w/label
                r=subprocess.run(['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-DARM64_BOARD_CONFIG_SANTONI',
                    '-I',str(w/'source/bsd/dev'),'-I',str(MESA/'include/drm-uapi'),'-I',str(ROOT/'tools/santoni-graphics'),
                    '-I',str(ROOT/'tests'),str(ROOT/'tests/test_santoni_graphics_msm.c'),
                    *[str(ROOT/'tools/santoni-graphics'/(name+'.c')) for name in ('client','commands','msm')],
                    str(w/'source/bsd/dev/santoni_gpu_pm4.c'),'-o',str(binary)],capture_output=True,text=True,timeout=60)
                self.assertEqual(r.returncode,0,r.stderr)
                for case in range(17):
                    run=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=20)
                    self.assertEqual(run.returncode,0,run.stdout+run.stderr)


if __name__=='__main__':unittest.main()
