"""Execute actual CP publication, fences and late-failure containment."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from tests.native_santoni_gpu_core import reconstruct, core_link_dependencies
from tests.test_santoni_gpu_ui import model_header

ROOT=Path(__file__).resolve().parents[1]
FILES=('bsd/dev/santoni_gpu_core.c','bsd/dev/santoni_gpu_core.h','bsd/dev/santoni_gpu_graphics_hw.h')
INPUTS=('tests/test_santoni_gpu_graphics_publish.c','tests/test_santoni_gpu_graphics_publish.py',
        'tests/native_santoni_gpu_core.py',
        'tests/reconstruct_santoni_touch.py','tests/test_santoni_gpu_ui.py',
        'tests/test_santoni_gpu_live.c','tests/test_santoni_gpu_session.c')
VARIANTS=(('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))
CASES=31


class GraphicsPublication(unittest.TestCase):
    def test_actual_publication(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='graphics-publish-',dir=preferred if preferred.is_dir() else None) as t:
            work=Path(t);source=work/'source';receipt=reconstruct(source,targets=FILES)
            (work/'santoni_gpu_live_ui_model.h').write_text(model_header())
            (work/'santoni_gpu_session_model.h').write_text((ROOT/'tests/test_santoni_gpu_session.c').read_text().split('static bool boot_session(',1)[0])
            rows=[]
            record={'success':False,'hardware_verified':False,'rows':rows,
                    'source_sha256':{**receipt['sha256'],**receipt['dependencies'],**receipt['native_link_dependencies']},
                    'inputs_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in INPUTS}}
            try:
                for label,flags in VARIANTS:
                    command=[*shlex.split(os.environ.get('HOST_CC','clang')),'-std=c11',*flags,
                        '-Wall','-Wextra','-Werror','-DARM64_BOARD_CONFIG_SANTONI','-I',str(source/'bsd/dev'),
                        '-I',str(work),'-I',str(ROOT/'tests'),str(ROOT/'tests/test_santoni_gpu_graphics_publish.c'),
                        str(source/'bsd/dev/santoni_gpu_core.c'),*core_link_dependencies(source/'bsd/dev'),'-o',str(work/label)]
                    built=subprocess.run(command,capture_output=True,text=True,timeout=90)
                    row={'label':label,'command':command,'compile_exit':built.returncode,'compile_stderr':built.stderr,'runs':[]};rows.append(row)
                    self.assertEqual(built.returncode,0,built.stderr)
                    for case in range(CASES):
                        ran=subprocess.run([str(work/label),str(case)],capture_output=True,text=True,timeout=30)
                        row['runs'].append({'case':case,'exit_code':ran.returncode,'stdout':ran.stdout,'stderr':ran.stderr})
                        self.assertEqual(ran.returncode,0,ran.stdout+ran.stderr)
                record['success']=True
            finally:
                path=os.environ.get('SANTONI_GRAPHICS_PUBLISH_RECORD')
                if path:Path(path).write_text(json.dumps(record,indent=2)+'\n')


if __name__=='__main__':unittest.main()
