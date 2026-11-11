"""Actual shared frontend, pinned API declarations, lifetime and bad variants."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from tests.santoni_graphics_sharing_record import write_sharing_record

ROOT=Path(__file__).resolve().parents[1]
WORK=ROOT/'tools/santoni-graphics'
from tests.reconstruct_santoni_touch import reconstruct
MESA=ROOT/'out/mesa-a505-25.0.7-reference'
VARIANTS=(('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))
MUTANTS=(
    ('missing-screen-hold','owner->references++;','(void)owner;',0),
    ('wrong-shared-context','&owner->frontend,&attribs,&error,shared->st','&owner->frontend,&attribs,&error,NULL',0),
    ('child-owned-screen','c->screen_owner=owner;','c->screen_owner=NULL;',0),
    ('wrong-peer-source','&owner->frontend,&attribs,&error,shared->st','&owner->frontend,&attribs,&error,owner->st',1),
    ('retaining-child-owner','shared->screen_owner?shared->screen_owner:shared','shared',1),
    ('overflow-reference','owner->references==UINT32_MAX','false',5),
    ('allow-false-capabilities','extensions && extensions[0]','extensions && 0',8),
)

class SharedFrontend(unittest.TestCase):
    def test_actual_shared_frontend_and_compiling_unsafe_variants(self):
        self.assertEqual(subprocess.check_output(['git','rev-parse','HEAD'],cwd=MESA,text=True).strip(),
                         '742a20f48c59e8649533c84c4d49dd95b403f5da')
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='gles-shared-',dir=preferred if preferred.is_dir() else None) as temporary:
            work=Path(temporary);(work/'util/format').mkdir(parents=True)
            with (work/'util/format/u_format_gen.h').open('x') as out:
                subprocess.run([sys.executable,str(MESA/'src/util/format/u_format_table.py'),'--enums',
                    str(MESA/'src/util/format/u_format.yaml')],stdout=out,check=True,timeout=30)
            reconstruct(work/'uapi',targets=('bsd/dev/santoni_gpu_core.h','bsd/dev/santoni_gpu_graphics.h','bsd/dev/santoni_gpu_graphics_uapi.h'))
            header=(MESA/'src/mesa/state_tracker/st_context.h').read_text()
            declarations=['#include "frontend/api.h"\n#include "main/menums.h"\n',
                re.search(r'struct st_context_attribs\s*\{.*?\n\};',header,re.S).group()]
            for name in ('st_api_create_context','st_api_make_current','st_api_get_current','st_destroy_context','st_screen_destroy'):
                declaration=re.search(r'(?:extern\s+)?(?:struct st_context\s*\*|bool|void)\s*'+name+r'\s*\([^;]*\);',header)
                self.assertIsNotNone(declaration);declarations.append(declaration.group())
            (work/'state_tracker').mkdir();(work/'state_tracker/st_context.h').write_text('\n'.join(declarations)+'\n')
            actual=(WORK/'gles.c').read_text().split('static GLuint shader(',1)[0]
            includes=(work,WORK,work/'uapi/bsd/dev',ROOT/'tools/santoni-graphics',MESA/'include',MESA/'include/drm-uapi',
                MESA/'src',MESA/'src/mesa',MESA/'src/gallium/include',MESA/'src/gallium/auxiliary',
                MESA/'src/gallium/drivers',MESA/'src/gallium/winsys')
            rows=[]
            for name,body,cases in [('actual',actual,range(11)),*[(name,actual.replace(old,new,1),[case]) for name,old,new,case in MUTANTS]]:
                if name!='actual':
                    old=next(old for key,old,new,case in MUTANTS if key==name);self.assertEqual(actual.count(old),1)
                (work/'gles_lifecycle.h').write_text(body)
                for label,flags in VARIANTS:
                    binary=work/(name+'-'+label)
                    command=['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-pthread','-D_POSIX_C_SOURCE=200809L',
                        '-DHAVE_PTHREAD=1','-DHAVE_STRUCT_TIMESPEC=1','-DHAVE_OPENGL_ES_2=1',
                        *['-I'+str(p) for p in includes],str(ROOT/'tests/test_santoni_graphics_gles_sharing.c'),'-o',str(binary)]
                    build=subprocess.run(command,capture_output=True,text=True,timeout=60)
                    row={'name':name+'-'+label,'command':command,'compile_exit':build.returncode,
                         'source_sha256':hashlib.sha256(body.encode()).hexdigest(),'compile_stderr':build.stderr,'runs':[]};rows.append(row)
                    self.assertEqual(build.returncode,0,build.stderr)
                    for case in cases:
                        run=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=15)
                        row['runs'].append({'case':case,'exit':run.returncode,'stdout':run.stdout,'stderr':run.stderr})
                        self.assertEqual(run.returncode==0,name=='actual',run.stdout+run.stderr)
            write_sharing_record('gles',{'success':True,'rows':rows,'positive_executions':33,
                'compiled_rejected_mutants':21,'GL_Mesa_IOSurface_modeled':True})

if __name__=='__main__':unittest.main(verbosity=2)
