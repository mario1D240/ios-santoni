"""Actual GLES creation/destruction with pinned Mesa ABI and unsafe mutants."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from tests.test_santoni_graphics_msm import ROOT,MESA
from tests.reconstruct_santoni_touch import reconstruct

class GLESLifecycleTests(unittest.TestCase):
    def test_actual_lifecycle_and_compiling_mutants(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='gles-lifecycle-',dir=preferred if preferred.is_dir() else None) as temporary:
            work=Path(temporary)
            (work/'util/format').mkdir(parents=True)
            with (work/'util/format/u_format_gen.h').open('x') as generated:
                subprocess.run([sys.executable,str(MESA/'src/util/format/u_format_table.py'),'--enums',
                    str(MESA/'src/util/format/u_format.yaml')],stdout=generated,check=True,timeout=30)
            reconstruct(work/'uapi',targets=('bsd/dev/santoni_gpu_core.h','bsd/dev/santoni_gpu_graphics.h','bsd/dev/santoni_gpu_graphics_uapi.h'))
            # Keep the complete public frontend/pipe/XML headers. Extract only
            # the used declarations from the heavy state-tracker header, never
            # substitute handwritten prototypes or context-attrib field types.
            header=(MESA/'src/mesa/state_tracker/st_context.h').read_text()
            declarations=['#include "frontend/api.h"\n#include "main/menums.h"\n']
            declarations.append(re.search(r'struct st_context_attribs\s*\{.*?\n\};',header,re.S).group())
            for name in ('st_api_create_context','st_api_make_current','st_api_get_current','st_destroy_context','st_screen_destroy'):
                declaration=re.search(r'(?:extern\s+)?(?:struct st_context\s*\*|bool|void)\s*'+name+r'\s*\([^;]*\);',header)
                self.assertIsNotNone(declaration,name);declarations.append(declaration.group())
            (work/'state_tracker').mkdir()
            (work/'state_tracker/st_context.h').write_text('\n'.join(declarations)+'\n')
            actual=(ROOT/'tools/santoni-graphics/gles.c').read_text().split('static GLuint shader(',1)[0]
            mutants={
                'missing-param':('c->frontend.get_param=sgfx_gles_frontend_param;','(void)sgfx_gles_frontend_param;'),
                'wrong-param':('(void)screen;(void)parameter;return 0;','(void)screen;(void)parameter;return 1;'),
                'missing-bookkeeping':('st_screen_destroy(&c->frontend);',''),
                'pipe-before-bookkeeping':('st_screen_destroy(&c->frontend);\n        if(c->frontend.screen)c->frontend.screen->destroy(c->frontend.screen);',
                    'if(c->frontend.screen)c->frontend.screen->destroy(c->frontend.screen);\n        st_screen_destroy(&c->frontend);'),
                'skip-failed-context-cleanup':('sgfx_gles_destroy(c);return NULL;}\n    return c;', 'return NULL;}\n    return c;'),
                'leave-current-dangling':('if(st_api_get_current()==c->st)st_api_make_current(NULL,NULL,NULL);',''),
                'destroy-other-current':('if(st_api_get_current()==c->st)st_api_make_current(NULL,NULL,NULL);','st_api_make_current(NULL,NULL,NULL);'),
            }
            includes=[work,work/'uapi/bsd/dev',ROOT/'tools/santoni-graphics',MESA/'include',MESA/'include/drm-uapi',
                MESA/'src',MESA/'src/mesa',MESA/'src/gallium/include',MESA/'src/gallium/auxiliary',
                MESA/'src/gallium/drivers',MESA/'src/gallium/winsys']
            for name,body in [('actual',actual),*[(name,actual.replace(old,new,1)) for name,(old,new) in mutants.items()]]:
                if name!='actual':self.assertEqual(actual.count(mutants[name][0]),1,name)
                (work/'gles_lifecycle.h').write_text(body)
                for label,flags in [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:
                    binary=work/(name+'-'+label)
                    command=['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-pthread','-D_POSIX_C_SOURCE=200809L',
                        '-DHAVE_PTHREAD=1','-DHAVE_STRUCT_TIMESPEC=1','-DHAVE_OPENGL_ES_2=1',
                        *['-I'+str(path) for path in includes],str(ROOT/'tests/test_santoni_graphics_gles.c'),'-o',str(binary)]
                    build=subprocess.run(command,capture_output=True,text=True,timeout=60)
                    self.assertEqual(build.returncode,0,build.stderr)
                    rejected=False
                    for case in range(14):
                        run=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=15)
                        if name=='actual':self.assertEqual(run.returncode,0,run.stdout+run.stderr)
                        elif run.returncode:rejected=True;break
                    if name!='actual':self.assertTrue(rejected,name+' survived lifecycle contracts')

if __name__=='__main__':unittest.main()
