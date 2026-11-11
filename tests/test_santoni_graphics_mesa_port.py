"""Compile actual ported factory with actual public/private Mesa declarations."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from tests.test_santoni_graphics_msm import ROOT,MESA
from tools.build_santoni_graphics_gles import prepare_source


class MesaPortTests(unittest.TestCase):
    def test_actual_readonly_submit_table_and_mutants(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='mesa-submit-',dir=preferred if preferred.is_dir() else None) as temporary:
            work=Path(temporary);source,_=prepare_source(MESA,work/'prepared')
            body=(source/'src/freedreno/drm/msm/msm_ringbuffer_sp.c').read_text()
            loop=re.search(r'   for \(unsigned i = 0; i < fd_submit->nr_bos; i\+\+\) \{.*?\n   \}',body,re.S).group()
            prefix='static void actual_submit_bos(struct fd_bo **bos,unsigned count,struct drm_msm_gem_submit_bo *submit_bos)\n{\n'+(
                'struct model_submit {unsigned nr_bos;struct fd_bo **bos;} model={count,bos};\n')+'const struct model_submit *fd_submit=&model;\n'
            variants={
                'missing-mask':('submit_bos[i].flags &= ~MSM_SUBMIT_BO_WRITE;','(void)submit_bos[i].flags;'),
                'inverted-owner':('if (fd_submit->bos[i]->alloc_flags & FD_BO_GPUREADONLY)',
                    'if (!(fd_submit->bos[i]->alloc_flags & FD_BO_GPUREADONLY))'),
                'wrong-permission':('~MSM_SUBMIT_BO_WRITE','~MSM_SUBMIT_BO_READ'),
                'drop-dump':('~MSM_SUBMIT_BO_WRITE','~(MSM_SUBMIT_BO_WRITE|MSM_SUBMIT_BO_DUMP)'),
            }
            for name,changed in [('actual',loop),*[(name,loop.replace(old,new,1)) for name,(old,new) in variants.items()]]:
                if name!='actual':self.assertEqual(loop.count(variants[name][0]),1,name)
                (work/'mesa_submit_bos.h').write_text(prefix+changed+'\n}\n')
                for label,flags in [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:
                    for enabled in ((False,True) if name=='actual' else (True,)):
                        binary=work/(name+'-'+label+str(enabled))
                        command=['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-pthread',
                            '-DHAVE_PTHREAD=1','-DHAVE_STRUCT_TIMESPEC=1','-D_GNU_SOURCE',
                            *(['-DSANTONI_GFX_MESA=1'] if enabled else []),'-I'+str(work),'-I'+str(source/'src'),
                            '-I'+str(source/'src/freedreno'),'-I'+str(source/'include'),'-I'+str(source/'include/drm-uapi'),
                            str(ROOT/'tests/test_santoni_graphics_mesa_submit.c'),'-o',str(binary)]
                        build=subprocess.run(command,capture_output=True,text=True,timeout=60)
                        self.assertEqual(build.returncode,0,build.stderr)
                        rejected=False
                        for case in range(8):
                            run=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=10)
                            if name=='actual':self.assertEqual(run.returncode,0,run.stdout+run.stderr)
                            elif run.returncode:rejected=True;break
                        if name!='actual':self.assertTrue(rejected,name+' survived BO-table contracts')
    def test_actual_factory_O0_O2_UBSan_and_argument_mutants(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='mesa-factory-',dir=preferred if preferred.is_dir() else None) as t:
            work=Path(t);source,_=prepare_source(MESA,work/'prepared')
            driver=source/'src/gallium/drivers/freedreno/freedreno_screen.h'
            public=source/'src/gallium/winsys/freedreno/drm/freedreno_drm_public.h'
            factory=(public.parent/'freedreno_drm_winsys.c').read_text()
            signature=re.search(r'struct pipe_screen\s*\*\s*fd_screen_create\s*\([^;]+;',driver.read_text()).group()
            start=re.search(r'struct pipe_screen\s*\*\s*\nfd_drm_screen_create_renderonly\s*\([^)]*\)\s*\{',factory).start()
            body=factory[start:factory.index('\n}',start)+2]
            prefix='struct pipe_screen;struct pipe_screen_config;struct renderonly;\n'+public.read_text()+'\n'+signature+'\n'
            good='return fd_screen_create(fd, config, ro);'
            self.assertEqual(body.count(good),1)
            mutations={
                'swap-cast':'return fd_screen_create(fd, (const struct pipe_screen_config *)ro, (struct renderonly *)config);',
                'drop-config':'(void)config;return fd_screen_create(fd, NULL, ro);',
                'drop-ro':'(void)ro;return fd_screen_create(fd, config, NULL);',
                'wrong-fd':'return fd_screen_create(fd+1, config, ro);',
            }
            variants=(('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))
            for name,changed in [('actual',body),*[(name,body.replace(good,bad,1)) for name,bad in mutations.items()]]:
                (work/'mesa_factory.h').write_text(prefix+changed+'\n')
                for label,flags in variants:
                    binary=work/(name+'-'+label)
                    command=['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-DSANTONI_GFX_MESA=1',
                        '-I',str(work),str(ROOT/'tests/test_santoni_graphics_mesa_port.c'),'-o',str(binary)]
                    build=subprocess.run(command,capture_output=True,text=True,timeout=30)
                    self.assertEqual(build.returncode,0,build.stderr)
                    failed=False
                    for case in range(4):
                        run=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=10)
                        if name=='actual':self.assertEqual(run.returncode,0,run.stdout+run.stderr)
                        elif run.returncode:failed=True;break
                    if name!='actual':self.assertTrue(failed,name+' survived actual factory contracts')


if __name__=='__main__':unittest.main()
