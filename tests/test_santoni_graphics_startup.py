"""Actual startup functions and constructor with modeled GL/dyld/clock endpoints."""
import os,re,subprocess,tempfile,unittest
from pathlib import Path
from tests.reconstruct_santoni_touch import reconstruct
from tests.test_santoni_graphics_msm import ROOT,MESA
WORK=ROOT/'tools/santoni-graphics'
VARIANTS=(('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))

class StartupContracts(unittest.TestCase):
    def setup_work(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        temporary=tempfile.TemporaryDirectory(prefix='graphics-startup-',dir=preferred if preferred.is_dir() else None)
        self.addCleanup(temporary.cleanup);work=Path(temporary.name)
        reconstruct(work/'uapi',targets=('bsd/dev/santoni_gpu_graphics_uapi.h',))
        return work

    def execute(self,work,name,flags,sources,cases,extra=(),constructor=False):
        binary=work/name
        command=['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-pthread',*extra,'-I',str(work),
            '-I',str(WORK),'-I',str(work/'uapi/bsd/dev'),'-I',str(MESA/'include'),*map(str,sources),'-o',str(binary)]
        built=subprocess.run(command,text=True,capture_output=True,timeout=90)
        self.assertEqual(built.returncode,0,built.stderr)
        for case in cases:
            env=os.environ.copy();env.pop('SGFX_LOADER_CASE',None)
            if constructor:env['SGFX_LOADER_CASE']=str(case)
            run=subprocess.run([str(binary),str(case)],text=True,capture_output=True,env=env,timeout=30)
            terminal=name.startswith('loader-') and case in (13,14,15)
            self.assertEqual(run.returncode,42 if terminal else 0,name+' case='+str(case)+'\n'+run.stdout+run.stderr)
            if name.startswith('loader-'):
                entry='SANTONI GPU: EAGL loader constructor entry\n'
                self.assertEqual(run.stderr.count(entry),int(constructor),(name,case,run.stderr))
                if constructor and case!=15:self.assertLess(run.stderr.index(entry),run.stderr.index('EAGL loader enter stage=1'))
                stage=0 if case==15 else 6 if case==13 else 3 if case==14 else 1 if case in (1,2) else 2 if case>=10 else 3 if case==3 else 4 if case==4 else 5 if case in (5,6) else 6
                entered=[int(value) for value in re.findall(r'EAGL loader enter stage=(\d+)',run.stderr)]
                self.assertEqual(entered,list(range(1,stage+1)),(name,case,run.stderr))
                result=re.findall(r'EAGL loader installed=(\d+) stage=(\d+)',run.stderr)
                expected=[] if terminal else [(str(int(case in (0,8,9))),str(stage))]
                self.assertEqual(result,expected,(name,case,run.stderr))

    def test_ES2_ES3_actual_readback_and_cleanup(self):
        work=self.setup_work();source=(WORK/'gles.c').read_text()
        (work/'readback_actual.h').write_text('static GLuint shader('+source.split('static GLuint shader(',1)[1])
        for name,flags in VARIANTS:
            self.execute(work,'readback-'+name,flags,[ROOT/'tests/test_santoni_graphics_readback.c',WORK/'ui_gl.c',WORK/'ui_surface.c'],range(40))

    def test_actual_bounded_renderer_readiness(self):
        work=self.setup_work()
        for name,flags in VARIANTS:
            self.execute(work,'readiness-'+name,flags,[ROOT/'tests/test_santoni_graphics_readiness.c',WORK/'readiness.c'],range(29),
                ['-D_POSIX_C_SOURCE=200809L','-Dclock_gettime=sgfx_test_clock_gettime','-Dnanosleep=sgfx_test_nanosleep'])

    def test_actual_explicit_loader_and_constructor(self):
        work=self.setup_work();good='/usr/local/lib/santoni-gpu-ui/'+'0123456789abcdef'*4+'/libsantoni-eagl.dylib'
        cases=[(good,[*range(10),13,14,15]),(good.replace('/usr/local/lib/','/tmp/'),[10]),
            (good.replace('0123456789abcdef','0123456789abcdeZ'),[11]),(good.replace('libsantoni-eagl.dylib','../libsantoni-eagl.dylib'),[12])]
        import json
        extra=['-Dpthread_mutex_lock=sgfx_test_loader_mutex_lock','-DRTLD_FIRST=0x100','-Dgetuid=sgfx_test_getuid','-Ddlopen=sgfx_test_dlopen','-Ddlsym=sgfx_test_dlsym',
            '-Ddlerror=sgfx_test_dlerror','-Ddlclose=sgfx_test_dlclose']
        for name,flags in VARIANTS:
            for index,(path,selected) in enumerate(cases):
                (work/'ui_loader_config.h').write_text('#define SANTONI_UI_LIBRARY_PATH '+json.dumps(path)+'\n')
                for constructor in ([False,True] if index==0 else [False]):
                    self.execute(work,'loader-'+name+'-'+str(index)+'-'+str(int(constructor)),flags,
                        [ROOT/'tests/test_santoni_graphics_loader.c',WORK/'ui_loader.c'],selected,
                        extra+([] if constructor else ['-DSANTONI_UI_LOADER_TEST_NO_CONSTRUCTOR=1']),constructor)

if __name__=='__main__':unittest.main()
