"""Reconstructed persistent-session contracts; mocks are never hardware evidence."""
from pathlib import Path
import os,shlex,subprocess,tempfile,unittest
from tests.native_santoni_gpu_core import reconstruct, core_link_dependencies
from tests.test_santoni_gpu_prepare import source_function
ROOT=Path(__file__).resolve().parents[1]
FILES=('bsd/dev/santoni_gpu.c','bsd/dev/santoni_gpu_core.c','bsd/dev/santoni_gpu_core.h')
LAUNCH_HEADERS=('bsd/dev/santoni_gpu_launch.h','bsd/dev/santoni_gpu_launch_core.h')
VARIANTS=(('O0',['-O0']),('O2',['-O2']),('UBSan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))
class SessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        cls.temp=tempfile.TemporaryDirectory(prefix='sgpu-session-',dir=preferred if preferred.is_dir() else None)
        cls.root=Path(cls.temp.name);reconstruct(cls.root/'current',targets=FILES+LAUNCH_HEADERS)
        reconstruct(cls.root/'previous',through=205,targets=FILES)
        cls.dev=cls.root/'current/bsd/dev';cls.core=(cls.dev/'santoni_gpu_core.c').read_text()
        cls.adapter=(cls.dev/'santoni_gpu.c').read_text()
        model=(ROOT/'tests/test_santoni_gpu_session.c').read_text().split('int main(int argc,',1)[0]
        (cls.root/'santoni_gpu_session_model.h').write_text(model)
        first=cls.adapter.index('/* Session role:');end=cls.adapter.index('static void sgpu_kernel_thread',first)
        section=cls.adapter[first:end]
        section=section.split('/* Once-only full-buffer diagnostic,',1)[0]
        if 'static bool __attribute__((noinline)) sgpu_user_options(' in section:
            # Its parser is tested by the new client harness. Preserve this
            # old harness's exact session parser/default producer scope.
            for name in ('sgpu_user_options','sgpu_user_test_options'):
                if name+'(' in section:
                    section=section.replace(source_function(cls.adapter,name),'')
        (cls.root/'santoni_gpu_session_adapter_actual.h').write_text(section)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def compile(self,name,harness,flags,source=None):
        folder=self.root/name;folder.mkdir()
        core=self.dev/'santoni_gpu_core.c'
        if source is not None:core=folder/'santoni_gpu_core.c';core.write_text(source)
        binary=folder/'run'
        cmd=[*shlex.split(os.environ.get('HOST_CC','clang')),'-std=c11',*flags,'-pthread','-Wall','-Wextra','-Werror',
            '-DARM64_BOARD_CONFIG_SANTONI','-I',str(self.root),'-I',str(self.dev),'-I',str(ROOT/'tests'),
            str(ROOT/'tests'/harness),str(core),*core_link_dependencies(self.dev),'-o',str(binary)]
        built=subprocess.run(cmd,capture_output=True,text=True,timeout=90)
        self.assertEqual(built.returncode,0,built.stderr)
        return binary
    def run_binary(self,binary,args=(),passed=True):
        ran=subprocess.run([str(binary),*args],capture_output=True,text=True,timeout=30)
        self.assertEqual(ran.returncode==0,passed,ran.stdout+ran.stderr)
    def test_core_lifetime_requests_faults_and_time(self):
        for name,flags in VARIANTS:
            binary=self.compile(name+'core','test_santoni_gpu_session.c',flags)
            for case in [*range(17),*range(20,25),*range(30,51),100,102]:
                with self.subTest(variant=name,case=case):self.run_binary(binary,[str(case)])
    def test_queue_and_real_threads(self):
        for name,flags in VARIANTS:
            for harness in ('test_santoni_gpu_session_queue.c','test_santoni_gpu_session_threads.c'):
                binary=self.compile(name+harness,harness,flags);self.run_binary(binary)
    def test_actual_adapter_options_and_wakeup(self):
        for name,flags in VARIANTS:
            binary=self.compile(name+'adapter','test_santoni_gpu_session_adapter.c',flags)
            for case in range(12):
                with self.subTest(variant=name,case=case):self.run_binary(binary,[str(case)])
    def test_old_modes_trace_identity(self):
        for role in ('default','SANTONI_GPU_STOCK_ONLY_TRACE','SANTONI_GPU_STOCK_PIXEL_TRACE'):
            outputs=[]
            for version in ('previous','current'):
                dev=self.root/version/'bsd/dev';binary=self.root/(role+version)
                cmd=[*shlex.split(os.environ.get('HOST_CC','clang')),'-std=c11','-O2','-Wall','-Wextra','-Werror',
                    '-DARM64_BOARD_CONFIG_SANTONI','-DSANTONI_GPU_TRACE_CLEANUP','-I',str(dev)]
                if role!='default':cmd.append('-D'+role)
                cmd+=[str(ROOT/'tests/fixtures/santoni_gpu_forward_trace.c'),str(dev/'santoni_gpu_core.c'),*core_link_dependencies(dev),'-o',str(binary)]
                subprocess.run(cmd,check=True,timeout=90);outputs.append(subprocess.check_output([str(binary)],timeout=30))
            self.assertEqual(*outputs,role)
    def test_original_hardware_helpers_unchanged(self):
        old=(self.root/'previous/bsd/dev/santoni_gpu_core.c').read_text()
        for name in ('sgpu_g3_prepare','sgpu_g3_test','sgpu_stock_transition','sgpu_stock_pixels_test',
                     'sgpu_g3_begin','sgpu_g3_complete','sgpu_tables_build','consume','checked_write32'):
            self.assertEqual(source_function(old,name),source_function(self.core,name),name)
    def test_compiled_unsafe_contracts_rejected(self):
        changes=(('lifetime','session_core.ops=*ops;','session_core.ops=*ops; session_core.ops.ctx=NULL;', 'core','0'),
            ('late-references','ib->last_seq=data->last_seq=fence->last_seq=seq;','ib->last_seq=data->last_seq=fence->last_seq=0;','core','0'),
            ('deadline','*now-session_core.start_us>=SGPU_SESSION_BUDGET_US','*now-session_core.start_us>=UINT64_MAX','core','11'),
            ('close','if (q->close_requested) {','if (false) {','queue',None),
            ('quota','q->status.admitted >= SGPU_SESSION_LIMIT','q->status.admitted > SGPU_SESSION_LIMIT','queue',None),
            ('data-compare','if (((volatile uint32_t *)(void *)data)[i]!=session_core.values[i])','if (false)','core','6'),
            ('guard','!sgpu_g3_mapping(g,&g->bo[i])','false','core','2'),
            ('terminal-cancellation','    session_cancel_queued(q);\n    q->status.active=0;',
             '    q->status.active=0;','queue',None))
        for name,old,new,kind,case in changes:
            self.assertIn(old,self.core,name)
            changed=self.core.replace(old,new,1)
            for variant,flags in VARIANTS:
                binary=self.compile(name+variant,'test_santoni_gpu_session'+('_queue' if kind=='queue' else '')+'.c',flags,changed)
                self.run_binary(binary,() if case is None else (case,),False)
if __name__=='__main__':unittest.main()
