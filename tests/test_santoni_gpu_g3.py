"""Execute reconstructed G3 contracts, including compiled omission variants."""
from pathlib import Path
import os,shlex,subprocess,tempfile,unittest
from tests.native_santoni_gpu_core import reconstruct, core_link_dependencies
from tests.test_santoni_gpu_prepare import source_function
ROOT=Path(__file__).resolve().parents[1]
FILES=('bsd/dev/santoni_gpu.c','bsd/dev/santoni_gpu_core.c','bsd/dev/santoni_gpu_core.h')
VARIANTS=(('O0',['-O0']),('O2',['-O2']),('UBSan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))
class G3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        cls.temp=tempfile.TemporaryDirectory(prefix='sgpu-g3-',dir=preferred if preferred.is_dir() else None)
        cls.root=Path(cls.temp.name);reconstruct(cls.root/'current',targets=FILES)
        reconstruct(cls.root/'previous',through=204,targets=FILES)
        cls.dev=cls.root/'current/bsd/dev';cls.core=(cls.dev/'santoni_gpu_core.c').read_text()
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def native(self,name,harness,flags,core=None,pass_expected=True):
        folder=self.root/name;folder.mkdir()
        if core is not None:(folder/'santoni_gpu_core.c').write_text(core)
        command=[*shlex.split(os.environ.get('HOST_CC','clang')),'-std=c11',*flags,'-Wall','-Wextra','-Werror',
                 '-DARM64_BOARD_CONFIG_SANTONI','-I',str(folder),'-I',str(self.dev),str(ROOT/'tests'/harness)]
        if harness=='test_santoni_gpu_g3.c':command.append(str(folder/'santoni_gpu_core.c' if core is not None else self.dev/'santoni_gpu_core.c'))
        command+=core_link_dependencies(self.dev)
        command+=['-o',str(folder/'run')]
        built=subprocess.run(command,capture_output=True,text=True,timeout=60)
        self.assertEqual(built.returncode,0,built.stderr)
        ran=subprocess.run([str(folder/'run')],capture_output=True,text=True,timeout=30)
        self.assertEqual(ran.returncode==0,pass_expected,ran.stdout+ran.stderr)
    def test_actual_g3_all_native_variants(self):
        for variant,flags in VARIANTS:
            for harness in ('test_santoni_gpu_g3.c','test_santoni_gpu_g3_contracts.c'):
                self.native(variant+harness,harness,flags)
    def test_old_transition_pixel_and_allocator_functions_preserved(self):
        old=(self.root/'previous/bsd/dev/santoni_gpu_core.c').read_text()
        for name in ('sgpu_tables_build','sgpu_stock_transition','sgpu_stock_pixels_test','render_test',
                     'sgpu_pixel_fence','checked_write32','consume'):
            self.assertEqual(source_function(old,name),source_function(self.core,name),name)
        old=(self.root/'previous/bsd/dev/santoni_gpu.c').read_text()
        new=(self.dev/'santoni_gpu.c').read_text()
        for name in ('sgpu_stock_options','sgpu_pixel_options','sgpu_scm_capability_probe',
                     'sgpu_pas_cache_preflight','sgpu_zap_allocation_preflight','sgpu_io_write32'):
            self.assertEqual(source_function(old,name),source_function(new,name),name)
    def test_compiled_g3_mutants_rejected(self):
        mutations=[
            ('owner','sgpu_g3_lookup','g->bo[i].owner == owner','g->bo[i].owner != 0','contracts'),
            ('free-busy','sgpu_g3_free','g->sealed || b->last_seq > g->completed','false','contracts'),
            ('guard','sgpu_g3_mapping','!l3[b->first+b->pages]','true','contracts'),
            ('nested-ib','sgpu_g3_begin','commands[i] != sgpu_packet7(0x3d,3)',
             '(commands[i] != sgpu_packet7(0x3d,3) && commands[i] != sgpu_packet7(0x3f,3))','contracts'),
            ('padding-target','sgpu_g3_begin','va-base > data->bytes-4','va-base > SGPU_PAGE-4','contracts'),
            ('fence-owner','sgpu_g3_complete','sgpu_g3_lookup(g,owner,fence_handle)','sgpu_g3_lookup(g,owner?1:0,fence_handle)','contracts'),
            ('future-fence','sgpu_g3_complete','observed != g->busy','observed < g->busy','contracts'),
            ('prior-inflight','sgpu_g3_begin','g->failed || g->busy','g->failed','contracts'),
            ('early-references','sgpu_g3_begin','ib->last_seq=data->last_seq=fence->last_seq=seq;','ib->last_seq=data->last_seq=fence->last_seq=0;','contracts'),
            ('guard-runtime','sgpu_g3_test','!sgpu_g3_mapping(g,ib)','false','hardware-model'),
            ('readback-skip','sgpu_g3_test','if (!consume(p,*wptr)) goto failed;','(void)consume(p,*wptr);','hardware-model'),
            ('fault-skip','sgpu_g3_test','if (has_fault(r))','if (false)','hardware-model'),
        ]
        for name,function,old,new,kind in mutations:
            body=source_function(self.core,function);self.assertIn(old,body)
            changed=self.core.replace(body,body.replace(old,new),1)
            harness='test_santoni_gpu_g3_contracts.c' if kind=='contracts' else 'test_santoni_gpu_g3.c'
            for variant,flags in VARIANTS:self.native(name+variant,harness,flags,changed,False)
    def test_complete_old_mode_stock_and_pixel_traces_identical(self):
        for role in ('default','SANTONI_GPU_STOCK_ONLY_TRACE','SANTONI_GPU_STOCK_PIXEL_TRACE'):
            outputs=[]
            for version in ('previous','current'):
                dev=self.root/version/'bsd/dev';binary=self.root/(role+version)
                command=[*shlex.split(os.environ.get('HOST_CC','clang')),'-std=c11','-O2','-Wall','-Wextra','-Werror',
                    '-DARM64_BOARD_CONFIG_SANTONI','-DSANTONI_GPU_TRACE_CLEANUP','-I',str(dev)]
                if role!='default':command.append('-D'+role)
                command += [str(ROOT/'tests/fixtures/santoni_gpu_forward_trace.c'),str(dev/'santoni_gpu_core.c'),*core_link_dependencies(dev),'-o',str(binary)]
                subprocess.run(command,check=True,timeout=60)
                outputs.append(subprocess.check_output([str(binary)],text=True,timeout=30))
            self.assertEqual(*outputs,role)
if __name__=='__main__':unittest.main()
