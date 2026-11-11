"""Reconstructed pixel contracts and exact preservation of all older roles."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from tests.native_santoni_gpu_core import reconstruct, core_link_dependencies
from tests.test_santoni_gpu_prepare import source_function

ROOT=Path(__file__).resolve().parents[1]
FILES=('bsd/dev/santoni_gpu.c','bsd/dev/santoni_gpu_core.c','bsd/dev/santoni_gpu_core.h')
VARIANTS=(('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))

class PixelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        cls.temp=tempfile.TemporaryDirectory(prefix='pixels-a505-',dir=preferred if preferred.is_dir() else None)
        cls.root=Path(cls.temp.name)
        reconstruct(cls.root/'current',targets=FILES)
        reconstruct(cls.root/'previous',through=203,targets=FILES)
        cls.dev=cls.root/'current/bsd/dev'
        cls.core=(cls.dev/'santoni_gpu_core.c').read_text()
        cls.adapter=(cls.dev/'santoni_gpu.c').read_text()
    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def run_native(self,folder,harness,flags,source=None,success=True):
        folder.mkdir()
        if source is not None: (folder/'santoni_gpu_core.c').write_text(source)
        command=[*shlex.split(os.environ.get('HOST_CC','clang')),'-std=c11',*flags,
                 '-Wall','-Wextra','-Werror','-DARM64_BOARD_CONFIG_SANTONI','-I',str(folder),
                 '-I',str(self.dev),str(ROOT/'tests'/harness)]
        if harness=='test_santoni_gpu_pixels.c':
            command.append(str(folder/'santoni_gpu_core.c' if source is not None else self.dev/'santoni_gpu_core.c'))
        command+=core_link_dependencies(self.dev)
        command+=['-o',str(folder/'test')]
        built=subprocess.run(command,capture_output=True,text=True,timeout=60)
        self.assertEqual(built.returncode,0,built.stderr)
        ran=subprocess.run([str(folder/'test')],capture_output=True,text=True,timeout=30)
        if success: self.assertEqual(ran.returncode,0,ran.stderr)
        else: self.assertNotEqual(ran.returncode,0,'compiled unsafe mutant survived: '+folder.name)

    def test_actual_native_pixel_state_and_private_entry(self):
        for variant,flags in VARIANTS:
            for harness in ('test_santoni_gpu_pixels.c','test_santoni_gpu_pixels_guards.c'):
                self.run_native(self.root/(variant+harness),harness,flags)

    def test_old_stock_transition_and_permission_functions_preserved(self):
        old_core=(self.root/'previous/bsd/dev/santoni_gpu_core.c').read_text()
        old_adapter=(self.root/'previous/bsd/dev/santoni_gpu.c').read_text()
        for name in ('sgpu_stock_transition','checked_write32','sgpu_blit_commands','sgpu_tables_build'):
            self.assertEqual(source_function(old_core,name),source_function(self.core,name),name)
        for name in ('sgpu_stock_options','sgpu_stock_write_allowed','sgpu_io_write32','sgpu_io_write64'):
            self.assertEqual(source_function(old_adapter,name),source_function(self.adapter,name),name)

    def test_pixel_scope_has_no_PAS_reset_or_direct_TRUST_write(self):
        helper=source_function(self.core,'sgpu_stock_pixels_test')
        for forbidden in ('smc','sgpu_scm','SG_RESET','sgpu_a505_halt','sgpu_smmu_restore','sgpu_restore_power'):
            self.assertNotIn(forbidden,helper)
        self.assertNotIn('write32',helper)
        self.assertIn('r->pixel.started = true;',helper)
        self.assertLess(helper.index('r->pixel.started = true;'),helper.index('before stock pixel readiness'))

    def test_old_stock_only_full_MMIO_cache_and_hold_trace_preserved(self):
        results=[]
        for label in ('previous','current'):
            dev=self.root/label/'bsd/dev'; binary=self.root/('stock-trace-'+label)
            subprocess.run([*shlex.split(os.environ.get('HOST_CC','clang')),'-std=c11','-O2',
                '-Wall','-Wextra','-Werror','-DARM64_BOARD_CONFIG_SANTONI',
                '-DSANTONI_GPU_TRACE_CLEANUP','-DSANTONI_GPU_STOCK_ONLY_TRACE','-I',str(dev),
                str(ROOT/'tests/fixtures/santoni_gpu_forward_trace.c'),str(dev/'santoni_gpu_core.c'),*core_link_dependencies(dev),
                '-o',str(binary)],check=True,timeout=60)
            results.append(subprocess.check_output([str(binary)],text=True,timeout=30))
        self.assertEqual(*results)

    def test_compiled_pixel_mutants_rejected(self):
        pixel=source_function(self.core,'sgpu_stock_pixels_test')
        changed=[
            ('permission','p->ops->stock_pixels != 1','p->ops->stock_pixels == 42','private'),
            ('prior-error','r->error != (r->stock.attempted ? SG_STOCK_HELD : SG_OK)',
             '(r->error == 42)','private'),
            ('memory','!sgpu_memory_validate(&p->memory)','false','private'),
            ('started','r->pixel.started = true;','r->pixel.started = false;','public'),
            ('hold','r->stock.held = true;','r->stock.held = false;','public'),
            ('trust','if (r->trust != 0)','if (false)','public'),
            ('faults','if (has_fault(r))','if (false)','public'),
            ('skip-render','if (!render_test(p, wptr))','if (false)','public'),
            ('hide-failure','if (!r->error) r->error = SG_MARKER_MISMATCH;',
             'r->error = SG_STOCK_HELD;','public'),
        ]
        for index,line in enumerate(pixel.splitlines()):
            if '!sgpu_stock_check32(p,' in line:
                expr=line.strip().removesuffix(' {').removesuffix(')') if line.endswith(' {') else line.strip().removesuffix(' ||')
                # The first condition in the SMMU group carries the if prefix.
                expr=expr.removeprefix('if (')
                changed.append((f'ready-{index}',expr,'false','public'))
        for name,old,new,kind in changed:
            self.assertIn(old,pixel,name)
            modified=self.core.replace(pixel,pixel.replace(old,new),1)
            harness='test_santoni_gpu_pixels_guards.c' if kind=='private' else 'test_santoni_gpu_pixels.c'
            for variant,flags in VARIANTS:
                self.run_native(self.root/(name+'-'+variant),harness,flags,modified,False)
        for name,old,new in (
            ('no-checked-wptr','if (p->report->pixel.started) {','if (false) {'),
            ('wptr-mask','checked_write32(p, SG_GPU, SG_RB_WPTR, ~0u, words)',
             'checked_write32(p, SG_GPU, SG_RB_WPTR, 0u, words)'),
            ('skip-fence-wait','p->report->pixel.started && !sgpu_pixel_fence(p)',
             'p->report->pixel.started && sgpu_pixel_fence(p) && false'),
            ('fence-cap','i <= POLL_US / 100','i < POLL_US / 100'),
            ('cleanup-already-zero','if (report->stock.attempted || report->pixel.started) {',
             'if (report->stock.attempted) {')):
            if name=='fence-cap':
                fence=source_function(self.core,'sgpu_pixel_fence')
                self.assertEqual(fence.count(old),1)
                modified=self.core.replace(fence,fence.replace(old,new,1),1)
            else:
                self.assertEqual(self.core.count(old),1)
                modified=self.core.replace(old,new,1)
            for variant,flags in VARIANTS:
                self.run_native(self.root/(name+'-'+variant),'test_santoni_gpu_pixels.c',flags,
                                modified,False)

if __name__=='__main__': unittest.main()
