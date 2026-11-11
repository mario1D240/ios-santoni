"""Actual hardware-controller/IOKit and combined PM4-buffer native contracts."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

from tests.reconstruct_santoni_touch import reconstruct
from tests.test_santoni_gpu_ui import model_header
from tests.test_santoni_gpu_prepare import source_function

ROOT=Path(os.environ.get('SANTONI_GRAPHICS_PROJECT',str(Path(__file__).resolve().parents[1])))
FIXTURES=Path(os.environ.get('SANTONI_GRAPHICS_FIXTURES',str(ROOT/'tests')))
FILES=('bsd/dev/santoni_gpu.c','bsd/dev/santoni_gpu_core.c','bsd/dev/santoni_gpu_core.h',
       'bsd/dev/santoni_gpu_graphics.c','bsd/dev/santoni_gpu_graphics.h',
       'bsd/dev/santoni_gpu_pm4.c','bsd/dev/santoni_gpu_pm4.h',
       'bsd/dev/santoni_gpu_graphics_hw.h','bsd/dev/santoni_gpu_graphics_uapi.h',
       'bsd/dev/santoni_gpu_vm.c','bsd/dev/santoni_gpu_vm.h',
       'bsd/dev/santoni_gpu_ir3.c','bsd/dev/santoni_gpu_ir3.h','bsd/dev/santoni_gpu_ir3_rules.h',
       'bsd/dev/santoni_gpu_descriptors.c','bsd/dev/santoni_gpu_descriptors.h','bsd/dev/santoni_gpu_descriptor_fields.h',
       'bsd/dev/santoni_gpu_raster.c','bsd/dev/santoni_gpu_raster.h','bsd/dev/santoni_gpu_raster_rules.h','bsd/dev/santoni_gpu_raster_fields.h',
       'bsd/dev/santoni_gpu_raster_batch.c','bsd/dev/santoni_gpu_raster_batch.h',
       'iokit/Kernel/arm/SantoniGraphics.cpp')
IOKIT_CASES=list(range(18))+list(range(19,30))
WIDE_IOKIT_CASES=list(range(86))
VARIANTS=(('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))
INPUTS=('tests/test_santoni_gpu_graphics_bridge.py','tests/test_santoni_gpu_graphics_hw.c',
    'tests/test_santoni_gpu_graphics_iokit.cpp','tests/santoni_gpu_graphics_iokit_stubs.h',
    'tests/test_santoni_gpu_graphics_iokit_wide.cpp',
    'tests/test_santoni_gpu_graphics_pipeline.c','tests/test_santoni_gpu_graphics.c',
    'tests/test_santoni_gpu_graphics_worker.c','tests/test_santoni_gpu_prepare.py',
    'tests/test_santoni_gpu_ui.py','tests/test_santoni_gpu_live.c','tests/test_santoni_gpu_session.c',
    'tests/reconstruct_santoni_touch.py')


class GraphicsBridge(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        cls.temp=tempfile.TemporaryDirectory(prefix='graphics-bridge-',dir=preferred if preferred.is_dir() else None)
        cls.work=Path(cls.temp.name)
        external=os.environ.get('SANTONI_GRAPHICS_BRIDGE_SOURCE')
        cls.source=Path(external) if external else cls.work/'source'
        if not external:reconstruct(cls.source,targets=FILES)
        cls.dev=cls.source/'bsd/dev';cls.rows=[]
        cls.inputs={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in INPUTS}
        # Canonical roles keep receipts portable across CI work directories.
        # Overrides still bind the bytes actually compiled, not ROOT's copy.
        cls.inputs['tests/test_santoni_gpu_graphics_bridge.py']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        for name in ('test_santoni_gpu_graphics_iokit.cpp','test_santoni_gpu_graphics_iokit_wide.cpp','santoni_gpu_graphics_iokit_stubs.h'):
            cls.inputs['tests/'+name]=hashlib.sha256((FIXTURES/name).read_bytes()).hexdigest()
        cls.cc=shlex.split(os.environ.get('CC','clang'));cls.cxx=shlex.split(os.environ.get('CXX','clang++'))
        (cls.work/'santoni_gpu_live_ui_model.h').write_text(model_header())
        (cls.work/'santoni_gpu_session_model.h').write_text((ROOT/'tests/test_santoni_gpu_session.c').read_text().split('static bool boot_session(',1)[0])
        cpp=(cls.source/FILES[-1]).read_text()
        cpp=re.sub(r'^#include <[^>]+>\n','',cpp,flags=re.M)
        cpp=re.sub(r'"../../../bsd/dev/([^\"]+)"',r'"\1"',cpp)
        (cls.work/'SantoniGraphics_actual.cpp').write_text(cpp)
        adapter=(cls.source/'bsd/dev/santoni_gpu.c').read_text()
        # Actual VM allocator is independently exercised by the allocation
        # harness. This worker model tests ordering/report/ready publication.
        worker='static uint32_t sgpu_graphics_enabled,sgpu_graphics_published;\n'
        worker+='static bool sgpu_graphics_vm_begin(void) {return sgpu_graphics_hw_begin(sg.mode,sgpu_graphics_enabled);}\n'
        worker+='\n\n'.join(
            source_function(adapter,n) for n in ('santoni_gpu_graphics_worker_ready','sgpu_graphics_options','sgpu_render_worker'))
        (cls.work/'santoni_gpu_graphics_worker_actual.h').write_text(worker)

    @classmethod
    def tearDownClass(cls):
        path=os.environ.get('SANTONI_GRAPHICS_BRIDGE_RECORD')
        if path:
            record={'success':len(cls.rows)==15 and all(r['compile_exit']==0 and
                all(x['exit_code']==0 for x in r['runs']) for r in cls.rows),
                'hardware_verified':False,'rows':cls.rows,
                'inputs_sha256':cls.inputs,
                'source_sha256':{f:hashlib.sha256((cls.source/f).read_bytes()).hexdigest() for f in FILES},
                'allocator_VM_begin_modeled':True,
                'scope':'actual controller/IOKit/PM4-buffer code; hardware and platform primitives modeled'}
            Path(path).write_text(json.dumps(record,indent=2)+'\n')
        cls.temp.cleanup()

    def execute(self,name,command,cases):
        r=subprocess.run(command,capture_output=True,text=True,timeout=90)
        row={'name':name,'command':command,'compile_exit':r.returncode,'compile_stderr':r.stderr,'runs':[]};self.rows.append(row)
        self.assertEqual(r.returncode,0,r.stderr)
        for args in cases:
            run=subprocess.run([str(self.work/name),*args],capture_output=True,text=True,timeout=40)
            row['runs'].append({'args':args,'exit_code':run.returncode,'stdout':run.stdout,'stderr':run.stderr})
            self.assertEqual(run.returncode,0,run.stderr)

    def test_actual_hardware_controller(self):
        for label,flags in VARIANTS:
            name='hardware-'+label
            self.execute(name,[*self.cc,'-std=c11',*flags,'-Wall','-Wextra','-Werror','-DARM64_BOARD_CONFIG_SANTONI',
                '-I',str(self.dev),'-I',str(self.work),'-I',str(ROOT/'tests'),str(ROOT/'tests/test_santoni_gpu_graphics_hw.c'),
                str(self.dev/'santoni_gpu_core.c'),str(self.dev/'santoni_gpu_vm.c'),'-o',str(self.work/name)],[[str(i)] for i in range(17)])

    def test_actual_IOKit_client(self):
        for label,flags in VARIANTS:
            objects=[]
            for module in ('santoni_gpu_graphics','santoni_gpu_pm4','santoni_gpu_ir3','santoni_gpu_descriptors','santoni_gpu_raster','santoni_gpu_raster_batch'):
                obj=self.work/(module+'-'+label+'.o')
                command=[*self.cc,'-std=c11',*flags,'-Wall','-Wextra','-Werror','-DARM64_BOARD_CONFIG_SANTONI',
                    '-I',str(self.dev),'-c',str(self.dev/(module+'.c')),'-o',str(obj)]
                built=subprocess.run(command,capture_output=True,text=True,timeout=40)
                self.assertEqual(built.returncode,0,built.stderr);objects.append(str(obj))
            for wide in (False,True):
                name=('iokit-wide-' if wide else 'iokit-')+label
                fixture=FIXTURES/('test_santoni_gpu_graphics_iokit_wide.cpp' if wide else 'test_santoni_gpu_graphics_iokit.cpp')
                self.execute(name,[*self.cxx,'-std=c++17',*flags,'-Wall','-Wextra','-Werror','-DARM64_BOARD_CONFIG_SANTONI',
                    '-I',str(self.dev),'-I',str(self.work),'-I',str(FIXTURES),'-I',str(ROOT/'tests'),str(fixture),
                    *objects,'-o',str(self.work/name)],[[str(i)] for i in (WIDE_IOKIT_CASES if wide else IOKIT_CASES)])

    def test_actual_private_nested_pipeline(self):
        for label,flags in VARIANTS:
            name='pipeline-'+label
            self.execute(name,[*self.cc,'-std=c11',*flags,'-Wall','-Wextra','-Werror','-DARM64_BOARD_CONFIG_SANTONI',
                '-I',str(self.dev),str(ROOT/'tests/test_santoni_gpu_graphics_pipeline.c'),
                *[str(self.dev/(m+'.c')) for m in ('santoni_gpu_graphics','santoni_gpu_pm4','santoni_gpu_core','santoni_gpu_vm')],
                '-o',str(self.work/name)],[[]])

    def test_actual_worker_publication(self):
        for label,flags in VARIANTS:
            name='worker-'+label
            self.execute(name,[*self.cc,'-std=c11',*flags,'-Wall','-Wextra','-Werror','-DARM64_BOARD_CONFIG_SANTONI',
                '-I',str(self.dev),'-I',str(self.work),str(ROOT/'tests/test_santoni_gpu_graphics_worker.c'),
                '-o',str(self.work/name)],[[str(i)] for i in range(8)])


if __name__=='__main__':unittest.main()
