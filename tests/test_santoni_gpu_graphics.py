"""Actual rendering-client buffer/snapshot/fence contracts; no hardware proof."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from tests.reconstruct_santoni_touch import reconstruct
from tests.test_santoni_gpu_prepare import source_function

ROOT=Path(__file__).resolve().parents[1]
FILES=('bsd/dev/santoni_gpu_core.c','bsd/dev/santoni_gpu_core.h',
       'bsd/dev/santoni_gpu_graphics.c','bsd/dev/santoni_gpu_graphics.h')
VARIANTS=(('O0',['-O0']),('O2',['-O2']),
          ('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))
MUTANTS=(
 ('owner','sgpu_graphics_admitted','owner && owner == c->owner','owner'),
 ('first-error','sgpu_graphics_fail','if (!c->error) c->error=error;','c->error=error;'),
 ('late-pa','sgpu_graphics_bo_valid','c->ops.page_pa(c->ops.ctx,&b->memory,i)!=c->pa[b->physical+i]', 'false'),
 ('guard','sgpu_graphics_bo_valid','if (c->ops.pte(c->ops.ctx,va+b->pages*SGPU_PAGE))','if (false)'),
 ('source-snapshot','sgpu_graphics_submit','memcpy(snapshot->memory.va,source->memory.va,source->bytes);',
        'memset(snapshot->memory.va,0,source->bytes);'),
 ('validator','sgpu_graphics_submit','if (!c->ops.validate_ib(c->ops.ctx,(const uint32_t *)(const void *)(snapshot->memory.va+input[i].offset),\n            input[i].bytes/4,ranges,nb))', 'if (snapshot && false)'),
 ('busy-free','sgpu_graphics_free','|| c->active','|| false'),
 ('unmap-proof','sgpu_graphics_retire','if (c->ops.pte(c->ops.ctx,va+i*SGPU_PAGE))','if (false)'),
 ('fence','sgpu_graphics_wait','if (fence==c->active && c->ops.idle(c->ops.ctx))','if (c->ops.idle(c->ops.ctx))'),
 ('idle','sgpu_graphics_wait','if (fence==c->active && c->ops.idle(c->ops.ctx))','if (fence==c->active)'),
 ('fault','sgpu_graphics_wait','if (c->ops.faulted(c->ops.ctx))','if (false)'),
 ('read-cap','sgpu_graphics_wait','i<SGPU_GRAPHICS_WAIT_READS','i<SGPU_GRAPHICS_WAIT_READS+1'),
 ('publish-failure','sgpu_graphics_submit','if (!c->ops.publish(c->ops.ctx,commands,ni,seq))','if (c->ops.publish(c->ops.ctx,commands,ni,seq) && false)'),
 ('zero-clean','sgpu_graphics_allocate','c->ops.clean(c->ops.ctx,m.va,pages*SGPU_PAGE);','(void)m;'),
)


class GraphicsContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        cls.temp=tempfile.TemporaryDirectory(prefix='graphics0224-',dir=preferred if preferred.is_dir() else None)
        cls.work=Path(cls.temp.name)
        external=os.environ.get('SANTONI_GRAPHICS_SOURCE')
        if external:
            cls.source=Path(external)
        else:
            cls.source=cls.work/'source';reconstruct(cls.source,targets=FILES)
        cls.dev=cls.source/'bsd/dev'
        cls.rows=[]
        cls.cc=shlex.split(os.environ.get('CC','clang'))

    @classmethod
    def tearDownClass(cls):
        path=os.environ.get('SANTONI_GRAPHICS_RECORD')
        if path:
            complete=len(cls.rows)==3+3*len(MUTANTS) and all(r['compile_exit']==0 and
                ((len(r['runs'])==45 and all(x['exit_code']==0 for x in r['runs'])) if not r['mutant'] else
                 (bool(r['runs']) and r['runs'][-1]['exit_code']!=0)) for r in cls.rows)
            record={'success':complete,
                'hardware_verified':False,'rows':cls.rows,
                'source_sha256':{f:hashlib.sha256((cls.source/f).read_bytes()).hexdigest() for f in FILES},
                'inputs_sha256':{f:hashlib.sha256((ROOT/f).read_bytes()).hexdigest() for f in
                    ('tests/test_santoni_gpu_graphics.c','tests/test_santoni_gpu_graphics.py','tests/reconstruct_santoni_touch.py')},
                'scope':'actual C functions; allocation/PTE/GPU/cache callbacks modeled; no shader or hardware result'}
            Path(path).write_text(json.dumps(record,indent=2)+'\n')
        cls.temp.cleanup()

    def run_variant(self,label,flags,source,mutant=False):
        binary=self.work/label
        compile=subprocess.run([*self.cc,'-std=c11',*flags,'-Wall','-Wextra','-Werror',
            '-DARM64_BOARD_CONFIG_SANTONI','-I',str(self.dev),str(ROOT/'tests/test_santoni_gpu_graphics.c'),
            str(source),'-o',str(binary)],capture_output=True,text=True)
        row={'label':label,'mutant':mutant,'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
             'compile_exit':compile.returncode,'compile_stderr':compile.stderr,'runs':[]}
        self.rows.append(row);self.assertEqual(compile.returncode,0,compile.stderr)
        for case in range(45):
            r=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=15)
            row['runs'].append({'case':case,'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
            if mutant and r.returncode:return
            if not mutant:self.assertEqual(r.returncode,0,r.stderr)
        if mutant:self.fail(label+' survived all actual-function contracts')

    def test_actual_functions_O0_O2_UBSan(self):
        for label,flags in VARIANTS:self.run_variant(label,flags,self.dev/'santoni_gpu_graphics.c')

    def test_compiling_unsafe_mutants(self):
        original=(self.dev/'santoni_gpu_graphics.c').read_text()
        for name,function,old,new in MUTANTS:
            body=source_function(original,function)
            self.assertEqual(body.count(old),1,(name,old))
            changed=original.replace(body,body.replace(old,new,1),1)
            if name=='busy-free':
                retire=source_function(changed,'sgpu_graphics_retire')
                needle='if (c->active || b->quarantine)'
                self.assertEqual(retire.count(needle),1)
                changed=changed.replace(retire,retire.replace(needle,'if (b->quarantine)',1),1)
            source=self.work/(name+'.c');source.write_text(changed)
            for variant,flags in VARIANTS:self.run_variant(name+'-'+variant,flags,source,True)

    def test_PTE_flags_match_programmed_Santoni_source(self):
        core=(self.dev/'santoni_gpu_core.c').read_text()
        graphics=(self.dev/'santoni_gpu_graphics.c').read_text()
        self.assertIn('(3ull<<53)',graphics)
        self.assertIn('(2ull<<8)',graphics)
        self.assertIn('(3ull << 53)',core)
        self.assertIn('(2ull << 8)',core)


if __name__=='__main__':unittest.main()
