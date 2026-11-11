"""Native actual PM4 relocation/ownership contracts; no GPU or shader execution."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from tests.test_santoni_gpu_prepare import source_function
from tests.reconstruct_santoni_touch import reconstruct

ROOT=Path(__file__).resolve().parents[1]
FILES=('bsd/dev/santoni_gpu_core.h','bsd/dev/santoni_gpu_graphics.h',
       'bsd/dev/santoni_gpu_pm4.h','bsd/dev/santoni_gpu_pm4.c')
VARIANTS=(('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))
MUTANTS=(
 ('parity','sgpu_pm4_parity','return p;','return p|1;'),
 ('write-ro','sgpu_pm4_data','(!write || r->flags==SGPU_GRAPHICS_RW)','(!write || true || r->flags==SGPU_GRAPHICS_RW)'),
 ('span','sgpu_pm4_data','bytes<=r->bytes-(va-r->gpu_va)','bytes<=r->bytes'),
 ('relocate','sgpu_pm4_child','va=s->gpu_va+va-s->source_va;*lo=va;','va=s->gpu_va+va-s->source_va;'),
 ('cycle','sgpu_pm4_walk','i<w->depth','i<w->depth && false'),
 ('depth','sgpu_pm4_walk','w->depth>=SGPU_PM4_DEPTH','w->depth>=SGPU_PM4_DEPTH-1'),
 ('a6xx','sgpu_pm4_packet','control&~0x1f0fffffu','control&~0x1f1fffffu'),
 ('high-address','sgpu_pm4_child','if (hi || !words','if ((hi && false) || !words'),
 ('packet-size','sgpu_pm4_walk','count>bytes/4-pos-1','count>bytes/4-pos'),
 ('nodes','sgpu_pm4_walk','w->nodes>=SGPU_PM4_NODES','w->nodes>SGPU_PM4_NODES'),
 ('budget','sgpu_pm4_walk','bytes/4>SGPU_PM4_WORDS-w->words','bytes/4>SGPU_PM4_WORDS'),
)


class PM4Contracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        cls.temp=tempfile.TemporaryDirectory(prefix='pm4-0224-',dir=preferred if preferred.is_dir() else None)
        cls.work=Path(cls.temp.name)
        external=os.environ.get('SANTONI_PM4_SOURCE')
        cls.source=Path(external) if external else cls.work/'source'
        if not external:reconstruct(cls.source,targets=FILES)
        cls.dev=cls.source/'bsd/dev';cls.rows=[];cls.cc=shlex.split(os.environ.get('CC','clang'))

    @classmethod
    def tearDownClass(cls):
        record=os.environ.get('SANTONI_PM4_RECORD')
        if record:
            ok=len(cls.rows)==3+3*len(MUTANTS) and all(r['compile_exit']==0 and
                ((len(r['runs'])==46 and all(x['exit_code']==0 for x in r['runs'])) if not r['mutant'] else
                 bool(r['runs']) and r['runs'][-1]['exit_code']!=0) for r in cls.rows)
            Path(record).write_text(json.dumps({'success':ok,'hardware_verified':False,'rows':cls.rows,
                'source_sha256':{f:hashlib.sha256((cls.source/f).read_bytes()).hexdigest() for f in FILES},
                'inputs_sha256':{f:hashlib.sha256((ROOT/f).read_bytes()).hexdigest() for f in
                    ('tests/test_santoni_gpu_pm4.c','tests/test_santoni_gpu_pm4.py','tests/reconstruct_santoni_touch.py')},
                'scope':'actual PM4 functions; private snapshots/ranges modeled; no hardware/shader result'},indent=2)+'\n')
        cls.temp.cleanup()

    def run_variant(self,label,flags,source,mutant):
        binary=self.work/label
        built=subprocess.run([*self.cc,'-std=c11',*flags,'-Wall','-Wextra','-Werror','-DARM64_BOARD_CONFIG_SANTONI',
            '-I',str(self.dev),str(ROOT/'tests/test_santoni_gpu_pm4.c'),str(source),'-o',str(binary)],capture_output=True,text=True)
        row={'label':label,'mutant':mutant,'compile_exit':built.returncode,'compile_stderr':built.stderr,
             'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'runs':[]};self.rows.append(row)
        self.assertEqual(built.returncode,0,built.stderr)
        for case in range(46):
            r=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=10)
            row['runs'].append({'case':case,'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
            if mutant and r.returncode:return
            if not mutant:self.assertEqual(r.returncode,0,r.stderr)
        if mutant:self.fail(label+' survived')

    def test_actual_O0_O2_UBSan(self):
        for label,flags in VARIANTS:self.run_variant(label,flags,self.dev/'santoni_gpu_pm4.c',False)

    def test_compiling_mutants(self):
        original=(self.dev/'santoni_gpu_pm4.c').read_text()
        for name,function,old,new in MUTANTS:
            body=source_function(original,function)
            if name=='a6xx' and body.count(old)==0:
                # The ordered callback adapter delegates framing to this
                # actual helper. Mutate the SAME exact A6xx exclusion there,
                # not the wrapper, and keep the compiled negative contract.
                self.assertIn('sgpu_pm4_packet_shape(w,op,p,n)',body)
                function='sgpu_pm4_packet_shape'
                body=source_function(original,function)
            self.assertEqual(body.count(old),1,(name,old))
            changed=original.replace(body,body.replace(old,new),1)
            source=self.work/(name+'.c');source.write_text(changed)
            for label,flags in VARIANTS:self.run_variant(name+'-'+label,flags,source,True)


if __name__=='__main__':unittest.main()
