"""Actual pinned/patched Mesa attr64 copy, failed allocation and compiling negatives."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from tests.reconstruct_santoni_touch import selected_sections
from tests.test_santoni_gpu_prepare import source_function
ROOT=Path(__file__).resolve().parents[1]
MESA=Path(os.environ.get('SANTONI_MESA_SOURCE',str(ROOT/'out/mesa-a505-25.0.7-reference')))
FILE='src/mesa/main/dlist.c'
VARIANTS=(('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))
INPUTS=('tests/test_santoni_graphics_mesa_oom.py','tests/test_santoni_graphics_mesa_oom.c',
    'tests/reconstruct_santoni_touch.py','tests/test_santoni_gpu_prepare.py',
    'tools/santoni-graphics/mesa-reference.json','tools/santoni-graphics/mesa-ios.patch')
MUTANTS=(('heap-copy','memcpy(ctx->ListState.CurrentAttrib[index], v, size * sizeof(uint64_t));',
    'memcpy(ctx->ListState.CurrentAttrib[index], &n[2], size * sizeof(uint64_t));',1),
    ('half-copy','size * sizeof(uint64_t)','size * sizeof(uint32_t)',0),
    ('wrong-index','attr -= VERT_ATTRIB_GENERIC0;','attr -= 0;',0))

class MesaOOM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        cls.temp=tempfile.TemporaryDirectory(prefix='mesa-attr64-oom-',dir=preferred if preferred.is_dir() else None)
        cls.work=Path(cls.temp.name);cls.rows=[]
        lock=json.loads((ROOT/'tools/santoni-graphics/mesa-reference.json').read_text())
        assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=MESA,text=True).strip()==lock['commit']
        baseline=subprocess.check_output(['git','show',lock['commit']+':'+FILE],cwd=MESA)
        assert hashlib.sha256(baseline).hexdigest()==lock['source_sha256'][FILE]
        assert baseline==(MESA/FILE).read_bytes()
        source=cls.work/'source';path=source/FILE;path.parent.mkdir(parents=True);path.write_bytes(baseline)
        subprocess.run(['git','init','--quiet',str(source)],check=True,timeout=15)
        section=selected_sections((ROOT/'tools/santoni-graphics/mesa-ios.patch').read_bytes(),targets=(FILE,))
        assert section
        for command in (['git','apply','--check','-'],['git','apply','-']):
            subprocess.run(command,cwd=source,input=section,check=True,capture_output=True,timeout=15)
        cls.baseline=source_function(baseline.decode(),'save_Attr64bit')
        cls.fixed=source_function(path.read_text(),'save_Attr64bit')
        text=baseline.decode();macro=text[text.index('#define ASSIGN_UINT64_TO_NODES'):text.index('#define ASSIGN_INT64_TO_NODES')].rstrip()
        (cls.work/'assign-nodes.h').write_text(macro+'\n')
        cls.source_sha256=hashlib.sha256(path.read_bytes()).hexdigest()
        cls.cc=shlex.split(os.environ.get('CC','clang'))

    @classmethod
    def tearDownClass(cls):
        output=os.environ.get('SANTONI_MESA_OOM_RECORD')
        if output:
            record={'rows':cls.rows,'patched_dlist_sha256':cls.source_sha256,
                'inputs_sha256':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in INPUTS},
                'hardware_verified':False}
            Path(output).write_text(json.dumps(record,indent=2)+'\n')
        cls.temp.cleanup()

    def execute(self,label,flags,body,cases,failed):
        directory=self.work/label;directory.mkdir();(directory/'function.h').write_text(body+'\n')
        command=[*self.cc,'-std=c11',*flags,'-Wall','-Wextra','-Werror','-I',str(directory),'-I',str(self.work),
            str(ROOT/'tests/test_santoni_graphics_mesa_oom.c'),'-o',str(directory/'test')]
        build=subprocess.run(command,capture_output=True,text=True,timeout=45)
        row={'label':label,'command':command,'compile_exit':build.returncode,'compile_stderr':build.stderr,
            'function_sha256':hashlib.sha256(body.encode()).hexdigest(),'runs':[]};self.rows.append(row)
        self.assertEqual(build.returncode,0,build.stderr)
        for case in cases:
            run=subprocess.run([str(directory/'test'),str(case)],capture_output=True,text=True,timeout=10)
            row['runs'].append({'case':case,'exit':run.returncode,'stdout':run.stdout,'stderr':run.stderr})
            self.assertEqual(bool(run.returncode),bool(failed(case)),run.stdout+run.stderr)

    def test_actual_fixed_O0_O2_UBSan(self):
        for label,flags in VARIANTS:self.execute('fixed-'+label,flags,self.fixed,range(40),lambda case:False)

    def test_baseline_failure_is_reproduced_not_a_forged_mutant(self):
        for label,flags in VARIANTS:self.execute('baseline-'+label,flags,self.baseline,range(40),lambda case:case&1)

    def test_compiling_wrong_copy_and_dispatch_variants_rejected(self):
        for name,old,new,case in MUTANTS:
            self.assertEqual(self.fixed.count(old),1)
            for label,flags in VARIANTS:self.execute(name+'-'+label,flags,self.fixed.replace(old,new,1),[case],lambda case:True)

if __name__=='__main__':unittest.main()
