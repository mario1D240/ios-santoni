"""Actual reconstructed shader policy, captured arrays and compiling negatives."""
import hashlib,json,os
from pathlib import Path
import shlex,subprocess,tempfile,unittest
from tests.reconstruct_santoni_touch import reconstruct

ROOT=Path(__file__).resolve().parents[1]
FILES=('bsd/dev/santoni_gpu_ir3.c','bsd/dev/santoni_gpu_ir3.h','bsd/dev/santoni_gpu_ir3_rules.h')
INPUTS=('tests/test_santoni_gpu_ir3.py','tests/test_santoni_gpu_ir3.c',
    'tests/santoni_gpu_ir3_captured.h','tests/reconstruct_santoni_touch.py')
VARIANTS=(('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))
MUTANTS=(
    ('constant-read-mask','r->constant_reads[scalar/64]|=UINT64_C(1)<<(scalar%64);','',46),
    ('coordinate-war','if(e->borrowed[s/64]&bit)return false;','if(false)return false;',78),
    ('late-coordinate-war','if(e->borrowed[s/64]&bit)return false;','if(false)return false;',85),
    ('pending-read','if(e->pending[s/64]&bit)return false;','if(false)return false;',2),
    ('end-pending','return e->pending[0] || e->pending[1] || e->pending[2] || e->pending[3];','(void)e;return false;',70),
    ('input-release','(r->bary_instructions && !r->input_released)','false',3),
    ('early-release','r->input_released || !reg(&e,ij','!reg(&e,ij',4),
    ('varying-bound','(inloc&0x3ffu)>=limits->varying_scalars','false',5),
    ('varying-limit','limits->varying_scalars>128','limits->varying_scalars>256',7),
    ('integer-tag','(inloc&~0x3ffu)!=0x2000u','false',11),
    ('bary-pair','!reg(&e,ij,2,READ_ALU)','!reg(&e,ij,1,READ_ALU)',8),
    ('sam-timing','if(r->steps<(access==READ_SAM?e->sam_ready[s]:e->alu_ready[s]))return false;','if(false)return false;',18),
    ('repeat-timing','e->alu_ready[s]=r->steps+4','e->alu_ready[s]=0',74),
    ('mul-destination-repeat','IR3_MUL_DST(value)+n','IR3_MUL_DST(value)',19),
    ('mul-source-repeat','IR3_MUL_SRC1(value),a?n:0','IR3_MUL_SRC1(value),0',20),
    ('mad-destination-repeat','IR3_MAD_DST(value)+n','IR3_MAD_DST(value)',40),
    ('mad-source2-repeat','IR3_MAD_SRC2(value)+(b?n:0)','IR3_MAD_SRC2(value)',43),
    ('mad-source1-repeat','IR3_MAD_SRC1(value),a?n:0','IR3_MAD_SRC1(value),0',44),
    ('mad-source3-repeat','IR3_MAD_SRC3(value),c?n:0','IR3_MAD_SRC3(value),0',45),
    ('cat3-constant-repeat','constant(&e->r,l,(value&0x7ffu)+increment)','constant(&e->r,l,value&0x7ffu)',41),
    ('cat2-constant-repeat','constant(&e->r,l,(mode&0x7ffu)+increment)','constant(&e->r,l,mode&0x7ffu)',50),
    ('flut-half','value==0x2801u && !increment','(value&~0x400u)==0x2801u && !increment',21),
    ('flut-index','value==0x2801u && !increment','(value==0x2801u || value==0x2802u) && !increment',22),
    ('flut-modifier','value==0x2801u && !increment','(value&0x3fffu)==0x2801u && !increment',23),
    ('padding','if(words[pad*2] || words[pad*2+1])return false;','(void)pad;',29),
)

class IR3Contracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        cls.temp=tempfile.TemporaryDirectory(prefix='ir3-raster-',dir=preferred if preferred.is_dir() else None)
        cls.work=Path(cls.temp.name);external=os.environ.get('SANTONI_IR3_SOURCE')
        cls.source=Path(external) if external else cls.work/'source'
        if not external:reconstruct(cls.source,targets=FILES)
        cls.dev=cls.source/'bsd/dev';cls.rows=[];cls.cc=shlex.split(os.environ.get('CC','clang'))
        fixtures=Path(os.environ.get('SANTONI_IR3_FIXTURES',str(ROOT/'tests')))
        cls.fixture=fixtures/'test_santoni_gpu_ir3.c'
        cls.headers=fixtures/'santoni_gpu_ir3_captured.h'

    @classmethod
    def tearDownClass(cls):
        output=os.environ.get('SANTONI_IR3_RECORD')
        if output:
            sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
            complete=len(cls.rows)==3*(1+len(MUTANTS)) and all(row['compile_exit']==0 and
                len(row['runs'])==(1 if row['mutant'] else 90) and
                all((run['exit']!=0)==row['mutant'] for run in row['runs']) for row in cls.rows)
            record={'success':complete,'rows':cls.rows,'source_sha256':{f:sha(cls.source/f) for f in FILES},
                'inputs_sha256':{'tests/test_santoni_gpu_ir3.py':sha(Path(__file__)),
                    'tests/test_santoni_gpu_ir3.c':sha(cls.fixture),'tests/santoni_gpu_ir3_captured.h':sha(cls.headers),
                    'tests/reconstruct_santoni_touch.py':sha(ROOT/'tests/reconstruct_santoni_touch.py')},
                'native_executions':270,'compiled_rejected_mutants':3*len(MUTANTS),'hardware_verified':False}
            Path(output).write_text(json.dumps(record,indent=2)+'\n')
        cls.temp.cleanup()

    def run_variant(self,name,flags,source,case=None):
        binary=self.work/name
        command=[*self.cc,'-std=c11',*flags,'-Wall','-Wextra','-Werror','-DARM64_BOARD_CONFIG_SANTONI',
            '-I'+str(self.dev),'-I'+str(self.headers.parent),str(self.fixture),str(source),'-o',str(binary)]
        build=subprocess.run(command,capture_output=True,text=True,timeout=45)
        row={'name':name,'mutant':case is not None,'compile_exit':build.returncode,'compile_stderr':build.stderr,
            'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'command':command,'runs':[]};self.rows.append(row)
        self.assertEqual(build.returncode,0,build.stderr)
        cases=[(0,k) for k in range(5)]+[(t,4) for t in range(1,86)] if case is None else [(case,4)]
        for t,k in cases:
            run=subprocess.run([str(binary),str(t),'embedded-capture',str(k)],capture_output=True,text=True,timeout=15)
            row['runs'].append({'case':t,'kind':k,'exit':run.returncode,'stdout':run.stdout,'stderr':run.stderr})
            if case is None:self.assertEqual(run.returncode,0,run.stdout+run.stderr)
            else:self.assertNotEqual(run.returncode,0,name+' survived')

    def test_actual_O0_O2_UBSan(self):
        for label,flags in VARIANTS:self.run_variant(label,flags,self.dev/'santoni_gpu_ir3.c')

    def test_compiling_mutants(self):
        original=(self.dev/'santoni_gpu_ir3.c').read_text()
        for name,old,new,case in MUTANTS:
            # Audit names are a mechanical port of the old callable tokens.
            for token in ('reg','constant'):
                old=old.replace(token+'(', 'sgpu_ir3_'+token+'(')
                new=new.replace(token+'(', 'sgpu_ir3_'+token+'(')
            self.assertEqual(original.count(old),1,(name,old))
            source=self.work/(name+'.c');source.write_text(original.replace(old,new,1))
            for label,flags in VARIANTS:self.run_variant(name+'-'+label,flags,source,case)

if __name__=='__main__':unittest.main()
