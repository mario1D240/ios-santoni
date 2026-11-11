"""Whole immutable actual Mesa quad streams; transport deliberately refuses IO."""
import hashlib,json,os
from pathlib import Path
import shlex,subprocess,tempfile,unittest
from tests.reconstruct_santoni_touch import reconstruct
ROOT=Path(__file__).resolve().parents[1]
INPUTS=('tests/test_santoni_gpu_raster.py','tests/test_santoni_gpu_raster.c',
    'tests/santoni_gpu_raster_captured.h','tests/reconstruct_santoni_touch.py',
    'tools/santoni-graphics/client.c','tools/santoni-graphics/commands.c')
MODULES=('santoni_gpu_pm4','santoni_gpu_ir3','santoni_gpu_descriptors','santoni_gpu_raster','santoni_gpu_raster_batch')
FILES=tuple('bsd/dev/'+name for name in (
    'santoni_gpu_core.h','santoni_gpu_graphics.h','santoni_gpu_pm4.h','santoni_gpu_pm4.c',
    'santoni_gpu_ir3.h','santoni_gpu_ir3.c','santoni_gpu_ir3_rules.h',
    'santoni_gpu_descriptors.h','santoni_gpu_descriptors.c','santoni_gpu_descriptor_fields.h',
    'santoni_gpu_raster.h','santoni_gpu_raster.c','santoni_gpu_raster_rules.h','santoni_gpu_raster_fields.h',
    'santoni_gpu_raster_batch.h','santoni_gpu_raster_batch.c','santoni_gpu_graphics_uapi.h'))
VARIANTS=(('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))
BINDING='if(!sgpu_raster_have(c,b->index) || c->registers[b->index]!=(varying?b->quad:b->plain))'
MUTANTS=(
    ('warm-context','santoni_gpu_raster_batch',
        'if(profile>SGPU_GRAPHICS_VM_WIDE || !sgpu_raster_init(context,ranges,nr))return false;',
        'if(profile>SGPU_GRAPHICS_VM_WIDE || (prepare && !sgpu_raster_init(context,ranges,nr)))return false;',32),
    ('missing-used-constant','santoni_gpu_raster','if(s->load.constant_reads[i]&~s->constants[i])return false;',
        'if(false && (s->load.constant_reads[i]&~s->constants[i]))return false;',19),
    ('unwritten-varying','santoni_gpu_raster','!sgpu_raster_all_lanes(c->stage[0].load.written,4,2)','false',43),
    ('varying-slot','santoni_gpu_raster','fs->varying_reads[0]!=3','false',41),
    ('varying-flag','santoni_gpu_raster','F_CTRL_VARYING(VALUE(c,SP_FS_CTRL_REG0))!=varying','false',7),
    ('initial-input-as-output','santoni_gpu_raster','!sgpu_raster_all_lanes(defined,output,4)',
        '!(sgpu_raster_all_lanes(defined,output,4) || sgpu_raster_all_lanes(c->stage[1].load.defined,output,4))',45),
)+tuple((name,'santoni_gpu_raster',BINDING,
    'if(b->index!=R_'+register+' && (!sgpu_raster_have(c,b->index) || c->registers[b->index]!=(varying?b->quad:b->plain)))',case)
    for name,register,case in (
        ('enable','VPC_VAR_0_DISABLE',1),('vs-map','SP_VS_OUT_0_REG',2),('locations','SP_VS_VPC_DST_0_REG',3),
        ('output-count','SP_PRIMITIVE_CNTL',4),('vpc-stride','VPC_CNTL_0',5),('ij-pair','HLSQ_CONTROL_3_REG',6),
        ('varying-count','VPC_PACK',8),('pc-stride','PC_PRIMITIVE_CNTL',9),('mrt-blend','RB_MRT_0_CONTROL',10),
        ('factors','RB_MRT_0_BLEND_CONTROL',11),('sp-blend','SP_BLEND_CNTL',12),('rb-blend','RB_BLEND_CNTL',13),
        ('inactive-control','RB_MRT_1_CONTROL',14),('inactive-factor','RB_MRT_7_BLEND_CONTROL',15)))

class RasterContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        cls.temp=tempfile.TemporaryDirectory(prefix='raster-contracts-',dir=preferred if preferred.is_dir() else None)
        cls.work=Path(cls.temp.name);external=os.environ.get('SANTONI_RASTER_SOURCE')
        cls.source=Path(external) if external else cls.work/'source'
        if not external:reconstruct(cls.source,targets=FILES)
        cls.dev=cls.source/'bsd/dev';cls.rows=[];cls.cc=shlex.split(os.environ.get('CC','clang'))
        fixtures=Path(os.environ.get('SANTONI_RASTER_FIXTURES',str(ROOT/'tests')))
        cls.fixture=fixtures/'test_santoni_gpu_raster.c';cls.header=fixtures/'santoni_gpu_raster_captured.h'
        cls.frontend=Path(os.environ.get('SANTONI_RASTER_FRONTEND',str(ROOT/'tools/santoni-graphics')))

    @classmethod
    def tearDownClass(cls):
        output=os.environ.get('SANTONI_RASTER_RECORD')
        if output:
            sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
            complete=len(cls.rows)==3*(1+len(MUTANTS)) and all(row['compile_exit']==0 and
                len(row['runs'])==(1 if row['mutant'] else 51) and
                all((run['exit']!=0)==row['mutant'] for run in row['runs']) for row in cls.rows)
            record={'success':complete,'rows':cls.rows,'source_sha256':{f:sha(cls.source/f) for f in FILES},
                'inputs_sha256':{'tests/test_santoni_gpu_raster.py':sha(Path(__file__)),
                    'tests/test_santoni_gpu_raster.c':sha(cls.fixture),'tests/santoni_gpu_raster_captured.h':sha(cls.header),
                    'tests/reconstruct_santoni_touch.py':sha(ROOT/'tests/reconstruct_santoni_touch.py'),
                    **{'tools/santoni-graphics/'+name:sha(cls.frontend/name) for name in ('client.c','commands.c')}},
                'native_executions':153,'compiled_rejected_mutants':3*len(MUTANTS),'hardware_verified':False,
                'transport_refused_after_validation':True}
            Path(output).write_text(json.dumps(record,indent=2)+'\n')
        cls.temp.cleanup()

    def run_variant(self,name,flags,replacement=None,case=None):
        binary=self.work/name
        sources=[cls for cls in (self.fixture,self.frontend/'client.c',self.frontend/'commands.c')]
        sources += [replacement[1] if replacement and replacement[0]==module else self.dev/(module+'.c') for module in MODULES]
        command=[*self.cc,'-std=c11',*flags,'-Wall','-Wextra','-Werror','-DARM64_BOARD_CONFIG_SANTONI',
            '-I'+str(self.dev),'-I'+str(self.header.parent),'-I'+str(self.frontend),*[str(p) for p in sources],'-o',str(binary)]
        build=subprocess.run(command,capture_output=True,text=True,timeout=45)
        row={'name':name,'command':command,'mutant':case is not None,'compile_exit':build.returncode,'compile_stderr':build.stderr,
            'source_sha256':{'tests/test_santoni_gpu_raster.c':hashlib.sha256(self.fixture.read_bytes()).hexdigest(),
                **{'tools/santoni-graphics/'+name:hashlib.sha256((self.frontend/name).read_bytes()).hexdigest() for name in ('client.c','commands.c')},
                **{'bsd/dev/'+module+'.c':hashlib.sha256((replacement[1] if replacement and replacement[0]==module else self.dev/(module+'.c')).read_bytes()).hexdigest()
                    for module in MODULES}},'runs':[]};self.rows.append(row)
        self.assertEqual(build.returncode,0,build.stderr)
        for t in range(51) if case is None else [case]:
            run=subprocess.run([str(binary),'embedded-capture','4',str(t)],capture_output=True,text=True,timeout=20)
            row['runs'].append({'case':t,'exit':run.returncode,'stdout':run.stdout,'stderr':run.stderr})
            if case is None:self.assertEqual(run.returncode,0,run.stdout+run.stderr)
            else:self.assertNotEqual(run.returncode,0,name+' survived')

    def test_actual_O0_O2_UBSan(self):
        for label,flags in VARIANTS:self.run_variant(label,flags)

    def test_compiling_mutants(self):
        for name,module,old,new,case in MUTANTS:
            original=(self.dev/(module+'.c')).read_text();self.assertEqual(original.count(old),1,(name,old))
            source=self.work/(name+'.c');source.write_text(original.replace(old,new,1))
            for label,flags in VARIANTS:self.run_variant(name+'-'+label,flags,(module,source),case)

if __name__=='__main__':unittest.main()
