"""Shader/constant snapshot and relocation contracts against the real packager."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from tests.reconstruct_santoni_touch import reconstruct

ROOT=Path(__file__).resolve().parents[1]
VARIANTS=(('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))
MUTANTS=(
    ('state-flags','offset,flags};','offset,0};',0),
    ('data-root','for(unsigned i=0;i<w->data_count;i++)if(w->data[i].copy==copy &&\n            at<',
                 'for(unsigned i=0;i<w->data_count && false;i++)if(w->data[i].copy==copy &&\n            at<',0),
    ('state-address','w->copy[w->reloc[i].copy].mirror->gpu_va+w->reloc[i].offset',
                     'w->copy[w->reloc[i].copy].source->gpu_va+w->reloc[i].offset',0),
    ('shader-span','type?16u:128u','type?16u:4u',3),
    ('source-span','bytes<=candidate->bytes-(va-candidate->gpu_va)',
                   'bytes<=candidate->bytes',25),
    ('shader-register','!command_blob(w,&p[i],p[i+1],0,0)',
                       '(!command_blob(w,&p[i],p[i+1],0,0) && false)',21),
)

class StateTests(unittest.TestCase):
    def test_actual_state_packaging_and_mutants(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode');rows=[]
        with tempfile.TemporaryDirectory(prefix='graphics-state-',dir=preferred if preferred.is_dir() else None) as t:
            w=Path(t);targets=('bsd/dev/santoni_gpu_core.h','bsd/dev/santoni_gpu_graphics.h',
                'bsd/dev/santoni_gpu_pm4.h','bsd/dev/santoni_gpu_pm4.c','bsd/dev/santoni_gpu_graphics_uapi.h')
            source=reconstruct(w/'source',targets=targets)
            original=(ROOT/'tools/santoni-graphics/commands.c').read_text()
            runs=[('actual',ROOT/'tools/santoni-graphics/commands.c',list(range(26)),False)]
            for name,old,new,case in MUTANTS:
                self.assertEqual(original.count(old),1,name)
                p=w/(name+'.c');p.write_text(original.replace(old,new,1));runs.append((name,p,[case],True))
            for name,p,cases,mutant in runs:
                for variant,flags in VARIANTS:
                    binary=w/(name+'-'+variant)
                    build=subprocess.run(['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror',
                        '-DARM64_BOARD_CONFIG_SANTONI','-I',str(w/'source/bsd/dev'),
                        '-I',str(ROOT/'tools/santoni-graphics'),str(ROOT/'tests/test_santoni_graphics_state.c'),
                        str(ROOT/'tools/santoni-graphics/client.c'),str(p),
                        str(w/'source/bsd/dev/santoni_gpu_pm4.c'),'-o',str(binary)],capture_output=True,text=True,timeout=60)
                    row={'label':name+'-'+variant,'mutant':mutant,'source_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
                         'compile_exit':build.returncode,'compile_stderr':build.stderr,'runs':[]};rows.append(row)
                    self.assertEqual(build.returncode,0,build.stderr)
                    for case in cases:
                        r=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=20)
                        row['runs'].append({'case':case,'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
                        if mutant:self.assertNotEqual(r.returncode,0,row)
                        else:self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            record=os.environ.get('SANTONI_GRAPHICS_STATE_RECORD')
            if record:
                inputs=('tools/santoni-graphics/commands.c','tools/santoni-graphics/commands.h',
                        'tools/santoni-graphics/client.c','tests/test_santoni_graphics_state.c',
                        'tests/test_santoni_graphics_state.py','tests/test_santoni_graphics_commands.c')
                Path(record).write_text(json.dumps({'success':True,'rows':rows,'kernel_source_sha256':source['sha256'],
                    'inputs_sha256':{f:hashlib.sha256((ROOT/f).read_bytes()).hexdigest() for f in inputs},
                    'positive_executions':78,'compiled_rejected_mutants':18,'hardware_verified':False,
                    'kernel_shader_admission_enabled':False},indent=2)+'\n')

if __name__=='__main__':unittest.main()
