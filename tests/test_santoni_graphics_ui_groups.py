"""Actual portable surface groups, context lifetimes and compiling refusals."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from tests.santoni_graphics_sharing_record import write_sharing_record
ROOT=Path(__file__).resolve().parents[1];WORK=ROOT/'tools/santoni-graphics'
from tests.test_santoni_gpu_prepare import source_function
VARIANTS=(('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))
MUTANTS=(
    ('isolated-peer','sgfx_ui_context_create_in_group','create_context(object,api,backend,NULL,group,dispatch)',
        'create_context(object,api,backend,&group->surface,NULL,dispatch)',0),
    ('premature-release','group_drop','if(--g->references)return true;','g->references--;',0),
    ('peer-poison','sgfx_ui_context_bind','c->group->first_failure','false',3),
    ('wrong-producer','transfer','output && t->dirty && t->producer!=c','false',8),
    ('overwrite-producer','sgfx_ui_context_dirty','t->dirty && t->producer!=c','false',4),
)
class SurfaceGroups(unittest.TestCase):
    def test_actual_group_surface_and_context_lifetimes(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='ui-groups-',dir=preferred if preferred.is_dir() else None) as temporary:
            work=Path(temporary);rows=[]
            prefix=(ROOT/'tests/test_santoni_graphics_ui_context.c').read_text().split('int main(',1)[0]
            (work/'context_models.h').write_text(prefix)
            actual=(WORK/'ui_context.c').read_text()
            variants=[('actual',actual,range(9))]
            for name,function,old,new,case in MUTANTS:
                scope=source_function(actual,function);self.assertEqual(scope.count(old),1,name)
                variants.append((name,actual.replace(scope,scope.replace(old,new,1),1),[case]))
            for name,body,cases in variants:
                source=work/(name+'.c');source.write_text(body)
                for label,flags in VARIANTS:
                    binary=work/(name+'-'+label)
                    command=['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-pthread','-I',str(WORK),'-I',str(work),
                        str(ROOT/'tests/test_santoni_graphics_ui_groups.c'),str(source),str(WORK/'ui_surface.c'),'-o',str(binary)]
                    build=subprocess.run(command,capture_output=True,text=True,timeout=45)
                    row={'name':name+'-'+label,'command':command,'compile_exit':build.returncode,'compile_stderr':build.stderr,
                        'source_sha256':hashlib.sha256(body.encode()).hexdigest(),'runs':[]};rows.append(row)
                    self.assertEqual(build.returncode,0,build.stderr)
                    for case in cases:
                        run=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=10)
                        row['runs'].append({'case':case,'exit':run.returncode,'stdout':run.stdout,'stderr':run.stderr})
                        self.assertEqual(run.returncode==0,name=='actual',name+'-'+label+' case='+str(case)+'\n'+run.stdout+run.stderr)
            write_sharing_record('surfaces',{'success':True,'rows':rows,'positive_executions':27,
                'compiled_rejected_mutants':15,'GL_Mesa_IOSurface_modeled':True})

if __name__=='__main__':unittest.main(verbosity=2)
