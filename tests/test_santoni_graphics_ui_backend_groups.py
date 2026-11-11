"""Actual shared backend factory, reference closure and metadata ownership."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from tests.santoni_graphics_sharing_record import write_sharing_record
ROOT=Path(__file__).resolve().parents[1];WORK=ROOT/'tools/santoni-graphics'
MESA=ROOT/'out/mesa-a505-25.0.7-reference'
FLAGS=(('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))
MUTANTS=(('missing-member-hold','c','!sgfx_ui_mesa_group_retain(g)','false',0),
    ('wrong-sharing','c','sgfx_gles_create_shared_api(api,g->anchor)','sgfx_gles_create_api(api)',0),
    ('leak-member-hold','c','if(m->group)sgfx_ui_mesa_group_release(m->group);','(void)m->group;',0),
    ('lost-root','c','g->anchor=sgfx_gles_create_api(api);','g->anchor=NULL;',0),
    ('isolated-shader-metadata','h','return m->group?m->group->shaders:m->shaders;','return m->shaders;',0),
    ('isolated-program-metadata','h','return m->group?m->group->programs:m->programs;','return m->programs;',0))
class BackendGroups(unittest.TestCase):
    def test_actual_groups_and_compiling_unsafe_variants(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        c=(WORK/'ui_backend.c').read_text();h=(WORK/'ui_backend.h').read_text();rows=[]
        with tempfile.TemporaryDirectory(prefix='backend-groups-',dir=preferred if preferred.is_dir() else None) as temporary:
            work=Path(temporary)
            variants=[('actual',c,h,range(7))]
            for name,kind,old,new,case in MUTANTS:
                self.assertEqual((c if kind=='c' else h).count(old),1,name)
                variants.append((name,c.replace(old,new,1) if kind=='c' else c,h.replace(old,new,1) if kind=='h' else h,[case]))
            for name,body,header,cases in variants:
                folder=work/name;folder.mkdir();(folder/'ui_backend.c').write_text(body);(folder/'ui_backend.h').write_text(header)
                (folder/'fixture.c').write_bytes((ROOT/'tests/test_santoni_graphics_ui_backend_groups.c').read_bytes())
                for label,flags in FLAGS:
                    binary=folder/label
                    command=['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-pthread',
                        '-I',str(folder),'-I',str(WORK),'-I',str(MESA/'include'),str(folder/'fixture.c'),str(folder/'ui_backend.c'),'-o',str(binary)]
                    build=subprocess.run(command,capture_output=True,text=True,timeout=45)
                    row={'name':name+'-'+label,'command':command,'compile_exit':build.returncode,'compile_stderr':build.stderr,
                        'source_sha256':hashlib.sha256(body.encode()).hexdigest(),'header_sha256':hashlib.sha256(header.encode()).hexdigest(),'runs':[]};rows.append(row)
                    self.assertEqual(build.returncode,0,build.stderr)
                    for case in cases:
                        run=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=10)
                        row['runs'].append({'case':case,'exit':run.returncode,'stdout':run.stdout,'stderr':run.stderr})
                        self.assertEqual(run.returncode==0,name=='actual',name+' '+run.stdout+run.stderr)
            write_sharing_record('backend',{'success':True,'rows':rows,'positive_executions':21,
                'compiled_rejected_mutants':18,'GL_Mesa_IOSurface_modeled':True})

if __name__=='__main__':unittest.main(verbosity=2)
