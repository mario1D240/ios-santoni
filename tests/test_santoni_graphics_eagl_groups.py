"""Compiling unsafe EAGL group/property variants against actual callbacks."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from tests.santoni_graphics_sharing_record import write_sharing_record
ROOT=Path(__file__).resolve().parents[1];WORK=ROOT/'tools/santoni-graphics'
from tests.reconstruct_santoni_touch import reconstruct
from tests.test_santoni_gpu_prepare import source_function
MESA=ROOT/'out/mesa-a505-25.0.7-reference'
FLAGS=(('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))
MUTANTS=(
    ('api-match', 'initialize', 'g->api==api', 'true', 17),
    ('existing-group-retain', 'initialize', 'if(!new)retain_object(g->object);', '(void)new;', 16),
    ('native-mixing', 'initialize', 'if(own_request)return nil;', '(void)own_request;', 17),
    ('group-lookup', 'sharegroup', 'return c?group:((id (*)(id,SEL))original_sharegroup)(self,command);', '(void)c;(void)group;return ((id (*)(id,SEL))original_sharegroup)(self,command);', 15),
    ('quarantine-association', 'deallocate', 'if(!sgfx_ui_context_destroy(c))return;', '(void)sgfx_ui_context_destroy(c);', 29),
    ('client-label-bound', 'properties_valid', 'if(value<0 || value>8)return false;', 'if(false)return false;', 21),
    ('unsupported-compute', 'properties_valid', 'if(value!=0)return false;', 'if(false)return false;', 19),
    ('group-ABI', 'sgfx_eagl_install', 'if(!encoding || strcmp(encoding,h->encoding) || !method_getImplementation(methods[i]))goto done;',
        'if(!encoding || !method_getImplementation(methods[i]))goto done;', 27),
    ('retain-client', 'set_current', 'bool manage=entry && !entry->client_managed;', 'bool manage=entry!=NULL;', 31),
    ('release-client', 'set_current', 'if(old_retained)release_object(old);return ok;', 'release_object(old);return ok;', 31),
    ('skip-owned-release', 'set_current', 'if(old_retained)release_object(old);return true;', '(void)old_retained;return true;', 36),
    ('stale-current', 'deallocate', 'if(held_current==self) {held_current=nil;held_current_retained=false;}', '(void)self;', 37),
    ('client-bool', 'properties_valid', 'if(value!=0 && value!=1)return false;', 'if(false)return false;', 34),
    ('software-as-gpu', 'properties_valid', 'if(value!=1)return false;', 'if(false)return false;', 33),
    ('release-failed-client', 'set_current', 'if(!sgfx_ui_context_bind(c)) {if(manage)release_object(object);return false;}', 'if(!sgfx_ui_context_bind(c)) {release_object(object);return false;}', 42),
    ('set-binds-rejected', 'set_parameter', 'return value?0x2710:0x271e;', 'sgfx_ui_bind(c);return value?0x2710:0x271e;', 45),
    ('set-poisons-context', 'set_parameter', 'return value?0x2710:0x271e;', 'if(value)sgfx_ui_unsupported(c,name);return value?0x2710:0x271e;', 43),
    ('get-binds-rejected', 'get_parameter', '*value=0;return 0x2710;', '*value=0;sgfx_ui_bind(c);return 0x2710;', 46),
    ('get-poisons-context', 'get_parameter', '*value=0;return 0x2710;', '*value=0;sgfx_ui_unsupported(c,name);return 0x2710;', 14),
    ('set-claims-success', 'set_parameter', 'return value?0x2710:0x271e;', 'return value?0:0x271e;', 43),
    ('get-claims-success', 'get_parameter', '*value=0;return 0x2710;', '*value=0;return 0;', 46),
    ('set-reads-rejected-input', 'set_parameter', 'return value?0x2710:0x271e;', 'return value?(*value==0?0x2710:0x2718):0x271e;', 45),
)
class EAGLGroupMutations(unittest.TestCase):
    def test_compiling_unsafe_group_paths(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        rows=[];success=False
        original=(WORK/'ui_eagl.c').read_text()
        try:
            with tempfile.TemporaryDirectory(prefix='eagl-group-mutants-',dir=preferred if preferred.is_dir() else None) as temporary:
                work=Path(temporary);reconstruct(work/'source',targets=('bsd/dev/santoni_gpu_graphics_uapi.h',))
                for name,function,old,new,case in MUTANTS:
                    scope=source_function(original,function);self.assertEqual(scope.count(old),1,name)
                    changed=original.replace(scope,scope.replace(old,new,1),1);source=work/(name+'.c');source.write_text(changed)
                    for label,flags in FLAGS:
                        binary=work/(name+'-'+label)
                        command=['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-pthread',
                            '-I',str(ROOT/'tests/ui_eagl_stubs'),'-I',str(WORK),'-I',str(ROOT/'tools/santoni-graphics'),'-I',str(MESA/'include'),
                            '-I',str(work/'source/bsd/dev'),str(ROOT/'tests/test_santoni_graphics_eagl.c'),str(source),str(WORK/'ui_context.c'),str(WORK/'ui_surface.c'),'-o',str(binary)]
                        build=subprocess.run(command,capture_output=True,text=True,timeout=45)
                        row={'name':name+'-'+label,'command':command,'compile_exit':build.returncode,'compile_stderr':build.stderr,
                            'source_sha256':hashlib.sha256(changed.encode()).hexdigest(),'case':case};rows.append(row)
                        self.assertEqual(build.returncode,0,build.stderr)
                        run=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=10)
                        row.update(exit=run.returncode,stdout=run.stdout,stderr=run.stderr)
                        self.assertNotEqual(run.returncode,0,name+' survived')
                success=True
        finally:
            write_sharing_record('eagl-mutants',{'success':success,'rows':rows,
                'compiled_rejected_mutants':sum(r.get('compile_exit')==0 and r.get('exit',0)!=0 for r in rows),
                'ObjC_GL_IOSurface_modeled':True})

if __name__=='__main__':unittest.main(verbosity=2)
