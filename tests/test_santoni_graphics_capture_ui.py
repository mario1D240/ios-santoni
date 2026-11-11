"""Actual optional emitter ordering/refusals; not shader or GPU rendering proof."""
import hashlib,json,os
from pathlib import Path
import subprocess,tempfile,unittest
from tests.test_santoni_graphics_msm import ROOT,MESA
from tests.test_santoni_gpu_prepare import source_function

class CaptureUI(unittest.TestCase):
    def test_actual_emitter_and_compiling_contract_mutants(self):
        body=source_function((ROOT/'tools/santoni-graphics/capture/main.c').read_text(),'ui_quad')
        mutants={
            'shader-failure':('if(!vs || !fs)return false;','if((!vs || !fs) && false)return false;',1),
            'link-failure':('if(!linked)return false;','if(!linked && false)return false;',3),
            'texture-guard':('!source || !vertices','!vertices',5),
            'vertex-guard':('!source || !vertices','!source',6),
            'premultiplied-blend':('glBlendFunc(GL_ONE,GL_ONE_MINUS_SRC_ALPHA)','glBlendFunc(GL_SRC_ALPHA,GL_ONE_MINUS_SRC_ALPHA)',0),
            'linear-min-filter':('GL_TEXTURE_MIN_FILTER,GL_LINEAR','GL_TEXTURE_MIN_FILTER,GL_NEAREST',0),
            'primitive':('glDrawArrays(GL_TRIANGLE_STRIP,0,4)','glDrawArrays(GL_TRIANGLES,0,4)',0),
            'vertex-count':('glDrawArrays(GL_TRIANGLE_STRIP,0,4)','glDrawArrays(GL_TRIANGLE_STRIP,0,3)',0),
            'vertex-span':('sizeof(data),data','sizeof(data)-sizeof(data[0]),data',0),
            'GL-error':('return glGetError()==GL_NO_ERROR;','return glGetError()==GL_NO_ERROR || true;',4),
        }
        rows=[];preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='capture-UI-emitter-',dir=preferred if preferred.is_dir() else None) as temporary:
            work=Path(temporary)
            variants=[('actual',body,None)]
            for name,(old,new,case) in mutants.items():
                self.assertEqual(body.count(old),1,name);variants.append((name,body.replace(old,new,1),case))
            for name,source,selected in variants:
                header=work/'capture_ui_actual.h';header.write_text(source)
                for label,flags in [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:
                    binary=work/(name+'-'+label)
                    command=['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-I'+str(work),'-I'+str(MESA/'include'),
                        str(ROOT/'tests/test_santoni_graphics_capture_ui.c'),'-o',str(binary)]
                    built=subprocess.run(command,capture_output=True,text=True,timeout=30)
                    row={'label':name+'-'+label,'compile_exit':built.returncode,'compile_stderr':built.stderr,'command':command,
                        'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'runs':[]};rows.append(row)
                    self.assertEqual(built.returncode,0,built.stderr)
                    for case in (range(7) if selected is None else [selected]):
                        run=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=15)
                        row['runs'].append({'case':case,'exit':run.returncode,'stdout':run.stdout,'stderr':run.stderr})
                        if selected is None:self.assertEqual(run.returncode,0,run.stdout+run.stderr)
                        else:self.assertNotEqual(run.returncode,0,name+' survived')
        record=os.environ.get('SANTONI_CAPTURE_UI_RECORD')
        if record:
            with Path(record).open('x') as output:json.dump({'success':True,'positive_executions':21,'compiled_rejected_mutants':30,'rows':rows,
                'main_source_sha256':hashlib.sha256((ROOT/'tools/santoni-graphics/capture/main.c').read_bytes()).hexdigest(),
                'GL_shader_compiler_GPU_are_models':True,'hardware_verified':False},output,indent=2)

if __name__=='__main__':unittest.main()
