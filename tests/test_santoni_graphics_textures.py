"""Actual direct texture packager; immutable descriptors/public pixels/default-off kernel."""
import hashlib,json,os
from pathlib import Path
import subprocess,tempfile,unittest
from tests.test_santoni_graphics_msm import ROOT
from tests.reconstruct_santoni_touch import reconstruct
class TexturePackagingTests(unittest.TestCase):
    def test_actual_texture_framing_and_mutants(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        rows=[]
        with tempfile.TemporaryDirectory(prefix='texture-packaging-',dir=preferred if preferred.is_dir() else None) as temporary:
            work=Path(temporary);reconstruct(work/'source',targets=('bsd/dev/santoni_gpu_core.h','bsd/dev/santoni_gpu_graphics.h',
                'bsd/dev/santoni_gpu_pm4.h','bsd/dev/santoni_gpu_pm4.c','bsd/dev/santoni_gpu_graphics_uapi.h'))
            source=(ROOT/'tools/santoni-graphics/commands.c').read_text()
            mutants={
                'high-address':('(texture[5]&0x1ffffu)','false',9),
                'missing-owner':('if(!owned)return command_fail(w,SGFX_CMD_ADDRESS);','if(!owned && false)return command_fail(w,SGFX_CMD_ADDRESS);',11),
                'descriptor-rewrite':('if(!owned)return command_fail(w,SGFX_CMD_ADDRESS);','if(!owned)return command_fail(w,SGFX_CMD_ADDRESS);p[3+unit*12+4]+=4;',0),
                'surface-in-ib':('owned=true;','{owned=true;(void)command_copy(w,bo);}',3),
                'direct-pointer':('type>1 || p[1]!=type ||','type>1 ||',15),
                'unit-bound':('!units || units>16 ||','!units ||',7),
            }
            variants=[('actual',ROOT/'tools/santoni-graphics/commands.c',None)]
            for name,(old,new,case) in mutants.items():
                self.assertEqual(source.count(old),1,name);path=work/(name+'.c');path.write_text(source.replace(old,new,1));variants.append((name,path,case))
            for name,path,case in variants:
                for label,flags in [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:
                    binary=work/(name+'-'+label)
                    command=['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-DARM64_BOARD_CONFIG_SANTONI',
                        '-I'+str(work/'source/bsd/dev'),'-I'+str(ROOT/'tools/santoni-graphics'),
                        str(ROOT/'tests/test_santoni_graphics_textures.c'),str(ROOT/'tools/santoni-graphics/client.c'),str(path),
                        str(work/'source/bsd/dev/santoni_gpu_pm4.c'),'-o',str(binary)]
                    build=subprocess.run(command,capture_output=True,text=True,timeout=45)
                    row={'label':name+'-'+label,'command':command,'source_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                        'compile_exit':build.returncode,'compile_stderr':build.stderr,'runs':[]};rows.append(row)
                    self.assertEqual(build.returncode,0,build.stderr)
                    for test in (range(22) if case is None else [case]):
                        run=subprocess.run([str(binary),str(test)],capture_output=True,text=True,timeout=15)
                        row['runs'].append({'case':test,'exit':run.returncode,'stdout':run.stdout,'stderr':run.stderr})
                        if case is None:self.assertEqual(run.returncode,0,run.stdout+run.stderr)
                        else:self.assertNotEqual(run.returncode,0,name+' survived actual texture framing')
            destination=os.environ.get('SANTONI_GRAPHICS_TEXTURE_RECORD')
            if destination:
                with Path(destination).open('x') as output:json.dump({'success':True,'rows':rows,'positive_executions':66,
                    'compiled_rejected_mutants':18,'hardware_verified':False,'kernel_GLES_enabled':False},output,indent=2)
if __name__=='__main__':unittest.main()
