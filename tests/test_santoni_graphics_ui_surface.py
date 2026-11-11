"""Exact padded-row transfer and fence contracts around the production UI bridge."""
from pathlib import Path
import subprocess,tempfile,unittest,os,json,hashlib
from tests.test_santoni_gpu_prepare import source_function
ROOT=Path(__file__).resolve().parents[1]
MUTANTS=(
 ('pending-fence','completed_fence','submitted!=completed','submitted<completed',12),
 ('source-stride','sgfx_ui_upload','(size_t)row*s.stride','(size_t)row*s.width*4',0),
 ('source-order','sgfx_ui_upload','dest[0]=source[2]','dest[0]=source[0]',0),
 ('metadata-swap','sgfx_ui_commit','s.width,s.height,pixels','surface->width,s.height,pixels',18),
 ('surface-span','sgfx_ui_surface_valid','span>s->allocation_bytes-s->offset','span>s->allocation_bytes',3),
 ('readback-fence','sgfx_ui_commit','after>=finished','after>=before',13),
 ('readback-refusal','sgfx_ui_commit','ops->read_rgba(ops->context,s.width,s.height,pixels) &&',
  '(ops->read_rgba(ops->context,s.width,s.height,pixels) || true) &&',11),
 ('flip','sgfx_ui_upload','s.flip_y?s.height-1-y:y','s.flip_y?y:y',1),
)
class UISurfaceTests(unittest.TestCase):
    def test_actual_surface_transfer(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode');rows=[]
        with tempfile.TemporaryDirectory(prefix='ui-surface-',dir=preferred if preferred.is_dir() else None) as t:
            source=ROOT/'tools/santoni-graphics/ui_surface.c';original=source.read_text()
            cases=[('actual',source,list(range(21)),False)]
            for name,function,old,new,case in MUTANTS:
                body=source_function(original,function);self.assertEqual(body.count(old),1,name)
                p=Path(t)/(name+'.c');p.write_text(original.replace(body,body.replace(old,new,1),1));cases.append((name,p,[case],True))
            for name,source,numbers,mutant in cases:
                for label,flags in [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:
                    binary=Path(t)/(name+'-'+label)
                    r=subprocess.run(['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-I',str(ROOT/'tools/santoni-graphics'),
                        str(ROOT/'tests/test_santoni_graphics_ui_surface.c'),str(source),'-o',str(binary)],capture_output=True,text=True)
                    row={'label':name+'-'+label,'mutant':mutant,'compile_exit':r.returncode,'compile_stderr':r.stderr,
                         'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'runs':[]};rows.append(row)
                    self.assertEqual(r.returncode,0,r.stderr)
                    for case in numbers:
                        r=subprocess.run([str(binary),str(case)],capture_output=True,text=True)
                        row['runs'].append({'case':case,'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
                        if mutant:self.assertNotEqual(r.returncode,0,row)
                        else:self.assertEqual(r.returncode,0,r.stdout+r.stderr)
            record=os.environ.get('SANTONI_UI_SURFACE_RECORD')
            if record:
                inputs=('tools/santoni-graphics/ui_surface.c','tools/santoni-graphics/ui_surface.h',
                        'tests/test_santoni_graphics_ui_surface.c','tests/test_santoni_graphics_ui_surface.py')
                Path(record).write_text(json.dumps({'success':True,'rows':rows,
                    'inputs_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in inputs},
                    'positive_cases':63,'compiled_rejected_mutants':24,'GLES_callbacks_modeled':True,
                    'hardware_verified':False},indent=2)+'\n')
if __name__=='__main__':unittest.main()
