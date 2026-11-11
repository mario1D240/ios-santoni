"""Bounded actual-source rectangle normalization and explicit unsupported negatives."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
class ShaderTests(unittest.TestCase):
    def test_actual_shader_source(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='ui-shader-',dir=preferred if preferred.is_dir() else None) as temporary:
            for label,flags in [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:
                binary=Path(temporary)/label
                run=subprocess.run(['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror',
                    '-I',str(ROOT/'tools/santoni-graphics'),str(ROOT/'tests/test_santoni_graphics_ui_shader.c'),
                    str(ROOT/'tools/santoni-graphics/ui_shader.c'),'-o',str(binary)],capture_output=True,text=True)
                self.assertEqual(run.returncode,0,run.stderr)
                for case in range(24):
                    run=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=15)
                    self.assertEqual(run.returncode,0,run.stdout+run.stderr)
    @unittest.skipUnless(shutil.which('glslangValidator'),'optional GLSL compiler unavailable')
    def test_projected_sources_compile(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='ui-projection-',dir=preferred if preferred.is_dir() else None) as temporary:
            binary=Path(temporary)/'normalize'
            subprocess.run(['clang','-std=c11','-O2','-Wall','-Wextra','-Werror',
                '-I',str(ROOT/'tools/santoni-graphics'),str(ROOT/'tests/test_santoni_graphics_ui_shader.c'),
                str(ROOT/'tools/santoni-graphics/ui_shader.c'),'-o',str(binary)],check=True,capture_output=True,text=True)
            for modern in (False,True):
                for coordinate in ('vec3(2.,3.,.5)','vec4(2.,3.,7.,.5)'):
                    for function_coordinate in (False,True):
                        with self.subTest(modern=modern,coordinate=coordinate,function_coordinate=function_coordinate):
                            prefix='#version 300 es\n' if modern else '#version 100\n'
                            prefix+='precision highp float;\n'
                            if modern:prefix+='out lowp vec4 color;\n'
                            sample='texture2DRectProj(tex,'+coordinate+')'
                            source=prefix+'uniform lowp sampler2DRect tex;\n'
                            if function_coordinate:
                                source+='highp '+coordinate[:4]+' coords(){return '+coordinate+';}\n'
                                sample='texture2DRectProj(tex,coords())'
                            source+='void main(){'+('color' if modern else 'gl_FragColor')+'='+sample+';}\n'
                            run=subprocess.run([str(binary),'source',source],capture_output=True,text=True,timeout=15)
                            self.assertEqual(run.returncode,0,run.stdout+run.stderr)
                            path=Path(temporary)/'projected.frag';path.write_text(run.stdout)
                            checked=subprocess.run(['glslangValidator','-S','frag',str(path)],capture_output=True,text=True,timeout=15)
                            self.assertEqual(checked.returncode,0,checked.stdout+checked.stderr)
if __name__=='__main__':unittest.main()
