"""Typed GLI argument/return forwarding against pinned Khronos prototypes."""
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from tools import generate_santoni_gl_dispatch as generator
from tests.test_santoni_graphics_msm import ROOT,MESA
from tests.test_santoni_gpu_prepare import source_function
HEADERS=('GL/gl.h','GL/glext.h','GLES/gl.h','GLES/glext.h','GLES2/gl2.h','GLES2/gl2ext.h','GLES3/gl3.h')
class DispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.layout=(ROOT/'tools/santoni-graphics/ios-dispatch-20H392.txt').read_text()
        cls.headers='\n'.join((MESA/'include'/name).read_text() for name in HEADERS)
        cls.symbols='\n'.join('00000001 T _'+name for name in generator.prototypes(cls.headers))
    def test_layout_and_alias_negatives(self):
        with self.assertRaisesRegex(ValueError,'layout differs'):
            generator.generate(self.layout.replace('5 glBindTexture','6 glBindTexture'),self.headers,self.symbols)
        old=generator.ALIASES.get('glGetUniformLocationARB')
        try:
            generator.ALIASES['glGetUniformLocationARB']='glUniform4f'
            with self.assertRaisesRegex(ValueError,'argument count mismatch'):
                generator.generate(self.layout,self.headers,self.symbols)
        finally:
            if old is None:generator.ALIASES.pop('glGetUniformLocationARB')
            else:generator.ALIASES['glGetUniformLocationARB']=old
        text,record=generator.generate(self.layout,self.headers,self.symbols)
        self.assertNotIn('glStencilFuncSeparateATI',self.layout)
        self.assertIn('glStencilOpSeparate',''.join(text.splitlines()))
        self.assertIn('glFramebufferParameterivAPPLE',record['manual_adapters'])
        self.assertIn('glLabelObjectWithResponsibleProcessAPPLE',record['manual_adapters'])
        self.assertEqual(hashlib.sha256(self.layout.encode()).hexdigest(),record['layout_sha256'])
        self.assertNotIn('NULL',text)
    def test_actual_generated_calls(self):
        text,record=generator.generate(self.layout,self.headers,self.symbols)
        # Direct calls into generated functions let --gc-sections discard other
        # wrappers/table. This is a prototype/call test, not linked Mesa evidence.
        slots={name:int(index) for index,name in (line.split() for line in self.layout.splitlines())}
        self.assertEqual(slots['glGetString'],117)
        table=text.split('void *const sgfx_ui_dispatch['+str(generator.SLOTS)+']={\n',1)[1].split('};',1)[0].splitlines()
        self.assertEqual(table[117].strip(),'(void *)sgfx_ui_GetString,')
        string_adapter=source_function((ROOT/'tools/santoni-graphics/ui_dispatch.c').read_text(),'sgfx_ui_GetString')
        probe=r'''
#include <assert.h>
#include <stdio.h>
static unsigned calls,failures;static bool bind_ok=true;
static const GLfloat values[16]={1,2,3,4};static const GLubyte description[]="Mesa fixture";
bool sgfx_ui_bind(void *context) {assert(context==(void *)0x1234);return bind_ok;}
GLenum sgfx_ui_target(void *context,GLenum target) {assert(context==(void *)0x1234);return target==GL_TEXTURE_RECTANGLE?GL_TEXTURE_2D:target;}
void sgfx_ui_unsupported(void *context,unsigned slot) {assert(context==(void *)0x1234 && slot<1036);failures++;}
void GLAPIENTRY glUniformMatrix4fv(GLint location,GLsizei count,GLboolean transpose,const GLfloat *value)
{assert(location==13 && count==1 && transpose==GL_FALSE && value==values);calls++;}
void GLAPIENTRY glUniform1f(GLint location,GLfloat value) {assert(location==8 && value==.75f);calls++;}
const GLubyte *GLAPIENTRY glGetString(GLenum name) {assert(name==GL_RENDERER);calls++;return description;}
GLuint GLAPIENTRY glCreateShader(GLenum type) {assert(type==GL_VERTEX_SHADER);calls++;return 0x44;}
GLint GLAPIENTRY glGetUniformLocation(GLuint program,const GLchar *name)
{assert(program==0x55 && name[0]=='u');calls++;return 3;}
void GLAPIENTRY glTexParameterf(GLenum target,GLenum pname,GLfloat value)
{assert(target==GL_TEXTURE_2D && pname==GL_TEXTURE_MIN_LOD && value==2.0f);calls++;}
int main(void) {
    void *context=(void *)0x1234;
    CALL_MATRIX(context,13,1,GL_FALSE,values);CALL_FLOAT(context,8,.75f);
    assert(CALL_STRING(context,GL_RENDERER)==description);
    assert((uintptr_t)CALL_CREATE(context,GL_VERTEX_SHADER)==0x44);
    assert(CALL_LOCATION(context,(GLhandleARB)(uintptr_t)0x55,"uniform")==3);
    CALL_TEX(context,GL_TEXTURE_RECTANGLE,GL_TEXTURE_MIN_LOD,2.0f);assert(calls==6 && !failures);
    assert(CALL_LOCATION(context,(GLhandleARB)(uintptr_t)UINT64_MAX,"uniform")==0 && failures==1 && calls==6);
    const GLubyte *private_extensions=CALL_STRING(context,0x8a1e);
    assert(private_extensions && !private_extensions[0] && calls==6 && failures==1);
    bind_ok=false;CALL_FLOAT(context,8,.75f);assert(!CALL_STRING(context,GL_RENDERER) && calls==6);
    puts("PASS typed GLI forwarding; prototypes and callbacks modeled");return 0;
}
'''
        names={'CALL_MATRIX':'glUniformMatrix4fv','CALL_FLOAT':'glUniform1f','CALL_STRING':'glGetString',
            'CALL_CREATE':'glCreateShaderObjectARB','CALL_LOCATION':'glGetUniformLocationARB','CALL_TEX':'glTexParameterf'}
        for alias,name in names.items():
            probe=probe.replace(alias,'sgfx_ui_GetString' if name=='glGetString' else 'wrap_'+str(slots[name]))
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='ui-dispatch-',dir=preferred if preferred.is_dir() else None) as temporary:
            source=Path(temporary)/'dispatch.c';source.write_text(text+'\n'+string_adapter+'\n'+probe)
            for label,flags in [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:
                binary=Path(temporary)/label
                import platform
                strip=['-Wl,-dead_strip'] if platform.system()=='Darwin' else ['-Wl,--gc-sections']
                run=subprocess.run(['clang','-std=c11',*flags,'-D__APPLE__','-Wall','-Wextra','-Werror',
                    '-ffunction-sections','-fdata-sections',*strip,
                    '-I',str(ROOT/'tools/santoni-graphics'),'-I',str(MESA/'include'),str(source),'-o',str(binary)],capture_output=True,text=True)
                self.assertEqual(run.returncode,0,run.stderr)
                run=subprocess.run([str(binary)],capture_output=True,text=True,timeout=15)
                self.assertEqual(run.returncode,0,run.stderr)
if __name__=='__main__':unittest.main()
