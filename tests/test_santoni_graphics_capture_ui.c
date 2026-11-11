/* Actual optional quad emitter; GL compiler/state/submission are host models. */
#include <GLES2/gl2.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned test,compiled,programs,draws,finishes,filters;
static bool blended;
static GLuint compile(GLenum type,const char *source)
{
    compiled++;assert(source);
    if(type==GL_VERTEX_SHADER) {
        assert(strstr(source,"varying highp vec2 uv;") && strstr(source,"uv=pos*.5+.5;"));
        return test==1?0:2;
    }
    assert(type==GL_FRAGMENT_SHADER && strstr(source,"varying highp vec2 uv;") && strstr(source,"texture2D(tex,uv)*vec4(.5)"));
    return test==2?0:3;
}
GLuint glCreateProgram(void){programs++;return 4;}
void glAttachShader(GLuint program,GLuint shader){assert(program==4 && (shader==2 || shader==3));}
void glBindAttribLocation(GLuint program,GLuint location,const GLchar *name){assert(program==4 && !location && !strcmp(name,"pos"));}
void glLinkProgram(GLuint program){assert(program==4);}
void glGetProgramiv(GLuint program,GLenum name,GLint *out){assert(program==4 && name==GL_LINK_STATUS && out);*out=test==3?0:1;}
void glUseProgram(GLuint program){assert(program==4);}
void glActiveTexture(GLenum unit){assert(unit==GL_TEXTURE0);}
void glBindTexture(GLenum target,GLuint texture){assert(target==GL_TEXTURE_2D && texture==20);}
void glTexParameteri(GLenum target,GLenum name,GLint value)
{assert(target==GL_TEXTURE_2D && value==GL_LINEAR && (name==GL_TEXTURE_MIN_FILTER || name==GL_TEXTURE_MAG_FILTER));filters++;}
GLint glGetUniformLocation(GLuint program,const GLchar *name){assert(program==4 && !strcmp(name,"tex"));return 5;}
void glUniform1i(GLint location,GLint value){assert(location==5 && !value);}
void glBindBuffer(GLenum target,GLuint buffer){assert(target==GL_ARRAY_BUFFER && buffer==10);}
void glBufferData(GLenum target,GLsizeiptr size,const void *data,GLenum usage)
{
    const GLfloat expected[]={-1,-1,1,-1,-1,1,1,1};
    assert(target==GL_ARRAY_BUFFER && size==(GLsizeiptr)sizeof(expected) && usage==GL_STATIC_DRAW && !memcmp(data,expected,sizeof(expected)));
}
void glEnableVertexAttribArray(GLuint index){assert(!index);}
void glVertexAttribPointer(GLuint index,GLint size,GLenum type,GLboolean normalized,GLsizei stride,const void *offset)
{assert(!index && size==2 && type==GL_FLOAT && !normalized && !stride && !offset);}
void glEnable(GLenum feature){assert(feature==GL_BLEND && !blended);blended=true;}
void glBlendFunc(GLenum source,GLenum destination){assert(blended && source==GL_ONE && destination==GL_ONE_MINUS_SRC_ALPHA);}
void glDrawArrays(GLenum mode,GLint first,GLsizei count){assert(blended && mode==GL_TRIANGLE_STRIP && !first && count==4 && filters==2);draws++;}
void glFinish(void){assert(draws==1 && blended);finishes++;}
void glDisable(GLenum feature){assert(feature==GL_BLEND && blended && finishes==1);blended=false;}
GLenum glGetError(void){assert(!blended && finishes==1);return test==4?GL_INVALID_OPERATION:GL_NO_ERROR;}
#include "capture_ui_actual.h"
int main(int argc,char **argv)
{
    assert(argc==2);test=(unsigned)strtoul(argv[1],NULL,10);assert(test<7);
    bool result=ui_quad(test==5?0:20,test==6?0:10);
    assert(result==(test==0));
    if(test>=5)assert(!compiled && !programs && !draws);
    else if(test==1 || test==2)assert(compiled==2 && !programs && !draws);
    else if(test==3)assert(compiled==2 && programs==1 && !draws);
    else assert(compiled==2 && programs==1 && draws==1 && finishes==1 && !blended);
    printf("PASS actual UI-like emitter case=%u; GL/GPU responses MODELED; hardware_verified=0\n",test);return 0;
}
