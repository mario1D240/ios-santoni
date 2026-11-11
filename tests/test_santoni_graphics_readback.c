/* Actual proof + transfer/GL adapter; Mesa contexts, GL/GPU responses modeled. */
#include "gles.h"
#include "ui_gl.h"
#include "santoni_drm.h"
#include <GLES3/gl3.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct sgfx_gles_context {int fd;void *st;unsigned api;};
static unsigned scenario,creates,destroys,draws,finishes,reads,shaders,deletes,major_queries,status_calls;
static uint32_t submitted,completed;
static bool live=true,context_live;
static struct sgfx_gles_context context;
static void *current;
static GLuint next_id=1;
static bool drawn,deleted;
static GLenum pending_error;
static unsigned shader_api[128];
void *st_api_get_current(void){return current;}
struct sgfx_gles_context *sgfx_gles_create_api(unsigned api)
{
    assert(api==2 || api==3);creates++;
    if(scenario==2)return NULL;
    assert(!context_live);context_live=true;drawn=deleted=false;
    context=(struct sgfx_gles_context){65537,(void *)0x505,scenario==26?2:api};return &context;
}
unsigned sgfx_gles_api(const struct sgfx_gles_context *c){assert(c==&context && context_live);return c->api;}
bool sgfx_gles_current(struct sgfx_gles_context *c)
{assert(c==&context && context_live);if(scenario==3)return false;current=c->st;return true;}
bool sgfx_drm_status(int fd,uint32_t *sub,uint32_t *done)
{
    assert(sub && done);
    status_calls++;
    if(fd!=65536 && fd!=65537)return false;
    if(!live || (scenario==16 && destroys) || (scenario==29 && reads))return false;
    *sub=submitted;*done=completed;
    if((scenario==35 && status_calls==6) || (scenario==36 && status_calls==10))(*done)++;
    if(scenario==37 && status_calls==6)*sub=*done=0;
    if(scenario==38 && (status_calls==10 || destroys))*sub=*done=1;
    if(scenario==39 && status_calls==2){*sub=1;*done=0;}
    return true;
}
bool sgfx_gles_status(const struct sgfx_gles_context *c,uint32_t *sub,uint32_t *done)
{assert(c==&context && context_live);return sgfx_drm_status(c->fd,sub,done);}
void sgfx_gles_destroy(struct sgfx_gles_context *c)
{
    assert(c==&context && context_live);destroys++;context_live=false;
    if(scenario!=34)current=NULL;
    if(scenario==17)submitted=++completed;
    if(scenario==18 && completed)completed--;
    if(scenario==32)live=false;
}
GLenum GL_APIENTRY glGetError(void)
{
    GLenum error=pending_error;pending_error=GL_NO_ERROR;
    if(scenario==15 && deleted)error=GL_INVALID_OPERATION;
    return error;
}
const GLubyte *GL_APIENTRY glGetString(GLenum name)
{assert(name==GL_RENDERER || name==GL_VERSION);return (const GLubyte *)(name==GL_RENDERER?"mock A505":"mock OpenGL ES");}
void GL_APIENTRY glGetIntegerv(GLenum pname,GLint *value)
{
    assert(value);*value=0;
    if(pname==GL_MAJOR_VERSION) {
        major_queries++;*value=scenario==4?2:3;
        if(scenario==27)pending_error=GL_INVALID_ENUM;
    }else if(pname==GL_PACK_ALIGNMENT || pname==GL_UNPACK_ALIGNMENT)*value=4;
    else assert(pname==GL_PIXEL_PACK_BUFFER_BINDING || pname==GL_PIXEL_UNPACK_BUFFER_BINDING ||
        pname==GL_PACK_ROW_LENGTH || pname==GL_UNPACK_ROW_LENGTH || pname==GL_PACK_SKIP_ROWS ||
        pname==GL_UNPACK_SKIP_ROWS || pname==GL_PACK_SKIP_PIXELS || pname==GL_UNPACK_SKIP_PIXELS);
}
void GL_APIENTRY glGenTextures(GLsizei n,GLuint *names){assert(n==1 && names);*names=next_id++;if(scenario==28)pending_error=GL_OUT_OF_MEMORY;}
void GL_APIENTRY glBindTexture(GLenum target,GLuint name){assert(target==GL_TEXTURE_2D && name);}
void GL_APIENTRY glTexImage2D(GLenum target,GLint level,GLint internal,GLsizei width,GLsizei height,
    GLint border,GLenum format,GLenum type,const void *data)
{assert(target==GL_TEXTURE_2D && !level && internal==(context.api==3?GL_RGBA8:GL_RGBA) && width==64 && height==64 && !border && format==GL_RGBA && type==GL_UNSIGNED_BYTE && !data);}
void GL_APIENTRY glTexParameteri(GLenum target,GLenum pname,GLint value)
{assert(target==GL_TEXTURE_2D && (pname==GL_TEXTURE_MIN_FILTER || pname==GL_TEXTURE_MAG_FILTER) && value==GL_NEAREST);}
void GL_APIENTRY glGenFramebuffers(GLsizei n,GLuint *names){assert(n==1 && names);*names=next_id++;}
void GL_APIENTRY glBindFramebuffer(GLenum target,GLuint name){assert(target==GL_FRAMEBUFFER && name);}
void GL_APIENTRY glFramebufferTexture2D(GLenum target,GLenum attachment,GLenum textarget,GLuint texture,GLint level)
{assert(target==GL_FRAMEBUFFER && attachment==GL_COLOR_ATTACHMENT0 && textarget==GL_TEXTURE_2D && texture && !level);}
GLenum GL_APIENTRY glCheckFramebufferStatus(GLenum target)
{assert(target==GL_FRAMEBUFFER || target==GL_READ_FRAMEBUFFER);return scenario==5?GL_FRAMEBUFFER_INCOMPLETE_ATTACHMENT:GL_FRAMEBUFFER_COMPLETE;}
void GL_APIENTRY glViewport(GLint x,GLint y,GLsizei width,GLsizei height){assert(!x && !y && width==64 && height==64);}
void GL_APIENTRY glClearColor(GLfloat r,GLfloat g,GLfloat b,GLfloat a){assert(r==0 && g==0 && b==1 && a==1);}
void GL_APIENTRY glClear(GLbitfield mask){assert(mask==GL_COLOR_BUFFER_BIT);drawn=false;}
GLuint GL_APIENTRY glCreateShader(GLenum type){assert(type==GL_VERTEX_SHADER || type==GL_FRAGMENT_SHADER);shaders++;GLuint name=next_id++;shader_api[name]=type;return name;}
void GL_APIENTRY glShaderSource(GLuint name,GLsizei count,const GLchar *const *strings,const GLint *lengths)
{
    assert(name<128 && shader_api[name] && count==1 && strings && strings[0] && !lengths);
    const char *text=strings[0];bool es3=!strncmp(text,"#version 300 es\n",16);
    assert(es3==(context.api==3));
    if(shader_api[name]==GL_VERTEX_SHADER)assert(strstr(text,context.api==3?"in vec2 position":"attribute vec2 position"));
    else assert(strstr(text,context.api==3?"fragmentColor=vec4(1.0,0.0,0.0,1.0)":"gl_FragColor=vec4(1.0,0.0,0.0,1.0)"));
}
void GL_APIENTRY glCompileShader(GLuint name){assert(name<128 && shader_api[name]);}
void GL_APIENTRY glGetShaderiv(GLuint name,GLenum pname,GLint *value)
{assert(name<128 && shader_api[name] && pname==GL_COMPILE_STATUS && value);*value=!((scenario==6 && shader_api[name]==GL_VERTEX_SHADER) || (scenario==7 && shader_api[name]==GL_FRAGMENT_SHADER));}
void GL_APIENTRY glGetShaderInfoLog(GLuint name,GLsizei size,GLsizei *length,GLchar *text)
{assert(name && size==1024 && !length && text);strcpy(text,"modeled compile refusal");}
GLuint GL_APIENTRY glCreateProgram(void){return next_id++;}
void GL_APIENTRY glAttachShader(GLuint program,GLuint shader){assert(program && shader);}
void GL_APIENTRY glBindAttribLocation(GLuint program,GLuint index,const GLchar *name){assert(program && !index && !strcmp(name,"position"));}
void GL_APIENTRY glLinkProgram(GLuint program){assert(program);}
void GL_APIENTRY glGetProgramiv(GLuint program,GLenum pname,GLint *value){assert(program && pname==GL_LINK_STATUS && value);*value=scenario!=8;}
void GL_APIENTRY glUseProgram(GLuint program){assert(program);}
void GL_APIENTRY glGenBuffers(GLsizei n,GLuint *names){assert(n==1 && names);*names=next_id++;}
void GL_APIENTRY glBindBuffer(GLenum target,GLuint name){assert(target==GL_ARRAY_BUFFER || target==GL_PIXEL_PACK_BUFFER || target==GL_PIXEL_UNPACK_BUFFER);if(target==GL_ARRAY_BUFFER)assert(name);else assert(!name);}
void GL_APIENTRY glBufferData(GLenum target,GLsizeiptr size,const void *data,GLenum usage)
{static const float expected[]={-1,-1,1,-1,-1,1};assert(target==GL_ARRAY_BUFFER && size==(GLsizeiptr)sizeof(expected) && data && !memcmp(data,expected,sizeof(expected)) && usage==GL_STATIC_DRAW);}
void GL_APIENTRY glEnableVertexAttribArray(GLuint index){assert(!index);}
void GL_APIENTRY glVertexAttribPointer(GLuint index,GLint size,GLenum type,GLboolean normalized,GLsizei stride,const void *pointer)
{assert(!index && size==2 && type==GL_FLOAT && normalized==GL_FALSE && !stride && !pointer);}
void GL_APIENTRY glDrawArrays(GLenum mode,GLint first,GLsizei count){assert(mode==GL_TRIANGLES && !first && count==3);drawn=true;draws++;}
void GL_APIENTRY glFinish(void)
{
    finishes++;
    if(scenario==13 && !drawn)return;
    if(!(scenario==14 && drawn))submitted++;
    completed=submitted;
    if((scenario==11 && !drawn) || (scenario==12 && drawn))completed++;
}
void GL_APIENTRY glPixelStorei(GLenum pname,GLint value)
{assert((pname==GL_PACK_ALIGNMENT || pname==GL_UNPACK_ALIGNMENT)?value==4:value==0);}
void GL_APIENTRY glReadPixels(GLint x,GLint y,GLsizei width,GLsizei height,GLenum format,GLenum type,void *output)
{
    assert(!x && !y && width==64 && height==64 && format==GL_RGBA && type==GL_UNSIGNED_BYTE && output);reads++;
    uint8_t *pixels=output;
    for(unsigned row=0;row<64;row++)for(unsigned col=0;col<64;col++) {
        bool red=drawn && row+col<63;uint8_t *p=pixels+4*(row*64+col);
        p[0]=red?255:0;p[1]=0;p[2]=red?0:255;p[3]=255;
    }
    if((scenario==9 && !drawn) || (scenario==10 && drawn))pixels[1]=1;
    if(scenario==33)memset(pixels,0,64*64*4);
    if(scenario==19 && drawn)current=NULL;
}
void GL_APIENTRY glDeleteBuffers(GLsizei n,const GLuint *names){assert(n==1 && names && *names);deleted=true;deletes++;}
void GL_APIENTRY glDeleteProgram(GLuint name){assert(name);deleted=true;deletes++;}
void GL_APIENTRY glDeleteShader(GLuint name){assert(name);deleted=true;deletes++;}
void GL_APIENTRY glDeleteFramebuffers(GLsizei n,const GLuint *names){assert(n==1 && names && *names);deleted=true;deletes++;}
void GL_APIENTRY glDeleteTextures(GLsizei n,const GLuint *names){assert(n==1 && names && *names);deleted=true;deletes++;}
#include "readback_actual.h"
int main(int argc,char **argv)
{
    assert(argc==2);scenario=(unsigned)strtoul(argv[1],NULL,10);assert(scenario<40);
    unsigned api=scenario==0?2:3;int lease=65536;
    if(scenario==20)lease=1;if(scenario==21)submitted=1;if(scenario==22)current=(void *)0x999;
    if(scenario==23)api=0;if(scenario==24)api=4;if(scenario==25)lease=-1;
    bool pass=scenario==32?sgfx_gles_readback_proof():sgfx_gles_ui_readback_proof(lease,api);
    assert(pass==(scenario==0 || scenario==1 || scenario==30 || scenario==31 || scenario==32));
    if(scenario>=20 && scenario<=25)assert(!creates && !destroys && !draws && !finishes);
    if(scenario==39)assert(!draws && !finishes);
    if(scenario==0 || scenario==1 || scenario==30 || scenario==31 || scenario==32) {
        assert(major_queries==((scenario==0 || scenario==32)?0u:1u)); /* ES2, including the legacy proof, never queries ES3-only GL_MAJOR_VERSION. */
        assert(creates==1 && destroys==1 && draws==1 && finishes==2 && reads==2 && shaders==2 && deletes==6 && submitted==2 && completed==2 && !current);
        if(scenario==31){assert(sgfx_gles_ui_readback_proof(lease,2));assert(submitted==4 && completed==4 && creates==2 && destroys==2 && draws==2 && deletes==12 && major_queries==1);}
    }
    printf("PASS readback gate case=%u; GL/Mesa/GPU modeled\n",scenario);return 0;
}
