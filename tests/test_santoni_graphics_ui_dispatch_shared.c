/* Actual manual GLI adapters, with modeled GL and context ownership. */
#include "ui_dispatch.h"
#include "ui_backend.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static struct sgfx_ui_mesa mesa;
static struct sgfx_ui_mesa peer;
static struct sgfx_ui_mesa_group shared_group={.lock=PTHREAD_MUTEX_INITIALIZER};
static void *const context=(void *)0x1234;
static void *const peer_context=(void *)0x5678;
static unsigned test,draws,dirty,refreshes,errors,deleted;
static GLint active=GL_TEXTURE0+3;
static GLuint bound[SGFX_UI_UNITS];
static char source_copy[1024];
static bool failed;
static const GLint signed_clear[4]={1,2,3,4};
static const GLuint unsigned_clear[4]={1,2,3,4};
static const GLfloat float_clear[4]={.1f,.2f,.3f,.4f};
bool sgfx_ui_context_bind(struct sgfx_ui_context *c) {assert((void *)c==context || (void *)c==peer_context);return !failed;}
void *sgfx_ui_context_backend(struct sgfx_ui_context *c) {assert((void *)c==context || (void *)c==peer_context);return failed?NULL:(void *)c==context?&mesa:&peer;}
bool sgfx_ui_context_fail(struct sgfx_ui_context *c,unsigned failure,uint32_t slot)
{assert(((void *)c==context || (void *)c==peer_context) && failure==SGFX_UI_UNSUPPORTED);(void)slot;errors++;failed=true;return false;}
bool sgfx_ui_context_refresh(struct sgfx_ui_context *c,uint32_t name)
{assert((void *)c==context && (name==17 || name==71));refreshes++;return test!=3;}
bool sgfx_ui_context_dirty(struct sgfx_ui_context *c,uint32_t name)
{assert((void *)c==context && name==17);dirty++;return true;}
bool sgfx_ui_context_forget(struct sgfx_ui_context *c,uint32_t name)
{assert((void *)c==context && name==17);return test!=7;}
void GLAPIENTRY glGetIntegerv(GLenum name,GLint *out)
{
    switch(name) {
    case GL_ACTIVE_TEXTURE:*out=active;return;
    case GL_CURRENT_PROGRAM:*out=test==8?0:39;return;
    case GL_FRAMEBUFFER_BINDING:*out=24;return;
    default:assert(false);
    }
}
void GLAPIENTRY glActiveTexture(GLenum value) {assert(value>=GL_TEXTURE0 && value<GL_TEXTURE0+64);active=(GLint)value;}
void GLAPIENTRY glBindTexture(GLenum target,GLuint name) {assert(target==GL_TEXTURE_2D);bound[active-GL_TEXTURE0]=name;}
void GLAPIENTRY glGetTexLevelParameteriv(GLenum target,GLint level,GLenum name,GLint *out)
{assert(target==GL_TEXTURE_2D && !level && active==GL_TEXTURE0+3 && bound[3]==17);
 *out=test==2?0:name==GL_TEXTURE_WIDTH?64:128;}
GLboolean GLAPIENTRY glIsShader(GLuint name) {return name==9;}
GLboolean GLAPIENTRY glIsProgram(GLuint name) {return name==39;}
void GLAPIENTRY glShaderSource(GLuint name,GLsizei count,const GLchar *const *parts,const GLint *length)
{assert(name==9 && count==1 && !length && strlen(parts[0])<sizeof(source_copy));strcpy(source_copy,parts[0]);}
void GLAPIENTRY glLinkProgram(GLuint name) {assert(name==39);}
void GLAPIENTRY glGetProgramiv(GLuint name,GLenum what,GLint *out) {assert(name==39 && what==GL_LINK_STATUS);*out=1;}
void GLAPIENTRY glGetAttachedShaders(GLuint name,GLsizei capacity,GLsizei *count,GLuint *names)
{assert(name==39 && capacity==64);names[0]=9;*count=1;}
GLint GLAPIENTRY glGetUniformLocation(GLuint name,const GLchar *uniform)
{assert(name==39);return !strcmp(uniform,"sgfx_rect_scale")?2:!strcmp(uniform,"tex")?1:-1;}
void GLAPIENTRY glGetUniformiv(GLuint name,GLint location,GLint *out) {assert(name==39 && location==1);*out=test==6?-1:3;}
void GLAPIENTRY glUniform2f(GLint location,GLfloat width,GLfloat height)
{assert(location==2 && width==1.0f/64 && height==1.0f/128 && active==GL_TEXTURE0+3);}
void GLAPIENTRY glDrawArrays(GLenum mode,GLint first,GLsizei count)
{assert(mode==GL_TRIANGLES && !first && count==3 && active==GL_TEXTURE0+5);draws++;
 assert(bound[0]==71 && bound[3]==(test==8?0:17));}
void GLAPIENTRY glGetFramebufferAttachmentParameteriv(GLenum target,GLenum attachment,GLenum what,GLint *out)
{assert(target==GL_FRAMEBUFFER && attachment==GL_COLOR_ATTACHMENT0);*out=what==GL_FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE?GL_TEXTURE:17;}
void GLAPIENTRY glDeleteTextures(GLsizei count,const GLuint *names) {assert(count==1 && names[0]==17);deleted++;}
void GLAPIENTRY glClearBufferiv(GLenum buffer,GLint draw,const GLint *value)
{assert(buffer==GL_COLOR && draw==0 && value==signed_clear);draws++;}
void GLAPIENTRY glClearBufferuiv(GLenum buffer,GLint draw,const GLuint *value)
{assert(buffer==GL_COLOR && draw==0 && value==unsigned_clear);draws++;}
void GLAPIENTRY glClearBufferfv(GLenum buffer,GLint draw,const GLfloat *value)
{assert(buffer==GL_COLOR && draw==0 && value==float_clear);draws++;}
void GLAPIENTRY glClearBufferfi(GLenum buffer,GLint draw,GLfloat depth,GLint stencil)
{assert(buffer==GL_DEPTH_STENCIL && draw==0 && depth==.5f && stencil==7);draws++;}
void GLAPIENTRY glDrawRangeElements(GLenum mode,GLuint start,GLuint end,GLsizei count,GLenum type,const void *indices)
{assert(mode==GL_TRIANGLES && !start && end==2 && count==3 && type==GL_UNSIGNED_SHORT && indices==(void *)0x44);
 glDrawArrays(mode,0,count);}
int main(int argc,char **argv)
{
    assert(argc==2);test=(unsigned)strtoul(argv[1],NULL,10);assert(test<15);
    if(test==14)mesa.group=peer.group=&shared_group;
    sgfx_ui_BindTexture(context,GL_TEXTURE_RECTANGLE,17);glActiveTexture(GL_TEXTURE0);
    sgfx_ui_BindTexture(context,GL_TEXTURE_2D,71);glActiveTexture(GL_TEXTURE0+5);
    const GLcharARB *parts[]={test==1?"uniform sampler2DRect tex[2];":"uniform sampler2DRect tex; void main(){texture2DRect(tex,vec2(2.));}"};
    sgfx_ui_ShaderSourceARB(context,(GLhandleARB)(uintptr_t)(test==4?UINT64_MAX:9),1,parts,NULL);
    if(test==1 || test==4) {assert(errors==1 && !source_copy[0] && !draws);return 0;}
    assert(strstr(source_copy,"#define sampler2DRect sampler2D") && !strcmp(sgfx_ui_mesa_shaders(&mesa)[0].sampler,"tex"));
    sgfx_ui_LinkProgramARB(test==14?peer_context:context,(GLhandleARB)(uintptr_t)39);
    struct sgfx_ui_program_record *programs=sgfx_ui_mesa_programs(&mesa);
    assert(programs[0].name==39 && programs[0].scale==2 && programs[0].sampler==1);
    if(test==14)assert(!mesa.shaders[0].name && !mesa.programs[0].name && !peer.shaders[0].name && !peer.programs[0].name);
    if(test==5) {
        sgfx_ui_FramebufferParameterivAPPLE(context,GL_FRAMEBUFFER,0x8a79,NULL);
        sgfx_ui_DrawArrays(context,GL_TRIANGLES,0,3);assert(errors==1 && !draws);return 0;
    }
    if(test==7) {
        GLuint name=17;sgfx_ui_DeleteTextures(context,1,&name);assert(!deleted && mesa.texture_rect[3]==17);return 0;
    }
    switch(test) {
    case 9:sgfx_ui_ClearBufferiv(context,GL_COLOR,0,signed_clear);break;
    case 10:sgfx_ui_ClearBufferuiv(context,GL_COLOR,0,unsigned_clear);break;
    case 11:sgfx_ui_ClearBufferfv(context,GL_COLOR,0,float_clear);break;
    case 12:sgfx_ui_ClearBufferfi(context,GL_DEPTH_STENCIL,0,.5f,7);break;
    case 13:sgfx_ui_DrawRangeElements(context,GL_TRIANGLES,0,2,3,GL_UNSIGNED_SHORT,(void *)0x44);break;
    default:sgfx_ui_DrawArrays(context,GL_TRIANGLES,0,3);break;
    }
    bool success=test==0 || test>=8;
    assert(draws==(unsigned)success && dirty==(unsigned)success && active==GL_TEXTURE0+5);
    assert(errors==(test==2 || test==6?1u:0u));
    if(test==0) {GLuint name=17;sgfx_ui_DeleteTextures(context,1,&name);assert(deleted==1 && !mesa.texture_rect[3]);}
    puts("PASS actual manual GLI/shader/draw path; context/GL responses modeled");return 0;
}
