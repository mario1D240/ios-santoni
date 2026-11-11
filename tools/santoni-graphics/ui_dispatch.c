/* GLI calls use the exact retained20H392 slot/signature metadata. Resource
 * import is CPU staging; this code never exposes IOSurface memory for DMA. */
#include "ui_dispatch.h"
#include "ui_backend.h"
#include <limits.h>
#include <stdlib.h>
#include <string.h>
bool sgfx_ui_bind(void *context)
{return context && sgfx_ui_context_bind(context);}
void sgfx_ui_unsupported(void *context,unsigned slot)
{sgfx_ui_context_fail(context,SGFX_UI_UNSUPPORTED,slot);}
_Noreturn void sgfx_ui_invalid(void *context)
{sgfx_ui_unsupported(context,UINT32_MAX);abort();}
void sgfx_ui_noop(void *context) {(void)context;}
static bool handle(void *context,GLhandleARB value,GLuint *out)
{
    if(!sgfx_ui_bind(context))return false;
    uintptr_t v=(uintptr_t)value;
    if(v>UINT32_MAX) {sgfx_ui_unsupported(context,UINT32_MAX);return false;}
    *out=(GLuint)v;return true;
}
static int unit(void *context)
{
    GLint active=0;glGetIntegerv(GL_ACTIVE_TEXTURE,&active);
    if(active<(GLint)GL_TEXTURE0 || (unsigned)(active-GL_TEXTURE0)>=SGFX_UI_UNITS) {
        sgfx_ui_unsupported(context,342);return -1;
    }
    return active-(GLint)GL_TEXTURE0;
}
GLenum sgfx_ui_target(void *context,GLenum target)
{
    if(target!=GL_TEXTURE_2D && target!=GL_TEXTURE_RECTANGLE)return target;
    struct sgfx_ui_mesa *m=sgfx_ui_context_backend(context);int u=unit(context);
    if(!m || u<0)return GL_TEXTURE_2D;
    glBindTexture(GL_TEXTURE_2D,target==GL_TEXTURE_RECTANGLE?m->texture_rect[u]:m->texture_2d[u]);
    return GL_TEXTURE_2D;
}
void sgfx_ui_DeleteObjectARB(void *context,GLhandleARB object)
{
    GLuint name;if(!handle(context,object,&name))return;
    if(glIsProgram(name))glDeleteProgram(name);else glDeleteShader(name);
}
void sgfx_ui_GetObjectParameterivARB(void *context,GLhandleARB object,GLenum pname,GLint *out)
{
    GLuint name;if(!out || !handle(context,object,&name))return;
    bool program=glIsProgram(name);
    if(pname==GL_OBJECT_TYPE_ARB)*out=program?GL_PROGRAM_OBJECT_ARB:GL_SHADER_OBJECT_ARB;
    else if(program)glGetProgramiv(name,pname,out);
    else glGetShaderiv(name,pname==GL_OBJECT_SUBTYPE_ARB?GL_SHADER_TYPE:pname,out);
}
void sgfx_ui_GetInfoLogARB(void *context,GLhandleARB object,GLsizei size,GLsizei *length,GLcharARB *out)
{
    GLuint name;if(!handle(context,object,&name))return;
    if(glIsProgram(name))glGetProgramInfoLog(name,size,length,out);else glGetShaderInfoLog(name,size,length,out);
}
void sgfx_ui_GetAttachedObjectsARB(void *context,GLhandleARB object,GLsizei max,GLsizei *count,GLhandleARB *out)
{
    GLuint name;if(!handle(context,object,&name))return;
    if(max<0 || (max && !out) || (unsigned)max>64) {sgfx_ui_unsupported(context,631);return;}
    GLuint names[64];GLsizei n=0;glGetAttachedShaders(name,max,&n,names);
    if(n<0 || n>max) {sgfx_ui_unsupported(context,631);return;}
    for(GLsizei i=0;i<n;i++)out[i]=(GLhandleARB)(uintptr_t)names[i];
    if(count)*count=n;
}
GLhandleARB sgfx_ui_GetHandleARB(void *context,GLenum pname)
{
    if(!sgfx_ui_bind(context))return (GLhandleARB)0;
    if(pname!=GL_PROGRAM_OBJECT_ARB) {sgfx_ui_unsupported(context,601);return (GLhandleARB)0;}
    GLint name=0;glGetIntegerv(GL_CURRENT_PROGRAM,&name);return (GLhandleARB)(uintptr_t)(GLuint)name;
}
void sgfx_ui_Flush(void *context)
{if(sgfx_ui_bind(context))sgfx_ui_context_flush(context);}
void sgfx_ui_Finish(void *context) {sgfx_ui_Flush(context);}
void sgfx_ui_FinishObjectAPPLE(void *context,GLenum object,GLint name)
{(void)object;(void)name;sgfx_ui_Flush(context);}
GLboolean sgfx_ui_TestObjectAPPLE(void *context,GLenum object,GLuint name)
{(void)object;(void)name;return sgfx_ui_bind(context) && sgfx_ui_context_flush(context)?GL_TRUE:GL_FALSE;}
void sgfx_ui_BindTexture(void *context,GLenum target,GLuint name)
{
    if(!sgfx_ui_bind(context))return;
    struct sgfx_ui_mesa *m=sgfx_ui_context_backend(context);
    if(target==GL_TEXTURE_2D || target==GL_TEXTURE_RECTANGLE) {
        int u=unit(context);if(!m || u<0)return;
        (target==GL_TEXTURE_RECTANGLE?m->texture_rect:m->texture_2d)[u]=name;target=GL_TEXTURE_2D;
    }
    glBindTexture(target,name);
}
void sgfx_ui_DeleteTextures(void *context,GLsizei count,const GLuint *names)
{
    if(!sgfx_ui_bind(context))return;
    if(count<0 || (count && !names)) {sgfx_ui_unsupported(context,59);return;}
    struct sgfx_ui_mesa *m=sgfx_ui_context_backend(context);if(!m)return;
    for(GLsizei i=0;i<count;i++) {
        if(!sgfx_ui_context_forget(context,names[i]))return;
        for(unsigned u=0;u<SGFX_UI_UNITS;u++) {
            if(m->texture_2d[u]==names[i])m->texture_2d[u]=0;
            if(m->texture_rect[u]==names[i])m->texture_rect[u]=0;
        }
    }
    glDeleteTextures(count,names);
}
void sgfx_ui_TexImage2D(void *context,GLenum target,GLint level,GLint internal,
    GLsizei width,GLsizei height,GLint border,GLenum format,GLenum type,const void *pixels)
{
    if(!sgfx_ui_bind(context))return;target=sgfx_ui_target(context,target);
    GLint texture=0;glGetIntegerv(GL_TEXTURE_BINDING_2D,&texture);
    if((target==GL_TEXTURE_2D && !sgfx_ui_context_forget(context,(GLuint)texture)))return;
    if(format==GL_BGRA && (internal==GL_RGBA || internal==GL_RGBA8))internal=GL_BGRA;
    glTexImage2D(target,level,internal,width,height,border,format,type,pixels);
}
void sgfx_ui_TexSubImage2D(void *context,GLenum target,GLint level,GLint x,GLint y,
    GLsizei width,GLsizei height,GLenum format,GLenum type,const void *pixels)
{
    if(!sgfx_ui_bind(context))return;
    glTexSubImage2D(sgfx_ui_target(context,target),level,x,y,width,height,format,type,pixels);
}
void sgfx_ui_TexParameteri(void *context,GLenum target,GLenum pname,GLint value)
{if(sgfx_ui_bind(context))glTexParameteri(sgfx_ui_target(context,target),pname,value);}
void sgfx_ui_FramebufferTexture2DEXT(void *context,GLenum target,GLenum attachment,GLenum textarget,GLuint texture,GLint level)
{
    if(!sgfx_ui_bind(context))return;
    if(textarget==GL_TEXTURE_RECTANGLE)textarget=GL_TEXTURE_2D;
    glFramebufferTexture2D(target,attachment,textarget,texture,level);
}
void sgfx_ui_BindFramebufferEXT(void *context,GLenum target,GLuint name)
{if(sgfx_ui_bind(context))glBindFramebuffer(target,name);}
void sgfx_ui_DeleteFramebuffersEXT(void *context,GLsizei count,const GLuint *names)
{if(sgfx_ui_bind(context))glDeleteFramebuffers(count,names);}
void sgfx_ui_ShaderSourceARB(void *context,GLhandleARB object,GLsizei count,const GLcharARB **text,const GLint *length)
{
    GLuint name;if(!handle(context,object,&name))return;
    if(count<0 || count>64 || (count && !text)) {sgfx_ui_unsupported(context,595);return;}
    struct sgfx_ui_mesa *m=sgfx_ui_context_backend(context);if(!m)return;
    char sampler[SGFX_UI_SHADER_NAME];char *source=sgfx_ui_shader_source(count,(const char *const *)text,length,sampler);
    if(!source) {sgfx_ui_unsupported(context,595);return;}
    sgfx_ui_mesa_meta_lock(m);struct sgfx_ui_shader_record *shaders=sgfx_ui_mesa_shaders(m);
    unsigned index=64;
    for(unsigned i=0;i<64;i++)if(shaders[i].name==name) {index=i;break;}
    if(index==64)for(unsigned i=0;i<64;i++)if(!shaders[i].name || !glIsShader(shaders[i].name)) {index=i;break;}
    if(index==64) {sgfx_ui_mesa_meta_unlock(m);free(source);sgfx_ui_unsupported(context,595);return;}
    const GLchar *part=source;glShaderSource(name,1,&part,NULL);free(source);
    shaders[index].name=name;memcpy(shaders[index].sampler,sampler,sizeof(sampler));
    sgfx_ui_mesa_meta_unlock(m);
}
void sgfx_ui_LinkProgramARB(void *context,GLhandleARB object)
{
    GLuint name;if(!handle(context,object,&name))return;
    struct sgfx_ui_mesa *m=sgfx_ui_context_backend(context);if(!m)return;
    sgfx_ui_mesa_meta_lock(m);
    struct sgfx_ui_shader_record *shaders=sgfx_ui_mesa_shaders(m);
    struct sgfx_ui_program_record *programs=sgfx_ui_mesa_programs(m);
    glLinkProgram(name);
    GLint linked=0;glGetProgramiv(name,GL_LINK_STATUS,&linked);
    if(!linked) {sgfx_ui_mesa_meta_unlock(m);return;}
    GLuint attached[64];GLsizei count=0;glGetAttachedShaders(name,64,&count,attached);
    if(count<0 || count>64) {sgfx_ui_mesa_meta_unlock(m);sgfx_ui_unsupported(context,597);return;}
    const char *sampler=NULL;
    for(GLsizei i=0;i<count;i++)for(unsigned s=0;s<64;s++)if(shaders[s].name==attached[i] && shaders[s].sampler[0]) {
        if(sampler && strcmp(sampler,shaders[s].sampler)) {sgfx_ui_mesa_meta_unlock(m);sgfx_ui_unsupported(context,597);return;}
        sampler=shaders[s].sampler;
    }
    unsigned index=64;
    for(unsigned i=0;i<64;i++)if(programs[i].name==name) {index=i;break;}
    if(index==64)for(unsigned i=0;i<64;i++)if(!programs[i].name || !glIsProgram(programs[i].name)) {index=i;break;}
    if(index==64) {sgfx_ui_mesa_meta_unlock(m);sgfx_ui_unsupported(context,597);return;}
    programs[index].name=name;programs[index].scale=programs[index].sampler=-1;
    if(sampler) {
        programs[index].scale=glGetUniformLocation(name,"sgfx_rect_scale");
        programs[index].sampler=glGetUniformLocation(name,sampler);
    }
    sgfx_ui_mesa_meta_unlock(m);
}
static bool before_draw(void *context)
{
    if(!sgfx_ui_bind(context))return false;
    struct sgfx_ui_mesa *m=sgfx_ui_context_backend(context);if(!m)return false;
    GLint program=0,active=0,rect_unit=-1,scale=-1;
    glGetIntegerv(GL_CURRENT_PROGRAM,&program);glGetIntegerv(GL_ACTIVE_TEXTURE,&active);
    sgfx_ui_mesa_meta_lock(m);struct sgfx_ui_program_record *programs=sgfx_ui_mesa_programs(m);
    GLint sampler_location=-1;
    for(unsigned i=0;i<64;i++)if(program>0 && programs[i].name==(uint32_t)program && programs[i].scale>=0) {
        sampler_location=programs[i].sampler;scale=programs[i].scale;break;
    }
    sgfx_ui_mesa_meta_unlock(m);
    if(scale>=0) {
        if(sampler_location<0) {sgfx_ui_unsupported(context,65);return false;}
        glGetUniformiv((GLuint)program,sampler_location,&rect_unit);
        if(rect_unit<0 || (unsigned)rect_unit>=SGFX_UI_UNITS) {sgfx_ui_unsupported(context,65);return false;}
    }
    for(unsigned u=0;u<SGFX_UI_UNITS;u++) {
        if((m->texture_2d[u] && !sgfx_ui_context_refresh(context,m->texture_2d[u])) ||
            (m->texture_rect[u] && !sgfx_ui_context_refresh(context,m->texture_rect[u]))) {
            glActiveTexture((GLenum)active);return false;
        }
        if(m->texture_2d[u] || m->texture_rect[u] || rect_unit==(GLint)u) {
            glActiveTexture(GL_TEXTURE0+u);glBindTexture(GL_TEXTURE_2D,rect_unit==(GLint)u?m->texture_rect[u]:m->texture_2d[u]);
            if(rect_unit==(GLint)u) {
                GLint width=0,height=0;
                glGetTexLevelParameteriv(GL_TEXTURE_2D,0,GL_TEXTURE_WIDTH,&width);
                glGetTexLevelParameteriv(GL_TEXTURE_2D,0,GL_TEXTURE_HEIGHT,&height);
                if(width<=0 || height<=0) {glActiveTexture((GLenum)active);sgfx_ui_unsupported(context,65);return false;}
                glUniform2f(scale,1.0f/(GLfloat)width,1.0f/(GLfloat)height);
            }
        }
    }
    glActiveTexture((GLenum)active);
    return true;
}
static void after_draw(void *context)
{
    GLint fbo=0,type=0,name=0;glGetIntegerv(GL_FRAMEBUFFER_BINDING,&fbo);if(!fbo)return;
    glGetFramebufferAttachmentParameteriv(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_FRAMEBUFFER_ATTACHMENT_OBJECT_TYPE,&type);
    if(type!=GL_TEXTURE)return;
    glGetFramebufferAttachmentParameteriv(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_FRAMEBUFFER_ATTACHMENT_OBJECT_NAME,&name);
    if(name>0)sgfx_ui_context_dirty(context,(GLuint)name);
}
void sgfx_ui_DrawArrays(void *context,GLenum mode,GLint first,GLsizei count)
{if(before_draw(context)) {glDrawArrays(mode,first,count);after_draw(context);}}
void sgfx_ui_DrawElements(void *context,GLenum mode,GLsizei count,GLenum type,const void *indices)
{if(before_draw(context)) {glDrawElements(mode,count,type,indices);after_draw(context);}}
void sgfx_ui_DrawArraysInstanced(void *context,GLenum mode,GLint first,GLsizei count,GLsizei instances)
{if(before_draw(context)) {glDrawArraysInstanced(mode,first,count,instances);after_draw(context);}}
void sgfx_ui_DrawElementsInstanced(void *context,GLenum mode,GLsizei count,GLenum type,const void *indices,GLsizei instances)
{if(before_draw(context)) {glDrawElementsInstanced(mode,count,type,indices,instances);after_draw(context);}}
void sgfx_ui_Clear(void *context,GLbitfield mask)
{if(sgfx_ui_bind(context)) {glClear(mask);after_draw(context);}}
void sgfx_ui_ClearBufferiv(void *context,GLenum buffer,GLint draw,const GLint *value)
{if(sgfx_ui_bind(context)) {glClearBufferiv(buffer,draw,value);after_draw(context);}}
void sgfx_ui_ClearBufferuiv(void *context,GLenum buffer,GLint draw,const GLuint *value)
{if(sgfx_ui_bind(context)) {glClearBufferuiv(buffer,draw,value);after_draw(context);}}
void sgfx_ui_ClearBufferfv(void *context,GLenum buffer,GLint draw,const GLfloat *value)
{if(sgfx_ui_bind(context)) {glClearBufferfv(buffer,draw,value);after_draw(context);}}
void sgfx_ui_ClearBufferfi(void *context,GLenum buffer,GLint draw,GLfloat depth,GLint stencil)
{if(sgfx_ui_bind(context)) {glClearBufferfi(buffer,draw,depth,stencil);after_draw(context);}}
void sgfx_ui_DrawRangeElements(void *context,GLenum mode,GLuint start,GLuint end,GLsizei count,GLenum type,const void *indices)
{if(before_draw(context)) {glDrawRangeElements(mode,start,end,count,type,indices);after_draw(context);}}
const GLubyte *sgfx_ui_GetString(void *context,GLenum name)
{
    if(!sgfx_ui_bind(context))return NULL;
    /* Retained20H392 recognizes0x8a1e as its separate private extension list.
     * Santoni implements none of those private extensions. Do not ask Mesa
     * to interpret this enum or consume the caller's existing GL error. */
    if(name==0x8a1e)return (const GLubyte *)"";
    return glGetString(name);
}
GLenum sgfx_ui_GetError(void *context)
{return sgfx_ui_bind(context)?glGetError():GL_INVALID_OPERATION;}
void sgfx_ui_GetIntegerv(void *context,GLenum pname,GLint *out)
{
    if(!out || !sgfx_ui_bind(context))return;
    if(pname==GL_TEXTURE_BINDING_2D || pname==GL_TEXTURE_BINDING_RECTANGLE) {
        struct sgfx_ui_mesa *m=sgfx_ui_context_backend(context);int u=unit(context);if(!m || u<0)return;
        *out=(GLint)(pname==GL_TEXTURE_BINDING_RECTANGLE?m->texture_rect[u]:m->texture_2d[u]);
    } else glGetIntegerv(pname,out);
}
/* The private framebuffer enum's rendering semantics are still unknown.
 * Refuse it explicitly; do not claim metadata-only emulation is equivalent. */
void sgfx_ui_FramebufferParameterivAPPLE(void *context,GLenum target,GLenum pname,const GLint *params)
{(void)target;(void)pname;(void)params;if(sgfx_ui_bind(context))sgfx_ui_unsupported(context,1024);}
void sgfx_ui_GetFramebufferParameterivAPPLE(void *context,GLenum target,GLenum pname,GLint *params)
{(void)target;(void)pname;if(params)*params=0;if(sgfx_ui_bind(context))sgfx_ui_unsupported(context,1025);}
void sgfx_ui_LabelObjectWithResponsibleProcessAPPLE(void *context,GLenum object,GLuint name,GLint process)
{(void)object;(void)name;(void)process;if(sgfx_ui_bind(context))sgfx_ui_unsupported(context,1033);}
