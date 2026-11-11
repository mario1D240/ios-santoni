#ifndef SANTONI_GRAPHICS_UI_DISPATCH_H
#define SANTONI_GRAPHICS_UI_DISPATCH_H
#define GL_GLEXT_PROTOTYPES 1
#include <GL/gl.h>
#include <GL/glext.h>
#include <GLES/gl.h>
#include <GLES/glext.h>
#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>
#include <stdint.h>
#include "ui_context.h"
extern void *const sgfx_ui_dispatch[SGFX_UI_SLOTS];
bool sgfx_ui_bind(void *);
GLenum sgfx_ui_target(void *,GLenum);
void sgfx_ui_unsupported(void *,unsigned);
_Noreturn void sgfx_ui_invalid(void *);
void sgfx_ui_noop(void *);
void sgfx_ui_DeleteObjectARB(void *,GLhandleARB);
void sgfx_ui_GetObjectParameterivARB(void *,GLhandleARB,GLenum,GLint *);
void sgfx_ui_GetInfoLogARB(void *,GLhandleARB,GLsizei,GLsizei *,GLcharARB *);
void sgfx_ui_GetAttachedObjectsARB(void *,GLhandleARB,GLsizei,GLsizei *,GLhandleARB *);
GLhandleARB sgfx_ui_GetHandleARB(void *,GLenum);
void sgfx_ui_Flush(void *);
void sgfx_ui_Finish(void *);
void sgfx_ui_FinishObjectAPPLE(void *,GLenum,GLint);
GLboolean sgfx_ui_TestObjectAPPLE(void *,GLenum,GLuint);
void sgfx_ui_BindTexture(void *,GLenum,GLuint);
void sgfx_ui_DeleteTextures(void *,GLsizei,const GLuint *);
void sgfx_ui_TexImage2D(void *,GLenum,GLint,GLint,GLsizei,GLsizei,GLint,GLenum,GLenum,const void *);
void sgfx_ui_TexSubImage2D(void *,GLenum,GLint,GLint,GLint,GLsizei,GLsizei,GLenum,GLenum,const void *);
void sgfx_ui_TexParameteri(void *,GLenum,GLenum,GLint);
void sgfx_ui_FramebufferTexture2DEXT(void *,GLenum,GLenum,GLenum,GLuint,GLint);
void sgfx_ui_BindFramebufferEXT(void *,GLenum,GLuint);
void sgfx_ui_DeleteFramebuffersEXT(void *,GLsizei,const GLuint *);
void sgfx_ui_ShaderSourceARB(void *,GLhandleARB,GLsizei,const GLcharARB **,const GLint *);
void sgfx_ui_LinkProgramARB(void *,GLhandleARB);
void sgfx_ui_DrawArrays(void *,GLenum,GLint,GLsizei);
void sgfx_ui_DrawElements(void *,GLenum,GLsizei,GLenum,const void *);
void sgfx_ui_DrawArraysInstanced(void *,GLenum,GLint,GLsizei,GLsizei);
void sgfx_ui_DrawElementsInstanced(void *,GLenum,GLsizei,GLenum,const void *,GLsizei);
void sgfx_ui_Clear(void *,GLbitfield);
void sgfx_ui_ClearBufferiv(void *,GLenum,GLint,const GLint *);
void sgfx_ui_ClearBufferuiv(void *,GLenum,GLint,const GLuint *);
void sgfx_ui_ClearBufferfv(void *,GLenum,GLint,const GLfloat *);
void sgfx_ui_ClearBufferfi(void *,GLenum,GLint,GLfloat,GLint);
void sgfx_ui_DrawRangeElements(void *,GLenum,GLuint,GLuint,GLsizei,GLenum,const void *);
const GLubyte *sgfx_ui_GetString(void *,GLenum);
GLenum sgfx_ui_GetError(void *);
void sgfx_ui_GetIntegerv(void *,GLenum,GLint *);
void sgfx_ui_FramebufferParameterivAPPLE(void *,GLenum,GLenum,const GLint *);
void sgfx_ui_GetFramebufferParameterivAPPLE(void *,GLenum,GLenum,GLint *);
void sgfx_ui_LabelObjectWithResponsibleProcessAPPLE(void *,GLenum,GLuint,GLint);
#endif
