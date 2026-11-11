/* Actual Mesa calls for the UI transfer core; no system OpenGLES linkage. */
#include "ui_gl.h"
#include <GLES3/gl3.h>
static bool gl_ok(struct sgfx_ui_gl *c)
{
    GLenum error=glGetError();
    if(error==GL_NO_ERROR)return true;
    if(!c->first_error)c->first_error=error;
    c->failed=true;return false;
}
static bool gl_current(struct sgfx_ui_gl *c)
{return c && !c->failed && c->gles && sgfx_gles_current(c->gles) && gl_ok(c);}
static bool gl_fence(void *context,uint32_t *submitted,uint32_t *completed)
{
    struct sgfx_ui_gl *c=context;
    if(!c || c->failed)return false;
    if(!sgfx_gles_status(c->gles,submitted,completed)) {c->failed=true;return false;}
    return true;
}
static bool gl_finish(void *context)
{
    struct sgfx_ui_gl *c=context;
    if(!gl_current(c))return false;
    glFinish();return gl_ok(c);
}
struct pixel_state {GLint alignment,buffer,row_length,skip_rows,skip_pixels;};
static bool pixel_begin(struct sgfx_ui_gl *c,bool pack,struct pixel_state *s)
{
    glGetIntegerv(pack?GL_PACK_ALIGNMENT:GL_UNPACK_ALIGNMENT,&s->alignment);
    if(sgfx_gles_api(c->gles)>=3) {
        glGetIntegerv(pack?GL_PIXEL_PACK_BUFFER_BINDING:GL_PIXEL_UNPACK_BUFFER_BINDING,&s->buffer);
        glGetIntegerv(pack?GL_PACK_ROW_LENGTH:GL_UNPACK_ROW_LENGTH,&s->row_length);
        glGetIntegerv(pack?GL_PACK_SKIP_ROWS:GL_UNPACK_SKIP_ROWS,&s->skip_rows);
        glGetIntegerv(pack?GL_PACK_SKIP_PIXELS:GL_UNPACK_SKIP_PIXELS,&s->skip_pixels);
    }
    if(!gl_ok(c))return false;
    if(sgfx_gles_api(c->gles)>=3) {
        glBindBuffer(pack?GL_PIXEL_PACK_BUFFER:GL_PIXEL_UNPACK_BUFFER,0);
        glPixelStorei(pack?GL_PACK_ROW_LENGTH:GL_UNPACK_ROW_LENGTH,0);
        glPixelStorei(pack?GL_PACK_SKIP_ROWS:GL_UNPACK_SKIP_ROWS,0);
        glPixelStorei(pack?GL_PACK_SKIP_PIXELS:GL_UNPACK_SKIP_PIXELS,0);
    }
    glPixelStorei(pack?GL_PACK_ALIGNMENT:GL_UNPACK_ALIGNMENT,4);
    return gl_ok(c);
}
static bool pixel_end(struct sgfx_ui_gl *c,bool pack,const struct pixel_state *s)
{
    glPixelStorei(pack?GL_PACK_ALIGNMENT:GL_UNPACK_ALIGNMENT,s->alignment);
    if(sgfx_gles_api(c->gles)>=3) {
        glPixelStorei(pack?GL_PACK_ROW_LENGTH:GL_UNPACK_ROW_LENGTH,s->row_length);
        glPixelStorei(pack?GL_PACK_SKIP_ROWS:GL_UNPACK_SKIP_ROWS,s->skip_rows);
        glPixelStorei(pack?GL_PACK_SKIP_PIXELS:GL_UNPACK_SKIP_PIXELS,s->skip_pixels);
        glBindBuffer(pack?GL_PIXEL_PACK_BUFFER:GL_PIXEL_UNPACK_BUFFER,(GLuint)s->buffer);
    }
    return gl_ok(c);
}
static bool gl_upload(void *context,uint32_t width,uint32_t height,const uint8_t *pixels)
{
    struct sgfx_ui_gl *c=context;struct pixel_state saved={0};
    if(!gl_current(c) || !pixel_begin(c,false,&saved))return false;
    glTexImage2D(GL_TEXTURE_2D,0,sgfx_gles_api(c->gles)>=3?GL_RGBA8:GL_RGBA,
        (GLsizei)width,(GLsizei)height,0,GL_RGBA,GL_UNSIGNED_BYTE,pixels);
    bool ok=gl_ok(c);bool restored=pixel_end(c,false,&saved);return ok && restored;
}
static bool gl_readback(void *context,uint32_t width,uint32_t height,uint8_t *pixels)
{
    struct sgfx_ui_gl *c=context;struct pixel_state saved={0};
    if(!gl_current(c) || !pixel_begin(c,true,&saved))return false;
    /* A complete FBO is necessary before calling this operation; dimensions
     * come from the retained target's validated IOSurface geometry. */
    GLenum status=glCheckFramebufferStatus(sgfx_gles_api(c->gles)>=3?GL_READ_FRAMEBUFFER:GL_FRAMEBUFFER);
    if(status!=GL_FRAMEBUFFER_COMPLETE) {
        if(!c->first_framebuffer_status)c->first_framebuffer_status=status;
        c->failed=true;(void)pixel_end(c,true,&saved);return false;
    }
    glReadPixels(0,0,(GLsizei)width,(GLsizei)height,GL_RGBA,GL_UNSIGNED_BYTE,pixels);
    bool ok=gl_ok(c);bool restored=pixel_end(c,true,&saved);return ok && restored;
}
bool sgfx_ui_gl_ops(struct sgfx_ui_gl *context,struct sgfx_ui_transfer_ops *ops)
{
    if(!context || !ops || !context->gles || context->failed)return false;
    *ops=(struct sgfx_ui_transfer_ops){context,gl_upload,gl_finish,gl_readback,gl_fence};return true;
}
