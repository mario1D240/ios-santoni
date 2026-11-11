/* Run the actual Mesa binding/transfer/backend functions. GL is modeled;
 * the test distinguishes read/draw FBOs and preserves caller pixel state. */
#include "ui_backend.h"
#include <GLES3/gl3.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct sgfx_gles_context {unsigned api;};
static unsigned test,destroys,reads;
static struct sgfx_gles_context gles,other={3};
static struct sgfx_gles_context *current=&other;
static GLint draw=123,read=456,texture=789,pack=8,unpack=8;
static uint32_t sequence=7;
static GLenum error;
struct sgfx_gles_context *sgfx_gles_create_api(unsigned api)
{if(test==1)return NULL;gles.api=api;return &gles;}
struct sgfx_gles_context *sgfx_gles_create_shared_api(unsigned api,struct sgfx_gles_context *parent)
{(void)api;(void)parent;assert(!"independent backend must not create a shared child");return NULL;}
unsigned sgfx_gles_api(const struct sgfx_gles_context *c) {return c?c->api:0;}
bool sgfx_gles_current(struct sgfx_gles_context *c) {current=c;return true;}
void sgfx_gles_destroy(struct sgfx_gles_context *c) {assert(c==&gles);destroys++;}
bool sgfx_gles_status(const struct sgfx_gles_context *c,uint32_t *s,uint32_t *d)
{assert(c==&gles);*s=sequence;*d=sequence-(test==6 && reads?1:0);return true;}
GLenum GL_APIENTRY glGetError(void) {GLenum old=error;error=0;return old;}
void GL_APIENTRY glGetIntegerv(GLenum name,GLint *out)
{
    switch(name) {
    case GL_TEXTURE_BINDING_2D:*out=texture;return;
    case GL_FRAMEBUFFER_BINDING:*out=draw;return;
    case GL_READ_FRAMEBUFFER_BINDING:*out=read;return;
    case GL_PACK_ALIGNMENT:*out=pack;return;
    case GL_UNPACK_ALIGNMENT:*out=unpack;return;
    case GL_PIXEL_PACK_BUFFER_BINDING:case GL_PIXEL_UNPACK_BUFFER_BINDING:
    case GL_PACK_ROW_LENGTH:case GL_UNPACK_ROW_LENGTH:case GL_PACK_SKIP_ROWS:
    case GL_UNPACK_SKIP_ROWS:case GL_PACK_SKIP_PIXELS:case GL_UNPACK_SKIP_PIXELS:*out=0;return;
    default:assert(false);
    }
}
void GL_APIENTRY glBindTexture(GLenum target,GLuint name) {assert(target==GL_TEXTURE_2D);texture=(GLint)name;}
void GL_APIENTRY glGenFramebuffers(GLsizei n,GLuint *name) {assert(n==1);*name=test==3?0:33;}
void GL_APIENTRY glBindFramebuffer(GLenum target,GLuint name)
{if(target==GL_READ_FRAMEBUFFER)read=(GLint)name;else {assert(target==GL_FRAMEBUFFER);draw=read=(GLint)name;}}
void GL_APIENTRY glFramebufferTexture2D(GLenum target,GLenum attachment,GLenum textarget,GLuint name,GLint level)
{assert(target==(gles.api==3?GL_READ_FRAMEBUFFER:GL_FRAMEBUFFER) && attachment==GL_COLOR_ATTACHMENT0 &&
    textarget==GL_TEXTURE_2D && name==17 && !level);if(test==4)error=GL_INVALID_OPERATION;}
GLenum GL_APIENTRY glCheckFramebufferStatus(GLenum target)
{assert(target==(gles.api==3?GL_READ_FRAMEBUFFER:GL_FRAMEBUFFER));return test==5?GL_FRAMEBUFFER_INCOMPLETE_ATTACHMENT:GL_FRAMEBUFFER_COMPLETE;}
void GL_APIENTRY glPixelStorei(GLenum name,GLint value)
{if(name==GL_PACK_ALIGNMENT)pack=value;else if(name==GL_UNPACK_ALIGNMENT)unpack=value;else assert(!value);}
void GL_APIENTRY glBindBuffer(GLenum target,GLuint name)
{assert((target==GL_PIXEL_PACK_BUFFER || target==GL_PIXEL_UNPACK_BUFFER) && !name);}
void GL_APIENTRY glFinish(void) {assert(current==&gles);}
void GL_APIENTRY glTexImage2D(GLenum target,GLint level,GLint internal,GLsizei w,GLsizei h,GLint border,GLenum format,GLenum type,const void *bytes)
{assert(target==GL_TEXTURE_2D && !level && internal==(gles.api==3?GL_RGBA8:GL_RGBA) &&
    w==2 && h==2 && !border && format==GL_RGBA && type==GL_UNSIGNED_BYTE && bytes && texture==17 && unpack==4);}
void GL_APIENTRY glReadPixels(GLint x,GLint y,GLsizei w,GLsizei h,GLenum format,GLenum type,void *bytes)
{assert(!x && !y && w==2 && h==2 && format==GL_RGBA && type==GL_UNSIGNED_BYTE && read==33 && pack==4);
 memset(bytes,255,16);sequence++;reads++;}
int main(int argc,char **argv)
{
    assert(argc==2);test=(unsigned)strtoul(argv[1],NULL,10);assert(test<8);
    struct sgfx_ui_backend backend;
    assert(sgfx_ui_mesa_create(test==2?2:3,&backend)==(test!=1));
    if(test==1) {assert(!destroys && current==&other);return 0;}
    assert(current==&other && backend.current(backend.context,true) && current==&gles);
    uint32_t saved=0;assert(backend.select(backend.context,17,false,&saved) && saved==789);
    uint8_t pixels[16];memset(pixels,42,16);
    struct sgfx_ui_surface surface={pixels,16,0,2,2,8,SGFX_UI_BGRA,false};
    assert(sgfx_ui_upload(&backend.transfer,&surface));assert(backend.restore(backend.context,saved,false) && texture==789 && unpack==8);
    if(test==2)read=draw; /* ES2 has one shared read/draw framebuffer binding. */
    bool selected=backend.select(backend.context,17,true,&saved);
    if(test==3) {assert(!selected && draw==123 && read==456);goto done;}
    assert(selected && saved==(test==2?123:456) && read==33 && draw==(test==2?33:123));
    uint8_t original[16];memcpy(original,pixels,16);uint32_t seq=0;
    assert(sgfx_ui_commit(&backend.transfer,&surface,&seq)==(test<4 || test==7));
    assert(backend.restore(backend.context,saved,true) && draw==123 && read==(test==2?123:456) && pack==8);
    if(test>=4 && test<=6)assert(!memcmp(original,pixels,16) && !seq);
    else assert(seq==8 && pixels[0]==255);
done:
    /* Destroying an inactive backend must not replace another current context. */
    current=&other;backend.destroy(backend.context);assert(current==&other && destroys==1);
    puts("PASS actual UI Mesa backend; GL and transport modeled");return 0;
}
