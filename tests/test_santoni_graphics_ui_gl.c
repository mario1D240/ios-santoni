/* Actual GL binding + transfer core; GLES and device responses are models.
 * Function signatures are checked against pinned Khronos GLES3 headers. */
#include "ui_gl.h"
#include <GLES3/gl3.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct sgfx_gles_context {unsigned api;};
struct pixels {GLint alignment,buffer,row,skip_rows,skip_pixels;};
static struct pixels pack,unpack,original_pack,original_unpack;
static unsigned test,uploads,reads,finishes,queries;
static GLenum error;
static uint32_t submitted=7,completed=7;
static uint8_t copied[24];
unsigned sgfx_gles_api(const struct sgfx_gles_context *c){return c?c->api:0;}
bool sgfx_gles_current(struct sgfx_gles_context *c){return c && test!=2;}
bool sgfx_gles_status(const struct sgfx_gles_context *c,uint32_t *s,uint32_t *d)
{if(!c || test==4)return false;*s=submitted;*d=completed;return true;}
GLenum GL_APIENTRY glGetError(void){GLenum e=error;error=0;return e;}
void GL_APIENTRY glGetIntegerv(GLenum name,GLint *value)
{
    queries++;if(test==5)error=GL_INVALID_ENUM;
    switch(name) {
    case GL_PACK_ALIGNMENT:*value=pack.alignment;return;
    case GL_UNPACK_ALIGNMENT:*value=unpack.alignment;return;
    case GL_PIXEL_PACK_BUFFER_BINDING:*value=pack.buffer;return;
    case GL_PIXEL_UNPACK_BUFFER_BINDING:*value=unpack.buffer;return;
    case GL_PACK_ROW_LENGTH:*value=pack.row;return;
    case GL_UNPACK_ROW_LENGTH:*value=unpack.row;return;
    case GL_PACK_SKIP_ROWS:*value=pack.skip_rows;return;
    case GL_UNPACK_SKIP_ROWS:*value=unpack.skip_rows;return;
    case GL_PACK_SKIP_PIXELS:*value=pack.skip_pixels;return;
    case GL_UNPACK_SKIP_PIXELS:*value=unpack.skip_pixels;return;
    default:assert(false);
    }
}
void GL_APIENTRY glPixelStorei(GLenum name,GLint value)
{
    switch(name) {
    case GL_PACK_ALIGNMENT:pack.alignment=value;return;
    case GL_UNPACK_ALIGNMENT:unpack.alignment=value;return;
    case GL_PACK_ROW_LENGTH:pack.row=value;return;
    case GL_UNPACK_ROW_LENGTH:unpack.row=value;return;
    case GL_PACK_SKIP_ROWS:pack.skip_rows=value;return;
    case GL_UNPACK_SKIP_ROWS:unpack.skip_rows=value;return;
    case GL_PACK_SKIP_PIXELS:pack.skip_pixels=value;return;
    case GL_UNPACK_SKIP_PIXELS:unpack.skip_pixels=value;return;
    default:assert(false);
    }
}
void GL_APIENTRY glBindBuffer(GLenum target,GLuint buffer)
{if(target==GL_PIXEL_PACK_BUFFER)pack.buffer=(GLint)buffer;else {assert(target==GL_PIXEL_UNPACK_BUFFER);unpack.buffer=(GLint)buffer;}}
void GL_APIENTRY glFinish(void){finishes++;submitted=completed=8;if(test==7)error=GL_INVALID_OPERATION;}
GLenum GL_APIENTRY glCheckFramebufferStatus(GLenum target)
{assert(target==(test==1?GL_FRAMEBUFFER:GL_READ_FRAMEBUFFER));return test==8?GL_FRAMEBUFFER_INCOMPLETE_ATTACHMENT:GL_FRAMEBUFFER_COMPLETE;}
void GL_APIENTRY glTexImage2D(GLenum target,GLint level,GLint format,GLsizei width,GLsizei height,
    GLint border,GLenum external,GLenum type,const void *pixels)
{
    uploads++;assert(target==GL_TEXTURE_2D && !level && !border && width==3 && height==2 &&
        external==GL_RGBA && type==GL_UNSIGNED_BYTE && format==(test==1?GL_RGBA:GL_RGBA8));
    assert(unpack.alignment==4 && !unpack.buffer && !unpack.row && !unpack.skip_rows && !unpack.skip_pixels);
    memcpy(copied,pixels,sizeof(copied));if(test==6)error=GL_OUT_OF_MEMORY;
}
void GL_APIENTRY glReadPixels(GLint x,GLint y,GLsizei width,GLsizei height,GLenum format,GLenum type,void *pixels)
{
    reads++;assert(!x && !y && width==3 && height==2 && format==GL_RGBA && type==GL_UNSIGNED_BYTE);
    assert(pack.alignment==4 && !pack.buffer && !pack.row && !pack.skip_rows && !pack.skip_pixels);
    uint8_t *p=pixels;for(unsigned i=0;i<6;i++) {p[i*4]=255;p[i*4+1]=0;p[i*4+2]=0;p[i*4+3]=255;}
    submitted=9;completed=test==10?8:9;if(test==9)error=GL_INVALID_OPERATION;
}
int main(int argc,char **argv)
{
    assert(argc==2);test=(unsigned)strtoul(argv[1],NULL,10);assert(test<12);
    struct sgfx_gles_context gles={test==1?2:3};struct sgfx_ui_gl context={.gles=&gles};
    pack=(struct pixels){8,test==1?0:17,test==1?0:11,test==1?0:3,test==1?0:2};
    unpack=(struct pixels){8,test==1?0:29,test==1?0:13,test==1?0:5,test==1?0:7};
    original_pack=pack;original_unpack=unpack;if(test==3)error=GL_INVALID_OPERATION;
    uint8_t bytes[48],original[48];memset(bytes,0xa7,sizeof(bytes));
    for(unsigned i=0;i<12;i++){bytes[4+i]=(uint8_t)(i+1);bytes[20+i]=(uint8_t)(i+13);}
    memcpy(original,bytes,sizeof(bytes));struct sgfx_ui_surface s={bytes,48,4,3,2,16,SGFX_UI_BGRA,false};
    struct sgfx_ui_transfer_ops ops;assert(sgfx_ui_gl_ops(&context,&ops));
    if(test==11){context.gles=NULL;assert(!sgfx_ui_gl_ops(&context,&ops));context.gles=&gles;context.failed=true;
        assert(!sgfx_ui_gl_ops(&context,&ops));return 0;}
    bool good=test==0 || test==1 || test>=7;
    assert(sgfx_ui_upload(&ops,&s)==good);
    assert(!memcmp(&pack,&original_pack,sizeof(pack)) && !memcmp(&unpack,&original_unpack,sizeof(unpack)));
    if(good) {
        const uint8_t rgba[]={3,2,1,4,7,6,5,8,11,10,9,12,15,14,13,16,19,18,17,20,23,22,21,24};
        assert(!memcmp(copied,rgba,24));
    }
    uint32_t seq=99;bool committed=sgfx_ui_commit(&ops,&s,&seq);
    assert(committed==(test==0 || test==1));
    if(committed){assert(seq==9);for(unsigned x=0;x<3;x++) {const uint8_t red[]={0,0,255,255};
        assert(!memcmp(bytes+4+x*4,red,4) && !memcmp(bytes+20+x*4,red,4));}}
    else {assert(seq==99 && !memcmp(bytes,original,48));}
    assert(!memcmp(&pack,&original_pack,sizeof(pack)) && !memcmp(&unpack,&original_unpack,sizeof(unpack)));
    if(test==3)assert(context.first_error==GL_INVALID_OPERATION && context.failed && !uploads && !reads);
    if(test==5)assert(context.first_error==GL_INVALID_ENUM && context.failed && !uploads);
    if(test==6)assert(context.first_error==GL_OUT_OF_MEMORY && context.failed);
    if(test==8)assert(context.first_framebuffer_status==GL_FRAMEBUFFER_INCOMPLETE_ATTACHMENT && context.failed && !reads);
    printf("PASS UI GL binding case=%u; actual transfer, modeled GLES/device\n",test);return 0;
}
