/* Actual backend-group implementation; GLES/GL calls are modeled. */
#include "ui_backend.h"
#include <GLES3/gl3.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct sgfx_gles_context {unsigned api,id;bool alive;struct sgfx_gles_context *shared_parent;};
static struct sgfx_gles_context contexts[8],foreign;
static struct sgfx_gles_context *current=&foreign;
static unsigned created,destroyed,test;
static bool fail_shared;
struct sgfx_gles_context *sgfx_gles_create_api(unsigned api)
{if(test==1)return NULL;struct sgfx_gles_context *c=&contexts[created];*c=(struct sgfx_gles_context){api,created,true,NULL};created++;return c;}
struct sgfx_gles_context *sgfx_gles_create_shared_api(unsigned api,struct sgfx_gles_context *parent)
{assert(parent==&contexts[0] && parent->alive);if(fail_shared)return NULL;struct sgfx_gles_context *c=&contexts[created];*c=(struct sgfx_gles_context){api,created,true,parent};created++;return c;}
unsigned sgfx_gles_api(const struct sgfx_gles_context *c){return c?c->api:0;}
bool sgfx_gles_current(struct sgfx_gles_context *c){assert(!c || c->alive);current=c;return true;}
void sgfx_gles_destroy(struct sgfx_gles_context *c){assert(c && c->alive && current!=c);c->alive=false;destroyed++;}
GLenum GL_APIENTRY glGetError(void){return GL_NO_ERROR;}
void GL_APIENTRY glGetIntegerv(GLenum name,GLint *value){(void)name;*value=0;}
void GL_APIENTRY glGenFramebuffers(GLsizei n,GLuint *name){assert(n==1);*name=1;}
void GL_APIENTRY glBindFramebuffer(GLenum target,GLuint name){(void)target;(void)name;}
void GL_APIENTRY glBindTexture(GLenum target,GLuint name){(void)target;(void)name;}
void GL_APIENTRY glFramebufferTexture2D(GLenum target,GLenum attachment,GLenum textarget,GLuint texture,GLint level)
{(void)target;(void)attachment;(void)textarget;(void)texture;(void)level;}
static bool upload(void *c,uint32_t w,uint32_t h,const uint8_t *p){(void)c;(void)w;(void)h;(void)p;return true;}
static bool finish(void *c){(void)c;return true;}
static bool read_pixels(void *c,uint32_t w,uint32_t h,uint8_t *p){(void)c;(void)w;(void)h;(void)p;return true;}
static bool fence(void *c,uint32_t *s,uint32_t *d){(void)c;*s=*d=1;return true;}
bool sgfx_ui_gl_ops(struct sgfx_ui_gl *gl,struct sgfx_ui_transfer_ops *out)
{assert(gl->gles && gl->gles->alive);if(test==4)return false;*out=(struct sgfx_ui_transfer_ops){gl,upload,finish,read_pixels,fence};return true;}
int main(int argc,char **argv)
{
    assert(argc==2);test=(unsigned)strtoul(argv[1],NULL,10);assert(test<7);
    assert(!sgfx_ui_mesa_group_create(1) && !created);
    struct sgfx_ui_mesa_group *g=sgfx_ui_mesa_group_create(3);
    if(test==1){assert(!g && !created);return 0;}
    assert(g && g->references==1 && created==1 && current==&foreign);
    struct sgfx_ui_backend a={0},b={0};
    if(test==2 || test==3 || test==4){
        if(test==2)fail_shared=true;
        if(test==3)g->references=UINT32_MAX;
        assert(!sgfx_ui_mesa_create_in_group(2,g,&a));
        assert(g->references==(test==3?UINT32_MAX:1) && contexts[0].alive && !a.context);
        if(test==4)assert(created==2 && destroyed==1);
        g->references=1;assert(sgfx_ui_mesa_group_release(g));assert(created==destroyed);return 0;
    }
    assert(sgfx_ui_mesa_create_in_group(2,g,&a) && sgfx_ui_mesa_create_in_group(3,g,&b));
    struct sgfx_ui_mesa *one=a.context,*two=b.context;
    assert(g->references==3 && one->group==g && two->group==g && one->gl.gles!=two->gl.gles);
    assert(one->gl.gles->shared_parent==g->anchor && two->gl.gles->shared_parent==g->anchor);
    sgfx_ui_mesa_meta_lock(one);struct sgfx_ui_shader_record *s=sgfx_ui_mesa_shaders(one);
    s[0].name=17;strcpy(s[0].sampler,"inputRect");
    struct sgfx_ui_program_record *p=sgfx_ui_mesa_programs(one);p[0]=(struct sgfx_ui_program_record){23,7,8};
    sgfx_ui_mesa_meta_unlock(one);
    sgfx_ui_mesa_meta_lock(two);
    assert(sgfx_ui_mesa_shaders(two)[0].name==17 && !strcmp(sgfx_ui_mesa_shaders(two)[0].sampler,"inputRect"));
    assert(sgfx_ui_mesa_programs(two)[0].name==23 && sgfx_ui_mesa_programs(two)[0].scale==7);
    sgfx_ui_mesa_meta_unlock(two);
    one->texture_rect[0]=99;assert(!two->texture_rect[0]);one->read_fbo=45;assert(!two->read_fbo);
    if(test==5){assert(sgfx_ui_mesa_group_retain(g));assert(sgfx_ui_mesa_group_release(g));}
    if(test==6){assert(!sgfx_ui_mesa_create_in_group(1,g,&a) && g->references==3);}
    assert(sgfx_ui_mesa_group_release(g) && g->references==2 && contexts[0].alive);
    a.destroy(a.context);assert(g->references==1 && contexts[0].alive && contexts[2].alive);
    b.destroy(b.context);assert(created==destroyed && current==&foreign);
    printf("PASS backend sharing case=%u; GLES/GL modeled\n",test);return 0;
}
