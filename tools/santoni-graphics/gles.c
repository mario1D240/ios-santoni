/* Mesa state-tracker/Gallium/IR3 frontend for the pinned A505 profile.
 * Patterns: Mesa's hgl frontend and ios-sailfish tools/sweetgl/sweetgl.c.
 * Device ID/GMEM/BO addresses come only from our checked Santoni transport. */
#include "gles.h"
#include "ui_gl.h"
#include "santoni_drm.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "pipe/p_screen.h"
#include "frontend/api.h"
#include "state_tracker/st_context.h"
#include "freedreno/drm/freedreno_drm_public.h"
#include "renderonly/renderonly.h"
#include "util/driconf.h"
#include "util/xmlconfig.h"
#include <GLES3/gl3.h>
struct sgfx_gles_context {
    struct pipe_frontend_screen frontend;
    struct st_context *st;
    driOptionCache option_info,options;
    int fd;
    unsigned api;
    uint32_t references;
    struct sgfx_gles_context *screen_owner;
};
static pthread_mutex_t sharing_lock=PTHREAD_MUTEX_INITIALIZER;
static const driOptionDescription options[] = {
#include "pipe-loader/driinfo_gallium.h"
#include "freedreno/driinfo_freedreno.h"
};
void renderonly_scanout_destroy(struct renderonly_scanout *scanout,struct renderonly *ro)
{(void)scanout;(void)ro;}
struct renderonly_scanout *renderonly_create_gpu_import_for_resource(struct pipe_resource *resource,
    struct renderonly *ro,struct winsys_handle *handle)
{(void)resource;(void)ro;(void)handle;return NULL;}
static int sgfx_gles_frontend_param(struct pipe_frontend_screen *screen,enum st_manager_param parameter)
{
    /* Mesa25.0.7 st_manager.c calls get_param unconditionally at context
     * creation. This surfaceless frontend has no legacy DRI invalidation. */
    (void)screen;(void)parameter;return 0;
}
struct sgfx_gles_context *sgfx_gles_create_api(unsigned api)
{
    if(api!=2 && api!=3)return NULL;
    /* Mesa appends even unknown MESA_EXTENSION_OVERRIDE names to its public
     * list. A505 renderer admission must use the driver's real capabilities. */
    const char *extensions=getenv("MESA_EXTENSION_OVERRIDE");
    if(extensions && extensions[0]) {
        fprintf(stderr,"GLES: extension override rejected before transport admission\n");return NULL;
    }
    int fd=sgfx_drm_open();if(fd<0)return NULL;
    struct sgfx_gles_context *c=calloc(1,sizeof(*c));
    if(!c) {sgfx_drm_close(fd);return NULL;}
    c->fd=fd;c->api=api;c->references=1;c->frontend.get_param=sgfx_gles_frontend_param;
    /* Initial isolated path uses sysmem: no GMEM resolve, tile imports or
     * native scanout. No environment override may select nohw or perf writes. */
    setenv("FD_MESA_DEBUG","sysmem,notile,noubwc,nofp16,inorder,noindirect",1);
    setenv("IR3_SHADER_DEBUG","nofp16",1);
    driParseOptionInfo(&c->option_info,options,ARRAY_SIZE(options));
    struct pipe_screen_config config={.options=&c->options,.options_info=&c->option_info};
    c->frontend.screen=fd_drm_screen_create_renderonly(fd,NULL,&config);
    if(!c->frontend.screen) {sgfx_gles_destroy(c);return NULL;}
    struct st_context_attribs attribs={.profile=API_OPENGLES2,.major=api,.minor=0};
    enum st_context_error error=ST_CONTEXT_SUCCESS;
    c->st=st_api_create_context(&c->frontend,&attribs,&error,NULL);
    if(!c->st) {fprintf(stderr,"GLES context error=%u\n",error);sgfx_gles_destroy(c);return NULL;}
    return c;
}
struct sgfx_gles_context *sgfx_gles_create(void)
{return sgfx_gles_create_api(2);}
unsigned sgfx_gles_api(const struct sgfx_gles_context *c)
{return c?c->api:0;}
bool sgfx_gles_status(const struct sgfx_gles_context *c,uint32_t *submitted,uint32_t *completed)
{return c && submitted && completed && sgfx_drm_status(c->fd,submitted,completed);}
bool sgfx_gles_current(struct sgfx_gles_context *c)
{return st_api_make_current(c?c->st:NULL,NULL,NULL);}
static void release_locked(struct sgfx_gles_context *c)
{
    if(--c->references)return;
    if(c->st) {
        st_destroy_context(c->st);
    }
    struct sgfx_gles_context *owner=c->screen_owner;
    if(!owner) {
        st_screen_destroy(&c->frontend);
        if(c->frontend.screen)c->frontend.screen->destroy(c->frontend.screen);
        driDestroyOptionCache(&c->options);driDestroyOptionInfo(&c->option_info);
        sgfx_drm_close(c->fd);
    }
    free(c);
    if(owner)release_locked(owner);
}
bool sgfx_gles_retain(struct sgfx_gles_context *c)
{
    if(!c)return false;
    pthread_mutex_lock(&sharing_lock);
    bool ok=c->references && c->references<UINT32_MAX;
    if(ok)c->references++;
    pthread_mutex_unlock(&sharing_lock);return ok;
}
struct sgfx_gles_context *sgfx_gles_create_shared_api(unsigned api,struct sgfx_gles_context *shared)
{
    if(api!=2 && api!=3)return NULL;
    if(!shared)return sgfx_gles_create_api(api);
    struct sgfx_gles_context *c=calloc(1,sizeof(*c));if(!c)return NULL;
    pthread_mutex_lock(&sharing_lock);
    struct sgfx_gles_context *owner=shared->screen_owner?shared->screen_owner:shared;
    if(!shared->st || !shared->references || !owner->st || owner->references==UINT32_MAX) {
        pthread_mutex_unlock(&sharing_lock);free(c);return NULL;
    }
    owner->references++;
    c->screen_owner=owner;c->references=1;c->fd=owner->fd;c->api=api;
    struct st_context_attribs attribs={.profile=API_OPENGLES2,.major=api,.minor=0};
    enum st_context_error error=ST_CONTEXT_SUCCESS;
    c->st=st_api_create_context(&owner->frontend,&attribs,&error,shared->st);
    if(!c->st) {release_locked(c);c=NULL;}
    pthread_mutex_unlock(&sharing_lock);return c;
}
void sgfx_gles_destroy(struct sgfx_gles_context *c)
{
    if(!c)return;
    pthread_mutex_lock(&sharing_lock);
    /* An external release unbinds this context even while its screen is
     * retained by children. It never changes another current context. */
    if(c->st) {
        if(st_api_get_current()==c->st)st_api_make_current(NULL,NULL,NULL);
    }
    release_locked(c);
    pthread_mutex_unlock(&sharing_lock);
}
static GLuint shader(GLenum type,const char *text)
{
    GLuint s=glCreateShader(type);if(!s)return 0;
    glShaderSource(s,1,&text,NULL);glCompileShader(s);
    GLint ok=0;glGetShaderiv(s,GL_COMPILE_STATUS,&ok);
    if(!ok) {
        char log[1024]={0};glGetShaderInfoLog(s,sizeof(log),NULL,log);
        fprintf(stderr,"GLES shader type=%x failed: %s\n",type,log);glDeleteShader(s);return 0;
    }
    return s;
}
static bool readback_proof(unsigned api,int retained_fd)
{
    uint32_t prior_submitted=0,prior_completed=0;
    if((api!=2 && api!=3) || (retained_fd>=0 &&
        (st_api_get_current() || !sgfx_drm_status(retained_fd,&prior_submitted,&prior_completed) ||
         prior_submitted!=prior_completed)))return false;
    struct sgfx_gles_context *c=sgfx_gles_create_api(api);
    if(!c) {fprintf(stderr,"GLES RESULT pass=0 reason=service-or-raster-capability\n");return false;}
    bool pass=false;GLuint tex=0,fbo=0,vbo=0,vs=0,fs=0,program=0;
    uint32_t start=0,clear_seq=0,draw_seq=0,completed=0;
    unsigned clear_pixels=0,triangle_pixels=0;
    uint8_t pixels[64*64*4];
    struct sgfx_ui_gl transfer={.gles=c};struct sgfx_ui_transfer_ops transfer_ops={0};
    struct sgfx_ui_surface surface={pixels,sizeof(pixels),0,64,64,64*4,SGFX_UI_BGRA,false};
    if(!sgfx_gles_current(c) || sgfx_gles_api(c)!=api ||
        !sgfx_drm_status(c->fd,&start,&completed) || start!=completed)goto done;
    if(api==3) {
        GLint major=0;glGetIntegerv(GL_MAJOR_VERSION,&major);
        if(major!=3 || glGetError()!=GL_NO_ERROR)goto done;
    }
    if(!sgfx_ui_gl_ops(&transfer,&transfer_ops))goto done;
    printf("GLES renderer=%s version=%s\n",glGetString(GL_RENDERER),glGetString(GL_VERSION));
    glGenTextures(1,&tex);glBindTexture(GL_TEXTURE_2D,tex);
    glTexImage2D(GL_TEXTURE_2D,0,api==3?GL_RGBA8:GL_RGBA,64,64,0,GL_RGBA,GL_UNSIGNED_BYTE,NULL);
    glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER,GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MAG_FILTER,GL_NEAREST);
    glGenFramebuffers(1,&fbo);glBindFramebuffer(GL_FRAMEBUFFER,fbo);
    glFramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,tex,0);
    if(glCheckFramebufferStatus(GL_FRAMEBUFFER)!=GL_FRAMEBUFFER_COMPLETE)goto done;
    glViewport(0,0,64,64);glClearColor(0,0,1,1);glClear(GL_COLOR_BUFFER_BIT);
    if(!sgfx_ui_commit(&transfer_ops,&surface,&clear_seq))goto done;
    if(glGetError()!=GL_NO_ERROR || !sgfx_drm_status(c->fd,&clear_seq,&completed) ||
        clear_seq<=start || completed!=clear_seq)goto done;
    for(unsigned i=0;i<64*64;i++) {
        const uint8_t *p=&pixels[i*4];if(p[0]!=255 || p[1] || p[2] || p[3]!=255)goto done;
        clear_pixels++;
    }
    vs=shader(GL_VERTEX_SHADER,api==3?
        "#version 300 es\nin vec2 position;void main(){gl_Position=vec4(position,0.0,1.0);}":
        "attribute vec2 position;void main(){gl_Position=vec4(position,0.0,1.0);}");
    fs=shader(GL_FRAGMENT_SHADER,api==3?
        "#version 300 es\nprecision highp float;out vec4 fragmentColor;void main(){fragmentColor=vec4(1.0,0.0,0.0,1.0);}":
        "precision highp float;void main(){gl_FragColor=vec4(1.0,0.0,0.0,1.0);}");
    if(!vs || !fs)goto done;
    program=glCreateProgram();glAttachShader(program,vs);glAttachShader(program,fs);
    glBindAttribLocation(program,0,"position");glLinkProgram(program);
    GLint linked=0;glGetProgramiv(program,GL_LINK_STATUS,&linked);if(!linked)goto done;
    glUseProgram(program);
    static const float triangle[]={-1,-1,1,-1,-1,1};
    glGenBuffers(1,&vbo);glBindBuffer(GL_ARRAY_BUFFER,vbo);
    glBufferData(GL_ARRAY_BUFFER,sizeof(triangle),triangle,GL_STATIC_DRAW);
    glEnableVertexAttribArray(0);glVertexAttribPointer(0,2,GL_FLOAT,GL_FALSE,0,NULL);
    glDrawArrays(GL_TRIANGLES,0,3);
    if(!sgfx_ui_commit(&transfer_ops,&surface,&draw_seq))goto done;
    if(glGetError()!=GL_NO_ERROR || !sgfx_drm_status(c->fd,&draw_seq,&completed) ||
        draw_seq<=clear_seq || completed!=draw_seq)goto done;
    for(unsigned y=0;y<64;y++)for(unsigned x=0;x<64;x++) {
        if(x+y==63)continue; /* exact diagonal coverage is a raster edge rule */
        const uint8_t *p=&pixels[(y*64+x)*4];bool red=x+y<63;
        if(p[0]!=(red?0:255) || p[1] || p[2]!=(red?255:0) || p[3]!=255)goto done;
        triangle_pixels++;
    }
    pass=clear_pixels==4096 && triangle_pixels==4032;
done:
    /* Deletion only calls checked owner-bound free. Failed submits/waits keep
     * their BO backing under the kernel's independent quarantine contract. */
    if(st_api_get_current()==c->st) {
        if(vbo)glDeleteBuffers(1,&vbo);
        if(program)glDeleteProgram(program);
        if(vs)glDeleteShader(vs);if(fs)glDeleteShader(fs);
        if(fbo)glDeleteFramebuffers(1,&fbo);if(tex)glDeleteTextures(1,&tex);
        if(glGetError()!=GL_NO_ERROR)pass=false;
    }else pass=false;
    sgfx_gles_destroy(c);
    if(retained_fd>=0) {
        uint32_t final_submitted=0,final_completed=0;
        if(st_api_get_current() || !sgfx_drm_status(retained_fd,&final_submitted,&final_completed) ||
            final_submitted!=draw_seq || final_completed!=final_submitted)pass=false;
    }
    printf("GLES RESULT api=%u pass=%u clear_pixels=%u triangle_pixels=%u clear_seq=%u draw_seq=%u completed=%u\n",
        api,pass?1u:0u,clear_pixels,triangle_pixels,clear_seq,draw_seq,completed);
    return pass;
}
bool sgfx_gles_readback_proof(void)
{return readback_proof(2,-1);}
bool sgfx_gles_ui_readback_proof(int retained_fd,unsigned api)
{return retained_fd>=0 && readback_proof(api,retained_fd);}
