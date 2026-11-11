/* Mesa-owned textures are the only GPU storage. IOSurface bytes are copied
 * through ui_surface after a synchronous transport fence. */
#include "ui_backend.h"
#include <GLES3/gl3.h>
#include <stdlib.h>
static bool current(void *opaque,bool bind)
{struct sgfx_ui_mesa *m=opaque;return sgfx_gles_current(bind?m->gl.gles:NULL);}
static void destroy(void *opaque)
{
    struct sgfx_ui_mesa *m=opaque;
    /* Mesa context destruction owns the private FBO. Do not make an inactive
     * context current here: another EAGL context may own this thread. */
    sgfx_gles_destroy(m->gl.gles);
    if(m->group)sgfx_ui_mesa_group_release(m->group);
    free(m);
}
static bool backend_select(void *opaque,uint32_t texture,bool read,uint32_t *saved)
{
    struct sgfx_ui_mesa *m=opaque;GLint value=0;
    if(read) {
        glGetIntegerv(sgfx_gles_api(m->gl.gles)>=3?GL_READ_FRAMEBUFFER_BINDING:GL_FRAMEBUFFER_BINDING,&value);
        if(!m->read_fbo)glGenFramebuffers(1,&m->read_fbo);
        if(!m->read_fbo || glGetError()!=GL_NO_ERROR)return false;
        *saved=(uint32_t)value;
        GLenum target=sgfx_gles_api(m->gl.gles)>=3?GL_READ_FRAMEBUFFER:GL_FRAMEBUFFER;
        glBindFramebuffer(target,m->read_fbo);
        glFramebufferTexture2D(target,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,texture,0);
    } else {
        glGetIntegerv(GL_TEXTURE_BINDING_2D,&value);
        if(glGetError()!=GL_NO_ERROR)return false;
        *saved=(uint32_t)value;glBindTexture(GL_TEXTURE_2D,texture);
    }
    /* A successful select means state must be restored even if GL just failed.
     * The transfer consumes that error and refuses any destination mutation. */
    return true;
}
static bool restore(void *opaque,uint32_t saved,bool read)
{
    struct sgfx_ui_mesa *m=opaque;
    if(read)glBindFramebuffer(sgfx_gles_api(m->gl.gles)>=3?GL_READ_FRAMEBUFFER:GL_FRAMEBUFFER,saved);
    else glBindTexture(GL_TEXTURE_2D,saved);
    return glGetError()==GL_NO_ERROR;
}
bool sgfx_ui_mesa_create(unsigned api,struct sgfx_ui_backend *out)
{
    if(!out)return false;
    struct sgfx_ui_mesa *m=calloc(1,sizeof(*m));if(!m)return false;
    m->gl.gles=sgfx_gles_create_api(api);
    if(!m->gl.gles) {free(m);return false;}
    struct sgfx_ui_transfer_ops transfer={0};
    if(!sgfx_ui_gl_ops(&m->gl,&transfer)) {sgfx_gles_destroy(m->gl.gles);free(m);return false;}
    *out=(struct sgfx_ui_backend){m,current,destroy,backend_select,restore,transfer};return true;
}
struct sgfx_ui_mesa_group *sgfx_ui_mesa_group_create(unsigned api)
{
    if(api!=2 && api!=3)return NULL;
    struct sgfx_ui_mesa_group *g=calloc(1,sizeof(*g));if(!g)return NULL;
    if(pthread_mutex_init(&g->lock,NULL)) {free(g);return NULL;}
    g->anchor=sgfx_gles_create_api(api);
    if(!g->anchor) {pthread_mutex_destroy(&g->lock);free(g);return NULL;}
    g->references=1;return g;
}
bool sgfx_ui_mesa_group_retain(struct sgfx_ui_mesa_group *g)
{
    if(!g)return false;
    pthread_mutex_lock(&g->lock);bool ok=g->references && g->references<UINT32_MAX;
    if(ok)g->references++;
    pthread_mutex_unlock(&g->lock);return ok;
}
bool sgfx_ui_mesa_group_release(struct sgfx_ui_mesa_group *g)
{
    if(!g)return false;
    pthread_mutex_lock(&g->lock);bool ok=g->references!=0,last=ok && --g->references==0;
    pthread_mutex_unlock(&g->lock);
    if(last) {sgfx_gles_destroy(g->anchor);pthread_mutex_destroy(&g->lock);free(g);}
    return ok;
}
bool sgfx_ui_mesa_create_in_group(unsigned api,struct sgfx_ui_mesa_group *g,struct sgfx_ui_backend *out)
{
    if(!out || !g || (api!=2 && api!=3) || !sgfx_ui_mesa_group_retain(g))return false;
    struct sgfx_ui_mesa *m=calloc(1,sizeof(*m));
    if(!m) {sgfx_ui_mesa_group_release(g);return false;}
    m->group=g;m->gl.gles=sgfx_gles_create_shared_api(api,g->anchor);
    if(!m->gl.gles) {sgfx_ui_mesa_group_release(g);free(m);return false;}
    struct sgfx_ui_transfer_ops transfer={0};
    if(!sgfx_ui_gl_ops(&m->gl,&transfer)) {destroy(m);return false;}
    *out=(struct sgfx_ui_backend){m,current,destroy,backend_select,restore,transfer};return true;
}
