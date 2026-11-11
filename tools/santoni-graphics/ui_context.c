#include "ui_context.h"
#include <pthread.h>
#include <string.h>
struct imported_texture {uint32_t name,seed;void *surface;bool inverted,dirty;
    struct sgfx_ui_context *producer;};
struct sgfx_ui_group {
    bool used,live;
    uint32_t references,first_failure,first_slot;
    struct sgfx_ui_surface_ops surface;
    struct imported_texture texture[SGFX_UI_TEXTURES];
};
struct sgfx_ui_context {
    struct sgfx_ui_macro macro; /* Exact {rctx,dispatch[1036]} GLI prefix. */
    void *object;
    unsigned api;
    bool used,live,owned;
    pthread_t owner;
    struct sgfx_ui_backend backend;
    struct sgfx_ui_surface_ops surface;
    struct sgfx_ui_report report;
    struct sgfx_ui_group *group;
};
/* Never recycle macro addresses: late GLI calls cannot resolve to a new object.
 * A destroyed context consumes only this bounded CPU record, not live DMA. */
static struct sgfx_ui_context contexts[SGFX_UI_CONTEXTS];
static struct sgfx_ui_group groups[SGFX_UI_CONTEXTS];
static pthread_mutex_t registry=PTHREAD_MUTEX_INITIALIZER;
static _Thread_local struct sgfx_ui_context *current;
static bool flush(struct sgfx_ui_context *);
static bool known(struct sgfx_ui_context *c)
{
    for(unsigned i=0;i<SGFX_UI_CONTEXTS;i++)if(c==&contexts[i])return c->used;
    return false;
}
static bool owned(struct sgfx_ui_context *c)
{return known(c) && c->live && c->owned && current==c && pthread_equal(c->owner,pthread_self());}
static bool ready(struct sgfx_ui_context *c)
{return owned(c) && !c->report.first_failure && !c->group->first_failure;}
static bool failure(struct sgfx_ui_context *c,unsigned why,uint32_t slot)
{
    if(!c->report.first_failure) {c->report.first_failure=why;c->report.first_slot=slot;}
    if(!c->group->first_failure) {c->group->first_failure=why;c->group->first_slot=slot;}
    return false;
}
static bool group_known(struct sgfx_ui_group *g)
{for(unsigned i=0;i<SGFX_UI_CONTEXTS;i++)if(g==&groups[i])return g->used && g->live;return false;}
static bool surface_valid(const struct sgfx_ui_surface_ops *s)
{return s && s->retain && s->release && s->lock && s->unlock;}
static struct sgfx_ui_group *group_new(const struct sgfx_ui_surface_ops *surface)
{
    for(unsigned i=0;i<SGFX_UI_CONTEXTS;i++)if(!groups[i].used) {
        struct sgfx_ui_group *g=&groups[i];g->used=g->live=true;g->references=1;g->surface=*surface;return g;
    }
    return NULL;
}
static bool group_drop(struct sgfx_ui_group *g)
{
    if(!group_known(g) || !g->references || g->first_failure)return false;
    if(--g->references)return true;
    for(unsigned i=0;i<SGFX_UI_TEXTURES;i++)if(g->texture[i].surface)g->surface.release(g->texture[i].surface);
    g->live=false;return true;
}
struct sgfx_ui_group *sgfx_ui_group_create(const struct sgfx_ui_surface_ops *surface)
{
    if(!surface_valid(surface))return NULL;
    pthread_mutex_lock(&registry);struct sgfx_ui_group *g=group_new(surface);pthread_mutex_unlock(&registry);return g;
}
bool sgfx_ui_group_retain(struct sgfx_ui_group *g)
{
    pthread_mutex_lock(&registry);bool ok=group_known(g) && !g->first_failure && g->references<UINT32_MAX;
    if(ok)g->references++;pthread_mutex_unlock(&registry);return ok;
}
bool sgfx_ui_group_release(struct sgfx_ui_group *g)
{pthread_mutex_lock(&registry);bool ok=group_drop(g);pthread_mutex_unlock(&registry);return ok;}
static struct sgfx_ui_context *create_context(void *object,unsigned api,
    const struct sgfx_ui_backend *backend,const struct sgfx_ui_surface_ops *surface,
    struct sgfx_ui_group *group,void *const *dispatch)
{
    if(!object || (api!=2 && api!=3) || !backend || !backend->context || !backend->current ||
        !backend->destroy || !backend->select || !backend->restore || !backend->transfer.upload_rgba ||
        !backend->transfer.finish || !backend->transfer.read_rgba || !backend->transfer.fence_status ||
        (!group && !surface_valid(surface)) || !dispatch)return NULL;
    for(unsigned i=0;i<SGFX_UI_SLOTS;i++)if(!dispatch[i])return NULL;
    pthread_mutex_lock(&registry);struct sgfx_ui_context *c=NULL;
    if(group && (!group_known(group) || group->first_failure || group->references==UINT32_MAX))goto done;
    for(unsigned i=0;i<SGFX_UI_CONTEXTS;i++)if(contexts[i].live && contexts[i].object==object)goto done;
    for(unsigned i=0;i<SGFX_UI_CONTEXTS;i++)if(!contexts[i].used) {
        struct sgfx_ui_group *g=group?group:group_new(surface);if(!g)goto done;
        if(group)g->references++;
        c=&contexts[i];c->used=c->live=c->report.live=true;c->object=object;c->api=api;c->group=g;
        c->backend=*backend;c->surface=g->surface;c->macro.context=c;
        memcpy(c->macro.dispatch,dispatch,sizeof(c->macro.dispatch));break;
    }
done:
    pthread_mutex_unlock(&registry);return c;
}
struct sgfx_ui_context *sgfx_ui_context_create(void *object,unsigned api,
    const struct sgfx_ui_backend *backend,const struct sgfx_ui_surface_ops *surface,void *const *dispatch)
{return create_context(object,api,backend,surface,NULL,dispatch);}
struct sgfx_ui_context *sgfx_ui_context_create_in_group(void *object,unsigned api,
    const struct sgfx_ui_backend *backend,struct sgfx_ui_group *group,void *const *dispatch)
{if(!group)return NULL;return create_context(object,api,backend,NULL,group,dispatch);}
struct sgfx_ui_context *sgfx_ui_context_lookup(void *object)
{
    pthread_mutex_lock(&registry);struct sgfx_ui_context *c=NULL;
    if(object)for(unsigned i=0;i<SGFX_UI_CONTEXTS;i++)if(contexts[i].live && contexts[i].object==object) {c=&contexts[i];break;}
    pthread_mutex_unlock(&registry);return c;
}
struct sgfx_ui_macro *sgfx_ui_context_macro(struct sgfx_ui_context *c)
{pthread_mutex_lock(&registry);struct sgfx_ui_macro *m=known(c) && c->live?&c->macro:NULL;pthread_mutex_unlock(&registry);return m;}
unsigned sgfx_ui_context_api(struct sgfx_ui_context *c)
{pthread_mutex_lock(&registry);unsigned api=known(c) && c->live?c->api:0;pthread_mutex_unlock(&registry);return api;}
bool sgfx_ui_context_bind(struct sgfx_ui_context *c)
{
    pthread_mutex_lock(&registry);bool ok=false;
    if(c && (!known(c) || !c->live || c->report.first_failure || c->group->first_failure ||
        (c->owned && !pthread_equal(c->owner,pthread_self()))))goto done;
    if(current==c) {ok=true;goto done;}
    struct sgfx_ui_context *old=current;
    if(old && !old->report.first_failure && !old->group->first_failure && !flush(old))goto done;
    if(c) {
        if(!c->backend.current(c->backend.context,true)) {
            failure(c,SGFX_UI_BIND,0);
            if(old && !old->backend.current(old->backend.context,true))failure(old,SGFX_UI_BIND,0);
            goto done;
        }
    } else if(old && !old->backend.current(old->backend.context,false)) {failure(old,SGFX_UI_BIND,0);goto done;}
    if(old)old->owned=false;
    current=c;
    if(c) {c->owned=true;c->owner=pthread_self();}
    ok=true;
done:
    pthread_mutex_unlock(&registry);return ok;
}
void *sgfx_ui_context_current(void)
{pthread_mutex_lock(&registry);void *object=current && current->live?current->object:NULL;pthread_mutex_unlock(&registry);return object;}
void *sgfx_ui_context_backend(struct sgfx_ui_context *c)
{pthread_mutex_lock(&registry);void *backend=ready(c)?c->backend.context:NULL;pthread_mutex_unlock(&registry);return backend;}
bool sgfx_ui_context_report(struct sgfx_ui_context *c,struct sgfx_ui_report *report)
{pthread_mutex_lock(&registry);bool ok=known(c) && report;if(ok) {*report=c->report;
    report->group_failure=c->group->first_failure;report->group_slot=c->group->first_slot;}
 pthread_mutex_unlock(&registry);return ok;}
bool sgfx_ui_context_fail(struct sgfx_ui_context *c,unsigned why,uint32_t slot)
{pthread_mutex_lock(&registry);if(owned(c) && why)failure(c,why,slot);pthread_mutex_unlock(&registry);return false;}
static struct imported_texture *find(struct sgfx_ui_context *c,uint32_t name)
{for(unsigned i=0;i<SGFX_UI_TEXTURES;i++)if(c->group->texture[i].name==name)return &c->group->texture[i];return NULL;}
static bool transfer(struct sgfx_ui_context *c,struct imported_texture *t,bool output,bool force)
{
    /* A peer's unsubmitted work must be synchronized by its own context.
     * Never claim fresh pixels by finishing the wrong thread's GL queue. */
    if(output && t->dirty && t->producer!=c)return failure(c,SGFX_UI_BIND,0);
    struct sgfx_ui_surface surface={0};uint32_t seed=0,saved=0,sequence=0;size_t packed=0;
    if(!c->surface.lock(t->surface,output,&surface,&seed))return failure(c,SGFX_UI_SURFACE,0);
    surface.flip_y=t->inverted;
    bool selected=false,ok=sgfx_ui_surface_valid(&surface,&packed);
    if(ok && (output || force || seed!=t->seed)) {
        selected=c->backend.select(c->backend.context,t->name,output,&saved);ok=selected;
        if(ok)ok=output?sgfx_ui_commit(&c->backend.transfer,&surface,&sequence):
            (c->backend.transfer.finish(c->backend.transfer.context) && sgfx_ui_upload(&c->backend.transfer,&surface));
        if(!ok)failure(c,SGFX_UI_TRANSFER,0);
        if(selected) {bool restored=c->backend.restore(c->backend.context,saved,output);
            if(!restored)c->report.restore_failed=true;
            ok=ok && restored;}
    }
    /* Always unlock a successfully acquired CPU surface, including malformed
     * metadata and select/finish/readback failures. Preserve first failure. */
    bool unlocked=c->surface.unlock(t->surface,output,&seed);
    if(!unlocked)c->report.unlock_failed=true;
    if(!ok || !unlocked)return failure(c,SGFX_UI_TRANSFER,0);
    t->seed=seed;
    if(output) {t->dirty=false;t->producer=NULL;c->report.frames++;c->report.sequence=sequence;}
    return true;
}
bool sgfx_ui_context_attach(struct sgfx_ui_context *c,uint32_t name,void *surface,bool inverted)
{
    pthread_mutex_lock(&registry);bool ok=false;
    if(!ready(c) || !name || !surface)goto done;
    struct imported_texture *t=find(c,name);
    if(t && t->dirty && !transfer(c,t,true,false))goto done;
    if(!t)for(unsigned i=0;i<SGFX_UI_TEXTURES;i++)if(!c->group->texture[i].name) {t=&c->group->texture[i];break;}
    if(!t) {failure(c,SGFX_UI_CAPACITY,0);goto done;}
    struct imported_texture replacement={.name=name,.surface=surface,.inverted=inverted};
    c->surface.retain(surface);
    if(!transfer(c,&replacement,false,true)) {c->surface.release(surface);goto done;}
    if(t->surface)c->surface.release(t->surface);
    *t=replacement;ok=true;
done:
    pthread_mutex_unlock(&registry);return ok;
}
bool sgfx_ui_context_refresh(struct sgfx_ui_context *c,uint32_t name)
{
    pthread_mutex_lock(&registry);bool ok=false;
    if(ready(c)) {struct imported_texture *t=find(c,name);ok=!t ||
        ((!t->dirty || transfer(c,t,true,false)) && transfer(c,t,false,false));}
    pthread_mutex_unlock(&registry);return ok;
}
bool sgfx_ui_context_dirty(struct sgfx_ui_context *c,uint32_t name)
{
    pthread_mutex_lock(&registry);bool ok=ready(c);
    if(ok) {struct imported_texture *t=find(c,name);if(t) {
        if(t->dirty && t->producer!=c)ok=failure(c,SGFX_UI_BIND,0);
        else {t->dirty=true;t->producer=c;}
    }}
    pthread_mutex_unlock(&registry);return ok;
}
static bool flush(struct sgfx_ui_context *c)
{
    bool dirty=false;
    for(unsigned i=0;i<SGFX_UI_TEXTURES;i++)if(c->group->texture[i].dirty) {
        dirty=true;if(!transfer(c,&c->group->texture[i],true,false))return false;
    }
    if(!dirty && !c->backend.transfer.finish(c->backend.transfer.context))return failure(c,SGFX_UI_TRANSFER,0);
    return true;
}
bool sgfx_ui_context_flush(struct sgfx_ui_context *c)
{pthread_mutex_lock(&registry);bool ok=ready(c) && flush(c);pthread_mutex_unlock(&registry);return ok;}
bool sgfx_ui_context_forget(struct sgfx_ui_context *c,uint32_t name)
{
    pthread_mutex_lock(&registry);bool ok=ready(c);
    if(ok) {struct imported_texture *t=find(c,name);if(t) {
        ok=!t->dirty || transfer(c,t,true,false);
        if(ok) {c->surface.release(t->surface);memset(t,0,sizeof(*t));}
    }}
    pthread_mutex_unlock(&registry);return ok;
}
bool sgfx_ui_context_destroy(struct sgfx_ui_context *c)
{
    pthread_mutex_lock(&registry);bool ok=false;
    if(!known(c) || !c->live || (c->owned && !pthread_equal(c->owner,pthread_self())))goto done;
    /* Failed make-current/transfer outcomes retain all backend and surface
     * state for process teardown. They are never retried by deallocation. */
    if(c->report.first_failure || c->group->first_failure)goto done;
    if(c->owned) {
        if(!flush(c) || !c->backend.current(c->backend.context,false)) {failure(c,SGFX_UI_BIND,0);goto done;}
        current=NULL;c->owned=false;
    } else {
        for(unsigned i=0;i<SGFX_UI_TEXTURES;i++)if(c->group->texture[i].dirty)goto done;
    }
    if(!group_drop(c->group))goto done;
    c->backend.destroy(c->backend.context);c->live=c->report.live=false;c->object=NULL;ok=true;
done:
    pthread_mutex_unlock(&registry);return ok;
}
