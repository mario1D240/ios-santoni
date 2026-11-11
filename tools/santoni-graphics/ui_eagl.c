/* Explicitly opt-in EAGL/GLI bridge for the retained20H392 method ABI.
 * It is inert until a caller asks to install it, and creates no context until
 * the real Santoni transport advertises audited raster capability. */
#include "ui_backend.h"
#include "ui_dispatch.h"
#include "ui_eagl.h"
#include "santoni_drm.h"
#include "gles.h"
#include <CoreFoundation/CoreFoundation.h>
#include <IOSurface/IOSurfaceRef.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>

static IMP original_init,original_dealloc,original_api,original_macro,original_macro_upper;
static IMP original_set_parameter,original_get_parameter,original_tex,original_attach;
static IMP original_set_current,original_current;
static IMP original_sharegroup,original_group_api,original_group_dealloc,original_group_shared;
static pthread_mutex_t install_lock=PTHREAD_MUTEX_INITIALIZER;
static _Atomic bool installed;
/* The transport closes permanently on its final token. Keep one for the
 * admitted process, so destroying/recreating EAGL contexts does not terminate
 * the GPU lease. Process exit owns cleanup; no failed path is retried here. */
static int renderer_lease=-1;
static bool lease_attempted,renderer_proven;
static _Thread_local id held_current;
static _Thread_local bool held_current_retained;
static void retain_surface(void *surface) {CFRetain(surface);}
static void release_surface(void *surface) {CFRelease(surface);}
static bool lock_surface(void *opaque,bool write,struct sgfx_ui_surface *out,uint32_t *seed)
{
    IOSurfaceRef surface=opaque;uint32_t options=write?0:kIOSurfaceLockReadOnly;
    if(IOSurfaceLock(surface,options,seed)!=0)return false;
    size_t width=IOSurfaceGetWidth(surface),height=IOSurfaceGetHeight(surface),stride=IOSurfaceGetBytesPerRow(surface);
    /* CoreAnimation's existing framebuffer admission uses exactly these BGRA
     * bytes. Other formats/planes must not be interpreted as this layout. */
    if(width>UINT32_MAX || height>UINT32_MAX || stride>UINT32_MAX ||
        IOSurfaceGetPlaneCount(surface)>1 || IOSurfaceGetBytesPerElement(surface)!=4) {
        *out=(struct sgfx_ui_surface){0};return true; /* Core always unlocks. */
    }
    *out=(struct sgfx_ui_surface){IOSurfaceGetBaseAddress(surface),IOSurfaceGetAllocSize(surface),0,
        (uint32_t)width,(uint32_t)height,(uint32_t)stride,IOSurfaceGetPixelFormat(surface),false};
    return true;
}
static bool unlock_surface(void *surface,bool write,uint32_t *seed)
{return IOSurfaceUnlock(surface,write?0:kIOSurfaceLockReadOnly,seed)==0;}
static const struct sgfx_ui_surface_ops surface_ops={retain_surface,release_surface,lock_surface,unlock_surface};
struct owned_group {id object;unsigned api;bool used,live;
    struct sgfx_ui_mesa_group *mesa;struct sgfx_ui_group *surfaces;};
struct owned_context {id object;struct owned_group *group;int32_t client_label;bool used,live,client_managed;};
static struct owned_group eagl_groups[SGFX_UI_CONTEXTS];
static struct owned_context eagl_contexts[SGFX_UI_CONTEXTS];
static pthread_mutex_t eagl_registry=PTHREAD_MUTEX_INITIALIZER;
static id retain_object(id);
static void release_object(id);
static struct owned_group *group_for(id object)
{for(unsigned i=0;i<SGFX_UI_CONTEXTS;i++)if(eagl_groups[i].live && eagl_groups[i].object==object)return &eagl_groups[i];return NULL;}
static struct owned_context *context_for(id object)
{for(unsigned i=0;i<SGFX_UI_CONTEXTS;i++)if(eagl_contexts[i].live && eagl_contexts[i].object==object)return &eagl_contexts[i];return NULL;}
static bool dictionary(id object)
{
    Class cls=objc_getClass("NSDictionary");
    return object && cls && ((bool (*)(id,SEL,Class))objc_msgSend)(object,sel_registerName("isKindOfClass:"),cls);
}
static bool integer_property(const void *value,int64_t *out)
{
    if(!value)return false;
    CFTypeID type=CFGetTypeID(value);
    if(type==CFBooleanGetTypeID()) {*out=CFBooleanGetValue(value)?1:0;return true;}
    return type==CFNumberGetTypeID() && !CFNumberIsFloatType(value) &&
        CFNumberGetValue(value,kCFNumberSInt64Type,out);
}
static bool properties_valid(id properties,int32_t *label,id *share,bool *client_managed)
{
    *label=1;*share=nil;*client_managed=false;if(!properties)return true;
    if(!dictionary(properties))return false;
    CFDictionaryRef p=(CFDictionaryRef)properties;CFIndex count=CFDictionaryGetCount(p);
    if(count<0 || count>5)return false;
    const void *keys[5],*values[5];CFDictionaryGetKeysAndValues(p,keys,values);
    for(CFIndex i=0;i<count;i++) {
        if(CFGetTypeID(keys[i])!=CFStringGetTypeID())return false;
        if(CFEqual(keys[i],CFSTR("EAGLContextPropertySharegroup"))) {*share=(id)values[i];continue;}
        int64_t value=0;if(!integer_property(values[i],&value))return false;
        if(CFEqual(keys[i],CFSTR("EAGLContextPropertyClientLabel"))) {
            if(value<0 || value>8)return false;*label=value?(int32_t)value:1;
        }else if(CFEqual(keys[i],CFSTR("EAGLContextPropertySharedWithCompute"))) {
            if(value!=0)return false;
        }else if(CFEqual(keys[i],CFSTR("EAGLContextPropertyClientRetainRelease"))) {
            /* Retained20H392 commonInit sets private flags bit0, and native
             * setCurrentContext skips both retain(new) and release(old) for
             * that bit. The caller must keep its context alive while current. */
            if(value!=0 && value!=1)return false;*client_managed=value==1;
        }else if(CFEqual(keys[i],CFSTR("EAGLContextPropertyAccelerated"))) {
            /* Installation already requires audited raster capability. A
             * request for software rendering belongs to the native path. */
            if(value!=1)return false;
        }else return false;
    }
    return true;
}
static struct owned_group *new_group(unsigned api)
{
    struct owned_group *g=NULL;
    for(unsigned i=0;i<SGFX_UI_CONTEXTS;i++)if(!eagl_groups[i].used) {g=&eagl_groups[i];break;}
    if(!g)return NULL;
    struct sgfx_ui_mesa_group *mesa=sgfx_ui_mesa_group_create(api);if(!mesa)return NULL;
    struct sgfx_ui_group *surfaces=sgfx_ui_group_create(&surface_ops);
    if(!surfaces) {sgfx_ui_mesa_group_release(mesa);return NULL;}
    id object=class_createInstance(objc_getClass("EAGLSharegroup"),0);
    if(!object) {sgfx_ui_group_release(surfaces);sgfx_ui_mesa_group_release(mesa);return NULL;}
    *g=(struct owned_group){object,api,true,true,mesa,surfaces};return g;
}
static unsigned long group_api(id self,SEL command)
{
    pthread_mutex_lock(&eagl_registry);struct owned_group *g=group_for(self);
    unsigned api=g?g->api:0;pthread_mutex_unlock(&eagl_registry);
    return g?api:((unsigned long (*)(id,SEL))original_group_api)(self,command);
}
static void *group_shared(id self,SEL command)
{
    pthread_mutex_lock(&eagl_registry);bool own=group_for(self)!=NULL;pthread_mutex_unlock(&eagl_registry);
    if(!own)return ((void *(*)(id,SEL))original_group_shared)(self,command);
    fprintf(stderr,"EAGL: private GLIShared requested for Mesa group; unsupported\n");return NULL;
}
static void group_deallocate(id self,SEL command)
{
    pthread_mutex_lock(&eagl_registry);struct owned_group *g=group_for(self);
    if(!g) {pthread_mutex_unlock(&eagl_registry);((void (*)(id,SEL))original_group_dealloc)(self,command);return;}
    if(!sgfx_ui_group_release(g->surfaces)) {pthread_mutex_unlock(&eagl_registry);return;}
    sgfx_ui_mesa_group_release(g->mesa);g->live=false;g->object=nil;
    pthread_mutex_unlock(&eagl_registry);
    /* The native private record was never initialized, but native dealloc
     * has a verified NULL-record path and releases the ordinary debug label. */
    ((void (*)(id,SEL))original_group_dealloc)(self,command);
}
static id sharegroup(id self,SEL command)
{
    pthread_mutex_lock(&eagl_registry);struct owned_context *c=context_for(self);
    id group=c?c->group->object:nil;pthread_mutex_unlock(&eagl_registry);
    return c?group:((id (*)(id,SEL))original_sharegroup)(self,command);
}
static id initialize(id self,SEL command,unsigned long api,id properties)
{
    pthread_mutex_lock(&eagl_registry);bool existing=context_for(self)!=NULL;pthread_mutex_unlock(&eagl_registry);
    if(existing)return nil;
    struct sgfx_ui_backend backend={0};
    int32_t label=1;id requested=nil;bool client_managed=false;bool valid=properties_valid(properties,&label,&requested,&client_managed);
    bool own_request=false;
    if(dictionary(properties)) {
        id candidate=(id)CFDictionaryGetValue((CFDictionaryRef)properties,CFSTR("EAGLContextPropertySharegroup"));
        pthread_mutex_lock(&eagl_registry);own_request=group_for(candidate)!=NULL;pthread_mutex_unlock(&eagl_registry);
    }
    if(atomic_load_explicit(&installed,memory_order_acquire) && object_getClass(self)==objc_getClass("EAGLContext") &&
        valid && (api==2 || api==3)) {
        pthread_mutex_lock(&eagl_registry);struct owned_context *entry=NULL;
        for(unsigned i=0;i<SGFX_UI_CONTEXTS;i++)if(!eagl_contexts[i].used) {entry=&eagl_contexts[i];break;}
        struct owned_group *g=requested?group_for(requested):NULL;
        bool new=false;
        if(entry && !requested) {g=new_group((unsigned)api);new=g!=NULL;}
        if(entry && g && g->api==api && sgfx_ui_mesa_create_in_group((unsigned)api,g->mesa,&backend)) {
            struct sgfx_ui_context *c=sgfx_ui_context_create_in_group(self,(unsigned)api,&backend,g->surfaces,sgfx_ui_dispatch);
            if(c) {
                if(!new)retain_object(g->object);
                *entry=(struct owned_context){self,g,label,true,true,client_managed};pthread_mutex_unlock(&eagl_registry);return self;
            }
            backend.destroy(backend.context);
        }
        id failed_group=new?g->object:nil;pthread_mutex_unlock(&eagl_registry);
        release_object(failed_group);
    }
    /* Native contexts cannot safely consume our synthetic private group. */
    if(own_request)return nil;
    return ((id (*)(id,SEL,unsigned long,id))original_init)(self,command,api,properties);
}
static void deallocate(id self,SEL command)
{
    struct sgfx_ui_context *c=sgfx_ui_context_lookup(self);
    if(!c) {((void (*)(id,SEL))original_dealloc)(self,command);return;}
    /* Failed contexts retain the object too: a recycled NSObject address must
     * never be mistaken for a quarantined macro context. This is bounded. */
    if(!sgfx_ui_context_destroy(c))return;
    if(held_current==self) {held_current=nil;held_current_retained=false;}
    pthread_mutex_lock(&eagl_registry);struct owned_context *entry=context_for(self);
    id group=entry?entry->group->object:nil;
    if(entry) {entry->live=false;entry->object=nil;}
    pthread_mutex_unlock(&eagl_registry);release_object(group);
    struct objc_super parent={self,class_getSuperclass(object_getClass(self))};
    ((void (*)(struct objc_super *,SEL))objc_msgSendSuper)(&parent,command);
}
static unsigned long api(id self,SEL command)
{
    struct sgfx_ui_context *c=sgfx_ui_context_lookup(self);
    return c?sgfx_ui_context_api(c):((unsigned long (*)(id,SEL))original_api)(self,command);
}
static void *macro(id self,SEL command)
{
    struct sgfx_ui_context *c=sgfx_ui_context_lookup(self);
    if(c)return sgfx_ui_context_macro(c);
    IMP original=command==sel_registerName("GetMacroContextPrivate")?original_macro_upper:original_macro;
    return ((void *(*)(id,SEL))original)(self,command);
}
static unsigned long set_parameter(id self,SEL command,uint32_t name,const int32_t *value)
{
    struct sgfx_ui_context *c=sgfx_ui_context_lookup(self);
    if(!c)return ((unsigned long (*)(id,SEL,uint32_t,const int32_t *))original_set_parameter)(self,command,name,value);
    /* Rejected context settings never enter Mesa or the GPU. A rejected
     * request returns its API error and leaves an existing renderer usable. */
    return value?0x2710:0x271e;
}
static unsigned long get_parameter(id self,SEL command,uint32_t name,int32_t *value)
{
    struct sgfx_ui_context *c=sgfx_ui_context_lookup(self);
    if(!c)return ((unsigned long (*)(id,SEL,uint32_t,int32_t *))original_get_parameter)(self,command,name,value);
    /* Retained20H392 _gliGetInteger: numeric query0xe0 returns32-bit0x2060
     * before examining/binding any GL context. Its semantic name is unknown;
     * do not interpret it as a renderer/pixels/acceleration capability. EAGL
     * getParameter:to: forwards the zero-extended32-bit status unchanged. */
    if(name==0xe0) {if(!value)return 0x271e;*value=0x2060;return 0;}
    if(!value)return 0x271e;
    *value=0;return 0x2710;
}
static bool attach_surface(struct sgfx_ui_context *c,IOSurfaceRef surface,unsigned long target,bool inverted)
{
    if(!sgfx_ui_bind(c) || !surface || (target!=GL_TEXTURE_2D && target!=GL_TEXTURE_RECTANGLE))return false;
    GLint texture=0;sgfx_ui_target(c,(GLenum)target);glGetIntegerv(GL_TEXTURE_BINDING_2D,&texture);
    return texture>0 && glGetError()==GL_NO_ERROR && sgfx_ui_context_attach(c,(uint32_t)texture,surface,inverted);
}
static bool texture_surface(id self,SEL command,IOSurfaceRef surface,unsigned long target,unsigned long internal,
    uint32_t width,uint32_t height,unsigned long format,unsigned long type,uint32_t plane,bool inverted)
{
    struct sgfx_ui_context *c=sgfx_ui_context_lookup(self);
    if(!c)return ((bool (*)(id,SEL,IOSurfaceRef,unsigned long,unsigned long,uint32_t,uint32_t,
        unsigned long,unsigned long,uint32_t,bool))original_tex)(self,command,surface,target,internal,width,height,format,type,plane,inverted);
    if(!surface || plane || width!=IOSurfaceGetWidth(surface) || height!=IOSurfaceGetHeight(surface) ||
        (internal!=GL_RGBA && internal!=GL_RGBA8 && internal!=GL_BGRA) ||
        (format!=GL_RGBA && format!=GL_BGRA) || type!=GL_UNSIGNED_BYTE)return false;
    return attach_surface(c,surface,target,inverted);
}
static bool attach(id self,SEL command,unsigned long target,IOSurfaceRef surface,bool inverted)
{
    struct sgfx_ui_context *c=sgfx_ui_context_lookup(self);
    if(!c)return ((bool (*)(id,SEL,unsigned long,IOSurfaceRef,bool))original_attach)(self,command,target,surface,inverted);
    return attach_surface(c,surface,target,inverted);
}
static id retain_object(id object)
{return object?((id (*)(id,SEL))objc_msgSend)(object,sel_registerName("retain")):nil;}
static void release_object(id object)
{if(object)((void (*)(id,SEL))objc_msgSend)(object,sel_registerName("release"));}
static bool set_current(id cls,SEL command,id object)
{
    struct sgfx_ui_context *c=sgfx_ui_context_lookup(object);id old=held_current;
    bool old_retained=held_current_retained;
    if(c) {
        pthread_mutex_lock(&eagl_registry);struct owned_context *entry=context_for(object);
        bool manage=entry && !entry->client_managed;pthread_mutex_unlock(&eagl_registry);
        if(!entry)return false;
        if(old==object)return sgfx_ui_context_bind(c);
        if(manage)retain_object(object);
        if(!sgfx_ui_context_bind(c)) {if(manage)release_object(object);return false;}
        held_current=object;held_current_retained=manage;
        if(old_retained)release_object(old);return true;
    }
    if(!sgfx_ui_context_bind(NULL))return false;
    bool ok=((bool (*)(id,SEL,id))original_set_current)(cls,command,object);
    if(!ok && old) {
        struct sgfx_ui_context *previous=sgfx_ui_context_lookup(old);
        if(previous && sgfx_ui_context_bind(previous))return false;
    }
    held_current=nil;held_current_retained=false;
    if(old_retained)release_object(old);return ok;
}
static id get_current(id cls,SEL command)
{return held_current?held_current:((id (*)(id,SEL))original_current)(cls,command);}
struct hook {bool class_method;const char *selector,*encoding;IMP replacement;IMP *original;};
/* Exact encodings read from the retained20H392 Objective-C method lists;
 * runtime mismatches refuse the entire installation before the first swap. */
static const struct hook hooks[]={
    {false,"initWithAPI:properties:","@32@0:8Q16@24",(IMP)initialize,&original_init},
    {false,"dealloc","v16@0:8",(IMP)deallocate,&original_dealloc},
    {false,"API","Q16@0:8",(IMP)api,&original_api},
    {false,"getMacroContextPrivate","^{EAGLMacroContext=}16@0:8",(IMP)macro,&original_macro},
    {false,"GetMacroContextPrivate","^{EAGLMacroContext=}16@0:8",(IMP)macro,&original_macro_upper},
    {false,"setParameter:to:","Q28@0:8I16^i20",(IMP)set_parameter,&original_set_parameter},
    {false,"getParameter:to:","Q28@0:8I16^i20",(IMP)get_parameter,&original_get_parameter},
    {false,"texImageIOSurface:target:internalFormat:width:height:format:type:plane:invert:",
        "B72@0:8^{__IOSurface=}16Q24Q32I40I44Q48Q56I64B68",(IMP)texture_surface,&original_tex},
    {false,"attachImage:toCoreSurface:invertedRender:","B36@0:8Q16^{__IOSurface=}24B32",(IMP)attach,&original_attach},
    {true,"setCurrentContext:","B24@0:8@16",(IMP)set_current,&original_set_current},
    {true,"currentContext","@16@0:8",(IMP)get_current,&original_current},
    {false,"sharegroup","@16@0:8",(IMP)sharegroup,&original_sharegroup},
};
static const struct hook group_hooks[]={
    {false,"APIs","Q16@0:8",(IMP)group_api,&original_group_api},
    {false,"dealloc","v16@0:8",(IMP)group_deallocate,&original_group_dealloc},
    {false,"getGLIShared","^{__GLISharedRec=}16@0:8",(IMP)group_shared,&original_group_shared},
};
bool sgfx_eagl_install(void)
{
    pthread_mutex_lock(&install_lock);bool ok=atomic_load_explicit(&installed,memory_order_acquire);
    if(ok)goto done;
    Class cls=objc_getClass("EAGLContext"),group_cls=objc_getClass("EAGLSharegroup");if(!cls || !group_cls)goto done;
    enum {CONTEXT_HOOKS=sizeof(hooks)/sizeof(hooks[0]),GROUP_HOOKS=sizeof(group_hooks)/sizeof(group_hooks[0]),TOTAL_HOOKS=CONTEXT_HOOKS+GROUP_HOOKS};
    Method methods[TOTAL_HOOKS];IMP validated[TOTAL_HOOKS],native_current_method=NULL;
    for(unsigned i=0;i<TOTAL_HOOKS;i++) {
        const struct hook *h=i<CONTEXT_HOOKS?&hooks[i]:&group_hooks[i-CONTEXT_HOOKS];Class owner=i<CONTEXT_HOOKS?cls:group_cls;
        methods[i]=h->class_method?class_getClassMethod(owner,sel_registerName(h->selector)):
            class_getInstanceMethod(owner,sel_registerName(h->selector));
        const char *encoding=methods[i]?method_getTypeEncoding(methods[i]):NULL;
        if(!encoding || strcmp(encoding,h->encoding) || !method_getImplementation(methods[i]))goto done;
        validated[i]=method_getImplementation(methods[i]);
        if(h->original==&original_current)native_current_method=validated[i];
    }
    /* The explicit loader must run before a native EAGL context is current.
     * Never replace a live native context to make renderer admission succeed. */
    if(!native_current_method || ((id (*)(id,SEL))native_current_method)((id)cls,sel_registerName("currentContext")))goto done;
    if(!lease_attempted) {
        lease_attempted=true;
        if(!sgfx_ios_renderer_wait())goto done;
        renderer_lease=sgfx_drm_open_renderer();
        if(renderer_lease<0 || !sgfx_gles_ui_readback_proof(renderer_lease,2) ||
            !sgfx_gles_ui_readback_proof(renderer_lease,3))goto done;
        uint32_t submitted=0,completed=0;
        if(!sgfx_drm_status(renderer_lease,&submitted,&completed) || submitted<4 || submitted!=completed)goto done;
        renderer_proven=true;
    }
    if(renderer_lease<0 || !renderer_proven)goto done;
    if(((id (*)(id,SEL))native_current_method)((id)cls,sel_registerName("currentContext")))goto done;
    /* Proof can compile/draw before installation. Refuse runtime method/ABI
     * changes that occurred during that interval before the first replacement. */
    for(unsigned i=0;i<TOTAL_HOOKS;i++) {
        const struct hook *h=i<CONTEXT_HOOKS?&hooks[i]:&group_hooks[i-CONTEXT_HOOKS];Class owner=i<CONTEXT_HOOKS?cls:group_cls;
        Method current=h->class_method?class_getClassMethod(owner,sel_registerName(h->selector)):
            class_getInstanceMethod(owner,sel_registerName(h->selector));
        const char *encoding=current?method_getTypeEncoding(current):NULL;
        if(current!=methods[i] || !encoding || strcmp(encoding,h->encoding) ||
            method_getImplementation(current)!=validated[i])goto done;
    }
    /* The embedding loader explicitly invokes this entry. No constructor,
     * environment-triggered injection or executable/rootfs mutation occurs. */
    const struct hook *all[TOTAL_HOOKS];for(unsigned i=0;i<TOTAL_HOOKS;i++)all[i]=i<CONTEXT_HOOKS?&hooks[i]:&group_hooks[i-CONTEXT_HOOKS];
    for(unsigned i=0;i<TOTAL_HOOKS;i++)*all[i]->original=validated[i];
    for(unsigned i=0;i<TOTAL_HOOKS;i++) {
        IMP displaced=method_setImplementation(methods[i],all[i]->replacement);
        if(displaced!=*all[i]->original) {
            method_setImplementation(methods[i],displaced);
            for(unsigned j=0;j<i;j++)if(method_getImplementation(methods[j])==all[j]->replacement)
                method_setImplementation(methods[j],*all[j]->original);
            goto done;
        }
    }
    atomic_store_explicit(&installed,true,memory_order_release);ok=true;
done:
    if(!ok && renderer_lease>=0) {
        sgfx_drm_close(renderer_lease);renderer_lease=-1;renderer_proven=false;
    }
    pthread_mutex_unlock(&install_lock);return ok;
}
