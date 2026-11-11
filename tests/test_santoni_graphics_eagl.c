/* Execute the actual EAGL hook functions with modeled ObjC/IOSurface/Mesa.
 * Runtime installation is not enabled on a phone by this harness. */
#include "ui_dispatch.h"
#include "ui_backend.h"
#include "ui_eagl.h"
#include "santoni_drm.h"
#define SGFX_MESSAGE_IMPLEMENTATION 1
#include <objc/message.h>
#include <IOSurface/IOSurfaceRef.h>
#include <CoreFoundation/CoreFoundation.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
struct test_class {int value;};
struct test_object {Class cls;unsigned holds;bool native;};
struct test_method {const char *name,*encoding;IMP impl;bool meta;};
struct test_surface {unsigned holds;bool locked;uint32_t seed;uint8_t bytes[16];};
static struct test_class cls={1},superclass={2},subclass={3};
static struct test_class group_class={4},dictionary_class={5};
static struct test_object native_group={&group_class,1,true};
static unsigned test,swaps,creates,backend_destroyed,native_init,native_dealloc,super_dealloc;
static unsigned native_set,uploads,reads,lease_opens,backend_bind_calls;
static unsigned readiness_calls,proof2_calls,proof3_calls,lease_closes,status_calls;
static char startup_events[32];static unsigned startup_event_count;
static bool lookup_changed;
static struct test_object startup_native={&cls,1,true};
static unsigned group_objects,group_deallocs;
struct mock_string {CFTypeID type;const char *value;};
struct mock_number {CFTypeID type;int64_t value;bool floating;};
struct mock_dictionary {struct test_object object;CFIndex count;const void *keys[6],*values[6];};
static struct mock_string strings[]={{1,"EAGLContextPropertySharegroup"},{1,"EAGLContextPropertyClientLabel"},
    {1,"EAGLContextPropertySharedWithCompute"},{1,"EAGLContextPropertyClientRetainRelease"},{1,"unknown"},{1,"EAGLContextPropertyAccelerated"}};
const void *mock_cfstr(const char *name){for(unsigned i=0;i<6;i++)if(!strcmp(strings[i].value,name))return &strings[i];assert(false);return NULL;}
CFTypeID CFGetTypeID(const void *value){return *(const CFTypeID *)value;}
CFTypeID CFStringGetTypeID(void){return 1;} CFTypeID CFBooleanGetTypeID(void){return 2;} CFTypeID CFNumberGetTypeID(void){return 3;}
bool CFBooleanGetValue(const void *v){return ((const struct mock_number *)v)->value!=0;}
bool CFNumberIsFloatType(const void *v){return ((const struct mock_number *)v)->floating;}
bool CFNumberGetValue(const void *v,int kind,void *out){assert(kind==kCFNumberSInt64Type);*(int64_t *)out=((const struct mock_number *)v)->value;return true;}
bool CFEqual(const void *a,const void *b){if(CFGetTypeID(a)!=1 || CFGetTypeID(b)!=1)return a==b;return !strcmp(((const struct mock_string *)a)->value,((const struct mock_string *)b)->value);}
CFIndex CFDictionaryGetCount(CFDictionaryRef p){return ((const struct mock_dictionary *)p)->count;}
void CFDictionaryGetKeysAndValues(CFDictionaryRef p,const void **keys,const void **values){const struct mock_dictionary *d=p;assert(d->count<=5);for(CFIndex i=0;i<d->count;i++){keys[i]=d->keys[i];values[i]=d->values[i];}}
const void *CFDictionaryGetValue(CFDictionaryRef p,const void *key){const struct mock_dictionary *d=p;for(CFIndex i=0;i<d->count;i++)if(CFEqual(key,d->keys[i]))return d->values[i];return NULL;}
static struct test_surface surface;
static id native_current;
static id original_init(id self,SEL cmd,unsigned long api,id properties)
{(void)cmd;(void)api;(void)properties;native_init++;self->native=true;return self;}
static void original_dealloc(id self,SEL cmd) {(void)cmd;assert(self->native);native_dealloc++;}
static unsigned long original_api(id self,SEL cmd) {(void)self;(void)cmd;return 2;}
static void *original_macro(id self,SEL cmd) {(void)self;(void)cmd;return (void *)0x4567;}
static unsigned long original_parameter(id self,SEL cmd,uint32_t name,const int32_t *value)
{(void)self;(void)cmd;(void)name;(void)value;return 0x123456789ul;}
static unsigned long original_get_parameter(id self,SEL cmd,uint32_t name,int32_t *value)
{(void)self;(void)cmd;(void)name;if(value)*value=17;return 0x123456789ul;}
static bool original_tex(id self,SEL cmd,IOSurfaceRef s,unsigned long target,unsigned long internal,
    uint32_t w,uint32_t h,unsigned long format,unsigned long type,uint32_t plane,bool invert)
{(void)self;(void)cmd;(void)s;(void)target;(void)internal;(void)w;(void)h;(void)format;(void)type;(void)plane;(void)invert;return true;}
static bool original_attach(id self,SEL cmd,unsigned long target,IOSurfaceRef s,bool invert)
{(void)self;(void)cmd;(void)target;(void)s;(void)invert;return true;}
static bool original_set_current(id self,SEL cmd,id object)
{(void)self;(void)cmd;native_set++;if((test==7 || test==39) && object)return false;native_current=object;return true;}
static id original_current(id self,SEL cmd) {(void)self;(void)cmd;return native_current;}
static id original_sharegroup(id self,SEL cmd){(void)self;(void)cmd;return &native_group;}
static unsigned long original_group_api(id self,SEL cmd){(void)self;(void)cmd;return 2;}
static void *original_group_shared(id self,SEL cmd){(void)self;(void)cmd;return (void *)0x2345;}
static void original_group_dealloc(id self,SEL cmd){assert(!strcmp(cmd,"dealloc") && self->cls==&group_class && !self->holds);group_deallocs++;free(self);}
static void raced(void) {}
static struct test_method methods[]={
    {"initWithAPI:properties:","@32@0:8Q16@24",(IMP)original_init,false},
    {"dealloc","v16@0:8",(IMP)original_dealloc,false},
    {"API","Q16@0:8",(IMP)original_api,false},
    {"getMacroContextPrivate","^{EAGLMacroContext=}16@0:8",(IMP)original_macro,false},
    {"GetMacroContextPrivate","^{EAGLMacroContext=}16@0:8",(IMP)original_macro,false},
    {"setParameter:to:","Q28@0:8I16^i20",(IMP)original_parameter,false},
    {"getParameter:to:","Q28@0:8I16^i20",(IMP)original_get_parameter,false},
    {"texImageIOSurface:target:internalFormat:width:height:format:type:plane:invert:",
        "B72@0:8^{__IOSurface=}16Q24Q32I40I44Q48Q56I64B68",(IMP)original_tex,false},
    {"attachImage:toCoreSurface:invertedRender:","B36@0:8Q16^{__IOSurface=}24B32",(IMP)original_attach,false},
    {"setCurrentContext:","B24@0:8@16",(IMP)original_set_current,true},
    {"currentContext","@16@0:8",(IMP)original_current,true},
    {"sharegroup","@16@0:8",(IMP)original_sharegroup,false},
};
static struct test_method group_methods[]={
    {"APIs","Q16@0:8",(IMP)original_group_api,false},
    {"dealloc","v16@0:8",(IMP)original_group_dealloc,false},
    {"getGLIShared","^{__GLISharedRec=}16@0:8",(IMP)original_group_shared,false}};
static struct test_method alternate;
static void startup_event(char value)
{assert(startup_event_count<sizeof(startup_events)-1);startup_events[startup_event_count++]=value;}
bool sgfx_ios_renderer_wait(void)
{assert(!swaps && !creates && !lease_opens);readiness_calls++;startup_event('R');return test!=50;}
int sgfx_drm_open_renderer(void)
{assert(readiness_calls==1 && !swaps && !creates);lease_opens++;startup_event('O');return test==10 || test==61?-1:65536;}
int sgfx_drm_open(void)
{assert(!"installer must select renderer role before the first open");return -1;}
bool sgfx_gles_ui_readback_proof(int fd,unsigned api)
{
    assert(fd==65536 && lease_opens==1 && !lease_closes && !swaps && !creates);
    if(api==2){assert(!proof2_calls && !proof3_calls);proof2_calls++;startup_event('2');return test!=51;}
    assert(api==3 && proof2_calls==1 && !proof3_calls);proof3_calls++;startup_event('3');
    if(test==57)native_current=&startup_native;
    if(test==58)methods[5].encoding="B16@0:8";
    if(test==59)methods[5].impl=(IMP)raced;
    if(test==60){alternate=methods[5];lookup_changed=true;}
    return test!=52;
}
bool sgfx_drm_status(int fd,uint32_t *submitted,uint32_t *completed)
{
    assert(fd==65536 && submitted && completed && !lease_closes && !swaps && proof2_calls==1 && proof3_calls==1);
    status_calls++;startup_event('S');
    *submitted=test==55?3:4;*completed=test==54?3:*submitted;return test!=53;
}
int sgfx_drm_close(int fd)
{assert(fd==65536 && lease_opens==1 && !lease_closes);lease_closes++;startup_event('C');return 0;}
Class objc_getClass(const char *name) {if(!strcmp(name,"EAGLContext"))return test==1?NULL:&cls;if(!strcmp(name,"EAGLSharegroup"))return &group_class;if(!strcmp(name,"NSDictionary"))return &dictionary_class;assert(false);return NULL;}
id class_createInstance(Class owner,unsigned long extra){assert(owner==&group_class && !extra);id object=calloc(1,sizeof(*object));assert(object);object->cls=owner;object->holds=1;group_objects++;return object;}
Class object_getClass(id object) {return object?object->cls:NULL;}
Class class_getSuperclass(Class object) {assert(object==&cls);return &superclass;}
SEL sel_registerName(const char *name) {return name;}
static Method method(SEL name,bool meta)
{for(unsigned i=0;i<12;i++)if(!strcmp(methods[i].name,name) && methods[i].meta==meta)return &methods[i];return NULL;}
Method class_getClassMethod(Class object,SEL name) {assert(object==&cls);return method(name,true);}
Method class_getInstanceMethod(Class object,SEL name) {if(object==&cls){if(lookup_changed && !strcmp(name,methods[5].name))return &alternate;return method(name,false);}assert(object==&group_class);for(unsigned i=0;i<3;i++)if(!strcmp(group_methods[i].name,name))return &group_methods[i];return NULL;}
const char *method_getTypeEncoding(Method m) {return (test==2 && m==&methods[5]) || (test==27 && m==&group_methods[0])?"B16@0:8":m->encoding;}
IMP method_getImplementation(Method m) {return m->impl;}
IMP method_setImplementation(Method m,IMP replacement)
{IMP previous=m->impl;m->impl=replacement;swaps++;return (test==3 && swaps==5) || (test==28 && swaps==14)?(IMP)raced:previous;}
/* ObjC's typed method arguments use ordinary registers. Darwin ARM64 C
 * varargs use the stack, so a va_arg mock cannot receive isKindOfClass:'s
 * Class argument from the real fixed-signature call in ui_eagl.c. */
__attribute__((no_sanitize("function"))) id objc_msgSend(id object,SEL cmd,Class wanted)
{
 if(!strcmp(cmd,"isKindOfClass:"))return (id)(uintptr_t)(object->cls==wanted);
 if(!strcmp(cmd,"retain"))object->holds++;
 else {assert(!strcmp(cmd,"release") && object->holds);if(!--object->holds && object->cls==&group_class)((void (*)(id,SEL))group_methods[1].impl)(object,"dealloc");}
 return object;}
void objc_msgSendSuper(struct objc_super *parent,SEL cmd)
{assert(parent->super_class==&superclass && !strcmp(cmd,"dealloc"));super_dealloc++;}
const void *CFRetain(const void *opaque) {struct test_surface *s=(void *)opaque;s->holds++;return opaque;}
void CFRelease(const void *opaque) {struct test_surface *s=(void *)opaque;assert(s->holds);s->holds--;}
int IOSurfaceLock(IOSurfaceRef s,uint32_t options,uint32_t *seed)
{assert(options<=1 && !s->locked);s->locked=true;*seed=s->seed;return 0;}
int IOSurfaceUnlock(IOSurfaceRef s,uint32_t options,uint32_t *seed)
{assert(options<=1 && s->locked);s->locked=false;if(!options)s->seed++;*seed=s->seed;return 0;}
size_t IOSurfaceGetWidth(IOSurfaceRef s) {(void)s;return test==9?UINT64_MAX:2;}
size_t IOSurfaceGetHeight(IOSurfaceRef s) {(void)s;return 2;}
size_t IOSurfaceGetBytesPerRow(IOSurfaceRef s) {(void)s;return 8;}
size_t IOSurfaceGetBytesPerElement(IOSurfaceRef s) {(void)s;return 4;}
size_t IOSurfaceGetPlaneCount(IOSurfaceRef s) {(void)s;return 0;}
size_t IOSurfaceGetAllocSize(IOSurfaceRef s) {(void)s;return 16;}
uint32_t IOSurfaceGetPixelFormat(IOSurfaceRef s) {(void)s;return SGFX_UI_BGRA;}
void *IOSurfaceGetBaseAddress(IOSurfaceRef s) {return s->bytes;}
struct mock_backend {struct sgfx_ui_mesa_group *group;unsigned ordinal;};
static bool bind_backend(void *opaque,bool enabled) {struct mock_backend *b=opaque;backend_bind_calls++;return !(test==42 && enabled && b->ordinal==2);}
static void destroy_backend(void *opaque) {struct mock_backend *b=opaque;sgfx_ui_mesa_group_release(b->group);free(b);backend_destroyed++;}
static bool select_backend(void *opaque,uint32_t name,bool read,uint32_t *saved)
{(void)opaque;(void)read;assert(name==17);*saved=0;return true;}
static bool restore_backend(void *opaque,uint32_t saved,bool read) {(void)opaque;(void)read;assert(!saved);return true;}
static bool upload(void *opaque,uint32_t w,uint32_t h,const uint8_t *bytes)
{(void)opaque;(void)bytes;assert(w==2 && h==2);uploads++;return true;}
static bool finish(void *opaque) {(void)opaque;return true;}
static bool read_pixels(void *opaque,uint32_t w,uint32_t h,uint8_t *bytes)
{(void)opaque;assert(w==2 && h==2);memset(bytes,255,16);reads++;return true;}
static bool fence(void *opaque,uint32_t *submitted,uint32_t *completed)
{(void)opaque;*submitted=7;*completed=(test==29 || test==38) && reads?6:7;return true;}
bool sgfx_ui_mesa_create(unsigned api,struct sgfx_ui_backend *out)
{
    assert(api==2 || api==3);creates++;if(test==4)return false;
    *out=(struct sgfx_ui_backend){(void *)0x99,bind_backend,destroy_backend,select_backend,restore_backend,
        {(void *)0x99,upload,finish,read_pixels,fence}};return true;
}
struct sgfx_ui_mesa_group *sgfx_ui_mesa_group_create(unsigned api){assert(api==2 || api==3);struct sgfx_ui_mesa_group *g=calloc(1,sizeof(*g));assert(g);g->references=1;return g;}
bool sgfx_ui_mesa_group_release(struct sgfx_ui_mesa_group *g){assert(g && g->references);if(!--g->references)free(g);return true;}
bool sgfx_ui_mesa_create_in_group(unsigned api,struct sgfx_ui_mesa_group *g,struct sgfx_ui_backend *out)
{
    assert(api==2 || api==3);creates++;if(test==4)return false;
    struct mock_backend *b=calloc(1,sizeof(*b));assert(b);b->group=g;b->ordinal=creates;g->references++;
    *out=(struct sgfx_ui_backend){b,bind_backend,destroy_backend,select_backend,restore_backend,
        {b,upload,finish,read_pixels,fence}};return true;
}
bool sgfx_ui_bind(void *context) {return sgfx_ui_context_bind(context);}
GLenum sgfx_ui_target(void *context,GLenum target) {(void)context;return target;}
void sgfx_ui_unsupported(void *context,unsigned slot) {sgfx_ui_context_fail(context,SGFX_UI_UNSUPPORTED,slot);}
GLenum GLAPIENTRY glGetError(void) {return GL_NO_ERROR;}
void GLAPIENTRY glGetIntegerv(GLenum name,GLint *out) {assert(name==GL_TEXTURE_BINDING_2D);*out=17;}
static void noop(void) {}
/* The real table is generated separately; this fixture tests method dispatch. */
void *const sgfx_ui_dispatch[SGFX_UI_SLOTS]={[0 ... SGFX_UI_SLOTS-1]=(void *)noop};
static void *other_thread_dealloc(void *object)
{
    ((void (*)(id,SEL))methods[1].impl)((id)object,"dealloc");return NULL;
}
struct parameter_probe {id object;unsigned long set_status,get_status;int32_t value;};
static void *startup_install_thread(void *out)
{*(bool *)out=sgfx_eagl_install();return NULL;}
static void *other_thread_parameters(void *opaque)
{
    struct parameter_probe *p=opaque;int32_t value=0;
    p->set_status=((unsigned long (*)(id,SEL,uint32_t,const int32_t *))methods[5].impl)(p->object,"setParameter:to:",0x260,&value);
    p->get_status=((unsigned long (*)(id,SEL,uint32_t,int32_t *))methods[6].impl)(p->object,"getParameter:to:",0x260,&p->value);
    return NULL;
}
int main(int argc,char **argv)
{
    assert(argc==2);test=(unsigned)strtoul(argv[1],NULL,10);assert(test<63);
    IMP saved[12];for(unsigned i=0;i<12;i++)saved[i]=methods[i].impl;
    assert(!swaps && !creates);
    if(test==56)native_current=&startup_native;
    bool ok;
    if(test==62){
        bool results[2]={false,false};pthread_t threads[2];
        for(unsigned i=0;i<2;i++)assert(!pthread_create(&threads[i],NULL,startup_install_thread,&results[i]));
        for(unsigned i=0;i<2;i++)assert(!pthread_join(threads[i],NULL));
        assert(results[0] && results[1]);ok=true;
    }else ok=sgfx_eagl_install();
    if(test>=50) {
        if(test==56){
            assert(!ok && !swaps && !creates && !readiness_calls && !lease_opens && !proof2_calls && !proof3_calls && !lease_closes);
            native_current=nil;assert(sgfx_eagl_install() && swaps==15 && !strcmp(startup_events,"RO23S"));return 0;
        }
        if(test==62){assert(ok && swaps==15 && !creates && !strcmp(startup_events,"RO23S") && !lease_closes && sgfx_eagl_install());return 0;}
        assert(!ok && !swaps && !creates && readiness_calls==1);
        if(test==50)assert(!strcmp(startup_events,"R") && !lease_opens);
        else if(test==61)assert(!strcmp(startup_events,"RO") && lease_opens==1 && !lease_closes);
        else {
            assert(lease_opens==1 && lease_closes==1 && proof2_calls==1);
            if(test==51)assert(!proof3_calls && !status_calls && !strcmp(startup_events,"RO2C"));
            else if(test==52)assert(proof3_calls==1 && !status_calls && !strcmp(startup_events,"RO23C"));
            else assert(proof3_calls==1 && status_calls==1 && !strcmp(startup_events,"RO23SC"));
        }
        for(unsigned i=0;i<12;i++)assert(methods[i].impl==(test==59 && i==5?(IMP)raced:saved[i]));
        unsigned before=startup_event_count;assert(!sgfx_eagl_install() && startup_event_count==before);return 0;
    }
    if(test==27 || test==28){
        assert(!ok && !creates);
        if(test==27)assert(!swaps && !lease_opens);
        else{
            for(unsigned i=0;i<12;i++)assert(methods[i].impl==saved[i]);
            assert(group_methods[0].impl==(IMP)original_group_api && group_methods[1].impl==(IMP)raced);
        }
        return 0;
    }
    if(test>=1 && test<=3) {
        assert(!ok && !creates);
        if(test<3)assert(!swaps && !lease_opens);
        else assert(lease_opens==1);
        for(unsigned i=0;i<12;i++)assert(methods[i].impl==(test==3 && i==4?(IMP)raced:saved[i]));return 0;
    }
    if(test==10) {assert(!ok && !swaps && !creates && lease_opens==1);
        assert(!sgfx_eagl_install() && lease_opens==1);return 0;}
    assert(ok && swaps==15 && !creates && sgfx_eagl_install() && swaps==15 && lease_opens==1);
    struct test_object object={test==8?&subclass:&cls,1,false},other={&cls,1,true};
    if(test>=43) {
        struct mock_number one={2,1,false};
        struct mock_dictionary properties={.object={&dictionary_class,1,false},.count=2,
            .keys={CFSTR("EAGLContextPropertyAccelerated"),CFSTR("EAGLContextPropertyClientRetainRelease")},
            .values={&one,&one}};
        other.native=false;id self=&object;
        assert(((id (*)(id,SEL,unsigned long,id))methods[0].impl)(self,methods[0].name,3,(id)&properties)==self);
        struct sgfx_ui_context *c=sgfx_ui_context_lookup(self);assert(c && !backend_bind_calls);
        if(test==43 || test==48 || test==49)assert(((bool (*)(id,SEL,id))methods[9].impl)(nil,"setCurrentContext:",self));
        unsigned bindings=backend_bind_calls;int32_t value=0;
        if(test==43)assert(((unsigned long (*)(id,SEL,uint32_t,const int32_t *))methods[5].impl)(self,"setParameter:to:",0x260,&value)==0x2710);
        if(test==44)assert(((unsigned long (*)(id,SEL,uint32_t,const int32_t *))methods[5].impl)(self,"setParameter:to:",0x260,NULL)==0x271e);
        if(test==45)assert(((unsigned long (*)(id,SEL,uint32_t,const int32_t *))methods[5].impl)(self,"setParameter:to:",0xffffffff,(const int32_t *)(uintptr_t)1)==0x2710);
        if(test==46){value=123;assert(((unsigned long (*)(id,SEL,uint32_t,int32_t *))methods[6].impl)(self,"getParameter:to:",0x260,&value)==0x2710 && value==0);}
        if(test==47)assert(((unsigned long (*)(id,SEL,uint32_t,int32_t *))methods[6].impl)(self,"getParameter:to:",0x260,NULL)==0x271e);
        if(test==48) {
            struct parameter_probe p={self,0,0,123};pthread_t visitor;
            assert(!pthread_create(&visitor,NULL,other_thread_parameters,&p));assert(!pthread_join(visitor,NULL));
            assert(p.set_status==0x2710 && p.get_status==0x2710 && !p.value);
        }
        if(test==49) {
            assert(!sgfx_ui_context_fail(c,SGFX_UI_TRANSFER,0));
            struct sgfx_ui_report before={0},after={0};assert(sgfx_ui_context_report(c,&before) && before.first_failure);
            assert(((unsigned long (*)(id,SEL,uint32_t,const int32_t *))methods[5].impl)(self,"setParameter:to:",0x260,&value)==0x2710);
            assert(((unsigned long (*)(id,SEL,uint32_t,int32_t *))methods[6].impl)(self,"getParameter:to:",0x260,&value)==0x2710);
            assert(sgfx_ui_context_report(c,&after) && !memcmp(&before,&after,sizeof(before)));
            ((void (*)(id,SEL))methods[1].impl)(self,"dealloc");
            assert(!backend_destroyed && !super_dealloc && sgfx_ui_context_lookup(self));return 0;
        }
        assert(backend_bind_calls==bindings && object.holds==1);
        struct sgfx_ui_report report={0};assert(sgfx_ui_context_report(c,&report) && !report.first_failure && !report.group_failure);
        assert(((bool (*)(id,SEL,id))methods[9].impl)(nil,"setCurrentContext:",self));
        assert(sgfx_ui_context_attach(c,17,&surface,false) && sgfx_ui_context_dirty(c,17) && sgfx_ui_context_flush(c));
        assert(reads==1 && !surface.locked && surface.bytes[0]==255);
        assert(((bool (*)(id,SEL,id))methods[9].impl)(nil,"setCurrentContext:",nil) && object.holds==1);
        ((void (*)(id,SEL))methods[1].impl)(self,"dealloc");
        assert(backend_destroyed==1 && super_dealloc==1 && !surface.holds);return 0;
    }
    if(test==42) {
        struct mock_number one={2,1,false};
        struct mock_dictionary properties={.object={&dictionary_class,1,false},.count=3,
            .keys={CFSTR("EAGLContextPropertyAccelerated"),CFSTR("EAGLContextPropertyClientRetainRelease"),CFSTR("EAGLContextPropertySharegroup")},
            .values={&one,&one,NULL}};
        other.native=false;
        assert(((id (*)(id,SEL,unsigned long,id))methods[0].impl)(&object,methods[0].name,3,nil)==&object);
        properties.values[2]=((id (*)(id,SEL))methods[11].impl)(&object,"sharegroup");
        assert(((bool (*)(id,SEL,id))methods[9].impl)(nil,"setCurrentContext:",&object) && object.holds==2);
        assert(((id (*)(id,SEL,unsigned long,id))methods[0].impl)(&other,methods[0].name,3,(id)&properties)==&other);
        assert(!((bool (*)(id,SEL,id))methods[9].impl)(nil,"setCurrentContext:",&other));
        assert(object.holds==2 && other.holds==1 && !backend_destroyed);
        assert(((id (*)(id,SEL))methods[10].impl)(nil,"currentContext")==&object);
        return 0;
    }
    if(test>=31) {
        struct mock_number zero={2,0,false},one={2,1,false},two={3,2,false},label={3,8,false};
        struct mock_dictionary properties={.object={&dictionary_class,1,false},.count=2,
            .keys={CFSTR("EAGLContextPropertyAccelerated"),CFSTR("EAGLContextPropertyClientRetainRelease")},
            .values={&one,&one}};
        if(test==32)properties.values[1]=&zero;
        if(test==33)properties.values[0]=&zero;
        if(test==34)properties.values[1]=&two;
        id self=&object;
        if(test==35 || test==36 || test==41) {
            assert(((id (*)(id,SEL,unsigned long,id))methods[0].impl)(self,methods[0].name,3,nil)==self);
            id group=((id (*)(id,SEL))methods[11].impl)(self,"sharegroup");
            properties.count=5;
            properties.keys[2]=CFSTR("EAGLContextPropertySharegroup");properties.values[2]=group;
            properties.keys[3]=CFSTR("EAGLContextPropertySharedWithCompute");properties.values[3]=&zero;
            properties.keys[4]=CFSTR("EAGLContextPropertyClientLabel");properties.values[4]=&label;
            if(test==35)properties.values[1]=&two;
            if(test==41){properties.count=6;properties.keys[5]=CFSTR("unknown");properties.values[5]=&one;}
            other.native=false;
            id result=((id (*)(id,SEL,unsigned long,id))methods[0].impl)(&other,methods[0].name,3,(id)&properties);
            if(test==35 || test==41) {
                assert(!result && !native_init && creates==1 && group->holds==1);
                ((void (*)(id,SEL))methods[1].impl)(self,"dealloc");return 0;
            }
            assert(result==&other && !other.native && group->holds==2 && creates==2);
            assert(((bool (*)(id,SEL,id))methods[9].impl)(nil,"setCurrentContext:",self) && self->holds==2);
            assert(((bool (*)(id,SEL,id))methods[9].impl)(nil,"setCurrentContext:",&other) && self->holds==1 && other.holds==1);
            assert(((bool (*)(id,SEL,id))methods[9].impl)(nil,"setCurrentContext:",self) && self->holds==2 && other.holds==1);
            assert(((bool (*)(id,SEL,id))methods[9].impl)(nil,"setCurrentContext:",nil) && self->holds==1 && other.holds==1);
            ((void (*)(id,SEL))methods[1].impl)(self,"dealloc");
            ((void (*)(id,SEL))methods[1].impl)(&other,"dealloc");
            assert(group_deallocs==1 && backend_destroyed==2);return 0;
        }
        assert(((id (*)(id,SEL,unsigned long,id))methods[0].impl)(self,methods[0].name,3,(id)&properties)==self);
        if(test==33 || test==34) {assert(self->native && native_init==1 && !creates);return 0;}
        assert(!self->native && !native_init && creates==1);
        assert(((bool (*)(id,SEL,id))methods[9].impl)(nil,"setCurrentContext:",self));
        assert(self->holds==(test==32?2u:1u));
        assert(((bool (*)(id,SEL,id))methods[9].impl)(nil,"setCurrentContext:",self));
        assert(self->holds==(test==32?2u:1u));
        if(test==38) {
            struct sgfx_ui_context *c=sgfx_ui_context_lookup(self);
            assert(sgfx_ui_context_attach(c,17,&surface,false) && sgfx_ui_context_dirty(c,17));
            assert(!sgfx_ui_context_flush(c));
            ((void (*)(id,SEL))methods[1].impl)(self,"dealloc");
            assert(!backend_destroyed && !group_deallocs && surface.holds==1 && self->holds==1);
            assert(((id (*)(id,SEL))methods[10].impl)(nil,"currentContext")==self);return 0;
        }
        if(test==39) {
            assert(!((bool (*)(id,SEL,id))methods[9].impl)(nil,"setCurrentContext:",&other));
            assert(((id (*)(id,SEL))methods[10].impl)(nil,"currentContext")==self && self->holds==1);
        }
        if(test==40) {
            pthread_t visitor;assert(!pthread_create(&visitor,NULL,other_thread_dealloc,self));
            assert(!pthread_join(visitor,NULL));
            assert(!backend_destroyed && !super_dealloc && sgfx_ui_context_lookup(self));
        }
        if(test==37 || test==40) {
            ((void (*)(id,SEL))methods[1].impl)(self,"dealloc");
            assert(!((id (*)(id,SEL))methods[10].impl)(nil,"currentContext"));
            assert(((bool (*)(id,SEL,id))methods[9].impl)(nil,"setCurrentContext:",nil));
            assert(self->holds==1 && backend_destroyed==1 && super_dealloc==1);return 0;
        }
        assert(((bool (*)(id,SEL,id))methods[9].impl)(nil,"setCurrentContext:",nil));
        assert(self->holds==1);
        ((void (*)(id,SEL))methods[1].impl)(self,"dealloc");
        assert(backend_destroyed==1 && super_dealloc==1 && group_objects==group_deallocs);
        return 0;
    }
    if(test>=15){
        other.native=false;
        struct mock_dictionary properties={.object={&dictionary_class,1,false}};
        id self=&object;
        assert(((id (*)(id,SEL,unsigned long,id))methods[0].impl)(self,methods[0].name,3,test==23?(id)&properties:nil)==self);
        id group=((id (*)(id,SEL))methods[11].impl)(self,methods[11].name);
        assert(group && group->cls==&group_class && group->holds==1 && group_objects==1);
        assert(((unsigned long (*)(id,SEL))group_methods[0].impl)(group,"APIs")==3);
        if(test==15)assert(!((void *(*)(id,SEL))group_methods[2].impl)(group,"getGLIShared"));
        if(test==30){assert(!((id (*)(id,SEL,unsigned long,id))methods[0].impl)(self,methods[0].name,3,nil) && creates==1 && !native_init);}
        struct mock_number label={3,8,false},zero={2,0,false},one={2,1,false};
        properties.count=4;
        properties.keys[0]=CFSTR("EAGLContextPropertySharegroup");properties.values[0]=group;
        properties.keys[1]=CFSTR("EAGLContextPropertyClientLabel");properties.values[1]=&label;
        properties.keys[2]=CFSTR("EAGLContextPropertySharedWithCompute");properties.values[2]=&zero;
        properties.keys[3]=CFSTR("EAGLContextPropertyClientRetainRelease");properties.values[3]=&zero;
        bool shared=test!=15 && test!=23 && test!=29 && test!=30;
        if(shared){
            if(test==18)properties.keys[3]=mock_cfstr("unknown");
            if(test==19)properties.values[2]=&one;
            if(test==20)properties.values[3]=&one;
            if(test==21)label.value=9;
            if(test==22)label.floating=true;
            if(test==24)label.value=0;
            if(test==25)properties.values[0]=&native_group;
            if(test==26)properties.keys[3]=&one;
            id result=((id (*)(id,SEL,unsigned long,id))methods[0].impl)(&other,methods[0].name,test==17?2:3,(id)&properties);
            bool refused=(test>=17 && test<=22 && test!=20) || test==26;
            if(refused){assert(!result && !native_init && creates==1 && group->holds==1);}
            else if(test==25){assert(result==&other && other.native && native_init==1 && creates==1);}
            else{
                assert(result==&other && !other.native && creates==2 && group->holds==2 && !native_init);
                assert(((id (*)(id,SEL))methods[11].impl)(&other,"sharegroup")==group);
                assert(((bool (*)(id,SEL,id))methods[9].impl)(nil,"setCurrentContext:",self));
                struct sgfx_ui_context *c=sgfx_ui_context_lookup(self);
                assert(sgfx_ui_context_attach(c,17,&surface,false) && surface.holds==1 && uploads==1);
                assert(((bool (*)(id,SEL,id))methods[9].impl)(nil,"setCurrentContext:",&other));
                assert(sgfx_ui_context_refresh(sgfx_ui_context_lookup(&other),17) && uploads==1);
                assert(((bool (*)(id,SEL,id))methods[9].impl)(nil,"setCurrentContext:",nil));
                ((void (*)(id,SEL))methods[1].impl)(self,"dealloc");
                assert(group->holds==1 && !group_deallocs && surface.holds==1);
                ((void (*)(id,SEL))methods[1].impl)(&other,"dealloc");
                assert(group_deallocs==1 && !surface.holds && backend_destroyed==2);return 0;
            }
        }
        if(test==29){
            assert(((bool (*)(id,SEL,id))methods[9].impl)(nil,"setCurrentContext:",self));
            struct sgfx_ui_context *c=sgfx_ui_context_lookup(self);
            assert(sgfx_ui_context_attach(c,17,&surface,false) && sgfx_ui_context_dirty(c,17));
            assert(!sgfx_ui_context_flush(c));((void (*)(id,SEL))methods[1].impl)(self,"dealloc");
            assert(((id (*)(id,SEL))methods[11].impl)(self,"sharegroup")==group && group->holds==1);
            assert(!backend_destroyed && !group_deallocs && surface.holds==1);return 0;
        }
        ((void (*)(id,SEL))methods[1].impl)(self,"dealloc");
        assert(group_deallocs==1 && backend_destroyed==1);return 0;
    }
    id self=&object;id result=((id (*)(id,SEL,unsigned long,id))methods[0].impl)(self,methods[0].name,3,test==5?&other:nil);
    assert(result==self);
    if(test==4 || test==5 || test==8) {
        assert(object.native && native_init==1);
        assert(((unsigned long (*)(id,SEL,uint32_t,const int32_t *))methods[5].impl)(self,methods[5].name,1,NULL)==0x123456789ul);
        ((void (*)(id,SEL))methods[1].impl)(self,methods[1].name);assert(native_dealloc==1 && !super_dealloc);return 0;
    }
    assert(!native_init && creates==1 && !object.native);
    assert(((unsigned long (*)(id,SEL))methods[2].impl)(self,methods[2].name)==3);
    struct sgfx_ui_macro *m=((void *(*)(id,SEL))methods[3].impl)(self,methods[3].name);assert(m && m->context);
    assert(((bool (*)(id,SEL,id))methods[9].impl)(nil,methods[9].name,self) && object.holds==2);
    assert(((id (*)(id,SEL))methods[10].impl)(nil,methods[10].name)==self);
    if(test==12 || test==13) {
        int32_t value=0;
        assert(((unsigned long (*)(id,SEL,uint32_t,int32_t *))methods[6].impl)(self,methods[6].name,0xe0,test==13?NULL:&value)==(test==13?0x271eul:0ul));
        assert(value==(test==13?0:0x2060));
        /* A failed null-output query must not poison the following surface
         * transfer. This constant does not bind or mutate GL state. */
    }
    if(test==14) {
        int32_t value=123;
        assert(((unsigned long (*)(id,SEL,uint32_t,int32_t *))methods[6].impl)(self,methods[6].name,1,&value)==0x2710 && !value);
        assert(sgfx_ui_context_lookup(self)); /* Rejected API request leaves the renderer valid. */
    }
    if(test==6) {
        int32_t value=1;assert(((unsigned long (*)(id,SEL,uint32_t,const int32_t *))methods[5].impl)(self,methods[5].name,1,&value)==0x2710);
        assert(sgfx_ui_context_lookup(self)); /* Rejected API request leaves the renderer valid. */
    }
    if(test==7) {
        assert(!((bool (*)(id,SEL,id))methods[9].impl)(nil,methods[9].name,&other));
        assert(((id (*)(id,SEL))methods[10].impl)(nil,methods[10].name)==self && object.holds==2);
    } else {
        bool attached=((bool (*)(id,SEL,unsigned long,IOSurfaceRef,bool))methods[8].impl)(self,methods[8].name,GL_TEXTURE_2D,&surface,false);
        assert(attached==(test!=9) && !surface.locked);
        if(test==9) {assert(!surface.holds && !uploads);return 0;}
        assert(surface.holds==1 && uploads==1 && sgfx_ui_context_dirty(m->context,17) && sgfx_ui_context_flush(m->context));
        assert(reads==1 && surface.bytes[0]==255 && !surface.locked);
    }
    assert(((bool (*)(id,SEL,id))methods[9].impl)(nil,methods[9].name,nil) && object.holds==1);
    ((void (*)(id,SEL))methods[1].impl)(self,methods[1].name);
    assert(backend_destroyed==1 && super_dealloc==1 && !native_dealloc && !surface.holds);
    if(test==11) {
        assert(((id (*)(id,SEL,unsigned long,id))methods[0].impl)(&other,methods[0].name,3,nil)==&other);
        assert(creates==2 && lease_opens==1);
        ((void (*)(id,SEL))methods[1].impl)(&other,methods[1].name);
        assert(backend_destroyed==2 && super_dealloc==2 && lease_opens==1);
    }
    puts("PASS actual EAGL callbacks; ObjC/IOSurface/Mesa modeled");return 0;
}
