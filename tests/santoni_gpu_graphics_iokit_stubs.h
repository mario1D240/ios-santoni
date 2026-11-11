/* External IOKit/VM boundary for actual reconstructed SantoniGraphics.cpp. */
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
using UInt32=uint32_t;using UInt64=uint64_t;using IOOptionBits=uint32_t;
using IOReturn=int;using task_t=void *;using pmap_t=void *;using addr64_t=uint64_t;using ppnum_t=uint64_t;
constexpr IOReturn kIOReturnSuccess=0,kIOReturnBadArgument=-1,kIOReturnBusy=-2,kIOReturnNotReady=-3,
    kIOReturnTimeout=-4,kIOReturnNotPermitted=-5,kIOReturnNoMemory=-6;
constexpr IOOptionBits kIODirectionInOut=1,kIOMemoryKernelUserShared=2;
constexpr const char *kIOUserClientClassKey="IOUserClientClass",*kIOClientPrivilegeAdministrator="admin";
#define APPLE_KEXT_OVERRIDE override
#define OSDeclareDefaultStructors(C) public:C()=default;~C() override=default
#define OSDefineMetaClassAndStructors(C,B)
static task_t test_task=(void *)0x1000,kernel_task=(void *)0xff000;
static pmap_t kernel_pmap=(void *)0x2000;
static bool test_admin=true;
static uint64_t test_clock=1000000;
static unsigned test_task_refs,test_service_registers,test_hw_maps,test_hw_pubs;
static int test_missing_page=-1;
static int test_boot_graphics=1,test_boot_mode=3,test_boot_render=1,test_boot_ui=0,test_boot_raster=0,test_boot_gles=0,test_boot_renderer=0;
static bool test_raster_present=true;
static void task_reference(task_t task){assert(task);test_task_refs++;}
static void task_deallocate(task_t task){assert(task && test_task_refs);test_task_refs--;}
static task_t current_task(){return test_task;}
static uint64_t mach_absolute_time(){return test_clock;}
static void absolutetime_to_nanoseconds(uint64_t t,uint64_t *out){*out=t;}
static void IOSleep(uint32_t ms){test_clock+=(uint64_t)ms*1000000;}
static void IOLog(const char *,...){}
struct IOLock {std::mutex guard;bool held=false;};
static IOLock *IOLockAlloc(){return new IOLock;}
static void IOLockLock(IOLock *l){assert(l);l->guard.lock();assert(!l->held);l->held=true;}
static void IOLockUnlock(IOLock *l){assert(l && l->held);l->held=false;l->guard.unlock();}
static bool PE_parse_boot_argn(const char *s,void *out,unsigned n)
{
    assert(n==4);int value=0;
    if(!strcmp(s,"santonigpu_graphics"))value=test_boot_graphics;
    else if(!strcmp(s,"santonigpu"))value=test_boot_mode;
    else if(!strcmp(s,"santonigpu_render"))value=test_boot_render;
    else if(!strcmp(s,"santonigpu_raster")){if(!test_raster_present)return false;value=test_boot_raster;}
    else if(!strcmp(s,"santonigpu_gles"))value=test_boot_gles;
    else if(!strcmp(s,"santonigpu_renderer"))value=test_boot_renderer;
    else {assert(!strcmp(s,"santonigpu_ui"));value=test_boot_ui;}
    *(int *)out=value;return true;
}
struct Vnode {unsigned held=0,puts=0;unsigned type=1,uid=0,mode=0755;};
struct Process {task_t task=(void *)0x1000;int pid=42;unsigned uid=501;Vnode *exe;const char *name;};
using proc_t=Process *;using vnode_t=Vnode *;using vfs_context_t=void *;
static Vnode genuine,other;
static Process process{test_task,42,501,&genuine,"backboardd"};
static proc_t active=&process;

static vfs_context_t current_context=(void *)0x8001;
static unsigned lookup_calls,attribute_calls;
static int lookup_error,attribute_error;
static bool null_lookup,uid_supported=true,mode_supported=true;
static vnode_t path_vnode=&genuine;
static void (*test_attribute_hook)();
constexpr unsigned VREG=1,VDIR=2;
constexpr int VNODE_LOOKUP_NOFOLLOW=1;
struct vnode_attr {unsigned va_uid=0,va_mode=0;uint64_t va_active=0,va_supported=0;};
constexpr uint64_t VNODE_ATTR_va_uid=1ull<<7,VNODE_ATTR_va_mode=1ull<<9;
#define VATTR_INIT(p) (*(p)=vnode_attr{})
#define VATTR_WANTED(p,k) ((p)->va_active|=VNODE_ATTR_##k)
#define VATTR_IS_SUPPORTED(p,k) (((p)->va_supported&VNODE_ATTR_##k)!=0)
static proc_t current_proc(){return active;}
extern "C" unsigned santoni_gpu_dyld_trace_begin(proc_t p,unsigned phase)
{assert(p==active && phase==1 && p->uid==501);return 0;}
extern "C" void santoni_gpu_dyld_trace_event(proc_t p,unsigned token,unsigned stage,int)
{assert(p==active && !token && stage>=10 && stage<=24);}


static task_t proc_task(proc_t p){assert(p);return p->task;}
static int proc_pid(proc_t p){assert(p);return p->pid;}
static uint32_t proc_getuid(proc_t p){assert(p);return p->uid;}
static vnode_t proc_getexecutablevnode(proc_t p){assert(p);if(p->exe)p->exe->held++;return p->exe;}
static vfs_context_t vfs_context_current(){return current_context;}
static int vnode_lookup(const char *path,int flags,vnode_t *out,vfs_context_t context)
{
    lookup_calls++;assert(!strcmp(path,"/usr/libexec/backboardd") && flags==VNODE_LOOKUP_NOFOLLOW && context==(void *)0x8001);
    assert(out && !*out);
    if(lookup_error)return lookup_error;
    if(!null_lookup){*out=path_vnode;path_vnode->held++;}return 0;
}
static unsigned vnode_vtype(vnode_t v){assert(v && v->held);return v->type;}
static int vnode_getattr(vnode_t v,vnode_attr *a,vfs_context_t context)
{
    attribute_calls++;assert(v && v->held && context==(void *)0x8001);
    assert(a->va_active==(VNODE_ATTR_va_uid|VNODE_ATTR_va_mode));
    if(test_attribute_hook)test_attribute_hook();
    if(attribute_error)return attribute_error;
    a->va_uid=v->uid;a->va_mode=v->mode;
    a->va_supported=(uid_supported?VNODE_ATTR_va_uid:0)|(mode_supported?VNODE_ATTR_va_mode:0);return 0;
}
static void vnode_put(vnode_t v){assert(v && v->held);v->held--;v->puts++;}

class OSObject {public:virtual ~OSObject()=default;};
class IOService:public OSObject {
public:virtual bool start(IOService *){return true;}
    void setProperty(const char *,const char *){}
    void registerService(){test_service_registers++;}
};
class IOMemoryDescriptor:public OSObject {
public:uint8_t *data=nullptr;uint64_t length=0;IOMemoryDescriptor *parent=nullptr;
    virtual uint64_t getLength()const{return length;}
    virtual void *getBytesNoCopy(){return data;}
};
class IOBufferMemoryDescriptor;
static std::vector<IOBufferMemoryDescriptor *> test_buffers;
class IOBufferMemoryDescriptor:public IOMemoryDescriptor {
public:uint64_t pa_base=0;IOOptionBits options=0;
    static IOBufferMemoryDescriptor *inTaskWithOptions(task_t owner,IOOptionBits flags,uint64_t bytes,uint64_t alignment)
    {
        assert(owner==kernel_task && alignment==4096 && bytes);
        auto *m=new IOBufferMemoryDescriptor;assert(!posix_memalign((void **)&m->data,alignment,bytes));
        memset(m->data,0xcc,bytes);m->length=bytes;m->options=flags;
        m->pa_base=(flags&kIOMemoryKernelUserShared)?0xa0000000:0xb0000000;test_buffers.push_back(m);return m;
    }
};
class IOSubMemoryDescriptor:public IOMemoryDescriptor {
public:static IOMemoryDescriptor *withSubRange(IOMemoryDescriptor *p,uint64_t offset,uint64_t bytes,IOOptionBits)
    {
        if(!p || offset>p->length || bytes>p->length-offset)return nullptr;
        auto *m=new IOSubMemoryDescriptor;m->parent=p;m->data=p->data+offset;m->length=bytes;return m;
    }
};
struct IOExternalMethodDispatch {};
struct IOExternalMethodArguments {
    uint32_t scalarInputCount=0,scalarOutputCount=0;
    const uint64_t *scalarInput=nullptr;uint64_t *scalarOutput=nullptr;
    uint64_t structureInputSize=0,structureOutputSize=0;
    const void *structureInput=nullptr;void *structureOutput=nullptr;
    IOMemoryDescriptor *structureInputDescriptor=nullptr,*structureOutputDescriptor=nullptr;
};
class IOUserClient:public IOService {
public:virtual bool initWithTask(task_t,void *,UInt32){return true;}
    virtual void free(){}
    virtual IOReturn clientClose(){return kIOReturnSuccess;}
    virtual IOReturn clientMemoryForType(UInt32,IOOptionBits *,IOMemoryDescriptor **){return kIOReturnBadArgument;}
    virtual IOReturn externalMethod(uint32_t,IOExternalMethodArguments *,IOExternalMethodDispatch *,OSObject *,void *){return kIOReturnBadArgument;}
    static IOReturn clientHasPrivilege(void *security,const char *){return test_admin && security==test_task?kIOReturnSuccess:kIOReturnNotPermitted;}
};
extern "C" ppnum_t pmap_find_phys(pmap_t pmap,addr64_t va)
{
    assert(pmap==kernel_pmap);
    for(auto *m:test_buffers) {
        uintptr_t base=(uintptr_t)m->data;
        if(va>=base && va-base<m->length) {
            unsigned page=(unsigned)((va-base)/4096);
            if(test_missing_page==(int)page)return 0;
            return (m->pa_base+(uint64_t)page*8192)>>12;
        }
    }
    return 0;
}
