#include "santoni_gpu_dyld_stubs.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <cstdarg>
struct proc {int pid;unsigned uid;};struct task {int unused;};
static proc process{42,501},other{43,502};
static task owner;
static uint64_t args[2],written;
static unsigned parses,identity_calls,copyins,copyouts;
static unsigned trace_calls,trace_stage,boundaries,names;
static bool reject_cas;
static const char *diagnostic_name="backboardd";
static uint64_t trace_flags;
static int trace_error;
static int trace_pid;
static unsigned trace_uid;
static bool identity,copyin_error;
static int copyout_error;
static int values[7];static bool present[7];
static const char *keys[]={"santonigpu_graphics","santonigpu","santonigpu_render",
    "santonigpu_ui","santonigpu_raster","santonigpu_gles","santonigpu_renderer"};
extern "C" proc_t current_proc(){return &process;}
extern "C" task_t current_task(){return &owner;}
extern "C" int proc_pid(proc_t p){assert(p);return p->pid;}
extern "C" unsigned proc_getuid(proc_t p){assert(p);return p->uid;}
bool gfx_renderer_task(task_t task){assert(task==&owner);
    if(present[6] && values[6]==1)assert(boundaries==1 && names==1);
    identity_calls++;return identity;}
extern "C" int PE_parse_boot_argn(const char *key,void *out,unsigned length)
{
    assert(out && length==4 && *(int *)out==0);int index=-1;
    for(int i=0;i<7;i++)if(!strcmp(key,keys[i]))index=i;
    assert(index>=0);parses++;
    if(!present[index])return 0;
    *(int *)out=values[index];return 1;
}
extern "C" int copyin(user_addr_t address,void *out,size_t length)
{
    copyins++;assert(address==(uintptr_t)args && out && length==16);
    memcpy(out,args,length);return copyin_error?5:0;
}
extern "C" int copyout(const void *input,user_addr_t address,size_t length)
{
    copyouts++;assert(input && address==(uintptr_t)&written && length==8);
    assert(*(const uint64_t *)input==0x22);
    if(copyout_error)return copyout_error;
    written=*(const uint64_t *)input;return 0;
}
extern "C" void proc_selfname(char *out,int size)
{assert(size==17 && boundaries==names+1);strncpy(out,diagnostic_name,(size_t)size);}
extern "C" int32_t OSAddAtomic(int32_t add,volatile int32_t *value)
{assert(add==0);return __atomic_fetch_add(value,add,__ATOMIC_RELAXED);}
extern "C" int OSCompareAndSwap(uint32_t old,uint32_t value,volatile uint32_t *address)
{assert(value==old+1 && old<32);return !reject_cas && __atomic_compare_exchange_n(address,&old,value,false,__ATOMIC_RELAXED,__ATOMIC_RELAXED);}
extern "C" int fixture_dyld_printf(const char *format,...)
{
    va_list ap;va_start(ap,format);
    if(!strcmp(format,"SANTONI GPU: dyld boundary pid=%d token=%u stage=%u result=%d\n")) {
        assert(va_arg(ap,int)==process.pid);unsigned token=va_arg(ap,unsigned);
        assert(token && token<=160);assert(va_arg(ap,unsigned)==0 && va_arg(ap,int)==0);boundaries++;
    }else if(!strcmp(format,"SANTONI GPU: dyld caller pid=%d uid=%u token=%u name=%.16s\n")) {
        assert(va_arg(ap,int)==process.pid && va_arg(ap,unsigned)==process.uid);
        assert(va_arg(ap,unsigned)>0);const char *name=va_arg(ap,const char *);
        assert(strlen(name)<=16);
        for(unsigned i=0;name[i];i++)assert((name[i]>='a' && name[i]<='z') ||
            (name[i]>='A' && name[i]<='Z') || (name[i]>='0' && name[i]<='9') ||
            name[i]=='_' || name[i]=='-' || name[i]=='.');names++;
    }else {
        assert(!strcmp(format,"SANTONI GPU: dyld syscall90 pid=%d uid=%u token=%u flags=%llx stage=%u error=%d\n"));
        assert(boundaries==1 && names==1);
        trace_pid=va_arg(ap,int);trace_uid=va_arg(ap,unsigned);assert(va_arg(ap,unsigned)==65);
        trace_flags=va_arg(ap,unsigned long long);trace_stage=va_arg(ap,unsigned);
        trace_error=va_arg(ap,int);trace_calls++;
    }
    va_end(ap);
    // A failed logger must never replace the policy/copy result.
    return -9;
}
static void reset()
{
    fixture_reset_trace();process.uid=501;reject_cas=false;diagnostic_name="backboardd";
    const int base[]={1,3,1,0,1,1,1};
    memcpy(values,base,sizeof(values));for(bool &v:present)v=true;
    identity=true;copyin_error=false;copyout_error=0;
    parses=identity_calls=copyins=copyouts=trace_calls=boundaries=names=0;
    trace_flags=~0ull;trace_stage=99;trace_error=-99;
    args[0]=0;args[1]=(uintptr_t)&written;written=0xfeedbeefcafef00dull;
}
static unsigned cases;
static void check(proc_t caller,int call,int result,unsigned expected_identity,
    unsigned expected_copyin,unsigned expected_copyout,unsigned expected_parses)
{
    assert(fixture_policy(caller,call,(uintptr_t)args)==result);
    assert(identity_calls==expected_identity && copyins==expected_copyin &&
        copyouts==expected_copyout && parses==expected_parses+(call==90 && caller==&process?1u:0u));
    bool traced=call==90 && caller==&process && present[6] && values[6]==1;
    assert(trace_calls==unsigned(traced) && boundaries==unsigned(traced) && names==unsigned(traced));
    if(traced) {
        assert(trace_pid==(caller?caller->pid:0) && trace_uid==(caller?caller->uid:~0u));
        bool valid=caller==&process && identity;
        for(int i=0;i<7;i++)valid=valid && (present[i]?values[i]:0)==(i==1?3:i==3?0:1);
        assert(trace_flags==(valid?0x22u:0u) && trace_error==result);
        assert(trace_stage==(valid?(copyin_error?2u:args[1]?4u:3u):1u));
    }
    assert(written==(result==0?0x22:0xfeedbeefcafef00dull));cases++;
}
int main()
{
    reset();check(&process,90,0,1,1,1,7);
    reset();check(nullptr,90,ENOPOLICY,0,0,0,0);
    reset();check(&other,90,ENOPOLICY,0,0,0,0);
    for(int call:{0,89,91,-1}){reset();check(&process,call,ENOPOLICY,0,0,0,0);}
    reset();identity=false;check(&process,90,ENOPOLICY,1,0,0,7);
    for(int index=0;index<7;index++) {
        reset();present[index]=false;
        if(index==3)check(&process,90,0,1,1,1,7);
        else check(&process,90,ENOPOLICY,0,0,0,7);
        for(int value:{-1,0,1,2,3,4}) {
            reset();values[index]=value;
            bool valid=value==(index==1?3:index==3?0:1);
            check(&process,90,valid?0:ENOPOLICY,valid?1:0,valid?1:0,valid?1:0,7);
        }
    }
    reset();for(bool &v:present)v=false;check(&process,90,ENOPOLICY,0,0,0,7);
    reset();copyin_error=true;check(&process,90,EFAULT,1,1,0,7);
    reset();args[1]=0;check(&process,90,EFAULT,1,1,0,7);
    reset();copyout_error=5;check(&process,90,5,1,1,1,7);
    for(uint64_t input:{2ull,4ull,6ull,~0ull}) {
        reset();args[0]=input;check(&process,90,0,1,1,1,7);
    }
    assert(cases==65);
    reset();process.uid=0;
    for(unsigned i=1;i<=32;i++)assert(santoni_gpu_dyld_trace_begin(&process,0)==i);
    assert(!santoni_gpu_dyld_trace_begin(&process,0) && !santoni_gpu_dyld_trace_begin(&process,1));
    process.uid=501;
    for(unsigned i=1;i<=32;i++)assert(santoni_gpu_dyld_trace_begin(&process,0)==64+i);
    assert(!santoni_gpu_dyld_trace_begin(&process,0));
    for(unsigned i=1;i<=32;i++)assert(santoni_gpu_dyld_trace_begin(&process,1)==128+i);
    for(unsigned i=0;i<128;i++)assert(!santoni_gpu_dyld_trace_begin(&process,1));
    assert(boundaries==96 && names==96 && !trace_calls);
    reset();reject_cas=true;assert(!santoni_gpu_dyld_trace_begin(&process,0) && !boundaries);
    reject_cas=false;diagnostic_name="Bad%\n\x01Name0123456789";
    assert(santoni_gpu_dyld_trace_begin(&process,0)==65 && boundaries==1 && names==1);
    assert(!santoni_gpu_dyld_trace_begin(&process,2));
    printf("passed %u dyld policy contract cases; bounded trace checks passed\n",cases);
}
