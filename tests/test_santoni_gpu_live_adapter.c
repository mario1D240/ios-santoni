/* Actual adapter allocation/options/worker/dispatch; kernel primitives and
 * the separately proved live-core boundary are modeled here. */
#define _POSIX_C_SOURCE 200112L
#include "santoni_gpu_core.h"
#include "santoni_gpu_graphics_hw.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uintptr_t vm_offset_t;
typedef unsigned ppnum_t;
typedef uint64_t addr64_t;
typedef void *DTEntry;
typedef int wait_result_t;
#ifndef __unused
#define __unused __attribute__((unused))
#endif
#define KERN_SUCCESS 0
#define KMA_DATA 1
#define KMA_ZERO 2
#define VM_KERN_MEMORY_IOKIT 3
#define kSuccess 0
static void *kernel_map=(void *)0x11,*kernel_pmap=(void *)0x22;
static int page_shift=12;
static uint64_t page_size=SGPU_PAGE;
#define LCK_MTX_DECLARE(name,group) int name
static unsigned ui_lock_depth;
static void lck_mtx_lock(int *lock){(void)lock;assert(!ui_lock_depth);ui_lock_depth++;}
static void lck_mtx_unlock(int *lock){(void)lock;assert(ui_lock_depth==1);ui_lock_depth--;}
/* This legacy worker harness explicitly keeps the new UI role disabled.
 * Actual UI admission/import/publication is exercised by the UI suite. */
bool sgpu_ui_start(uint32_t on){(void)on;assert(!"legacy UI role must stay disabled");return false;}
int sgpu_ui_copy(const struct sgpu_ui_image *s,const uint8_t **out,uint32_t *stride){
    (void)s;(void)out;(void)stride;assert(!"legacy UI role must stay disabled");return 0;
}
bool sgpu_ui_frame(const uint8_t **out,uint32_t *stride){
    (void)out;(void)stride;assert(!"legacy UI role must stay disabled");return false;
}
void sgpu_ui_snapshot(struct sgpu_ui_result *out){
    (void)out;assert(!"legacy UI role must stay disabled");
}
static unsigned testcase,allocs,frees,translations,core_calls,probes,sessions,loops,terminations;
/* The new graphics transport is absent from this legacy/UI adapter fixture. */
bool sgpu_graphics_hw_begin(uint32_t mode,uint32_t enabled){(void)mode;(void)enabled;assert(!"graphics VM reached legacy fixture");return false;}
bool sgpu_graphics_hw_begin_vm(uint32_t mode,uint32_t enabled,const struct gvm_memory *memory,const struct gvm_ops *ops){
    (void)mode;(void)enabled;(void)memory;(void)ops;assert(!"wide graphics VM reached legacy fixture");return false;
}
bool sgpu_graphics_hw_legacy_reserved(uint64_t pa){(void)pa;assert(!"graphics PA query reached legacy fixture");return false;}
void sgpu_graphics_hw_snapshot(struct sgpu_graphics_hw_result *out){(void)out;assert(!"graphics snapshot reached legacy fixture");}
static struct { uintptr_t va;size_t bytes; } allocation[2];
static uint8_t firmware[64];

static int kmem_alloc(void *map,vm_offset_t *out,size_t bytes,unsigned flags,unsigned tag)
{
    assert(map==kernel_map && flags==(KMA_DATA|KMA_ZERO) && tag==VM_KERN_MEMORY_IOKIT);
    unsigned index=allocs++;assert(index<2);
    if((testcase==1 && index==0)||(testcase==2 && index==1))return 1;
    void *p=NULL;assert(!posix_memalign(&p,SGPU_PAGE,bytes));memset(p,0,bytes);
    allocation[index].va=(uintptr_t)p;allocation[index].bytes=bytes;*out=(uintptr_t)p;return 0;
}
static void kmem_free(void *map,vm_offset_t addr,size_t bytes)
{
    assert(map==kernel_map);
    for(unsigned i=0;i<2;i++)if(allocation[i].va==addr) {
        assert(allocation[i].bytes==bytes);free((void *)addr);allocation[i].va=0;frees++;return;
    }
    assert(!"free did not belong to this allocation");
}
static ppnum_t pmap_find_phys(void *pmap,addr64_t va)
{
    assert(pmap==kernel_pmap);translations++;
    for(unsigned i=0;i<2;i++)if(va>=allocation[i].va && va-allocation[i].va<allocation[i].bytes) {
        unsigned page=(unsigned)((va-allocation[i].va)/SGPU_PAGE);
        uint64_t pa=(i?0xa1000000ull:0xa0000000ull)+page*2*SGPU_PAGE;
        if(i && page==SGPU_RENDER_LIVE_PAGES-1 && testcase==3)return 0;
        if(i && page==SGPU_RENDER_LIVE_PAGES-1 && testcase==4)pa-=2*SGPU_PAGE;
        if(i && !page && testcase==5)pa=0xa0000000;
        if(i && page==SGPU_RENDER_LIVE_PAGES-1 && testcase==6)pa=SGPU_DMA_END;
        return (ppnum_t)(pa>>12);
    }
    assert(!"pmap looked outside an owned span");return 0;
}

static bool PE_parse_boot_argn(const char *name,void *out,int bytes)
{
    assert(bytes==4);uint32_t value=0;
    if(!strcmp(name,"santonigpu_render"))value=testcase==11?2:(testcase==10 || testcase==31?0:1);
    else if(!strcmp(name,"santonigpu_stock") || !strcmp(name,"santonigpu_pixels") ||
            !strcmp(name,"santonigpu_submit") || !strcmp(name,"santonigpu_session"))value=testcase==31?0:1;
    else if(!strcmp(name,"santonigpu_graphics"))value=0;
    else if(!strcmp(name,"santonigpu_user"))value=testcase==12?1:0;
    else if(!strcmp(name,"santonigpu_user_test"))value=testcase==13?1:0;
    else if(!strcmp(name,"santonigpu_user_exec"))value=testcase==14?1:0;
    else if(!strcmp(name,"santonigpu_zap"))value=testcase==15?1:0;
    else if(!strcmp(name,"santonigpu_scm"))value=testcase==16?1:0;
    else if(!strcmp(name,"santonigpu_cache"))value=testcase==17?1:0;
    else if(!strcmp(name,"santonigpu_ui"))value=0;
    else assert(!"unreviewed option parser");
    memcpy(out,&value,4);return true;
}
static void sgpu_failure_summary(const char *name,const struct sgpu_failure *failure)
{ assert(name && failure); }
bool sgpu_render_live_start(const struct sgpu_ops *ops,uint32_t mode,uint32_t enabled,
    const uint8_t *fw,size_t bytes,const struct sgpu_render_memory *memory,
    struct sgpu_report *boot,struct sgpu_render_live_result *result)
{
    assert(ops && mode==3 && enabled==1 && fw==firmware && bytes==64 && memory && boot && result);
    assert(memory->pages==1920 && memory->tables==(uint8_t *)allocation[0].va &&
        memory->pixels==(uint8_t *)allocation[1].va && sgpu_render_validate(memory));
    core_calls++;boot->memory_retained=true;
    *result=(struct sgpu_render_live_result){.requested=true,.started=true,
        .exposed=testcase==7 || testcase==8,.passed=testcase==8,.phase=SG_LIVE_DONE,
        .submitted=2,.completed=2,.sequence=2,.wptr=316,.pixels=1843200};
    return testcase==8;
}
static bool santoni_gpu_user_launch_options_ok(uint32_t mode){(void)mode;return true;}
static bool santoni_gpu_user_launch_worker_ready(uint32_t mode){(void)mode;return true;}
static void sgpu_kernel_wait_us(void *ctx,uint32_t us){(void)ctx;(void)us;}
static void thread_terminate_self(void){terminations++;}
static bool sgpu_pas_cache_preflight(uint32_t mode){(void)mode;return false;}
static bool sgpu_scm_capability_probe(uint32_t mode){(void)mode;return false;}
static void sgpu_zap_allocation_preflight(uint32_t mode){(void)mode;}
static int SecureDTLookupEntry(void *x,const char *name,DTEntry *out)
{assert(!x && !strcmp(name,"/chosen"));*out=(void *)0x33;return 0;}
static int SecureDTGetProperty(DTEntry x,const char *name,const void **out,unsigned *bytes)
{assert(x==(void *)0x33 && !strcmp(name,"santoni-gpu-firmware"));*out=firmware;*bytes=64;return 0;}
static bool io_map(void *ctx,enum sgpu_block block,uint32_t pa,uint32_t bytes)
{(void)ctx;(void)block;(void)pa;(void)bytes;assert(!"adapter-route fixture must not map MMIO");return false;}
static uint32_t sgpu_io_read32(void *ctx,enum sgpu_block block,uint32_t off)
{(void)ctx;(void)block;(void)off;assert(!"unexpected MMIO");return 0;}
static uint64_t sgpu_io_read64(void *ctx,enum sgpu_block block,uint32_t off)
{return sgpu_io_read32(ctx,block,off);}
static void sgpu_io_write32(void *ctx,enum sgpu_block block,uint32_t off,uint32_t value)
{(void)value;(void)sgpu_io_read32(ctx,block,off);}
static void sgpu_io_write64(void *ctx,enum sgpu_block block,uint32_t off,uint64_t value)
{(void)value;(void)sgpu_io_read32(ctx,block,off);}
static uint64_t now_us(void *ctx){(void)ctx;return 0;}
static bool allocate(void *ctx,struct sgpu_memory *m){(void)ctx;(void)m;assert(!"unexpected bootstrap allocate");return false;}
static void release(void *ctx,struct sgpu_memory *m){(void)ctx;(void)m;}
static void clean(void *ctx,const void *p,uint32_t n){(void)ctx;(void)p;(void)n;}
static void sgpu_cache_invalidate(void *ctx,const void *p,uint32_t n){clean(ctx,p,n);}
static void trace(void *ctx,const char *s,uint32_t a,uint32_t b,uint32_t c)
{(void)ctx;(void)s;(void)a;(void)b;(void)c;}
bool sgpu_session_start(const struct sgpu_ops *ops,uint32_t mode,const uint8_t *fw,size_t n,struct sgpu_report *r)
{(void)ops;(void)mode;(void)fw;(void)n;(void)r;sessions++;return false;}
bool sgpu_probe(const struct sgpu_ops *ops,uint32_t mode,const uint8_t *fw,size_t n,struct sgpu_report *r)
{(void)ops;(void)mode;(void)fw;(void)n;(void)r;probes++;return true;}
static void sgpu_session_loop(void){loops++;}
void sgpu_session_failure_result(struct sgpu_session_result *r){memset(r,0,sizeof(*r));}

#include "santoni_gpu_live_adapter_actual.h"

int main(int argc,char **argv)
{
    assert(argc==2);testcase=(unsigned)strtoul(argv[1],NULL,10);
    sg.mode=testcase==31?1:testcase==18?2:3;
    sg.stock_unsecure=sg.stock_pixels=sg.g3=sg.session=1;
    sg.user=testcase==12;sg.user_test=testcase==13;
    if(testcase>=30) {
        sgpu_kernel_thread(NULL,0);
        assert(terminations==1);
        if(testcase==31)assert(probes==1 && !sessions && !core_calls && !allocs);
        else assert(core_calls==1 && !probes && !sessions && !loops);
    } else {
        bool role=sgpu_render_options(sg.mode);
        bool valid=!(testcase>=11 && testcase<=18);
        assert(role==valid && sgpu_render_enabled==(valid && testcase!=10));
        if(testcase==19)page_shift=14;
        if(testcase==20)page_size=16384;
        struct sgpu_ops ops={0};struct sgpu_report boot={0};
        sgpu_render_worker(&ops,firmware,64,&boot);
        if(!valid || testcase==10 || testcase==19 || testcase==20)assert(!allocs && !translations && !core_calls);
        else if(testcase>=1 && testcase<=6)assert(!core_calls && !sgpu_render_pixels_kva && !sgpu_render_tables_kva);
        else {
            assert(core_calls==1 && allocs==2 && translations==1927);
            if(testcase==7 || testcase==8) {
                assert(sgpu_render_allocation_retained && !frees);
                sgpu_render_release();assert(!frees && sgpu_render_pixels_kva);
            } else assert(frees==2 && !sgpu_render_pixels_kva && !sgpu_render_tables_kva);
        }
        unsigned before=allocs;assert(!sgpu_render_allocate());assert(allocs==before);
    }
    for(unsigned i=0;i<2;i++)if(allocation[i].va)free((void *)allocation[i].va); /* host fixture only */
    printf("PASS live adapter case=%u allocations=%u frees=%u core_calls=%u; route/ownership model only\n",testcase,allocs,frees,core_calls);
    return 0;
}
