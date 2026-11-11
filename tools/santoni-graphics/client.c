#include "client.h"
#include <limits.h>
#include <string.h>
_Static_assert(sizeof(struct sgpu_graphics_wire_submit)==336,"graphics submit wire ABI must remain pointer-free v1");
static bool live(const struct sgfx_client *c)
{return c && c->initialized && !c->failed && !c->closed;}
static bool failed(struct sgfx_client *c) {c->failed=true;return false;}
static struct sgfx_bo *lookup(struct sgfx_client *c,uint32_t handle)
{
    for(unsigned i=0;i<SGPU_GRAPHICS_UAPI_HANDLES;i++)if(c->bo[i].handle==handle && handle)return &c->bo[i];
    return NULL;
}
static bool call(struct sgfx_client *c,uint32_t selector,const uint64_t *in,uint32_t ni,
    uint64_t *out,uint32_t no,const void *wire,size_t bytes)
{return c->transport.call(c->transport.context,selector,in,ni,out,no,wire,bytes) || failed(c);}
bool sgfx_init(struct sgfx_client *c,const struct sgfx_transport *transport)
{
    if(!c || !transport || !transport->call || !transport->map || !transport->unmap || !transport->close ||
        c->initialized || c->closed || c->failed)return false;
    c->transport=*transport;
    if(!call(c,SG_GFX_INFO,NULL,0,c->info,10,NULL,0))return false;
    if(c->info[0]!=SGPU_GRAPHICS_UAPI_VERSION || c->info[1]!=4096 || !c->info[2] || !c->info[3] ||
        !c->info[4] || c->info[4]>UINT32_MAX || c->info[5]<3*4096 || c->info[5]>UINT32_MAX-c->info[4] ||
        !c->info[6] || c->info[6]>c->info[5]-2*4096 || !c->info[7] || c->info[7]>c->info[6])return failed(c);
    c->initialized=true;return true;
}
struct sgfx_bo *sgfx_new(struct sgfx_client *c,uint32_t bytes,uint32_t flags)
{
    if(!live(c) || !bytes || bytes>c->info[6] || (flags!=SGFX_READ && flags!=SGFX_WRITE) ||
        c->submitted!=c->completed)return NULL;
    unsigned slot=0;while(slot<SGPU_GRAPHICS_UAPI_HANDLES && c->bo[slot].handle)slot++;
    if(slot==SGPU_GRAPHICS_UAPI_HANDLES)return NULL;
    uint64_t input[2]={bytes,flags},output[4]={};
    if(!call(c,SG_GFX_NEW,input,2,output,4,NULL,0))return NULL;
    uint64_t page=c->info[1],rounded=((uint64_t)bytes+page-1)&~(page-1);
    if(!output[0] || output[0]>UINT32_MAX || lookup(c,(uint32_t)output[0]) || output[3]!=output[0] ||
        output[2]!=bytes || output[1]<c->info[4]+page || output[1]>c->info[4]+c->info[5]-rounded-page ||
        (output[1]&(page-1))) {failed(c);return NULL;}
    for(unsigned i=0;i<SGPU_GRAPHICS_UAPI_HANDLES;i++)if(c->bo[i].handle) {
        uint64_t old=c->bo[i].gpu_va,span=((uint64_t)c->bo[i].bytes+page-1)&~(page-1);
        if(output[1]<old+span+page && old<output[1]+rounded+page) {failed(c);return NULL;}
    }
    /* Preserve the kernel lease before a failed/malformed mapping response. */
    struct sgfx_bo *bo=&c->bo[slot];*bo=(struct sgfx_bo){(uint32_t)output[0],(uint32_t)output[1],bytes,flags,NULL};
    uint64_t length=0;
    if(!c->transport.map(c->transport.context,bo->handle,&bo->cpu,&length) || !bo->cpu ||
        ((uintptr_t)bo->cpu&(page-1)) || length!=rounded || (uintptr_t)bo->cpu>UINTPTR_MAX-rounded) {
        failed(c);return NULL;
    }
    return bo;
}
bool sgfx_wait(struct sgfx_client *c,uint32_t sequence)
{
    if(!live(c) || !sequence || sequence>c->submitted)return false;
    if(sequence<=c->completed)return true;
    uint64_t input=sequence;
    if(!call(c,SG_GFX_WAIT,&input,1,NULL,0,NULL,0))return false;
    c->completed=sequence;return true;
}
bool sgfx_cpu_prep(struct sgfx_client *c,uint32_t handle)
{
    if(!live(c) || !lookup(c,handle))return false;
    if(c->submitted!=c->completed && !sgfx_wait(c,c->submitted))return false;
    uint64_t input=handle;return call(c,SG_GFX_CPU_PREP,&input,1,NULL,0,NULL,0);
}
bool sgfx_free(struct sgfx_client *c,uint32_t handle)
{
    if(!live(c))return false;
    struct sgfx_bo *bo=lookup(c,handle);
    if(!bo || (c->submitted!=c->completed && !sgfx_wait(c,c->submitted)))return false;
    uint64_t input=handle;
    if(!call(c,SG_GFX_FREE,&input,1,NULL,0,NULL,0))return false;
    if(bo->cpu)c->transport.unmap(c->transport.context,handle,bo->cpu);
    memset(bo,0,sizeof(*bo));return true;
}
uint32_t sgfx_submit(struct sgfx_client *c,const struct sgpu_graphics_wire_ib *ibs,uint32_t ni,
    const uint32_t *handles,uint32_t nb)
{
    if(!live(c) || !ibs || !handles || !ni || ni>SGPU_GRAPHICS_UAPI_IBS || !nb ||
        nb>SGPU_GRAPHICS_UAPI_HANDLES || c->submitted==UINT32_MAX || c->submitted!=c->completed)return 0;
    for(unsigned i=0;i<nb;i++) {
        if(!lookup(c,handles[i]))return 0;
        for(unsigned j=0;j<i;j++)if(handles[i]==handles[j])return 0;
    }
    for(unsigned i=0;i<ni;i++) {
        struct sgfx_bo *bo=lookup(c,ibs[i].handle);bool listed=false;
        for(unsigned j=0;j<nb;j++)if(handles[j]==ibs[i].handle)listed=true;
        if(!bo || !listed || bo->bytes>c->info[7] || !ibs[i].bytes || ((ibs[i].offset|ibs[i].bytes)&3) ||
            ibs[i].offset>bo->bytes || ibs[i].bytes>bo->bytes-ibs[i].offset)return 0;
    }
    struct sgpu_graphics_wire_submit wire={0};wire.version=SGPU_GRAPHICS_UAPI_VERSION;wire.ibs=ni;wire.handles=nb;
    memcpy(wire.ib,ibs,ni*sizeof(*ibs));memcpy(wire.handle,handles,nb*sizeof(*handles));
    uint64_t output=0;
    if(!call(c,SG_GFX_SUBMIT,NULL,0,&output,1,&wire,sizeof(wire)))return 0;
    if(output!=c->submitted+1ull) {failed(c);return 0;}
    c->submitted=(uint32_t)output;return c->submitted;
}
void sgfx_close(struct sgfx_client *c)
{
    if(!c || c->closed || !c->transport.close)return;
    /* Closing userspace aliases cannot free a potentially live GPU allocation.
     * The kernel's close contract independently waits or quarantines backing. */
    for(unsigned i=0;i<SGPU_GRAPHICS_UAPI_HANDLES;i++)if(c->bo[i].cpu)
        c->transport.unmap(c->transport.context,c->bo[i].handle,c->bo[i].cpu);
    c->transport.close(c->transport.context);c->closed=true;
}
