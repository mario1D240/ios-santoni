/* HOST-ONLY memory transport. Never link into a phone library or kernel.
 * Actual client/MSM/Mesa code runs above it; no GPU or IOKit is accessed. */
#define _POSIX_C_SOURCE 200809L
#include "santoni_drm.h"
#include "santoni_gpu_core.h"
#include "santoni_gpu_graphics.h"
#include <stdlib.h>
#include <string.h>
struct model_bo {uint32_t handle,va,bytes,pages;uint8_t *cpu;bool live;};
static struct model_bo buffers[SGPU_GRAPHICS_BOS];
static bool pages[SGPU_RENDER_MAX_PAGES];
static uint32_t next_handle=1;
static struct model_bo *find(uint32_t handle)
{for(unsigned i=0;i<SGPU_GRAPHICS_BOS;i++)if(buffers[i].handle==handle && handle)return &buffers[i];return NULL;}
static bool model_call(void *context,uint32_t selector,const uint64_t *in,uint32_t ni,
    uint64_t *out,uint32_t no,const void *wire,size_t size)
{
    (void)context;if(wire || size)return false;
    switch(selector) {
    case SG_GFX_INFO:
        if(ni || no!=10)return false;
        memset(out,0,10*sizeof(*out));out[0]=SGPU_GRAPHICS_UAPI_VERSION;out[1]=SGPU_PAGE;
        out[2]=0x05000500;out[3]=SGPU_GMEM_BYTES;out[4]=SGPU_RENDER_VA;
        out[5]=SGPU_RENDER_MAX_PAGES*SGPU_PAGE;out[6]=out[5]-2*SGPU_PAGE;
        out[7]=SGPU_GRAPHICS_IB_BYTES;out[9]=1; /* MODELED admission, never a hardware gate. */
        return true;
    case SG_GFX_NEW: {
        if(ni!=2 || no!=4 || !in[0] || in[0]>SGPU_RENDER_MAX_PAGES*SGPU_PAGE-2*SGPU_PAGE ||
            (in[1]!=SGFX_READ && in[1]!=SGFX_WRITE) || next_handle==UINT32_MAX)return false;
        unsigned slot=0;while(slot<SGPU_GRAPHICS_BOS && buffers[slot].cpu)slot++;
        if(slot==SGPU_GRAPHICS_BOS)return false;
        uint32_t count=((uint32_t)in[0]+SGPU_PAGE-1)/SGPU_PAGE,first=1;
        for(;first+count<SGPU_RENDER_MAX_PAGES;first++) {
            unsigned i=0;while(i<=count && !pages[first+i])i++;
            if(i>count)break;
        }
        if(first+count>=SGPU_RENDER_MAX_PAGES)return false;
        void *allocation=NULL;if(posix_memalign(&allocation,SGPU_PAGE,(size_t)count*SGPU_PAGE))return false;
        uint8_t *cpu=allocation;
        memset(cpu,0,(size_t)count*SGPU_PAGE);
        for(unsigned i=0;i<=count;i++)pages[first+i]=true; /* Unmapped modeled guard included. */
        struct model_bo *b=&buffers[slot];*b=(struct model_bo){next_handle++,SGPU_RENDER_VA+first*SGPU_PAGE,
            (uint32_t)in[0],count,cpu,true};
        out[0]=b->handle;out[1]=b->va;out[2]=b->bytes;out[3]=b->handle;return true;
    }
    case SG_GFX_FREE: {
        if(ni!=1 || no || in[0]>UINT32_MAX)return false;
        struct model_bo *b=find((uint32_t)in[0]);if(!b || !b->live)return false;
        unsigned first=(b->va-SGPU_RENDER_VA)/SGPU_PAGE;
        for(unsigned i=0;i<=b->pages;i++)pages[first+i]=false;
        b->live=false;return true;
    }
    case SG_GFX_CPU_PREP:
        return ni==1 && !no && in[0]<=UINT32_MAX && find((uint32_t)in[0])!=NULL;
    /* The capture submitter supplies its own explicitly modeled completion.
     * Any accidental normal submit/wait path is refused. */
    default:return false;
    }
}
static bool model_map(void *context,uint32_t handle,uint8_t **cpu,uint64_t *size)
{(void)context;struct model_bo *b=find(handle);if(!b || !b->live)return false;*cpu=b->cpu;*size=(uint64_t)b->pages*SGPU_PAGE;return true;}
static void model_unmap(void *context,uint32_t handle,uint8_t *cpu)
{
    (void)context;struct model_bo *b=find(handle);if(!b || b->cpu!=cpu)abort();
    if(b->live) {unsigned first=(b->va-SGPU_RENDER_VA)/SGPU_PAGE;for(unsigned i=0;i<=b->pages;i++)pages[first+i]=false;}
    free(b->cpu);memset(b,0,sizeof(*b));
}
static void model_close(void *context) {(void)context;}
bool sgfx_ios_connect(struct sgfx_transport *transport)
{if(!transport)return false;*transport=(struct sgfx_transport){NULL,model_call,model_map,model_unmap,model_close};return true;}
/* Both facade roles use this same HOST-ONLY memory provider. This models
 * renderer selection; it never opens an IOKit client or supplies a phone gate. */
bool sgfx_ios_connect_renderer(struct sgfx_transport *transport)
{return sgfx_ios_connect(transport);}
