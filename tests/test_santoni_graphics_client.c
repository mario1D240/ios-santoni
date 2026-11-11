/* Actual userspace transport with a modeled IOKit peer; no GPU execution. */
#define _POSIX_C_SOURCE 200112L
#include "client.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct peer {
    unsigned scenario,calls[8],maps,unmaps,closes,next;
    uint8_t *memory[4];
};
static bool call(void *ctx,uint32_t selector,const uint64_t *in,uint32_t ni,uint64_t *out,uint32_t no,
    const void *wire,size_t bytes)
{
    struct peer *p=ctx;assert(selector<8);p->calls[selector]++;
    if(selector==SG_GFX_INFO) {
        assert(!ni && no==10 && !wire && !bytes);
        uint64_t values[10]={1,4096,0x05000500,136*1024,0x1200000,8*1024*1024,3840*1024,64*1024,0,0};
        memcpy(out,values,sizeof(values));if(p->scenario==1)out[0]++;if(p->scenario==2)out[1]=16384;
        return true;
    }
    if(selector==SG_GFX_NEW) {
        assert(ni==2 && no==4 && !bytes && in[0] && (in[1]==SGFX_READ || in[1]==SGFX_WRITE));
        unsigned handle=++p->next;assert(handle<4);
        out[0]=handle;out[1]=0x1200000+handle*2*4096;out[2]=in[0];out[3]=handle;
        if(p->scenario==3)out[2]++;
        if(p->scenario==4)out[3]++;
        if(p->scenario==5)out[1]=0x1200000;
        if(p->scenario==6 && handle==2)out[1]=0x1200000+2*4096;
        return true;
    }
    if(selector==SG_GFX_SUBMIT) {
        assert(!ni && no==1 && bytes==sizeof(struct sgpu_graphics_wire_submit));
        const struct sgpu_graphics_wire_submit *r=wire;
        assert(r && r->version==1 && r->ibs==1 && r->handles==2 && !r->reserved);
        for(unsigned i=1;i<SGPU_GRAPHICS_UAPI_IBS;i++)assert(!r->ib[i].handle && !r->ib[i].offset && !r->ib[i].bytes);
        for(unsigned i=2;i<SGPU_GRAPHICS_UAPI_HANDLES;i++)assert(!r->handle[i]);
        out[0]=p->calls[selector]+(p->scenario==9);return true;
    }
    assert(ni==1 && !no && !bytes && in[0] && !wire);
    return !(p->scenario==10 && selector==SG_GFX_WAIT);
}
static bool map(void *ctx,uint32_t handle,uint8_t **out,uint64_t *length)
{
    struct peer *p=ctx;assert(handle<4);p->maps++;
    if(p->scenario==7)return false;
    assert(!posix_memalign((void **)&p->memory[handle],4096,4096));
    *out=p->memory[handle];*length=p->scenario==8?16384:4096;return true;
}
static void unmap(void *ctx,uint32_t handle,uint8_t *address)
{struct peer *p=ctx;assert(address==p->memory[handle]);p->unmaps++;}
static void close_peer(void *ctx){((struct peer *)ctx)->closes++;}
int main(int argc,char **argv)
{
    assert(argc==2);struct peer p={.scenario=(unsigned)strtoul(argv[1],NULL,10)};assert(p.scenario<15);
    struct sgfx_transport transport={&p,call,map,unmap,close_peer};struct sgfx_client c={0};
    bool initialized=sgfx_init(&c,&transport);
    if(p.scenario==1 || p.scenario==2) {assert(!initialized && c.failed);goto done;}
    assert(initialized && !c.info[9]);
    assert(!sgfx_new(&c,0,SGFX_READ) && !sgfx_new(&c,UINT32_MAX,SGFX_READ) && !sgfx_new(&c,16,3));
    assert(!p.calls[SG_GFX_NEW]);
    struct sgfx_bo *command=sgfx_new(&c,16,SGFX_READ);
    if((p.scenario>=3 && p.scenario<=5) || p.scenario==7 || p.scenario==8) {assert(!command && c.failed);goto done;}
    assert(command);struct sgfx_bo *data=sgfx_new(&c,128,SGFX_WRITE);
    if(p.scenario==6) {assert(!data && c.failed);goto done;}
    assert(data);
    struct sgpu_graphics_wire_ib ib={command->handle,0,16};uint32_t handles[2]={command->handle,data->handle};
    if(p.scenario==11)ib.offset=4;
    if(p.scenario==12)handles[1]=handles[0];
    if(p.scenario==13)ib.handle=99;
    if(p.scenario==14)ib.bytes=UINT32_MAX;
    uint32_t sequence=sgfx_submit(&c,&ib,1,handles,2);
    if(p.scenario>=11) {assert(!sequence && !p.calls[SG_GFX_SUBMIT] && !c.failed);goto done;}
    if(p.scenario==9) {assert(!sequence && c.failed);goto done;}
    assert(sequence==1 && c.submitted==1 && !c.completed);
    assert(!sgfx_submit(&c,&ib,1,handles,2) && p.calls[SG_GFX_SUBMIT]==1);
    assert(!sgfx_new(&c,16,SGFX_READ));
    if(p.scenario==10) {assert(!sgfx_free(&c,data->handle) && c.failed && !p.calls[SG_GFX_FREE]);goto done;}
    assert(sgfx_wait(&c,sequence) && c.completed==1 && sgfx_cpu_prep(&c,data->handle));
    assert(sgfx_free(&c,command->handle) && sgfx_free(&c,data->handle) && p.unmaps==2);
done:
    sgfx_close(&c);sgfx_close(&c);assert(p.closes==1 && c.closed);
    assert(!sgfx_new(&c,16,SGFX_READ) && !sgfx_wait(&c,1));
    for(unsigned i=0;i<4;i++)free(p.memory[i]);
    printf("PASS actual userspace client case=%u; IOKit peer modeled, no GPU claim\n",p.scenario);return 0;
}
