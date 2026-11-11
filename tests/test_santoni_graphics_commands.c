/* Actual userspace command packaging + actual kernel PM4 validation.
 * IOKit, allocation, and execution/readback are explicitly CPU models. */
#define _POSIX_C_SOURCE 200112L
#include "commands.h"
#include "santoni_gpu_pm4.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct peer_bo {uint32_t handle,va,bytes,flags;uint8_t *memory;bool live;};
struct peer {struct peer_bo bo[64];unsigned next,submits,frees,writes,scenario;uint32_t sequence;};
static struct peer_bo *bo(struct peer *p,uint32_t handle)
{for(unsigned i=0;i<p->next;i++)if(p->bo[i].handle==handle)return &p->bo[i];return NULL;}
static uint32_t packet7(uint32_t op,uint32_t count)
{unsigned a=1,b=1;for(unsigned n=op;n;n>>=1)a^=n&1;for(unsigned n=count;n;n>>=1)b^=n&1;return 0x70000000|(op<<16)|(a<<23)|count|(b<<15);}
static const uint32_t *private_words(const struct sgpu_graphics_snapshot *s,unsigned ns,uint32_t va,uint32_t bytes)
{
    for(unsigned i=0;i<ns;i++)if(va>=s[i].gpu_va && va-s[i].gpu_va<=s[i].bytes && bytes<=s[i].bytes-(va-s[i].gpu_va))
        return s[i].words+(va-s[i].gpu_va)/4;
    assert(false);return NULL;
}
static void execute(struct peer *p,const struct sgpu_graphics_snapshot *s,unsigned ns,uint32_t va,uint32_t bytes,unsigned depth)
{
    assert(depth<8);const uint32_t *words=private_words(s,ns,va,bytes);
    for(unsigned i=0;i<bytes/4;) {
        uint32_t h=words[i++],n=h&0x3fff,op=(h>>16)&127;assert((h>>28)==7 && n<=bytes/4-i);
        if(op==0x3f || op==0x37)execute(p,s,ns,words[i],words[i+2]*4,depth+1);
        else if(op==0x3d) {
            assert(n==3 && !words[i+1]);bool written=false;
            for(unsigned j=0;j<p->next;j++)if(p->bo[j].live && p->bo[j].flags==SGFX_WRITE && words[i]>=p->bo[j].va && words[i]-p->bo[j].va<=p->bo[j].bytes-4) {
                memcpy(p->bo[j].memory+words[i]-p->bo[j].va,&words[i+2],4);written=true;p->writes++;break;
            }
            assert(written);
        } else if(op==0x43) {
            /* Draw-state installation is validated here; no draw is modeled. */
            for(unsigned j=0;j<n;j+=3)if(words[i+j]&0xffff)
                assert(private_words(s,ns,words[i+j+1],(words[i+j]&0xffff)*4));
        } else assert(op==0x10);
        i+=n;
    }
}
static bool submit(struct peer *p,const struct sgpu_graphics_wire_submit *request)
{
    p->submits++;assert(request->version==1 && !request->reserved && request->ibs<=8 && request->handles<=56);
    struct sgpu_graphics_snapshot snapshots[8]={0};struct sgpu_graphics_command roots[8]={0};struct sgpu_graphics_range ranges[56]={0};unsigned ns=0;
    for(unsigned i=0;i<request->handles;i++) {
        struct peer_bo *b=bo(p,request->handle[i]);assert(b && b->live);
        ranges[i]=(struct sgpu_graphics_range){b->handle,b->va,b->bytes,b->flags};
    }
    for(unsigned i=0;i<request->ibs;i++) {
        struct peer_bo *b=bo(p,request->ib[i].handle);assert(b && b->live && b->handle>3 && b->flags==SGFX_READ);
        unsigned index=0;for(;index<ns;index++)if(snapshots[index].source_va==b->va)break;
        if(index==ns) {
            uint32_t *copy=malloc(b->bytes);assert(copy);memcpy(copy,b->memory,b->bytes);
            snapshots[ns]=(struct sgpu_graphics_snapshot){b->va,SGPU_RENDER_VA+0x400000+ns*0x10000,b->bytes,copy};ns++;
        }
        roots[i]=(struct sgpu_graphics_command){snapshots[index].gpu_va+request->ib[i].offset,request->ib[i].bytes};
    }
    struct sgpu_pm4_policy policy={0};
    bool valid=sgpu_pm4_prepare(&policy,snapshots,ns,roots,request->ibs,ranges,request->handles) &&
        sgpu_pm4_validate(&policy,snapshots,ns,roots,request->ibs,ranges,request->handles);
    if(valid) {
        /* An original command rewrite after validation cannot affect mirrors
         * or the kernel's separately copied/relocated private snapshots. */
        memset(p->bo[0].memory,0xff,p->bo[0].bytes);
        for(unsigned i=0;i<request->ibs;i++)execute(p,snapshots,ns,roots[i].gpu_va,roots[i].bytes,0);
    }
    for(unsigned i=0;i<ns;i++)free(snapshots[i].words);
    return valid;
}
static bool call(void *ctx,uint32_t selector,const uint64_t *in,uint32_t ni,uint64_t *out,uint32_t no,const void *wire,size_t bytes)
{
    struct peer *p=ctx;
    if(selector==SG_GFX_INFO) {uint64_t info[10]={1,4096,0x05000500,139264,SGPU_RENDER_VA,0x800000,3932160,65536,0,0};assert(!ni && no==10);memcpy(out,info,sizeof(info));return true;}
    if(selector==SG_GFX_NEW) {
        assert(ni==2 && no==4 && p->next<64);struct peer_bo *b=&p->bo[p->next];
        b->handle=++p->next;b->va=SGPU_RENDER_VA+b->handle*0x2000;b->bytes=(uint32_t)in[0];b->flags=(uint32_t)in[1];b->live=true;
        assert(b->bytes<=4096);assert(!posix_memalign((void **)&b->memory,4096,4096));memset(b->memory,0,4096);
        out[0]=out[3]=b->handle;out[1]=b->va;out[2]=b->bytes;return true;
    }
    if(selector==SG_GFX_SUBMIT) {assert(!ni && no==1 && bytes==sizeof(struct sgpu_graphics_wire_submit));if(!submit(p,wire))return false;*out=++p->sequence;return true;}
    assert(ni==1 && !no && in[0]);
    if(selector==SG_GFX_WAIT)return p->scenario!=15;
    if(selector==SG_GFX_FREE) {struct peer_bo *b=bo(p,(uint32_t)in[0]);assert(b && b->live);b->live=false;p->frees++;return true;}
    assert(selector==SG_GFX_CPU_PREP);return true;
}
static bool map(void *ctx,uint32_t handle,uint8_t **out,uint64_t *length)
{struct peer_bo *b=bo(ctx,handle);assert(b && b->live);*out=b->memory;*length=4096;return true;}
static void unmap(void *ctx,uint32_t handle,uint8_t *address)
{assert(bo(ctx,handle)->memory==address);}
static void close_peer(void *ctx){(void)ctx;}
int main(int argc,char **argv)
{
    assert(argc==2);struct peer p={.scenario=(unsigned)strtoul(argv[1],NULL,10)};assert(p.scenario<20);
    struct sgfx_client c={0};struct sgfx_transport t={&p,call,map,unmap,close_peer};assert(sgfx_init(&c,&t));
    struct sgfx_bo *root=sgfx_new(&c,128,SGFX_READ),*leaf=sgfx_new(&c,128,SGFX_READ),*data=sgfx_new(&c,4,SGFX_WRITE);assert(root && leaf && data);
    uint32_t *r=(uint32_t *)(void *)root->cpu,*l=(uint32_t *)(void *)(leaf->cpu+64);
    r[0]=packet7(0x3f,3);r[1]=leaf->gpu_va+64;r[2]=0;r[3]=4;
    l[0]=packet7(0x3d,3);l[1]=data->gpu_va;l[2]=0;l[3]=0xa505cafe;
    struct sgpu_graphics_wire_ib ib[2]={{root->handle,0,16},{root->handle,0,16}};uint32_t nr=1;
    uint32_t handles[56]={root->handle,leaf->handle,data->handle};unsigned nh=3;
    if(p.scenario==1) {memcpy(root->cpu+64,l,16);r[1]=root->gpu_va+64;}
    if(p.scenario==2) {memcpy(r+4,r,16);ib[0].bytes=32;}
    if(p.scenario==3) {r[0]=packet7(0x43,3);r[1]=4;r[2]=leaf->gpu_va+64;r[3]=0;}
    if(p.scenario==4) {l[0]=packet7(0x3f,3);l[1]=root->gpu_va;l[2]=0;l[3]=4;}
    if(p.scenario==5)r[1]=leaf->gpu_va+124;
    if(p.scenario==6)r[2]=1;
    if(p.scenario==7){handles[1]=data->handle;nh=2;}
    if(p.scenario==8)r[0]^=1u<<15;
    if(p.scenario==9)ib[0].bytes=12;
    if(p.scenario==10) {r[0]=packet7(0x43,3);r[1]=4|(1u<<20);r[2]=leaf->gpu_va+64;r[3]=0;}
    if(p.scenario==11) {r[0]=packet7(0x43,3);r[1]=1u<<18;r[2]=leaf->gpu_va+64;r[3]=0;}
    if(p.scenario==12) {
        struct sgfx_bo *previous=leaf;
        for(unsigned i=0;i<8;i++) {struct sgfx_bo *next=sgfx_new(&c,128,SGFX_READ);assert(next);handles[nh++]=next->handle;uint32_t *w=(uint32_t *)(void *)(previous->cpu+64);w[0]=packet7(0x3f,3);w[1]=next->gpu_va+64;w[2]=0;w[3]=4;previous=next;}
    }
    if(p.scenario==13) {r[1]=leaf->gpu_va;r[3]=32;uint32_t *w=(uint32_t *)(void *)leaf->cpu;for(unsigned i=0;i<32;i++)w[i]=packet7(0x10,0);}
    if(p.scenario==14)for(unsigned i=3;i<55;i++){struct sgfx_bo *b=sgfx_new(&c,4,SGFX_WRITE);assert(b);handles[nh++]=b->handle;}
    if(p.scenario==16) {ib[0].handle=99;}
    if(p.scenario==17)r[0]=packet7(0x30,3); /* untouched opaque payload is still rejected by current kernel policy */
    if(p.scenario==18)r[0]=packet7(0x57,3);
    if(p.scenario==19)nr=2;
    struct sgfx_command_result result;uint32_t seq=sgfx_submit_commands(&c,ib,nr,handles,nh,&result);
    bool positive=p.scenario<=3 || p.scenario==13 || p.scenario==19;
    if(positive) {
        assert(seq==1 && result.submitted && result.completed && !result.error);
        assert(result.command_buffers==(p.scenario==1?1u:2u));
        assert(p.frees==result.command_buffers && p.submits==1);
        unsigned expected=p.scenario==3 || p.scenario==13?0:p.scenario==2 || p.scenario==19?2:1;
        assert(p.writes==expected);uint32_t value;memcpy(&value,data->cpu,4);assert(value==(expected?0xa505cafeu:0));
    } else {
        assert(!seq && result.error);
        if(p.scenario==15) {assert(result.submitted && !result.completed && c.failed && !p.frees);assert(p.next==5 && p.bo[3].live && p.bo[4].live);}
        else assert(!p.submits);
    }
    sgfx_close(&c);for(unsigned i=0;i<p.next;i++)free(p.bo[i].memory);
    printf("PASS userspace nested-command case=%u; actual kernel PM4, allocation/execution modeled\n",p.scenario);return 0;
}
