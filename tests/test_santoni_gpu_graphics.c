#define _POSIX_C_SOURCE 200112L
#include "santoni_gpu_graphics.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MODEL_PHYS_MASK 0xfffff000ull
#define MODEL_PTE_RO 0x0060000000000ec7ull
#define MODEL_PTE_RW 0x0060000000000e47ull

/* Actual portable functions, external allocation/PTE/GPU/cache model only. */
struct allocation { uint8_t *va,*dma; uint64_t *pa; uint32_t pages; bool used,private_mem; };
struct model {
    struct sgpu_graphics *client;
    struct allocation memory[80];
    uint64_t ptes[SGPU_RENDER_MAX_PAGES];
    uint64_t clock;
    uint32_t allocated,released,maps,unmaps,cleaned,job_cleans,invalidated,published,reads,waits,inflight;
    uint32_t ready,inject,expected_ibs,expected_bytes,last_job_cleans;
    bool prepared;
    bool stopped,expired,backward;
    uint8_t *original;
};
static bool ready(void *p){return ((struct model *)p)->ready==1;}
static struct allocation *allocation(struct sgpu_graphics_memory *m){return (struct allocation *)m->cookie;}
static bool allocate(void *p,uint32_t bytes,bool private_mem,struct sgpu_graphics_memory *out)
{
    struct model *m=p;
    if(m->inject==1)return false;
    unsigned i=0;while(i<80 && m->memory[i].used)i++;assert(i<80);
    struct allocation *a=&m->memory[i];a->pages=bytes/SGPU_PAGE;
    assert(!posix_memalign((void **)&a->va,SGPU_PAGE,bytes));memset(a->va,0xa5,bytes);
    a->dma=malloc(bytes);assert(a->dma);memset(a->dma,0xa5,bytes);
    a->pa=calloc(a->pages,sizeof(*a->pa));assert(a->pa);a->used=true;a->private_mem=private_mem;
    for(unsigned j=0;j<a->pages;j++)a->pa[j]=(private_mem?0xb0000000ull:0x99000000ull)+(uint64_t)i*0x200000+j*8192;
    *out=(struct sgpu_graphics_memory){a->va,a->pa,(uintptr_t)a,a->pages};m->allocated++;
    if(m->inject==2)a->pa[a->pages-1]=SGPU_DMA_END;
    if(m->inject==3 && a->pages>1)a->pa[a->pages-1]=a->pa[0];
    if(m->inject==4)a->pa[0]=0x98000000;
    if(m->inject==5)out->pages++;
    return true;
}
static void release(void *p,struct sgpu_graphics_memory *out)
{
    struct model *m=p;struct allocation *a=allocation(out);
    assert(a && a->used && !m->inflight && !m->client->active);
    for(unsigned i=1;i<SGPU_RENDER_MAX_PAGES;i++)for(unsigned j=0;j<a->pages;j++)
        assert((m->ptes[i]&MODEL_PHYS_MASK)!=a->pa[j]);
    free(a->va);free(a->dma);free(a->pa);memset(a,0,sizeof(*a));m->released++;
}
static uint64_t page_pa(void *p,const struct sgpu_graphics_memory *out,uint32_t page)
{
    struct model *m=p;struct allocation *a=(struct allocation *)out->cookie;
    assert(a && a->used && page<a->pages);
    uint64_t value=a->pa[page];
    if(m->inject==6 && page==a->pages-1)value+=SGPU_PAGE;
    return value;
}
static bool reserved(void *p,uint64_t pa){(void)p;return pa==0x98000000;}
static bool map(void *p,uint32_t va,const uint64_t *pa,uint32_t pages,uint64_t attrs,uint32_t guard)
{
    struct model *m=p;assert(!m->inflight);m->maps++;
    assert(va>=SGPU_RENDER_VA && guard==va+pages*SGPU_PAGE &&
           (attrs==MODEL_PTE_RO || attrs==MODEL_PTE_RW));
    unsigned first=(va-SGPU_RENDER_VA)/SGPU_PAGE;assert(first+pages<SGPU_RENDER_MAX_PAGES);
    for(unsigned i=0;i<80;i++)if(m->memory[i].used && m->memory[i].pa[0]==pa[0])
        for(unsigned j=0;j<pages*SGPU_PAGE;j++)assert(!m->memory[i].dma[j]);
    for(unsigned i=0;i<pages;i++) {assert(!m->ptes[first+i]);m->ptes[first+i]=pa[i]|attrs;}
    assert(!m->ptes[first+pages]);
    if(m->inject==7)return false;
    if(m->inject==8)m->ptes[first+pages]=pa[0]|attrs;
    return true;
}
static bool unmap(void *p,uint32_t va,uint32_t pages,uint32_t guard)
{
    struct model *m=p;assert(!m->inflight && guard==va+pages*SGPU_PAGE);m->unmaps++;
    unsigned first=(va-SGPU_RENDER_VA)/SGPU_PAGE;
    if(m->inject==9)return false;
    for(unsigned i=0;i<=pages;i++)m->ptes[first+i]=0;
    if(m->inject==10)m->ptes[first]=0x99000fc7;
    return true;
}
static uint64_t pte(void *p,uint32_t va)
{
    struct model *m=p;assert(va>=SGPU_RENDER_VA && !(va&(SGPU_PAGE-1)));
    unsigned slot=(va-SGPU_RENDER_VA)/SGPU_PAGE;assert(slot<SGPU_RENDER_MAX_PAGES);
    return m->ptes[slot];
}
static void clean(void *p,const void *va,uint32_t bytes)
{
    struct model *m=p;assert(va && bytes && !(bytes&(SGPU_PAGE-1)));m->cleaned++;
    if(m->client->active)m->job_cleans++;
    else {
        bool unpublished=false;
        for(unsigned i=0;i<SGPU_GRAPHICS_BOS;i++)if(m->client->bo[i].live &&
            !m->client->bo[i].exposed && va==m->client->bo[i].memory.va)unpublished=true;
        assert(unpublished && !m->inflight);
    }
    bool copied=false;
    for(unsigned i=0;i<80;i++)if(m->memory[i].used && va==m->memory[i].va) {
        assert(bytes==m->memory[i].pages*SGPU_PAGE);memcpy(m->memory[i].dma,va,bytes);copied=true;
    }
    assert(copied);
    if(m->inject==11)m->memory[0].pa[0]+=SGPU_PAGE;
    if(m->inject==12)m->ready=0;
}
static void invalidate(void *p,const void *va,uint32_t bytes)
{
    struct model *m=p;assert(va && bytes && !m->inflight);m->invalidated++;
}
static bool prepare(void *p,const struct sgpu_graphics_snapshot *snapshots,uint32_t count,
    const struct sgpu_graphics_command *roots,uint32_t nroots,
    const struct sgpu_graphics_range *ranges,uint32_t nranges)
{
    struct model *m=p;assert(count && count<=m->expected_ibs && nranges==2 && ranges[0].handle);
    assert(!m->client->active && !m->inflight && m->client->snapshot_count==count);
    assert(nroots==m->expected_ibs);
    for(unsigned i=0;i<nroots;i++)assert(roots[i].bytes==m->expected_bytes);
    for(unsigned i=0;i<count;i++) {
        assert(snapshots[i].words!=(uint32_t *)(void *)m->original && snapshots[i].bytes>=m->expected_bytes);
        assert(snapshots[i].source_va!=snapshots[i].gpu_va);
    }
    m->prepared=true;return m->inject!=19;
}
static bool validate(void *p,const uint32_t *words,uint32_t count,
    const struct sgpu_graphics_range *ranges,uint32_t n)
{
    struct model *m=p;assert(n==2 && ranges[0].handle && ranges[1].handle);
    assert(words!=(const uint32_t *)(const void *)m->original);
    assert(m->prepared && count==m->expected_bytes/4 && words[0]==0x12345678 && words[1]==0xabcdef01);
    for(unsigned i=2;i<count;i++)assert(words[i]==((i*0x9e37u)^0xa505u));
    /* This is a contract model, not an A505 opcode whitelist or shader test. */
    return m->inject!=13;
}
static bool publish(void *p,const struct sgpu_graphics_command *commands,uint32_t count,uint32_t seq)
{
    struct model *m=p;assert(count==m->expected_ibs &&
        m->job_cleans-m->last_job_cleans>=2+m->client->snapshot_count && m->client->active==seq);
    m->last_job_cleans=m->job_cleans;
    for(unsigned k=0;k<count;k++) {
        unsigned first=(commands[k].gpu_va-SGPU_RENDER_VA)/SGPU_PAGE;
        assert(commands[k].bytes==m->expected_bytes && (m->ptes[first]&~MODEL_PHYS_MASK)==MODEL_PTE_RO);
        bool found=false;
        for(unsigned i=0;i<80;i++)if(m->memory[i].used && m->memory[i].pa[0]==(m->ptes[first]&MODEL_PHYS_MASK)) {
            const uint32_t *w=(const uint32_t *)(const void *)m->memory[i].dma;
            assert(m->memory[i].private_mem && w[0]==0x12345678 && w[1]==0xabcdef01);
            for(unsigned j=2;j<m->expected_bytes/4;j++)assert(w[j]==((j*0x9e37u)^0xa505u));
            for(unsigned j=m->expected_bytes;j<m->memory[i].pages*SGPU_PAGE;j++)assert(!m->memory[i].dma[j]);
            found=true;
        }
        assert(found);
    }
    m->published++;m->inflight=seq;
    memset(m->original,0x55,8); /* user mutates original AFTER private copy */
    return m->inject!=14;
}
static void invalidate_fence(void *p){((struct model *)p)->reads++;}
static uint32_t fence(void *p)
{
    struct model *m=p;
    if(!m->inflight)return m->client->completed;
    if(m->inject==15)return 0;
    if(m->inject==16)return m->inflight+1;
    if(m->inject==17)return 0;
    uint32_t seq=m->inflight;m->inflight=0;return seq;
}
static bool faulted(void *p){return ((struct model *)p)->inject==17;}
static bool idle(void *p){return ((struct model *)p)->inject!=18;}
static uint64_t now(void *p){struct model *m=p;return m->backward && m->waits?0:m->clock;}
static void wait(void *p,uint32_t us)
{
    struct model *m=p;assert(us==100);m->waits++;
    if(!m->stopped)m->clock+=m->expired?SGPU_RENDER_WAIT_US:100;
}
static void dispose(struct model *m)
{
    /* Test-model process teardown, not driver cleanup: deliberately retained
     * allocations are not counted as kernel releases or clean GPU teardown. */
    for(unsigned i=0;i<80;i++)if(m->memory[i].used) {free(m->memory[i].va);free(m->memory[i].dma);free(m->memory[i].pa);}
}
int main(int argc,char **argv)
{
    assert(argc==2);unsigned test=(unsigned)strtoul(argv[1],NULL,10);
    assert(test<45);
    struct sgpu_graphics *c=calloc(1,sizeof(*c));assert(c);
    struct model m={.client=c,.clock=1000,.ready=1,.expected_ibs=1,.expected_bytes=8};m.ptes[0]=0x98000000|MODEL_PTE_RW;
    struct sgpu_graphics_ops ops={.ctx=&m,.fence_pa=0x98000000,.ready=ready,.allocate=allocate,.release=release,
        .page_pa=page_pa,.reserved_pa=reserved,.map=map,.unmap=unmap,.pte=pte,.clean=clean,.invalidate=invalidate,
        .prepare_ibs=prepare,.validate_ib=validate,.publish=publish,.invalidate_fence=invalidate_fence,.fence=fence,
        .faulted=faulted,.idle=idle,.now_us=now,.wait_us=wait};
    uint64_t owner=0x100000001ull;
    if(test==1) {m.ready=0;assert(!sgpu_graphics_init(c,owner,&ops));assert(!m.allocated);goto done;}
    if(test==2) {ops.validate_ib=NULL;assert(!sgpu_graphics_init(c,owner,&ops));goto done;}
    if(test==3) {m.ptes[7]=0x99000f47;assert(!sgpu_graphics_init(c,owner,&ops));goto done;}
    if(test==4) {ops.fence_pa=0x98000001;assert(!sgpu_graphics_init(c,owner,&ops));goto done;}
    assert(sgpu_graphics_init(c,owner,&ops));assert(!sgpu_graphics_init(c,owner,&ops));
    if(test==5) {
        assert(!sgpu_graphics_new(c,owner+1,4,SGPU_GRAPHICS_RW));
        assert(!sgpu_graphics_new(c,owner,0,SGPU_GRAPHICS_RW));
        assert(!sgpu_graphics_new(c,owner,SGPU_RENDER_BO_BYTES+1,SGPU_GRAPHICS_RW));
        assert(!sgpu_graphics_new(c,owner,4,3));assert(!m.allocated);goto done;
    }
    if(test>=6 && test<=10) {
        m.inject=test-4;
        assert(!sgpu_graphics_new(c,owner,2*SGPU_PAGE,SGPU_GRAPHICS_RO));
        assert(m.released==1 && !m.maps && !c->quarantined);goto done;
    }
    if(test==11 || test==12) {
        m.inject=test==11?7:8;assert(!sgpu_graphics_new(c,owner,SGPU_PAGE,SGPU_GRAPHICS_RO));
        assert(c->quarantined && c->retained_pages==1 && !m.released);goto done;
    }
    if(test==37) {
        uint32_t handle=sgpu_graphics_new(c,owner,SGPU_RENDER_BO_BYTES,SGPU_GRAPHICS_RW);assert(handle);
        assert(!sgpu_graphics_new(c,owner,SGPU_RENDER_BO_BYTES,SGPU_GRAPHICS_RW));
        assert(m.allocated==1 && c->retained_pages==1024);assert(sgpu_graphics_close(c,owner));goto done;
    }
    if(test==43)m.expected_bytes=SGPU_GRAPHICS_IB_BYTES;
    uint32_t src=sgpu_graphics_new(c,owner,test==43?SGPU_GRAPHICS_IB_BYTES:SGPU_PAGE,SGPU_GRAPHICS_RO);
    uint32_t dst=sgpu_graphics_new(c,owner,SGPU_PAGE,SGPU_GRAPHICS_RW);assert(src==1 && dst==2);
    uint8_t *cpu=NULL;assert(sgpu_graphics_cpu(c,owner,src,0,m.expected_bytes,&cpu));
    m.original=cpu;uint32_t words[2]={0x12345678,0xabcdef01};memcpy(cpu,words,8);
    if(test==43)for(unsigned i=2;i<m.expected_bytes/4;i++)((uint32_t *)(void *)cpu)[i]=(i*0x9e37u)^0xa505u;
    struct sgpu_graphics_ib ib={src,0,m.expected_bytes};uint32_t ids[2]={src,dst};
    if(test==44) {m.inject=19;assert(!sgpu_graphics_submit(c,owner,&ib,1,ids,2));assert(!m.published && m.released==1 && !c->quarantined);goto done;}
    if(test==36) {
        for(unsigned i=2;i<SGPU_GRAPHICS_BOS;i++)assert(sgpu_graphics_new(c,owner,4,SGPU_GRAPHICS_RO));
        assert(!sgpu_graphics_new(c,owner,4,SGPU_GRAPHICS_RO));
        assert(!sgpu_graphics_submit(c,owner,&ib,1,ids,2));assert(!m.published && m.allocated==SGPU_GRAPHICS_BOS);
        assert(sgpu_graphics_close(c,owner));assert(m.released==SGPU_GRAPHICS_BOS);goto done;
    }
    if(test==38) {
        struct sgpu_graphics_ib many[2]={ib,ib};m.expected_ibs=2;
        assert(sgpu_graphics_submit(c,owner,many,2,ids,2)==1);
        assert(c->snapshot_count==1);assert(sgpu_graphics_wait(c,owner,1));
        assert(m.released==1 && c->retained_pages==2);assert(sgpu_graphics_close(c,owner));goto done;
    }
    if(test==39) {
        for(unsigned i=1;i<=64;i++) {
            memcpy(m.original,words,8);assert(sgpu_graphics_submit(c,owner,&ib,1,ids,2)==i);
            struct sgpu_graphics_range info={0};uint8_t *private=NULL;
            assert(!sgpu_graphics_info(c,owner,c->snapshots[0],&info));
            assert(!sgpu_graphics_cpu(c,owner,c->snapshots[0],0,8,&private));
            assert(sgpu_graphics_wait(c,owner,i));assert(c->retained_pages==2 && c->completed==i);
        }
        assert(m.published==64 && m.released==64);assert(sgpu_graphics_close(c,owner));goto done;
    }
    if(test==40) {c->submitted=UINT32_MAX;assert(!sgpu_graphics_submit(c,owner,&ib,1,ids,2));assert(m.allocated==2 && !m.published);goto done;}
    if(test==41) {m.ready=0;assert(!sgpu_graphics_submit(c,owner,&ib,1,ids,2));assert(c->quarantined && c->error==SG_GRAPHICS_OFF && !m.published);goto done;}
    if(test==42) {
        m.ptes[2]=0x99000000|MODEL_PTE_RO;
        assert(!sgpu_graphics_submit(c,owner,&ib,1,ids,2));
        assert(c->quarantined && c->error==SG_GRAPHICS_MAP && !m.published);goto done;
    }
    if(test==13) {assert(sgpu_graphics_free(c,owner,src));assert(!sgpu_graphics_cpu(c,owner,src,0,8,&cpu));goto done;}
    if(test==14) {m.inject=9;assert(!sgpu_graphics_free(c,owner,src));assert(!m.released && c->quarantined);goto done;}
    if(test==15) {m.inject=10;assert(!sgpu_graphics_free(c,owner,src));assert(!m.released && c->quarantined);goto done;}
    if(test>=16 && test<=20) {
        if(test==16)ids[1]=src;
        if(test==17)ib.handle=dst+1;
        if(test==18)ib.offset=SGPU_PAGE-4;
        if(test==19)ib.bytes=7;
        if(test==20)ids[1]=UINT32_MAX;
        assert(!sgpu_graphics_submit(c,owner,&ib,1,ids,2));assert(!m.published && m.allocated==2);goto done;
    }
    if(test==21)m.inject=13;
    if(test==22)m.inject=11;
    if(test==23)m.inject=12;
    if(test==24)m.inject=14;
    uint32_t seq=sgpu_graphics_submit(c,owner,&ib,1,ids,2);
    if(test>=21 && test<=24) {
        assert(!seq);
        if(test==21) {assert(!c->quarantined && c->retained_pages==2 && m.released==1);goto done;}
        assert(c->quarantined && !m.released);
        assert(m.published==(test==24));uint32_t error=c->error,published=m.published;
        assert(!sgpu_graphics_submit(c,owner,&ib,1,ids,2) && c->error==error && m.published==published);goto done;
    }
    assert(seq==1 && m.published==1 && c->snapshot_count==1);
    assert(!sgpu_graphics_cpu(c,owner,src,0,8,&cpu) && !sgpu_graphics_free(c,owner,src));
    assert(!sgpu_graphics_wait(c,owner+1,seq) && !sgpu_graphics_wait(c,owner,seq+1));
    if(test==25)m.inject=15;
    if(test==26) {m.inject=15;m.stopped=true;}
    if(test==27) {m.inject=15;m.expired=true;}
    if(test==28)m.inject=16;
    if(test==29)m.inject=17;
    if(test==30)m.inject=18;
    if(test==31) {m.inject=15;m.backward=true;}
    if(test==32)m.inject=9;
    if(test==33)m.inject=6;
    if(test==34) {m.inject=15;assert(!sgpu_graphics_close(c,owner));assert(c->closed && c->quarantined && !m.released);goto done;}
    if(test==35) {assert(sgpu_graphics_close(c,owner));assert(c->closed && !c->retained_pages && m.released==3);goto done;}
    bool success=sgpu_graphics_wait(c,owner,seq);
    if(test>=25 && test<=33) {
        assert(!success && c->quarantined && !m.released && c->retained_pages==3);
        uint32_t expected=test==28?SG_GRAPHICS_FENCE:test==29?SG_GRAPHICS_FAULT:
            test==32?SG_GRAPHICS_UNMAP:test==33?SG_GRAPHICS_PAGES_CHANGED:SG_GRAPHICS_TIMEOUT;
        assert(c->error==expected);
        assert(m.waits<=SGPU_GRAPHICS_WAIT_READS && m.reads<=SGPU_GRAPHICS_WAIT_READS+1);
        if(test==26)assert(m.waits==SGPU_GRAPHICS_WAIT_READS);
        uint32_t error=c->error;assert(!sgpu_graphics_free(c,owner,src) && !sgpu_graphics_wait(c,owner,seq));
        assert(c->error==error);goto done;
    }
    assert(success && c->completed==1 && !c->active && !c->snapshot_count && m.released==1);
    assert(sgpu_graphics_wait(c,owner,seq));assert(sgpu_graphics_close(c,owner));assert(m.released==3);
done:
    if(c->error) {
        uint32_t first=c->error;
        sgpu_graphics_abort(c,owner,first==SG_GRAPHICS_FAULT?SG_GRAPHICS_OFF:SG_GRAPHICS_FAULT);
        assert(c->error==first);
    }
    printf("PASS graphics case=%u releases=%u retains=%u publishes=%u reads=%u; host callbacks only\n",
        test,m.released,c->retained_pages,m.published,m.reads);
    dispose(&m);free(c);return 0;
}
