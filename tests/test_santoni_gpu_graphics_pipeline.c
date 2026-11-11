/* Combined actual buffer/fence and PM4 code. GPU/cache/allocation are models. */
#define main graphics_fixture_main
#include "test_santoni_gpu_graphics.c"
#undef main
#include "santoni_gpu_pm4.h"

struct pipeline {
    struct model model;
    struct sgpu_graphics_snapshot snapshots[SGPU_GRAPHICS_IBS];
    uint32_t count;
    struct sgpu_pm4_policy policy;
};
static bool real_prepare(void *ctx,const struct sgpu_graphics_snapshot *s,uint32_t ns,
    const struct sgpu_graphics_command *roots,uint32_t ni,const struct sgpu_graphics_range *ranges,uint32_t nr)
{
    struct pipeline *p=ctx;assert(ns<=SGPU_GRAPHICS_IBS);
    memcpy(p->snapshots,s,ns*sizeof(*s));p->count=ns;
    return sgpu_pm4_prepare(&p->policy,s,ns,roots,ni,ranges,nr);
}
static bool real_validate(void *ctx,const uint32_t *words,uint32_t n,const struct sgpu_graphics_range *r,uint32_t nr)
{
    struct pipeline *p=ctx;
    for(unsigned i=0;i<p->count;i++) {
        const struct sgpu_graphics_snapshot *s=&p->snapshots[i];
        uintptr_t word=(uintptr_t)words,base=(uintptr_t)s->words;
        if(word>=base && word-base<=s->bytes && n*4<=s->bytes-(word-base)) {
            struct sgpu_graphics_command root={s->gpu_va+(uint32_t)(word-base),n*4};
            return sgpu_pm4_validate(&p->policy,p->snapshots,p->count,&root,1,r,nr);
        }
    }
    return false;
}
static uint8_t *gpu_pointer(struct pipeline *p,uint32_t va,uint32_t bytes,bool write)
{
    struct model *m=&p->model;unsigned slot=(va-SGPU_RENDER_VA)/SGPU_PAGE,off=va&(SGPU_PAGE-1);
    assert(slot<SGPU_RENDER_MAX_PAGES && bytes<=SGPU_PAGE-off);
    uint64_t entry=m->ptes[slot];assert(entry && (!write || (entry&~MODEL_PHYS_MASK)==MODEL_PTE_RW));
    for(unsigned i=0;i<80;i++)if(m->memory[i].used)for(unsigned j=0;j<m->memory[i].pages;j++)
        if(m->memory[i].pa[j]==(entry&MODEL_PHYS_MASK))return m->memory[i].dma+j*SGPU_PAGE+off;
    assert(false);return NULL;
}
static void execute(struct pipeline *p,uint32_t va,uint32_t bytes,unsigned depth)
{
    assert(depth<SGPU_PM4_DEPTH);
    const uint32_t *words=(const uint32_t *)(const void *)gpu_pointer(p,va,bytes,false);
    assert(bytes==16 && (words[0]>>28)==7 && (words[0]&0x3fff)==3);
    unsigned op=(words[0]>>16)&127;
    if(op==0x3f) {assert(!words[2]);execute(p,words[1],words[3]*4,depth+1);}
    else {assert(op==0x3d && !words[2]);memcpy(gpu_pointer(p,words[1],4,true),&words[3],4);}
}
static bool real_publish(void *ctx,const struct sgpu_graphics_command *cmd,uint32_t n,uint32_t seq)
{
    struct pipeline *p=ctx;struct model *m=&p->model;assert(n==1 && m->client->active==seq);
    /* Make an adversarial user's post-validation leaf rewrite visible to the
     * simulated GPU. It must execute the PRIVATE relocated leaf instead. */
    uint32_t *original=(uint32_t *)(void *)m->original;
    original[17]=SGPU_RING_VA;original[19]=0xdeadbeef;
    memcpy(m->memory[0].dma,m->original,m->memory[0].pages*SGPU_PAGE);
    execute(p,cmd[0].gpu_va,cmd[0].bytes,0);
    m->published++;m->inflight=seq;return true;
}
static void real_invalidate(void *ctx,const void *va,uint32_t bytes)
{
    struct pipeline *p=ctx;struct model *m=&p->model;invalidate(m,va,bytes);
    for(unsigned i=0;i<80;i++)if(m->memory[i].used && va==m->memory[i].va) {
        assert(bytes<=m->memory[i].pages*SGPU_PAGE);memcpy(m->memory[i].va,m->memory[i].dma,bytes);return;
    }
    assert(false);
}
int main(void)
{
    struct sgpu_graphics *c=calloc(1,sizeof(*c));assert(c);
    struct pipeline p={0};p.model.client=c;p.model.ready=1;p.model.clock=1000;p.model.ptes[0]=0x98000000|MODEL_PTE_RW;
    struct sgpu_graphics_ops ops={.ctx=&p,.fence_pa=0x98000000,.ready=ready,.allocate=allocate,.release=release,
        .page_pa=page_pa,.reserved_pa=reserved,.map=map,.unmap=unmap,.pte=pte,.clean=clean,.invalidate=real_invalidate,
        .prepare_ibs=real_prepare,.validate_ib=real_validate,.publish=real_publish,.invalidate_fence=invalidate_fence,
        .fence=fence,.faulted=faulted,.idle=idle,.now_us=now,.wait_us=wait};
    uint64_t owner=0x100000001ull;assert(sgpu_graphics_init(c,owner,&ops));
    uint32_t source=sgpu_graphics_new(c,owner,256,SGPU_GRAPHICS_RO),dest=sgpu_graphics_new(c,owner,SGPU_PAGE,SGPU_GRAPHICS_RW);
    assert(source && dest);struct sgpu_graphics_range src,dst;
    assert(sgpu_graphics_info(c,owner,source,&src) && sgpu_graphics_info(c,owner,dest,&dst));
    uint8_t *cpu=NULL;assert(sgpu_graphics_cpu(c,owner,source,0,256,&cpu));p.model.original=cpu;
    uint32_t *words=(uint32_t *)(void *)cpu;
    words[0]=sgpu_packet7(0x3f,3);words[1]=src.gpu_va+64;words[2]=0;words[3]=4;
    words[16]=sgpu_packet7(0x3d,3);words[17]=dst.gpu_va;words[18]=0;words[19]=0xa505cafe;
    struct sgpu_graphics_ib ib={source,0,16};uint32_t handles[2]={source,dest};
    assert(sgpu_graphics_submit(c,owner,&ib,1,handles,2)==1);
    assert(sgpu_graphics_wait(c,owner,1));assert(sgpu_graphics_cpu(c,owner,dest,0,4,&cpu));
    uint32_t result=0;memcpy(&result,cpu,4);assert(result==0xa505cafe && p.model.published==1);
    assert(sgpu_graphics_close(c,owner));assert(!c->retained_pages);
    printf("PASS actual graphics+PM4 pipeline: relocated private nested IB survives user rewrite; GPU modeled\n");
    dispose(&p.model);free(c);return 0;
}
