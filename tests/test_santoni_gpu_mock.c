/* Host-only execution of the actual patched A505 state machine.
 * Separate CPU/PoC views, a real 4K page-table walker, and bounded MMIO model.
 * This proves driver contracts, NOT actual Adreno execution or TZ acceptance.
 */
#define _POSIX_C_SOURCE 200112L
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h> /* Darwin stdlib already imports wait; exercise that namespace here too. */
#include "santoni_gpu_core.h"

#define B(n) (1u << (n))
#define WORDS 65536u
/* Source-fragment oracle: drivers/iommu/arm-smmu.c:191-195. */
enum arm_smmu_s2cr_type { S2CR_TYPE_TRANS, S2CR_TYPE_BYPASS, S2CR_TYPE_FAULT };
_Static_assert(SG_S2CR_FAULT == ((unsigned)S2CR_TYPE_FAULT << 16), "FAULT is 2, not BYPASS=1");
enum injection { NONE, BAD_FW, ALLOC_FAIL, BAD_PA, DUP_PA, MAP_FAIL,
    CX_TIMEOUT, GX_TIMEOUT, TCU_TIMEOUT, RCG_TIMEOUT, NO_AON, BUSY_GPU,
    BAD_LAYOUT, NO_S1, MATCH_CONFLICT, CB_CONFLICT, WRITE_DENIED,
    TLB_TIMEOUT, NO_CONSUME, NO_MARKER, GPU_FAULT, UNSTOPPABLE,
    NO_CLEAN, NO_INVALIDATE, SECURE_GPU, BAD_PIXELS, NO_RENDER_FENCE,
    WAIT_JITTER, BAD_RING_LOW, BAD_RING_HIGH, BAD_PM4_LOW, BAD_PM4_HIGH,
    BAD_PFP_LOW, BAD_PFP_HIGH, MANY_MATCHES, INDEXED };
struct model {
    uint32_t *regs[SG_BLOCKS], sizes[SG_BLOCKS];
    bool mapped[SG_BLOCKS];
    uint8_t *cpu, *dma;
    uint64_t pa[SGPU_POOL_PAGES], us;
    uint32_t maps, writes, allocs, frees, cleans, invalidates, last, packets, blits, s2cr_writes;
    unsigned resume_step, resume_count, reset_count;
    enum injection inject;
    bool exposed;
};

static uint32_t *reg(struct model *m, enum sgpu_block b, uint32_t off)
{
    assert((unsigned)b < SG_BLOCKS && !(off & 3) && off < m->sizes[b]);
#ifndef SANTONI_GPU_ALLOW_LEGACY_GMEM
    assert(!(b == SG_CC && off == 0x24)); /* not in the MSM8937 GPU clock list */
#endif
    assert(m->mapped[b]);
    return &m->regs[b][off / 4];
}

static bool map(void *ctx, enum sgpu_block b, uint32_t pa, uint32_t n)
{
    struct model *m=ctx;
    const uint32_t expected[SG_BLOCKS]={0x01859000,0x0185b000,0x01845000,0x01812000,0x01c00000,0x01c40000};
    assert((unsigned)b<SG_BLOCKS && pa==expected[b] && n==m->sizes[b]);
    m->maps++;
    if(m->inject==MAP_FAIL && b==SG_GPU) return false;
    if(b==SG_GPU || b==SG_SMMU) {
        assert((m->regs[SG_CC][0x44/4]&B(31)) && (m->regs[SG_CC][0x1c/4]&B(31)));
        assert(!(m->regs[SG_MISC][3]&1));
        assert((m->regs[SG_CC][1]&0x371f)==1); /* ALL source bits cleared: actual XO */
        assert((m->regs[SG_VOTE][3]&14)==14);
        const unsigned br[]={0x20,0x28,0x30,0x34,0x40,0x4c};
        for(unsigned i=0;i<6;i++) assert(!(m->regs[SG_CC][br[i]/4]&B(31)));
    }
    m->mapped[b]=true;
    return true;
}

static uint8_t *physical(struct model *m,uint64_t pa,uint32_t n)
{
    for(unsigned i=0;i<SGPU_POOL_PAGES;i++) {
        if(pa>=m->pa[i] && pa-m->pa[i]<SGPU_PAGE) {
            uint64_t off=pa-m->pa[i];
            assert(off+n<=SGPU_PAGE);
            return m->dma+i*SGPU_PAGE+off;
        }
    }
    return NULL;
}

static uint8_t *gpu_address(struct model *m,uint32_t va,uint32_t n,bool write)
{
    uint64_t ttbr=(uint64_t)m->regs[SG_SMMU][SG_CB_TTBR0/4] |
        ((uint64_t)m->regs[SG_SMMU][SG_CB_TTBR0/4+1]<<32);
    if(!(m->regs[SG_SMMU][SG_CB/4]&1) || m->regs[SG_SMMU][SG_S2CR0/4]!=0) return NULL;
    uint64_t pa=ttbr&0x0000fffffffff000ull;
    uint64_t *table=(uint64_t *)(void *)physical(m,pa,SGPU_PAGE);
    if(!table) return NULL;
    const uint32_t shifts[3]={30,21,12};
    for(unsigned level=0;level<3;level++) {
        uint64_t entry=table[(va>>shifts[level])&511];
        if((entry&3)!=3) return NULL;
        pa=entry&0x0000fffffffff000ull;
        if(level==2) {
            if(write && (entry&(1ull<<7))) return NULL;
            return physical(m,pa+(va&(SGPU_PAGE-1)),n);
        }
        table=(uint64_t *)(void *)physical(m,pa,SGPU_PAGE);
        if(!table) return NULL;
    }
    return NULL;
}

static void gpu_write(struct model *m,uint32_t va,uint32_t value)
{
    uint8_t *p=gpu_address(m,va,4,true);
    if(!p) {m->regs[SG_SMMU][SG_CB_FSR/4]|=2; return;}
    memcpy(p,&value,4);
}

static uint32_t parity(uint32_t v)
{
    return (0x9669>>(15&(v^(v>>4)^(v>>8)^(v>>12)^(v>>16)^(v>>20)^(v>>24)^(v>>28))))&1;
}

static uint64_t configured_base(struct model *m, uint32_t low, uint32_t high)
{
    return m->regs[SG_GPU][low/4] | ((uint64_t)m->regs[SG_GPU][high/4] << 32);
}

static void execute(struct model *m,uint32_t words)
{
    if(m->inject==NO_CONSUME || m->inject==WAIT_JITTER || m->inject==UNSTOPPABLE) {
        m->regs[SG_GPU][SG_STATUS/4]=2;
        return;
    }
    assert(words>m->last && words<SGPU_PAGE/4);
    assert((m->regs[SG_GPU][SG_ME_CNTL/4]&3u)==0); /* vendor A5xx CP/PFP stop bits */
    assert((m->regs[SG_GPU][SG_RB_CNTL/4]&31)==9);
    uint64_t rb=configured_base(m,SG_RB_BASE,SG_RB_BASE_HI);
    uint64_t pm4=configured_base(m,SG_PM4_BASE,SG_PM4_BASE+4);
    uint64_t pfp=configured_base(m,SG_PFP_BASE,SG_PFP_BASE+4);
    if(rb!=SGPU_RING_VA || pm4!=SGPU_PM4_VA || pfp!=SGPU_PFP_VA ||
        !gpu_address(m,(uint32_t)pm4,4,false) || !gpu_address(m,(uint32_t)pfp,4,false)) {
        m->regs[SG_SMMU][SG_CB_FSR/4]|=2; return;
    }
    uint32_t *ring=(uint32_t *)(void *)gpu_address(m,(uint32_t)rb,SGPU_PAGE,false);
    if(!ring) {m->regs[SG_SMMU][SG_CB_FSR/4]|=2; return;}
    unsigned i=m->last;
    while(i<words) {
        uint32_t h=ring[i++];
        unsigned type=h>>28;
        unsigned n=type==7 ? h&0x3fff : h&0x7f;
        unsigned op=type==7 ? (h>>16)&0x7f : (h>>8)&0x3ffff;
        assert(type==7 || type==4);
        assert(i+n<=words);
        if(type==7) {
            assert(((h>>15)&1)==parity(n) && ((h>>23)&1)==parity(op));
            if(op==0x48) {
                assert(n==8 && ring[i]==0x2f && ring[i+5]==0xb);
                assert(!gpu_address(m,SGPU_PM4_VA,4,true));
                assert(!gpu_address(m,SGPU_PFP_VA,4,true));
                assert(!gpu_address(m,SGPU_RING_VA,4,true));
                assert(!gpu_address(m,SGPU_SOURCE_VA,4,true));
                assert(!gpu_address(m,SGPU_PM4_VA+SGPU_PAGE,4,false));
                assert(!gpu_address(m,(uint32_t)m->pa[7],4,false));
                assert(gpu_address(m,SGPU_DEST_VA,4,true));
            }
            else if(op==0x3d) {
                assert(n==3 && ring[i+1]==0);
                if(m->inject!=NO_MARKER) gpu_write(m,ring[i],ring[i+2]);
            } else if(op==0x2c) {
                assert(n==5 && ring[i]==1 && ring[i+2]==0x000f000f && ring[i+4]==0x000f000f);
                assert(m->regs[SG_GPU][0x2107]==0x30 && m->regs[SG_GPU][0x2110]==0x30);
                uint32_t sva=m->regs[SG_GPU][0x2108], dva=m->regs[SG_GPU][0x2111];
                uint8_t *src=gpu_address(m,sva,1024,false), *dst=gpu_address(m,dva,1024,true);
                assert(src && dst);
                assert(m->regs[SG_GPU][0x210a]==0x00100001 && m->regs[SG_GPU][0x2113]==0x00100001);
                memcpy(dst,src,1024);
                if(m->inject==BAD_PIXELS) dst[515]^=1;
                m->blits++;
            } else if(op==0x46) {
                assert(n==4 && ring[i+2]==0 && (ring[i]==4 || ring[i]==0x1d));
                if(m->inject!=NO_RENDER_FENCE) gpu_write(m,ring[i+1],ring[i+3]);
            } else assert(op==0x26 || op==0x6c);
        } else {
            assert(((h>>27)&1)==parity(op) && ((h>>7)&1)==parity(n));
            assert((uint64_t)op*4+n*4<=0x40000);
            assert(op*4<0x3c000); /* no protected-register packet */
            for(unsigned j=0;j<n;j++) m->regs[SG_GPU][op+j]=ring[i+j];
        }
        i+=n;
        m->packets++;
    }
    m->last=words;
    m->regs[SG_GPU][SG_RB_RPTR/4]=words;
    m->regs[SG_GPU][SG_STATUS/4]=0;
    if(m->inject==GPU_FAULT) m->regs[SG_SMMU][SG_CB_FSR/4]|=2;
}

static uint32_t read32(void *ctx,enum sgpu_block b,uint32_t off)
{
    struct model *m=ctx;
#ifndef SANTONI_GPU_ALLOW_LEGACY_CP
    /* Ordering evidence only: no invented physical reset values/echo masks. */
    if((b==SG_SMMU && !m->exposed) || (b==SG_GPU && off==SG_ME_CNTL))
        assert(m->resume_step==4); /* startup order; late SMMU fault reads remain allowed */
#endif
    if(b==SG_SMMU && off>=SG_CB && m->inject==BAD_LAYOUT) assert(!"invalid layout accessed a CB");
    if(b==SG_GPU && off==SG_AON_LO && m->inject!=NO_AON) return (uint32_t)((m->us*192)/10);
    return *reg(m,b,off);
}
static uint64_t read64(void *ctx,enum sgpu_block b,uint32_t off)
{
    return read32(ctx,b,off)|((uint64_t)read32(ctx,b,off+4)<<32);
}

static void write32(void *ctx,enum sgpu_block b,uint32_t off,uint32_t value)
{
    struct model *m=ctx;
    uint32_t *r=reg(m,b,off);
    m->writes++;
    assert(!(b==SG_GPU && off>=0x3c000));
    if(b==SG_SMMU && off==SG_S2CR0 && m->s2cr_writes++==0)
        assert(value==((unsigned)S2CR_TYPE_FAULT << 16)); /* gate BEFORE replacing any CB state */
#ifndef SANTONI_GPU_ALLOW_LEGACY_HWCG
    if(b==SG_GPU && off==SG_ME_CNTL && value==0) {
        assert(!(m->regs[SG_GPU][SG_CLOCK_CNTL/4]&0xffu));
        assert(m->regs[SG_GPU][SG_ISDB_CNT/4]==0x182u);
    }
#endif
#ifndef SANTONI_GPU_ALLOW_LEGACY_CP
    if(b==SG_GPU && off==SG_ME_CNTL) {
        assert(m->resume_step==4);
        if(value) assert(value==(*r|3u)); /* independent A5xx dispatcher RMW contract */
    }
    if(b==SG_GPU && off==SG_CLOCK_CNTL && value==0x55u) m->resume_step=1;
    if(b==SG_GPU && off==SG_CLOCK_CNTL && value!=0x55u) {
        if(m->resume_step==1) { assert(value==0xaaa8aa00u); m->resume_step=2; }
        else {
            assert(m->resume_step==3 && value==(*r&~0xffu));
            m->resume_step=4; m->resume_count++;
        }
    }
    if(b==SG_GPU && off==SG_ISDB_CNT && value==0x182u) {
        assert(m->resume_step==2); m->resume_step=3;
    }
#endif
    if(b==SG_CC && off==0) {
        *r=(value&~(1u|B(31))) | ((value&2) ? 0 : B(31));
        if(m->inject==RCG_TIMEOUT && (value&1)) *r|=1;
    } else if(b==SG_CC && (off==0x44 || off==0x1c)) {
        *r=(value&~B(31)) | ((value&1) ? 0 : B(31));
        if((m->inject==CX_TIMEOUT && off==0x44) || (m->inject==GX_TIMEOUT && off==0x1c)) *r&=~B(31);
    } else if(b==SG_CC && (off==0x20 || off==0x28 || off==0x30 || off==0x34 || off==0x40 || off==0x4c)) {
        if(off==0x34 && (value&1)) assert((m->regs[SG_VOTE][3]&2)==2); /* APSS dependency */
        *r=(value&~0xf0000000u) | ((value&1) ? 0 : B(31));
    } else if(b==SG_VOTE) {
        *r=value;
        const unsigned offsets[]={0x10,0x18,0x20},bits[]={3,1,2};
        for(unsigned i=0;i<3;i++) m->regs[SG_TCU][offsets[i]/4]=(value&B(bits[i])) ? 0 : B(31);
        if(m->inject==TCU_TIMEOUT) m->regs[SG_TCU][0x20/4]|=B(31);
    } else if(b==SG_SMMU && (off==SG_CB_FSR || off==0x48)) *r&=~value;
    else if(b==SG_SMMU && off==SG_CB_TLBSYNC) {
        *r=value;
        m->regs[SG_SMMU][SG_CB_TLBSTATUS/4]=(m->inject==TLB_TIMEOUT) ? 1 : 0;
    } else if(b==SG_SMMU && off==SG_CB && m->inject==WRITE_DENIED && value) { /* denied */ }
    else if(b==SG_GPU && off==SG_RESET) {
        *r=value;
        if(value) { m->resume_step=0; m->reset_count++; }
        if(value && m->inject!=UNSTOPPABLE) {
            m->regs[SG_GPU][SG_RB_RPTR/4]=0; m->last=0;
            m->regs[SG_GPU][SG_STATUS/4]=0;
        }
    } else {
        *r=value;
        if(b==SG_GPU &&
            ((m->inject==BAD_RING_LOW && off==SG_RB_BASE) ||
             (m->inject==BAD_PM4_LOW && off==SG_PM4_BASE) ||
             (m->inject==BAD_PFP_LOW && off==SG_PFP_BASE))) *r=SGPU_VA_BASE+0x1f000u;
        if(b==SG_GPU &&
            ((m->inject==BAD_RING_HIGH && off==SG_RB_BASE_HI) ||
             (m->inject==BAD_PM4_HIGH && off==SG_PM4_BASE+4) ||
             (m->inject==BAD_PFP_HIGH && off==SG_PFP_BASE+4))) *r=1;
        if(b==SG_GPU && off==SG_RB_WPTR) execute(m,value);
    }
}
static void write64(void *ctx,enum sgpu_block b,uint32_t off,uint64_t value)
{
    struct model *m=ctx;
    if(b==SG_SMMU && off==SG_CB_TTBR0) m->exposed=true;
    write32(ctx,b,off,(uint32_t)value); write32(ctx,b,off+4,(uint32_t)(value>>32));
}
static uint64_t now(void *ctx) {return ((struct model *)ctx)->us;}
static void mock_wait_us(void *ctx,uint32_t us)
{
    struct model *m=ctx;
    m->us+=us + ((m->inject==WAIT_JITTER && us>=50) ? 10000 : 0);
}
static bool alloc(void *ctx,struct sgpu_memory *mem)
{
    struct model *m=ctx;
    m->allocs++;
    if(m->inject==ALLOC_FAIL) return false;
    mem->va=m->cpu;
    for(unsigned i=0;i<SGPU_POOL_PAGES;i++) mem->pa[i]=m->pa[i];
    if(m->inject==BAD_PA) mem->pa[4]=0x85ff0000;
    if(m->inject==DUP_PA) mem->pa[5]=mem->pa[6];
    return true;
}
static void release(void *ctx,struct sgpu_memory *mem)
{
    struct model *m=ctx;
    assert(!m->exposed); /* must never free even a page-table walk reference */
    m->frees++; mem->va=NULL;
}
static void clean(void *ctx,const void *va,uint32_t n)
{
    struct model *m=ctx; m->cleans++;
    uintptr_t off=(const uint8_t *)va-m->cpu;
    assert(off+n<=SGPU_POOL_BYTES);
    if(m->inject!=NO_CLEAN) memcpy(m->dma+off,va,n);
}
static void invalidate(void *ctx,const void *va,uint32_t n)
{
    struct model *m=ctx; m->invalidates++;
    uintptr_t off=(const uint8_t *)va-m->cpu;
    assert(off+n<=SGPU_POOL_BYTES);
    if(m->inject!=NO_INVALIDATE) memcpy((void *)va,m->dma+off,n);
}
static void trace(void *ctx,const char *s,uint32_t a,uint32_t b,uint32_t c)
{(void)ctx;(void)s;(void)a;(void)b;(void)c;}

static void init(struct model *m,enum injection inject)
{
    memset(m,0,sizeof(*m)); m->inject=inject;
    void *cpu=NULL, *dma=NULL;
    assert(posix_memalign(&cpu,SGPU_PAGE,SGPU_POOL_BYTES)==0);
    assert(posix_memalign(&dma,SGPU_PAGE,SGPU_POOL_BYTES)==0);
    m->cpu=cpu; m->dma=dma;
    assert(m->cpu && m->dma);
    memset(m->cpu,0xa5,SGPU_POOL_BYTES); memset(m->dma,0,SGPU_POOL_BYTES);
    for(unsigned b=0;b<SG_BLOCKS;b++) {
        m->sizes[b]=b==SG_GPU ? 0x40000 : b==SG_SMMU ? 0x10000 : 0x1000;
        m->regs[b]=calloc(m->sizes[b],1); assert(m->regs[b]);
    }
    m->regs[SG_CC][0]=B(31); m->regs[SG_CC][1]=0x20507; /* source bit10 must be cleared */
    m->regs[SG_CC][0x1c/4]=0x00282001; m->regs[SG_CC][0x44/4]=0x00282001;
    const unsigned br[]={0x20,0x28,0x30,0x34,0x40,0x4c};
    for(unsigned i=0;i<6;i++) m->regs[SG_CC][br[i]/4]=B(31);
    m->regs[SG_MISC][3]=0x21; m->regs[SG_VOTE][3]=B(7);
    m->regs[SG_TCU][0x10/4]=m->regs[SG_TCU][0x18/4]=m->regs[SG_TCU][0x20/4]=B(31);
    m->regs[SG_GPU][SG_VBIF_VERSION/4]=0x20050001;
    m->regs[SG_GPU][SG_TRUST/4]=inject==SECURE_GPU ? 1 : 0;
    m->regs[SG_SMMU][0x20/4]=B(30)|B(27)|5;
    m->regs[SG_SMMU][0x24/4]=0x20000005;
    m->regs[SG_SMMU][0x28/4]=B(12)|0x222;
    m->regs[SG_SMMU][SG_S2CR0/4]=(unsigned)S2CR_TYPE_BYPASS << 16;
    for(unsigned i=0;i<SGPU_POOL_PAGES;i++) m->pa[i]=0x98010000ull+i*3*SGPU_PAGE;
    if(inject==BAD_LAYOUT) m->regs[SG_SMMU][0x24/4]|=B(31);
    if(inject==NO_S1) m->regs[SG_SMMU][0x20/4]&=~B(30);
    if(inject==MATCH_CONFLICT) m->regs[SG_SMMU][SG_SMR0/4+1]=B(31)|0x00010001;
    if(inject==CB_CONFLICT) {
        m->regs[SG_SMMU][SG_SMR0/4+1]=B(31)|2;
        m->regs[SG_SMMU][SG_S2CR0/4+1]=0;
    }
    if(inject==BUSY_GPU) m->regs[SG_GPU][SG_STATUS/4]=2;
    if(inject==MANY_MATCHES) m->regs[SG_SMMU][0x20/4]=B(30)|B(27)|197;
    if(inject==INDEXED) {
        m->regs[SG_SMMU][0x20/4]=B(30)|(3u<<9);
        for(unsigned sid=1;sid<8;sid++) m->regs[SG_SMMU][SG_S2CR0/4+sid]=SG_S2CR_FAULT;
    }
}
static void destroy(struct model *m)
{
    for(unsigned i=0;i<SG_BLOCKS;i++) free(m->regs[i]);
    free(m->cpu);free(m->dma);
}
static struct sgpu_ops ops(struct model *m)
{
    return (struct sgpu_ops){.ctx=m,.map=map,.read32=read32,.read64=read64,
        .write32=write32,.write64=write64,.now_us=now,.wait_us=mock_wait_us,
        .allocate=alloc,.release=release,.clean=clean,.invalidate=invalidate,.trace=trace};
}

static void word(uint8_t *p,uint32_t v) {memcpy(p,&v,4);}
static void firmware(uint8_t *p)
{
    memset(p,0,64);memcpy(p,"SGPUA505",8);
    word(p+8,1);word(p+12,SGPU_CHIPID);word(p+16,16);word(p+20,16);
    word(p+36,0x5ff066);word(p+52,0x5ff114);
    word(p+24,sgpu_crc32(p+32,16));word(p+28,sgpu_crc32(p+48,16));
}

int main(void)
{
    uint8_t fw[64];firmware(fw);
    struct sgpu_report report;
    assert(sgpu_probe(NULL,0,NULL,0,&report) && report.stage==SG_OFF);
    assert(!sgpu_probe(NULL,99,NULL,0,&report));
    assert(sgpu_crc32((const uint8_t *)"123456789",9)==0xcbf43926);
    unsigned cases=2;
    for(enum injection inject=NONE;inject<=INDEXED;inject++) {
        struct model m;init(&m,inject);struct sgpu_ops io=ops(&m);
        uint8_t data[64];memcpy(data,fw,64);
        if(inject==BAD_FW) data[43]^=1;
        uint32_t mode=(inject==BAD_PIXELS || inject==NO_RENDER_FENCE || inject==SECURE_GPU || inject==NONE) ? 3 : 2;
        bool ok=sgpu_probe(&io,mode,data,64,&report);
        bool expected=inject==NONE || inject==MANY_MATCHES || inject==INDEXED;
        if(ok!=expected) {
            fprintf(stderr,"injection=%u ok=%u expected=%u stage=%u error=%u markers=%u pixels=%u\n",
                inject,ok,expected,report.stage,report.error,report.markers,report.pixels);
            abort();
        }
        assert(m.us<1500000); /* bounded even when scheduler sleeps much longer */
        if(expected) assert(report.markers==16 && report.restored && report.memory_retained && m.frees==0);
        if(inject==NONE) assert(report.pixels==256 && m.blits==1);
        if(inject==SECURE_GPU) assert(report.error==SG_NEEDS_UNSECURE && report.markers==16 && !m.blits);
        if(inject==TLB_TIMEOUT || inject==WRITE_DENIED) assert(report.memory_retained && !m.frees);
        if(inject==UNSTOPPABLE) assert(report.memory_retained && !report.restored && !m.frees);
        if(inject>=BAD_RING_LOW && inject<=BAD_PFP_HIGH)
            assert(!ok && !m.packets && !m.blits && !report.markers && report.smmu_fsr);
#ifndef SANTONI_GPU_LEGACY_REPORT
        if(inject==BUSY_GPU) assert(!report.restored && !report.gpu_quiescent && report.power_pending==13);
#endif
        if(inject==BAD_FW || inject==ALLOC_FAIL) assert(!m.maps && !m.writes);
        if(report.restored && m.mapped[SG_CC]) {
            assert(m.regs[SG_CC][1]==0x20507 && m.regs[SG_VOTE][3]==B(7));
            assert(m.regs[SG_CC][0x1c/4]==0x00282001 && m.regs[SG_CC][0x44/4]==0x00282001);
        }
        destroy(&m);cases++;
    }
    for(unsigned mode=0;mode<=1;mode++) {
        struct model m;init(&m,NONE);struct sgpu_ops io=ops(&m);
        assert(sgpu_probe(&io,mode,NULL,0,&report));
        assert(!m.allocs && !m.frees && !m.packets);
        if(!mode) assert(!m.maps && !m.writes);
        destroy(&m);cases++;
    }
    uint32_t cmd[110];for(unsigned i=0;i<110;i++)cmd[i]=0xdeadbeef;
    assert(!sgpu_blit_commands(cmd,99,SGPU_MARKER_VA+768));
    assert(!sgpu_blit_commands(cmd,100,0x98000000));
    uint32_t count=sgpu_blit_commands(cmd,100,SGPU_MARKER_VA+768);
    assert(count<100 && cmd[count]==0xdeadbeef);
    printf("PASS %u actual-driver scenarios; separate PoC/CPU cache views; 4K walker; guarded DMA; offscreen pixels\n",cases);
    return 0;
}
