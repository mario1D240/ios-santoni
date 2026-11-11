/* Actual production core, separate CPU/PoC views, real table walk and two
 * full padded copies. This is a host model, never hardware pixel evidence. */
#include "santoni_gpu_session_model.h"

struct live_model {
    struct session_model session;
    struct sgpu_render_memory memory;
    uint64_t pages[SGPU_RENDER_LIVE_PAGES];
    uint8_t *tables_dma, *pixels_dma;
    bool live, tlbi, sync;
    unsigned injection, full_blits, status_reads, live_writes, cp_reads;
    struct { uint32_t block, offset, value; } delta[10];
};

static uint8_t *live_physical(struct live_model *m,uint64_t pa,uint32_t bytes)
{
    uint8_t *old=physical(&m->session.base,pa,bytes);
    if(old)return old;
    for(unsigned i=0;i<SGPU_RENDER_TABLE_PAGES;i++)
        if(pa>=m->memory.table_pa[i] && pa-m->memory.table_pa[i]<SGPU_PAGE) {
            unsigned off=(unsigned)(pa-m->memory.table_pa[i]);assert(bytes<=SGPU_PAGE-off);
            return m->tables_dma+i*SGPU_PAGE+off;
        }
    for(unsigned i=0;i<SGPU_RENDER_LIVE_PAGES;i++)
        if(pa>=m->pages[i] && pa-m->pages[i]<SGPU_PAGE) {
            unsigned off=(unsigned)(pa-m->pages[i]);assert(bytes<=SGPU_PAGE-off);
            return m->pixels_dma+i*SGPU_PAGE+off;
        }
    return NULL;
}

static uint8_t *live_address(struct live_model *m,uint32_t va,uint32_t bytes,bool write)
{
    struct model *b=&m->session.base;
    if(!(*reg(b,SG_SMMU,SG_CB)&1) || *reg(b,SG_SMMU,SG_S2CR0)!=0)return NULL;
    uint64_t ttbr=(uint64_t)*reg(b,SG_SMMU,SG_CB_TTBR0) |
        ((uint64_t)*reg(b,SG_SMMU,SG_CB_TTBR0+4)<<32);
    assert(ttbr==(b->pa[0]|(1ull<<48)));
    uint64_t *table=(uint64_t *)(void *)live_physical(m,ttbr&0x0000fffffffff000ull,SGPU_PAGE);
    const unsigned shift[3]={30,21,12};
    for(unsigned level=0;level<3;level++) {
        if(!table)return NULL;
        uint64_t pte=table[(va>>shift[level])&511];
        if((pte&3)!=3)return NULL;
        uint64_t pa=pte&0x0000fffffffff000ull;
        if(level==2) {
            if(write && (pte&(1ull<<7)))return NULL;
            return live_physical(m,pa+(va&(SGPU_PAGE-1)),bytes);
        }
        table=(uint64_t *)(void *)live_physical(m,pa,SGPU_PAGE);
    }
    return NULL;
}

static void live_store(struct live_model *m,uint32_t va,uint32_t value)
{
    uint8_t *p=live_address(m,va,4,true);assert(p);memcpy(p,&value,4);
}

static void live_execute(struct live_model *m,uint32_t end)
{
    struct model *b=&m->session.base;
    uint32_t cp=*reg(b,SG_GPU,SG_ME_CNTL);
    assert(end==b->last+73 && (cp==0 || cp==12) && *reg(b,SG_SMMU,SG_CB)==0x1127);
    assert(m->tlbi && m->sync && m->status_reads);
    uint32_t *ring=(uint32_t *)(void *)live_address(m,SGPU_RING_VA,SGPU_PAGE,false);
    assert(ring);
    uint32_t src=0,dst=0,pitch=0,width=0,height=0;
    for(unsigned i=b->last;i<end;) {
        uint32_t header=ring[i++];unsigned type=header>>28;
        unsigned count=header&(type==4?127:0x3fff);assert(count<=end-i);
        if(type==4) {
            unsigned r=(header>>8)&0x3ffff;
            if(r==0x2107 || r==0x2110) {
                assert(count==9 && ring[i]==0x30 && ring[i+2]==0 && ring[i+3]==0xf0000030);
                if(r==0x2107)src=ring[i+1];else dst=ring[i+1];pitch=(ring[i+3]&65535)*64;
            }
        } else {
            assert(type==7);unsigned op=(header>>16)&127;
            if(op==0x2c) {
                assert(count==5 && ring[i]==1 && !ring[i+1] && !ring[i+3] && ring[i+2]==ring[i+4]);
                width=(ring[i+2]&65535)+1;height=(ring[i+2]>>16)+1;
                assert(width==720 && height==1280 && pitch==3072);
                assert(src==SGPU_RENDER_VA+SGPU_PAGE && dst==SGPU_RENDER_VA+962*SGPU_PAGE);
                for(unsigned y=0;y<height;y++) {
                    unsigned offset=0;
                    while(offset<width*4) {
                        unsigned sva=src+y*pitch+offset,dva=dst+y*pitch+offset;
                        unsigned n=SGPU_PAGE-(sva&(SGPU_PAGE-1));
                        if(n>SGPU_PAGE-(dva&(SGPU_PAGE-1)))n=SGPU_PAGE-(dva&(SGPU_PAGE-1));
                        if(n>width*4-offset)n=width*4-offset;
                        uint8_t *s=live_address(m,sva,n,false),*d=live_address(m,dva,n,true);
                        assert(s && d);memcpy(d,s,n);offset+=n;
                    }
                }
                m->full_blits++;
                if(m->injection==10)m->pixels_dma[SGPU_RENDER_BYTES]^=1;
                if(m->injection==11)m->pixels_dma[SGPU_RENDER_BYTES+2880]^=1;
            } else if(op==0x46) {
                assert(count==4 && ring[i+1]==SGPU_RENDER_VA && ring[i+2]==0);
                if(ring[i]==0x1d)live_store(m,ring[i+1],0);
                else {
                    assert(ring[i]==4 && ring[i+3]==m->full_blits);
                    if(m->injection!=8)live_store(m,ring[i+1],ring[i+3]+(m->injection==9));
                }
            } else assert(op==0x26 || op==0x6c);
        }
        i+=count;
    }
    b->last=end;*reg(b,SG_GPU,SG_RB_RPTR)=end;*reg(b,SG_GPU,SG_STATUS)=0;
    if(m->injection==16)*reg(b,SG_SMMU,SG_CB_FSR)=2;
    if(m->injection==18)*reg(b,SG_SMMU,0x48)=8;
}

static void live_trace(void *ctx,const char *text,uint32_t a,uint32_t b,uint32_t c)
{
    struct live_model *m=ctx;session_trace(&m->session,text,a,b,c);
    if(!strncmp(text,"RENDER owned link",17)) {
        m->live=true;
        if(m->injection==13)m->pages[SGPU_RENDER_LIVE_PAGES-1]=0;
        if(m->injection==20)*reg(&m->session.base,SG_SMMU,SG_CB_TTBR0)^=SGPU_PAGE;
    }
}
static uint32_t live_read(void *ctx,enum sgpu_block block,uint32_t off)
{
    struct live_model *m=ctx;
    if(m->live && block==SG_SMMU && off==SG_CB_TLBSTATUS)m->status_reads++;
    if(m->live && block==SG_GPU && off==SG_ME_CNTL)m->cp_reads++;
    return session_read(&m->session,block,off);
}
static uint64_t live_read64(void *ctx,enum sgpu_block block,uint32_t off)
{struct live_model *m=ctx;return session_read64(&m->session,block,off);}
static void live_write(void *ctx,enum sgpu_block block,uint32_t off,uint32_t value)
{
    struct live_model *m=ctx;struct model *b=&m->session.base;
    if(!m->live) {session_write(&m->session,block,off,value);return;}
    assert(m->live_writes<10);
    m->delta[m->live_writes].block=block;m->delta[m->live_writes].offset=off;
    m->delta[m->live_writes++].value=value;
    if(block==SG_GPU && off==SG_ME_CNTL) {
        assert(value==0 || value==3);
        if((m->injection==2 && value==3)||(m->injection==5 && value==0))return;
        /* Captured A505 response: request3 reads15, rather than an echo.
         * Other responses below are explicit host negatives/uncertainty cases. */
        uint32_t response=value==3 ? 15 : 0;
        if(value==3) {
            if(m->injection==22)response=3;
            if(m->injection==23)response=7;
            if(m->injection==24)response=11;
            if(m->injection==27)response=19;
            if(m->injection==29)response=13;
            if(m->injection==30)response=14;
            if(m->injection==31)response=12;
            if(m->injection==35)*reg(b,SG_GPU,SG_STATUS)=2;
        } else {
            if(m->injection==25)response=12;
            if(m->injection==26)response=15;
            if(m->injection==28)response=16;
            if(m->injection==34)response=1;
        }
        *reg(b,block,off)=response;return;
    } else if(block==SG_SMMU && off==SG_CB) {
        assert(value==0x1126 || value==0x1127);
        if((m->injection==3 && value==0x1126)||(m->injection==4 && value==0x1127))return;
        if(value==0x1127)assert(m->tlbi && m->sync && m->status_reads);
        assert(*reg(b,SG_SMMU,SG_S2CR0)==SG_S2CR_FAULT);
        if(m->injection==32 && value==0x1126)*reg(b,SG_GPU,SG_ME_CNTL)=14;
    } else if(block==SG_SMMU && off==SG_S2CR0) {
        uint32_t cp=*reg(b,SG_GPU,SG_ME_CNTL);
        assert((value==SG_S2CR_FAULT || value==0) && (cp==3 || cp==7 || cp==11 || cp==15));
        assert(*reg(b,SG_SMMU,SG_CB)==0x1127);
        if(value==0)assert(m->tlbi && m->sync && m->status_reads);
    } else if(block==SG_SMMU && off==SG_CB_TLBIASID) {
        uint32_t cp=*reg(b,SG_GPU,SG_ME_CNTL);
        assert(value==1 && (cp==3 || cp==7 || cp==11 || cp==15) && *reg(b,SG_SMMU,SG_CB)==0x1126);
        const uint64_t *l2=(const uint64_t *)(const void *)(b->dma+SGPU_PAGE);
        for(unsigned i=0;i<4;i++)assert(l2[(SGPU_RENDER_VA>>21)+i]==(m->memory.table_pa[2+i]|3));
        m->tlbi=true;
        if(m->injection==33)*reg(b,SG_GPU,SG_ME_CNTL)=19;
    } else if(block==SG_SMMU && off==SG_CB_TLBSYNC) {
        assert(value==0 && m->tlbi);m->sync=true;
        if(m->injection==1)*reg(b,SG_SMMU,SG_CB_TLBSTATUS)=1;
    } else {
        assert(block==SG_GPU && off==SG_RB_WPTR && value==b->last+73);
        *reg(b,block,off)=value;
        if(m->injection==6) {*reg(b,block,off)=value+1;return;}
        if(m->injection==7 || (m->injection==17 && m->full_blits==1))return;
        live_execute(m,value);return;
    }
    *reg(b,block,off)=value;
}
static void live_clean(void *ctx,const void *p,uint32_t n)
{
    struct live_model *m=ctx;uintptr_t ptr=(uintptr_t)p;
    uintptr_t table=(uintptr_t)m->memory.tables,pixel=(uintptr_t)m->memory.pixels;
    if(ptr>=table && ptr-table<SGPU_RENDER_TABLE_PAGES*SGPU_PAGE) {
        assert(n<=SGPU_RENDER_TABLE_PAGES*SGPU_PAGE-(ptr-table));
        memcpy(m->tables_dma+(ptr-table),p,n);
        if(m->injection==14 && m->live)((uint64_t *)(void *)(m->memory.tables+2*SGPU_PAGE))[961]=3;
    } else if(ptr>=pixel && ptr-pixel<2*SGPU_RENDER_BYTES) {
        assert(n<=2*SGPU_RENDER_BYTES-(ptr-pixel));memcpy(m->pixels_dma+(ptr-pixel),p,n);
    } else if(n==292) {
        if(m->injection==12)((uint64_t *)(void *)(m->session.base.cpu+SGPU_PAGE))[SGPU_RENDER_VA>>21]=0;
        if(m->injection==15)((uint64_t *)(void *)(m->session.base.cpu+2*SGPU_PAGE))[SGPU_SOURCE_VA/SGPU_PAGE&511]^=SGPU_PAGE;
    } else session_clean(&m->session,p,n);
}
static void live_invalidate(void *ctx,const void *p,uint32_t n)
{
    struct live_model *m=ctx;uintptr_t ptr=(uintptr_t)p;
    uintptr_t table=(uintptr_t)m->memory.tables,pixel=(uintptr_t)m->memory.pixels;
    if(ptr>=table && ptr-table<SGPU_RENDER_TABLE_PAGES*SGPU_PAGE) {
        assert(n<=SGPU_RENDER_TABLE_PAGES*SGPU_PAGE-(ptr-table));memcpy((void *)p,m->tables_dma+(ptr-table),n);
    } else if(ptr>=pixel && ptr-pixel<2*SGPU_RENDER_BYTES) {
        assert(n<=2*SGPU_RENDER_BYTES-(ptr-pixel));
        if(m->injection!=19)memcpy((void *)p,m->pixels_dma+(ptr-pixel),n);
    } else session_invalidate(&m->session,p,n);
}
static uint64_t live_now(void *ctx){struct live_model *m=ctx;return session_now(&m->session);}
static void live_wait(void *ctx,uint32_t us){struct live_model *m=ctx;session_wait(&m->session,us);}

int main(int argc,char **argv)
{
    assert(argc==2);unsigned test=(unsigned)strtoul(argv[1],NULL,10);
    struct live_model m={0};init(&m.session.base,SECURE_GPU);m.injection=test;
    void *tables=NULL,*pixels=NULL;assert(!posix_memalign(&tables,SGPU_PAGE,7*SGPU_PAGE));
    assert(!posix_memalign(&pixels,SGPU_PAGE,2*SGPU_RENDER_BYTES));
    m.memory=(struct sgpu_render_memory){.tables=tables,.pixels=pixels,.pa=m.pages,.pages=SGPU_RENDER_LIVE_PAGES};
    m.tables_dma=calloc(1,7*SGPU_PAGE);m.pixels_dma=calloc(1,2*SGPU_RENDER_BYTES);assert(m.tables_dma && m.pixels_dma);
    for(unsigned i=0;i<7;i++)m.memory.table_pa[i]=0xa0000000ull+i*2*SGPU_PAGE;
    for(unsigned i=0;i<SGPU_RENDER_LIVE_PAGES;i++)m.pages[i]=0xa1000000ull+i*2*SGPU_PAGE;
    if(test==21)m.pages[SGPU_RENDER_LIVE_PAGES-1]=0;
    struct sgpu_ops io=ops(&m.session.base);io.ctx=&m;io.trace=live_trace;
    io.read32=live_read;io.read64=live_read64;io.write32=live_write;io.clean=live_clean;
    io.invalidate=live_invalidate;io.wait_us=live_wait;io.now_us=live_now;
    io.stock_unsecure=io.stock_pixels=io.g3=io.session=1;
    struct sgpu_report boot={0};struct sgpu_render_live_result result={0};uint8_t fw[64];firmware(fw);
    bool pass=sgpu_render_live_start(&io,test>=100?test-100:3,test==102?0:1,fw,sizeof(fw),&m.memory,&boot,&result);
    if(test>=100 || test==21) {
        assert(!pass && !m.session.base.maps && !m.session.base.allocs && !m.live_writes && !result.requested);
    } else if(test==0 || (test>=22 && test<=25)) {
        assert(pass && result.passed && result.phase==SG_LIVE_DONE && !result.error && result.exposed);
        assert(result.submitted==2 && result.completed==2 && result.sequence==2 && result.wptr==316 && result.pixels==1843200);
        const unsigned delta[][3]={{SG_GPU,SG_ME_CNTL,3},{SG_SMMU,SG_S2CR0,SG_S2CR_FAULT},{SG_SMMU,SG_CB,0x1126},
            {SG_SMMU,SG_CB_TLBIASID,1},{SG_SMMU,SG_CB_TLBSYNC,0},{SG_SMMU,SG_CB,0x1127},
            {SG_SMMU,SG_S2CR0,0},{SG_GPU,SG_ME_CNTL,0},{SG_GPU,SG_RB_WPTR,243},{SG_GPU,SG_RB_WPTR,316}};
        assert(m.live_writes==10);
        for(unsigned i=0;i<10;i++)assert(m.delta[i].block==delta[i][0] && m.delta[i].offset==delta[i][1] && m.delta[i].value==delta[i][2]);
        assert(m.full_blits==2 && m.session.ibs==2 && !m.session.base.frees);
        assert(!live_address(&m,SGPU_RENDER_VA+961*SGPU_PAGE,4,false));
        assert(!live_address(&m,SGPU_RENDER_VA+1922*SGPU_PAGE,4,false));
        assert(*reg(&m.session.base,SG_SMMU,SG_CB_TTBR0)==m.session.base.pa[0]);
    } else {
        assert(!pass && result.error && result.requested && result.started && !result.passed);
        assert(result.exposed==(test!=13 && test!=20));
        if(test==17)assert(result.completed==1 && result.submitted==2);
        if(test==10 || test==11 || test==19)assert(result.phase==SG_LIVE_COMPARE && result.error==SG_MARKER_MISMATCH);
        if(test==8 || test==9)assert(result.phase==SG_LIVE_FENCE && result.error==SG_COMMAND_TIMEOUT);
        if(test==12 || test==15)assert(!result.publish_attempted && result.submitted==0);
        if(test>=26 && test<=35) {
            assert(!result.publish_attempted && !result.submitted && !result.completed && !m.full_blits);
            assert(result.failure.kind && result.failure.block==SG_GPU);
            assert(result.failure.offset==(test==35 ? SG_STATUS : SG_ME_CNTL));
            if(test!=35)assert(result.failure.mask==0xfffffff3u);
            if(test==26 || test==27 || test==28 || test==29 || test==30 || test==31 || test==34)
                assert(result.failure.kind==SG_FAIL_READBACK && !result.failure.elapsed_us && !result.failure.budget_us);
            if(test==27 || test==29 || test==30 || test==31 || test==35) {
                assert(result.phase==SG_LIVE_HALT && m.live_writes==1 && !m.tlbi && !m.sync);
                const uint64_t *l2=(const uint64_t *)(const void *)(m.session.base.cpu+SGPU_PAGE);
                for(unsigned i=0;i<4;i++)assert(!l2[(SGPU_RENDER_VA>>21)+i]);
            }
            if(test==32 || test==33) {
                assert(result.failure.kind==SG_FAIL_POLL && result.failure.budget_us==10000);
                assert(result.failure.elapsed_us==10000 && m.cp_reads<=130);
            }
            if(test==35)assert(result.failure.kind==SG_FAIL_POLL && result.failure.budget_us==10000);
        }
        assert(!m.session.base.frees);
    }
    struct sgpu_render_live_result again={0};unsigned before=m.session.base.writes;
    if(test<100) {
        assert(!sgpu_render_live_start(&io,3,1,fw,sizeof(fw),&m.memory,&boot,&again));
        assert(m.session.base.writes==before);
    }
    printf("PASS live0221 case=%u pass=%u phase=%u error=%u completed=%u wptr=%u exposed=%u; host model only\n",
        test,pass?1u:0u,result.phase,result.error,result.completed,result.wptr,result.exposed?1u:0u);
    free(tables);free(pixels);free(m.tables_dma);free(m.pixels_dma);destroy(&m.session.base);return 0;
}
