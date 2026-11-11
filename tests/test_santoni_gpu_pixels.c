/* Execute the reconstructed core with owned-page DMA and exact new-role writes.
 * No real hardware: source/host contracts are not A505 rendering evidence. */
#define main sgpu_existing_model_main
#include "test_santoni_gpu_mock.c"
#undef main

_Static_assert(offsetof(struct sgpu_ops,stock_pixels)==108,"pixel Ops layout");
_Static_assert(offsetof(struct sgpu_report,pixel)==172,"pixel report layout");

struct pixel_model {
    struct model base;
    struct sgpu_report *report;
    unsigned late, trust_writes, kicks, writes_after_echo, fence_reads, fence_delay;
    bool stopped_clock;
    bool checkpoint, ended, deny_trust, deny_wptr, post_fault, padding;
    enum injection pixel_inject;
};

static uint32_t pixel_read(void *ctx, enum sgpu_block b, uint32_t off)
{
    struct pixel_model *m=ctx; assert(!m->ended);
    if(m->trust_writes && !(b==SG_GPU && off==SG_TRUST && !m->checkpoint))
        assert(m->report->pixel.started);
    return read32(&m->base,b,off);
}
static uint64_t pixel_read64(void *ctx,enum sgpu_block b,uint32_t off)
{ return pixel_read(ctx,b,off)|((uint64_t)pixel_read(ctx,b,off+4)<<32); }

static void pixel_write(void *ctx,enum sgpu_block b,uint32_t off,uint32_t value)
{
    struct pixel_model *m=ctx; assert(!m->ended);
    if(b==SG_GPU && off>=0x3c000) {
        assert(off==0x3d000 && value==0 && !m->trust_writes && !m->checkpoint);
        assert(m->report->stock.attempted && m->report->stock.held);
        m->trust_writes++;
        if(!m->deny_trust) *reg(&m->base,b,off)=0;
        return;
    }
    if(m->checkpoint) {
        /* Exact additional register delta: one WPTR 75 -> 148, nothing else. */
        assert(m->report->pixel.started && m->report->stock.held);
        assert(b==SG_GPU && off==SG_RB_WPTR && value==148 && !m->kicks);
        assert(*reg(&m->base,b,off)==75);
        m->kicks++; m->writes_after_echo++;
    }
    write32(&m->base,b,off,value);
    if(m->checkpoint) {
        if(m->deny_wptr) *reg(&m->base,b,off)=149;
        if(m->post_fault) *reg(&m->base,SG_GPU,SG_INT_STATUS)=2;
        if(m->padding) m->base.dma[6*SGPU_PAGE+2048]^=1;
        if(m->fence_delay) memset(m->base.dma+4*SGPU_PAGE+768,0,4);
    }
}
static void pixel_write64(void *ctx,enum sgpu_block b,uint32_t off,uint64_t value)
{
    struct pixel_model *m=ctx; assert(!m->checkpoint && !m->ended);
    write64(&m->base,b,off,value);
}

struct bad_reg { enum sgpu_block block; uint32_t off, flip; };
static const struct bad_reg late_regs[]={
    {SG_GPU,SG_TRUST,1},{SG_GPU,SG_STATUS,2},{SG_GPU,SG_RB_RPTR,1},
    {SG_GPU,SG_RB_WPTR,1},{SG_GPU,SG_ME_CNTL,1},{SG_GPU,SG_INT_MASK,1},
    {SG_GPU,SG_RB_BASE,1},{SG_GPU,SG_RB_BASE_HI,1},{SG_GPU,SG_RB_CNTL,1},
    {SG_GPU,SG_PM4_BASE,1},{SG_GPU,SG_PM4_BASE+4,1},
    {SG_GPU,SG_PFP_BASE,1},{SG_GPU,SG_PFP_BASE+4,1},
    {SG_SMMU,SG_CB,1},{SG_SMMU,SG_S2CR0,1},{SG_SMMU,SG_GR1_CBA2R0,1},
    {SG_SMMU,SG_GR1_CBAR0,1},{SG_SMMU,SG_CB_TTBCR,1},{SG_SMMU,SG_CB_TTBCR2,1},
    {SG_SMMU,SG_CB_MAIR0,1},{SG_SMMU,SG_CB_MAIR0+4,1},
    {SG_SMMU,SG_CB_TTBR0,1},{SG_SMMU,SG_CB_TTBR0+4,1},
    {SG_GPU,SG_INT_STATUS,2},{SG_SMMU,SG_CB_FSR,2},{SG_SMMU,0x48,1},
};

static void pixel_trace(void *ctx,const char *message,uint32_t a,uint32_t b,uint32_t c)
{
    struct pixel_model *m=ctx; (void)a;(void)b;(void)c;
    if(!strcmp(message,"before stock pixel readiness; owned 16x16; NO PAS; state held")) {
        assert(m->report->pixel.started && m->report->stock.held && !m->checkpoint);
        m->checkpoint=true;
        if(m->late) {
            struct bad_reg bad=late_regs[m->late-1];
            *reg(&m->base,bad.block,bad.off)^=bad.flip;
        }
        m->base.inject=m->pixel_inject;
    }
    if(!strcmp(message,"stock pixel test ended; state HELD until reboot; no cleanup")) m->ended=true;
}

static void pixel_invalidate(void *ctx,const void *va,uint32_t n)
{
    struct pixel_model *m=ctx;
    if(m->checkpoint && va==m->base.cpu+4*SGPU_PAGE+768) {
        assert(n==64 && ++m->fence_reads<=2002);
        if(m->fence_delay && m->fence_reads==m->fence_delay) {
            uint32_t value=0xa5052d01u;
            memcpy(m->base.dma+4*SGPU_PAGE+768,&value,4);
        }
    }
    invalidate(&m->base,va,n);
}
static uint64_t pixel_now(void *ctx)
{
    struct pixel_model *m=ctx;
    return m->stopped_clock && m->checkpoint ? 0 : now(&m->base);
}

static struct sgpu_ops pixel_ops(struct pixel_model *m)
{
    struct sgpu_ops io=ops(&m->base);
    io.ctx=m; io.read32=pixel_read; io.read64=pixel_read64;
    io.write32=pixel_write; io.write64=pixel_write64; io.trace=pixel_trace;
    io.invalidate=pixel_invalidate; io.now_us=pixel_now;
    io.stock_unsecure=1; io.stock_pixels=1;
    return io;
}

static void retained(const struct pixel_model *m,const struct sgpu_report *r)
{
    assert(r->stock.held && r->memory_retained && !m->base.frees);
    assert(!r->restored && !r->gpu_quiescent && !r->smmu_restored && r->power_pending==13);
    assert(m->base.reset_count==1 && !r->rollback_failure.kind);
}

int main(void)
{
    uint8_t fw[64]; firmware(fw); unsigned cases=0;
    for(unsigned secured=0;secured<2;secured++) {
        struct pixel_model m={0}; init(&m.base,secured?SECURE_GPU:NONE);
        struct sgpu_report r; m.report=&r; struct sgpu_ops io=pixel_ops(&m);
        assert(!sgpu_probe(&io,3,fw,sizeof(fw),&r)); /* overall false: intentional hold */
        assert(r.pixel.requested && r.pixel.started && r.pixel.passed && r.pixels==256);
        assert(r.error==SG_STOCK_HELD && r.stage==SG_STOCK_PIXELS && r.markers==16);
        assert(m.kicks==1 && m.trust_writes==secured && m.ended);
        assert(!r.failure.kind && r.stock.echo_zero && r.trust==0);
        retained(&m,&r); destroy(&m.base); cases++;
    }
    for(unsigned late=1;late<=sizeof(late_regs)/sizeof(late_regs[0]);late++) {
        struct pixel_model m={.late=late}; init(&m.base,SECURE_GPU);
        struct sgpu_report r; m.report=&r; struct sgpu_ops io=pixel_ops(&m);
        assert(!sgpu_probe(&io,3,fw,sizeof(fw),&r));
        assert(m.trust_writes==1 && m.checkpoint && !m.kicks && !m.base.blits && m.ended);
        assert(!r.pixel.passed && !r.pixels && r.error!=SG_STOCK_HELD && r.error!=SG_OK);
        assert(m.base.us<1000000);
        if(late<=23) assert(r.failure.offset==late_regs[late-1].off);
        retained(&m,&r); destroy(&m.base); cases++;
    }
    for(unsigned scenario=0;scenario<7;scenario++) {
        struct pixel_model m={.deny_wptr=scenario==0,.post_fault=scenario==5,.padding=scenario==6};
        if(scenario==1) m.pixel_inject=NO_CONSUME;
        if(scenario==2) m.pixel_inject=BAD_PIXELS;
        if(scenario==3) m.pixel_inject=NO_RENDER_FENCE;
        if(scenario==4) m.pixel_inject=NO_INVALIDATE;
        init(&m.base,SECURE_GPU);
        struct sgpu_report r; m.report=&r; struct sgpu_ops io=pixel_ops(&m);
        assert(!sgpu_probe(&io,3,fw,sizeof(fw),&r));
        assert(m.kicks==1 && m.trust_writes==1 && !r.pixel.passed && m.ended);
        assert(r.pixels==(scenario==5?256u:0u));
        assert(r.error==(scenario==0||scenario==5?SG_FAULT:
               scenario==1||scenario==3||scenario==4?SG_COMMAND_TIMEOUT:SG_MARKER_MISMATCH));
        if(scenario==0) {
            assert(r.failure.kind==SG_FAIL_READBACK && r.failure.offset==SG_RB_WPTR);
            assert(r.failure.old==75 && r.failure.written==148 && r.failure.got==149 && r.failure.mask==~0u);
        }
        retained(&m,&r); destroy(&m.base); cases++;
    }
    for(unsigned stalled=0;stalled<2;stalled++) for(unsigned delay=1;delay<=3;delay++) {
        struct pixel_model m={.stopped_clock=stalled,.fence_delay=delay==1?4:delay==2?2001:2002};
        init(&m.base,SECURE_GPU);
        struct sgpu_report r; m.report=&r; struct sgpu_ops io=pixel_ops(&m);
        assert(!sgpu_probe(&io,3,fw,sizeof(fw),&r));
        assert(r.pixel.passed==(delay!=3) && r.pixels==(delay!=3?256u:0u));
        assert(m.fence_reads==(delay==3?2001:m.fence_delay+1));
        assert(r.error==(delay==3?SG_COMMAND_TIMEOUT:SG_STOCK_HELD));
        assert(m.base.us<1000000 && m.kicks==1 && m.ended);
        retained(&m,&r); destroy(&m.base); cases++;
    }
    {
        struct pixel_model m={.deny_trust=true}; init(&m.base,SECURE_GPU);
        struct sgpu_report r; m.report=&r; struct sgpu_ops io=pixel_ops(&m);
        assert(!sgpu_probe(&io,3,fw,sizeof(fw),&r));
        assert(m.trust_writes==1 && !m.checkpoint && !m.kicks && !r.pixel.started && !r.pixel.passed);
        assert(r.error==SG_FAULT && r.failure.offset==SG_TRUST && !r.pixels);
        retained(&m,&r); destroy(&m.base); cases++;
    }
    for(unsigned mode=0;mode<=4;mode++) for(unsigned stock=0;stock<=2;stock++)
        for(unsigned pixels=1;pixels<=2;pixels++) {
            if(mode==3&&stock==1&&pixels==1) continue;
            struct pixel_model m={0}; init(&m.base,NONE);
            struct sgpu_report r; m.report=&r; struct sgpu_ops io=pixel_ops(&m);
            io.stock_unsecure=stock; io.stock_pixels=pixels;
            assert(sgpu_probe(&io,mode,fw,sizeof(fw),&r)==(mode==0));
            assert(!m.base.maps && !m.base.allocs && !m.base.writes && !m.kicks && !r.pixels);
            destroy(&m.base); cases++;
        }
    printf("PASS stock pixel contracts: %u cases; fixed owned blit, first failures and retention\n",cases);
    return 0;
}
