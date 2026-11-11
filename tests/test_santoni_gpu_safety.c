/* Adversarial regressions for audit findings. These execute the shipped core
 * through the existing MMIO/cache model; they are not hardware proof. */
#define main sgpu_existing_model_main
#include "test_santoni_gpu_mock.c"
#undef main

enum scenario { HEALTHY, BUSY_INHERITED, CLOCK_DENIED, CLOCK_DELAYED, CLOCK_STUCK,
    RESTORE_DENIED, START_DENIED, ROUTE_ALIAS, IRQ_ERROR, RENDER_TIMEOUT, DUAL_FAILURE,
    BUSY_DURING_PAUSE, BUSY_DURING_IRQ, LATE_GPU_FAULT, LATE_SMMU_FAULT, NOC_ON,
    BUSY_DURING_HALT, ONE_SHOT_GPU_FAULT, ONE_SHOT_SMMU_FAULT,
    ROOT_DELAYED, ROOT_STUCK, HWCG_DENIED };
struct safety_model {
    struct model base;
    struct sgpu_report *report;
    enum scenario scenario;
    uint32_t target, irq, denied, unsafe, halt_writes, reset_writes, first_traces, rollback_traces, more_traces;
    uint32_t late_fault_reads;
    uint64_t halt_at, root_off_at;
    struct sgpu_failure first;
    bool high_half, live_alias, no_alias;
};

static uint32_t safety_read(void *ctx, enum sgpu_block b, uint32_t off)
{
    struct safety_model *m=ctx;
    if ((m->scenario==CLOCK_DELAYED || m->scenario==CLOCK_STUCK) &&
        b==SG_CC && off==m->target && m->halt_at && m->base.us>=m->halt_at)
        m->base.regs[b][off/4]|=B(31);
    if ((m->scenario==ROOT_DELAYED || m->scenario==ROOT_STUCK) &&
        b==SG_CC && off==0 && m->root_off_at && m->base.us>=m->root_off_at)
        m->base.regs[b][0]|=B(31);
    if (m->scenario==IRQ_ERROR && b==SG_GPU && off==SG_INT_STATUS && m->base.packets)
        m->base.regs[b][off/4]|=m->irq;
    if (m->report->stage==SG_COMPLETE && m->scenario==LATE_GPU_FAULT && b==SG_GPU && off==SG_INT_STATUS)
        m->base.regs[b][off/4]|=B(7);
    if (m->report->stage==SG_COMPLETE && m->scenario==LATE_SMMU_FAULT && b==SG_SMMU && off==SG_CB_FSR)
        m->base.regs[b][off/4]|=2;
    if (m->report->stage==SG_COMPLETE &&
        ((m->scenario==ONE_SHOT_GPU_FAULT && b==SG_GPU && off==SG_INT_STATUS) ||
         (m->scenario==ONE_SHOT_SMMU_FAULT && b==SG_SMMU && off==SG_CB_FSR)))
        return m->late_fault_reads++ == 0 ? (b==SG_GPU ? B(7) : 2u) : 0;
    if (m->scenario==NOC_ON && b==SG_CC &&
        (off==0x20 || off==0x28 || off==0x30 || off==0x34 || off==0x40 || off==0x4c) &&
        (m->base.regs[b][off/4]&1))
        return (read32(&m->base,b,off)&~0xf0000000u)|B(29);
    return read32(&m->base,b,off);
}

static void safety_write(void *ctx, enum sgpu_block b, uint32_t off, uint32_t value)
{
    struct safety_model *m=ctx;
    uint32_t old=*reg(&m->base,b,off);
    if (b==SG_GPU && off==SG_ME_CNTL) m->halt_writes++;
    if (b==SG_GPU && off==SG_RESET && value) m->reset_writes++;
    if (b==SG_CC && off==0x1c && (value&1) && !(old&1)) {
        uint32_t branch=m->base.regs[SG_CC][0x20/4];
        if ((branch&1) || !(branch&B(31)) ||
            (m->base.mapped[SG_GPU] && (m->base.regs[SG_GPU][SG_STATUS/4]&SG_BUSY_MASK)))
            m->unsafe++;
    }
    if (m->scenario==CLOCK_DENIED && b==SG_CC && off==m->target && !(value&1) && (old&1)) {
        m->base.writes++; m->denied++; return;
    }
    if (m->scenario==HWCG_DENIED && b==SG_GPU && off==m->target && value==m->irq &&
        (value!=0xaaa8aa00u || m->base.resume_step==3)) {
        /* A final zero-to-zero RMW denial is indistinguishable from success.
         * Inject an actual bad echo for this site rather than invent a failure. */
        if (off==SG_CLOCK_CNTL && value==0xaaa8aa00u) *reg(&m->base,b,off)^=1u;
        m->base.writes++; m->denied++; return;
    }
    bool restore=m->report->stage==SG_COMPLETE || (m->scenario==DUAL_FAILURE && m->first_traces);
    if (((m->scenario==RESTORE_DENIED || m->scenario==DUAL_FAILURE) && restore &&
            b==SG_SMMU && off==m->target) ||
        (m->scenario==START_DENIED && !restore && b==SG_SMMU && off==m->target && value)) {
        m->base.writes++; m->denied++; return;
    }
    if ((m->scenario==RENDER_TIMEOUT || m->scenario==DUAL_FAILURE) &&
        b==SG_GPU && off==SG_RB_WPTR && m->report->stage==SG_RENDER)
        m->base.inject=NO_CONSUME;
    write32(&m->base,b,off,value);
    if ((m->scenario==ROOT_DELAYED || m->scenario==ROOT_STUCK) &&
        b==SG_CC && off==0 && !(value&2) && (old&2)) {
        m->base.regs[b][0]&=~B(31);
        m->root_off_at=m->scenario==ROOT_DELAYED ? m->base.us+100 : ~(uint64_t)0;
    }
    if (m->scenario==BUSY_DURING_IRQ && b==SG_GPU && off==SG_INT_MASK && !value)
        m->base.regs[SG_GPU][SG_STATUS/4]=2;
    if (m->scenario==BUSY_DURING_HALT && b==SG_GPU && off==SG_ME_CNTL)
        m->base.regs[SG_GPU][SG_STATUS/4]=2;
    if ((m->scenario==CLOCK_DELAYED || m->scenario==CLOCK_STUCK) &&
        b==SG_CC && off==m->target && !(value&1) && (old&1)) {
        m->base.regs[b][off/4]&=~B(31);
        m->halt_at=m->scenario==CLOCK_DELAYED ? m->base.us+100 : ~(uint64_t)0;
    }
}

static void safety_write64(void *ctx, enum sgpu_block b, uint32_t off, uint64_t value)
{
    struct safety_model *m=ctx;
    bool restore=m->report->stage==SG_COMPLETE || (m->scenario==DUAL_FAILURE && m->first_traces);
    if (((m->scenario==RESTORE_DENIED || m->scenario==DUAL_FAILURE) && restore) ||
        (m->scenario==START_DENIED && !restore)) {
        if (b==SG_SMMU && off==m->target) {
            m->base.writes++; m->denied++;
            if (m->high_half) m->base.regs[b][off/4]=(uint32_t)value;
            return;
        }
    }
    write64(&m->base,b,off,value);
}

static void safety_trace(void *ctx, const char *s, uint32_t a, uint32_t b, uint32_t c)
{
    (void)a; (void)b; (void)c;
    struct safety_model *m=ctx;
    if (m->scenario==BUSY_DURING_PAUSE && strcmp(s,"before powered SMMU read/setup")==0)
        m->base.regs[SG_GPU][SG_STATUS/4]=2;
    if (strcmp(s,"FAIL stage/kind/block")==0) {
        m->first_traces++;
        m->first=m->report->failure;
    }
    if (strcmp(s,"ROLLBACK_FAIL stage/kind/block")==0) m->rollback_traces++;
    if (strcmp(s,"ROLLBACK_MORE stage/kind/block")==0) m->more_traces++;
}

static void safety_init(struct safety_model *m, struct sgpu_report *r, enum scenario scenario)
{
    memset(m,0,sizeof(*m)); m->report=r; m->scenario=scenario;
    init(&m->base,scenario==BUSY_INHERITED ? BUSY_GPU : NONE);
}

static struct sgpu_ops safety_ops(struct safety_model *m)
{
    struct sgpu_ops io=ops(&m->base);
    io.ctx=m; io.read32=safety_read; io.write32=safety_write;
    io.write64=safety_write64; io.trace=safety_trace;
    return io;
}

static void retained_power(const struct safety_model *m, const struct sgpu_report *r)
{
    assert(!r->restored && r->power_pending && !m->unsafe);
    assert((m->base.regs[SG_CC][0]&2) && (m->base.regs[SG_CC][0x1c/4]&B(31)));
    assert(m->base.us<1500000);
}

int main(void)
{
    uint8_t fw[64]; firmware(fw);
    struct sgpu_report r;
    unsigned cases=0;
    const uint32_t domains[]={0x44,0x1c}, states[]={0,B(31),B(31)|1u};
    for(unsigned domain=0;domain<2;domain++) for(unsigned state=0;state<3;state++) {
        struct safety_model m; safety_init(&m,&r,HEALTHY);
        m.base.regs[SG_CC][domains[domain]/4]=0x00282000u|states[state];
        struct sgpu_ops io=safety_ops(&m);
        assert(!sgpu_probe(&io,1,NULL,0,&r));
        assert(r.error==SG_POWER_TIMEOUT && r.failure.kind==SG_FAIL_OWNER);
        assert(r.failure.offset==domains[domain] && !r.failure.saved_count);
        assert(r.restored && !r.power_pending && !m.base.writes && !m.base.mapped[SG_GPU]);
        destroy(&m.base); cases++;
    }
    const uint32_t roots[]={0,2,B(31)|2u};
    for(unsigned i=0;i<3;i++) {
        struct safety_model m; safety_init(&m,&r,HEALTHY); m.base.regs[SG_CC][0]=roots[i];
        struct sgpu_ops io=safety_ops(&m);
        assert(!sgpu_probe(&io,1,NULL,0,&r));
        assert(r.failure.kind==SG_FAIL_OWNER && !r.failure.offset && !r.failure.saved_count);
        assert(r.restored && !m.base.writes && !m.base.mapped[SG_GPU]);
        destroy(&m.base); cases++;
    }
    {
        struct safety_model m; safety_init(&m,&r,HEALTHY);
        m.base.regs[SG_CC][0x20/4]=B(31)|1u;
        struct sgpu_ops io=safety_ops(&m);
        assert(!sgpu_probe(&io,1,NULL,0,&r));
        assert(r.error==SG_POWER_TIMEOUT && r.failure.kind==SG_FAIL_OWNER && r.failure.offset==0x20);
        assert(r.restored && !r.power_pending && !m.base.writes && !m.unsafe && !m.base.mapped[SG_GPU]);
        destroy(&m.base); cases++;
    }
    for(unsigned mode=1;mode<=3;mode++) {
        struct safety_model m; safety_init(&m,&r,BUSY_INHERITED);
        struct sgpu_ops io=safety_ops(&m);
        assert(!sgpu_probe(&io,mode,fw,sizeof(fw),&r));
        retained_power(&m,&r);
        assert(r.error==SG_BUSY && !r.gpu_quiescent && !m.halt_writes);
        assert(!m.base.mapped[SG_SMMU] && !r.memory_retained);
        destroy(&m.base); cases++;
    }
    const uint32_t branches[]={0x20,0x28,0x30,0x34,0x40,0x4c};
    for(unsigned i=0;i<6;i++) for(enum scenario scenario=CLOCK_DENIED;scenario<=CLOCK_STUCK;scenario++) {
        struct safety_model m; safety_init(&m,&r,scenario); m.target=branches[i];
        struct sgpu_ops io=safety_ops(&m);
        bool passed=sgpu_probe(&io,1,NULL,0,&r);
        assert(!m.unsafe);
        if(scenario==CLOCK_DELAYED) {
            assert(passed && r.restored && !r.power_pending && m.base.us>=m.halt_at);
        } else {
            retained_power(&m,&r);
            assert(!passed && r.error==SG_ROLLBACK_FAILED && m.rollback_traces==1);
            assert(r.rollback_failure.offset==m.target);
            assert(r.rollback_failure.kind==(scenario==CLOCK_DENIED ? SG_FAIL_READBACK : SG_FAIL_POLL));
        }
        destroy(&m.base); cases++;
    }
    const uint32_t config32[]={SG_GR1_CBA2R0,SG_GR1_CBAR0,SG_CB_TTBCR2,SG_CB_TTBCR,
        SG_CB_MAIR0,SG_CB_MAIR0+4,SG_SMR0,SG_CB,0};
    for(unsigned i=0;i<sizeof(config32)/sizeof(config32[0]);i++) {
        struct safety_model m; safety_init(&m,&r,RESTORE_DENIED); m.target=config32[i];
        /* A nonzero inherited value makes every restore observable, including MAIR1. */
        uint32_t initial=m.target==SG_CB ? 0x100u : m.target==SG_SMR0 ? 0x10000u : 0x40u;
        m.base.regs[SG_SMMU][m.target/4]=initial;
        struct sgpu_ops io=safety_ops(&m);
        assert(!sgpu_probe(&io,2,fw,sizeof(fw),&r));
        retained_power(&m,&r);
        assert(r.memory_retained && !m.base.frees && !r.smmu_restored);
        assert(m.denied && r.rollback_failure.kind==SG_FAIL_READBACK);
        assert(r.rollback_failure.offset==m.target);
        assert(m.base.regs[SG_SMMU][SG_S2CR0/4]==SG_S2CR_FAULT);
        destroy(&m.base); cases++;
    }
    const uint32_t config64[]={SG_CB_TTBR0,SG_CB_TTBR1};
    for(unsigned i=0;i<2;i++) for(unsigned high=0;high<2;high++) {
        struct safety_model m; safety_init(&m,&r,RESTORE_DENIED);
        m.target=config64[i]; m.high_half=high!=0;
        m.base.regs[SG_SMMU][m.target/4]=0x98123000;
        m.base.regs[SG_SMMU][m.target/4+1]=0x20000;
        struct sgpu_ops io=safety_ops(&m);
        assert(!sgpu_probe(&io,2,fw,sizeof(fw),&r));
        retained_power(&m,&r);
        assert(r.memory_retained && !r.smmu_restored && !m.base.frees);
        assert(r.rollback_failure.offset==m.target+(high ? 4u : 0u));
        assert(r.rollback_failure.kind==SG_FAIL_READBACK);
        destroy(&m.base); cases++;
    }
    for(unsigned i=0;i<sizeof(config32)/sizeof(config32[0]);i++) {
        if(config32[i]==SG_CB_MAIR0+4) continue; /* zero-to-zero denial is observationally identical */
        struct safety_model m; safety_init(&m,&r,START_DENIED); m.target=config32[i];
        struct sgpu_ops io=safety_ops(&m);
        assert(!sgpu_probe(&io,2,fw,sizeof(fw),&r));
        assert(r.error==SG_BAD_SMMU && r.failure.kind==SG_FAIL_READBACK && !m.base.packets);
        assert(r.failure.offset==m.target && m.denied);
        destroy(&m.base); cases++;
    }
    for(unsigned live=0;live<2;live++) {
        struct safety_model m; safety_init(&m,&r,ROUTE_ALIAS);
        m.base.regs[SG_SMMU][0x20/4]=B(30)|(3u<<9);
        for(unsigned sid=1;sid<8;sid++) m.base.regs[SG_SMMU][SG_S2CR0/4+sid]=SG_S2CR_FAULT;
        m.base.regs[SG_SMMU][SG_S2CR0/4+1]=0;
        m.base.regs[SG_SMMU][SG_CB/4]=live;
        m.base.regs[SG_SMMU][SG_GR1_CBAR0/4]=B(16)|0xf300;
        m.base.regs[SG_SMMU][SG_CB_TTBR0/4]=0x98123000;
        struct sgpu_ops io=safety_ops(&m);
        assert(!sgpu_probe(&io,2,fw,sizeof(fw),&r));
        assert(r.error==SG_BAD_SMMU && !m.base.exposed && !m.base.packets && !r.memory_retained);
        assert(m.base.regs[SG_SMMU][SG_CB_TTBR0/4]==0x98123000);
        destroy(&m.base); cases++;
    }
    for(unsigned bit=0;bit<32;bit++) for(unsigned mode=2;mode<=3;mode++) {
        struct safety_model m; safety_init(&m,&r,IRQ_ERROR); m.irq=B(bit);
        struct sgpu_ops io=safety_ops(&m);
        bool passed=sgpu_probe(&io,mode,fw,sizeof(fw),&r);
        bool error=(m.irq&SG_ERROR_IRQ_MASK)!=0;
        assert(passed==!error && r.markers==16 && r.restored);
        if(error) assert(r.error==SG_FAULT && !m.base.blits && !r.trust_read && !r.pixels);
        else assert(r.error==SG_OK && r.pixels==(mode==3 ? 256u : 0u));
        destroy(&m.base); cases++;
    }
    for(enum scenario scenario=RENDER_TIMEOUT;scenario<=DUAL_FAILURE;scenario++) {
        struct safety_model m; safety_init(&m,&r,scenario); m.target=SG_CB_TTBCR;
        struct sgpu_ops io=safety_ops(&m);
        assert(!sgpu_probe(&io,3,fw,sizeof(fw),&r));
        assert(r.error==SG_COMMAND_TIMEOUT && r.failure.kind==SG_FAIL_POLL && r.failure.offset==SG_RB_RPTR);
        assert(memcmp(&m.first,&r.failure,sizeof(m.first))==0 && m.first_traces==1);
        if(scenario==DUAL_FAILURE) {
            retained_power(&m,&r);
            assert(!r.smmu_restored && r.rollback_failure.kind==SG_FAIL_POLL);
            assert(m.more_traces && m.denied);
        } else assert(r.restored);
        destroy(&m.base); cases++;
    }
    for(enum scenario scenario=BUSY_DURING_PAUSE;scenario<=BUSY_DURING_IRQ;scenario++) {
        struct safety_model m; safety_init(&m,&r,scenario);
        struct sgpu_ops io=safety_ops(&m);
        assert(!sgpu_probe(&io,2,fw,sizeof(fw),&r));
        retained_power(&m,&r);
        assert(r.error==SG_BUSY && !m.reset_writes && !m.halt_writes && !m.base.packets);
        assert(!r.memory_retained && !m.base.exposed);
        destroy(&m.base); cases++;
    }
    for(enum scenario scenario=LATE_GPU_FAULT;scenario<=LATE_SMMU_FAULT;scenario++) {
        struct safety_model m; safety_init(&m,&r,scenario);
        struct sgpu_ops io=safety_ops(&m);
        assert(!sgpu_probe(&io,3,fw,sizeof(fw),&r));
        assert(r.error==SG_FAULT && r.restored && r.markers==16 && r.pixels==256);
        if(scenario==LATE_GPU_FAULT) assert(r.interrupt_status&B(7));
        else assert(r.smmu_fsr&2);
        destroy(&m.base); cases++;
    }
    {
        struct safety_model m; safety_init(&m,&r,BUSY_DURING_HALT);
        struct sgpu_ops io=safety_ops(&m);
        assert(!sgpu_probe(&io,2,fw,sizeof(fw),&r));
        retained_power(&m,&r);
        assert(r.error==SG_BUSY && m.halt_writes==1 && !m.reset_writes && !m.base.packets);
        assert(!r.memory_retained && !m.base.exposed);
        destroy(&m.base); cases++;
    }
    for(enum scenario scenario=ONE_SHOT_GPU_FAULT;scenario<=ONE_SHOT_SMMU_FAULT;scenario++) {
        struct safety_model m; safety_init(&m,&r,scenario);
        struct sgpu_ops io=safety_ops(&m);
        assert(!sgpu_probe(&io,3,fw,sizeof(fw),&r));
        assert(r.error==SG_FAULT && r.restored && m.late_fault_reads>=2);
        assert(scenario==ONE_SHOT_GPU_FAULT ? (r.interrupt_status&B(7)) : (r.smmu_fsr&2));
        destroy(&m.base); cases++;
    }
    for(enum scenario scenario=ROOT_DELAYED;scenario<=ROOT_STUCK;scenario++) {
        struct safety_model m; safety_init(&m,&r,scenario);
        struct sgpu_ops io=safety_ops(&m);
        bool passed=sgpu_probe(&io,1,NULL,0,&r);
        assert(!m.unsafe && m.root_off_at && m.base.us<1500000);
        if(scenario==ROOT_DELAYED) {
            assert(passed && r.restored && !r.power_pending && m.base.us>=m.root_off_at);
        } else {
            assert(!passed && !r.restored && r.power_pending==1 && r.error==SG_ROLLBACK_FAILED);
            assert(r.rollback_failure.kind==SG_FAIL_POLL && !r.rollback_failure.offset);
            assert(r.rollback_failure.mask==B(31) && r.rollback_failure.want==B(31));
            assert(r.rollback_failure.budget_us==10000 && r.rollback_failure.saved_count==1);
        }
        destroy(&m.base); cases++;
    }
    const uint32_t hwcg_regs[]={SG_CLOCK_CNTL,SG_CLOCK_CNTL,SG_ISDB_CNT};
    const uint32_t hwcg_values[]={0x55u,0xaaa8aa00u,0x182u};
    for(unsigned i=0;i<3;i++) {
        struct safety_model m; safety_init(&m,&r,HWCG_DENIED);
        m.target=hwcg_regs[i]; m.irq=hwcg_values[i];
        struct sgpu_ops io=safety_ops(&m);
        assert(!sgpu_probe(&io,3,fw,sizeof(fw),&r));
        assert(r.error==SG_FAULT && r.failure.kind==SG_FAIL_READBACK && r.failure.offset==m.target);
        assert(!m.base.packets && !m.base.blits && !r.trust_read && !r.markers && !r.pixels);
        retained_power(&m,&r);
        assert(!r.memory_retained && m.base.frees==1 && m.denied);
        destroy(&m.base); cases++;
    }
    {
        struct safety_model m; safety_init(&m,&r,NOC_ON);
        struct sgpu_ops io=safety_ops(&m);
        assert(sgpu_probe(&io,1,NULL,0,&r) && r.restored && !m.unsafe && !r.power_pending);
        destroy(&m.base); cases++;
    }
    printf("PASS %u audit safety scenarios; quiescence, halt acknowledgement, checked translation restore, SID isolation, IRQ errors and timeout classes\n",cases);
    return 0;
}
