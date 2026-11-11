/* Execute the production core with an independent A505 CP stop contract.
 * adreno_dispatch.c's A5xx branch uses old | (1 | (1 << 1)), not bit28.
 * These are register-operation/ordering oracles, not physical readback claims. */
#define main sgpu_existing_model_main
#include "test_santoni_gpu_mock.c"
#undef main

enum { VENDOR_A505_STOP = 1u | (1u << 1) };
struct cp_model {
    struct model base;
    unsigned stops, releases;
    uint32_t first_old, first_written;
    unsigned deny_stop, deny_bit, seen_sites;
    bool deny_release, busy_resume, deny_resume;
    unsigned deny_reset_epoch, deny_resume_write;
};

static void cp_write(void *ctx, enum sgpu_block b, uint32_t off, uint32_t value)
{
    struct cp_model *m=ctx;
    const uint32_t regs[]={SG_CLOCK_CNTL,SG_ISDB_CNT,SG_CLOCK_CNTL};
    const uint32_t values[]={0x55u,0x182u,0xaaa8aa00u};
    if (m->deny_resume && m->base.reset_count==m->deny_reset_epoch &&
        b==SG_GPU && off==regs[m->deny_resume_write] && value==values[m->deny_resume_write] &&
        (m->deny_resume_write!=2 || m->base.resume_step==3)) {
        m->base.writes++; *reg(&m->base,b,off)=value^1u; return; /* injected failed echo */
    }
    if (b==SG_GPU && off==SG_ME_CNTL) {
        uint32_t old=*reg(&m->base,b,off);
        if (value) {
            if (!m->stops) { m->first_old=old; m->first_written=value; }
            assert(value==(old|VENDOR_A505_STOP));
            m->stops++;
        } else {
            assert((old&VENDOR_A505_STOP)==VENDOR_A505_STOP);
            m->releases++;
        }
    }
    write32(&m->base,b,off,value);
    if (b==SG_GPU && off==SG_ME_CNTL) {
        if (value && m->stops==m->deny_stop) *reg(&m->base,b,off)&=~(1u<<m->deny_bit);
        if (!value && m->deny_release) *reg(&m->base,b,off)|=1u<<m->deny_bit;
    }
    if (m->busy_resume && b==SG_GPU && off==SG_ISDB_CNT && value==0x182u)
        m->base.regs[SG_GPU][SG_STATUS/4]=2;
}

static void cp_trace(void *ctx,const char *message,uint32_t a,uint32_t b,uint32_t c)
{
    struct cp_model *m=ctx;
    (void)b; (void)c;
    if (!strcmp(message,"A505 CP halt site/old/got")) {
        assert(a>=1 && a<=4); m->seen_sites|=1u<<a;
    }
}

static struct sgpu_ops cp_ops(struct cp_model *m)
{
    struct sgpu_ops io=ops(&m->base);
    io.ctx=m; io.write32=cp_write; io.trace=cp_trace;
    return io;
}

int main(void)
{
    uint8_t fw[64]; firmware(fw);
    unsigned cases=0;
    const uint32_t initial[]={0,1,2,3,0x300,0x303};
    for (unsigned i=0;i<sizeof(initial)/sizeof(initial[0]);i++) {
        struct cp_model m={0}; init(&m.base,NONE);
        m.base.regs[SG_GPU][SG_ME_CNTL/4]=initial[i];
        struct sgpu_ops io=cp_ops(&m);
        struct sgpu_report r;
        assert(sgpu_probe(&io,2,fw,sizeof(fw),&r));
        assert(m.first_old==initial[i] && m.first_written==(initial[i]|VENDOR_A505_STOP));
        assert(m.stops==3 && m.releases==1 && r.markers==16 && !r.pixels && !r.trust_read);
        assert(m.base.reset_count==1 && m.base.resume_count==2 && m.seen_sites==0x0e);
        assert(r.restored && r.memory_retained && !m.base.frees);
        destroy(&m.base); cases++;
    }
    for (unsigned site=1;site<=4;site++) for (unsigned bit=0;bit<2;bit++) {
        struct cp_model m={.deny_stop=site,.deny_bit=bit};
        init(&m.base,site==4 ? NO_CONSUME : NONE);
        struct sgpu_ops io=cp_ops(&m); struct sgpu_report r;
        bool ok=sgpu_probe(&io,2,fw,sizeof(fw),&r);
        assert(ok==(site==3)); /* recovered final halt may complete successfully */
        const struct sgpu_failure *failure=site<=2 ? &r.failure : &r.rollback_failure;
        if (site!=4) {
            assert(failure->kind==SG_FAIL_READBACK && failure->offset==SG_ME_CNTL);
            assert(failure->mask==VENDOR_A505_STOP && failure->want==VENDOR_A505_STOP);
            assert((failure->got&VENDOR_A505_STOP)!=(failure->want));
        }
        if (site==1) assert(!m.base.reset_count && !m.base.exposed && m.base.frees==1);
        if (site==2) assert(m.base.reset_count==1 && !m.base.exposed && m.base.frees==1);
        if (site<=2) assert(!r.markers && !m.base.packets && r.restored);
        else {
            assert(m.base.reset_count==2 && m.base.resume_count==3 && (m.seen_sites&(1u<<4)));
            assert(r.memory_retained && !m.base.frees);
            if (site==3) assert(r.restored && r.markers==16);
            else assert(!r.restored && r.power_pending==13 && !r.gpu_quiescent);
        }
        assert(m.base.us<1500000);
        destroy(&m.base); cases++;
    }
    for (unsigned bit=0;bit<2;bit++) {
        struct cp_model m={.deny_release=true,.deny_bit=bit}; init(&m.base,NONE);
        struct sgpu_ops io=cp_ops(&m); struct sgpu_report r;
        assert(!sgpu_probe(&io,2,fw,sizeof(fw),&r));
        assert(r.failure.kind==SG_FAIL_READBACK && r.failure.offset==SG_ME_CNTL);
        assert(r.failure.mask==VENDOR_A505_STOP && r.failure.want==0 && r.failure.got==(1u<<bit));
        assert(!m.base.packets && !r.markers && r.restored && r.memory_retained && !m.base.frees);
        destroy(&m.base); cases++;
    }
    for (unsigned epoch=0;epoch<3;epoch++) for (unsigned step=0;step<3;step++) {
        struct cp_model m={.deny_resume=true,.deny_reset_epoch=epoch,.deny_resume_write=step};
        init(&m.base,epoch==2 ? NO_CONSUME : NONE);
        struct sgpu_ops io=cp_ops(&m); struct sgpu_report r;
        assert(!sgpu_probe(&io,2,fw,sizeof(fw),&r));
        assert(m.base.reset_count==epoch && m.base.resume_count==epoch);
        if (epoch==0) {
            assert(!r.restored && r.power_pending==13 && !r.gpu_quiescent);
            assert(!m.stops && !m.base.exposed && m.base.frees==1);
        }
        else {
            assert(!r.restored && r.power_pending==13 && !r.gpu_quiescent);
            assert(epoch==1 ? m.stops==1 : !(m.seen_sites&(1u<<4)));
            assert(r.memory_retained==(epoch==2) && m.base.frees==(epoch==1));
        }
        assert(!r.markers && !r.pixels && !r.trust_read && m.base.us<1500000);
        destroy(&m.base); cases++;
    }
    {
        struct cp_model m={.busy_resume=true}; init(&m.base,NONE);
        struct sgpu_ops io=cp_ops(&m); struct sgpu_report r;
        assert(!sgpu_probe(&io,2,fw,sizeof(fw),&r));
        assert(r.error==SG_BUSY && !m.stops && !m.base.reset_count && !m.base.exposed);
        assert(!r.restored && r.power_pending==13 && m.base.frees==1);
        destroy(&m.base); cases++;
    }
    printf("PASS %u A505 stop/resume scenarios; paired bits, preserved fields, checked release and reset epochs\n",cases);
    return 0;
}
