/* Actual reconstructed core, independent one-write and no-post-write-IO oracle.
 * Host mocks only: this does not prove live TRUST permission or hardware safety. */
#define main sgpu_existing_model_main
#include "test_santoni_gpu_mock.c"
#undef main

_Static_assert(offsetof(struct sgpu_ops, stock_unsecure)==104, "binary-audit Ops layout");
_Static_assert(offsetof(struct sgpu_report, stock)==160, "binary-audit stock report layout");

struct stock_model {
    struct model base;
    struct sgpu_report *report;
    unsigned trust_writes, echo_reads, checkpoints, late;
    unsigned trust_reads;
    uint32_t echo, changed_old;
    bool change_old;
};

static uint32_t stock_read(void *ctx, enum sgpu_block b, uint32_t off)
{
    struct stock_model *m = ctx;
    if (b == SG_GPU && off == SG_TRUST && ++m->trust_reads == 2 && m->change_old)
        return m->changed_old;
    if (m->trust_writes) {
        /* Exactly the checked-write echo, then NO further hardware accesses. */
        assert(b == SG_GPU && off == SG_TRUST && m->echo_reads++ == 0);
        return m->echo;
    }
    return read32(&m->base, b, off);
}

static uint64_t stock_read64(void *ctx, enum sgpu_block b, uint32_t off)
{
    return stock_read(ctx, b, off) | ((uint64_t)stock_read(ctx, b, off + 4) << 32);
}

static void stock_write(void *ctx, enum sgpu_block b, uint32_t off, uint32_t value)
{
    struct stock_model *m = ctx;
    assert(!m->trust_writes); /* no retry, reset, halt, cleanup or later packet */
    if (b == SG_GPU && off >= 0x3c000) {
        assert(off == 0x3d000 && value == 0);
        assert(m->checkpoints == 1 && m->base.last == 75 && m->base.blits == 0);
        assert(m->report->stock.attempted && m->report->stock.held);
        assert(m->report->markers == 16 && !m->report->pixels);
        m->trust_writes++;
        *reg(&m->base, b, off) = m->echo;
        return;
    }
    write32(&m->base, b, off, value);
}

static void stock_write64(void *ctx, enum sgpu_block b, uint32_t off, uint64_t v)
{
    struct stock_model *m = ctx;
    assert(!m->trust_writes);
    write64(&m->base, b, off, v);
}

static void stock_trace(void *ctx, const char *s, uint32_t a, uint32_t b, uint32_t c)
{
    struct stock_model *m = ctx;
    (void)a; (void)b; (void)c;
    if (strcmp(s, "before stock A505 TRUST transition; NO PAS; NO PIXELS")) return;
    m->checkpoints++;
    /* Perturb the live state AFTER the logging pause: every guard must see it. */
    static const uint32_t offsets[] = {SG_STATUS, SG_RB_RPTR, SG_RB_WPTR,
        SG_ME_CNTL, SG_INT_MASK, SG_RB_BASE, SG_RB_BASE_HI, SG_CB, SG_S2CR0,
        SG_GR1_CBA2R0, SG_CB_TTBR0, SG_CB_TTBR0 + 4, SG_INT_STATUS, SG_CB_FSR, 0x48};
    if (m->late) {
        unsigned i = m->late - 1;
        enum sgpu_block block = (i >= 7 && i != 12) ? SG_SMMU : SG_GPU;
        assert(i < sizeof(offsets) / sizeof(offsets[0]));
        uint32_t mask = (i == 0 || i == 12 || i == 13) ? 2u : 1u;
        *reg(&m->base, block, offsets[i]) ^= mask;
    }
}

static struct sgpu_ops stock_ops(struct stock_model *m)
{
    struct sgpu_ops io = ops(&m->base);
    io.ctx=m; io.read32=stock_read; io.read64=stock_read64;
    io.write32=stock_write; io.write64=stock_write64; io.trace=stock_trace;
    io.stock_unsecure=1;
    return io;
}

int main(void)
{
    uint8_t fw[64]; firmware(fw);
    unsigned cases=0;
    const uint32_t echoes[] = {0, 1, 2, 0x80000000u, ~0u};
    for (unsigned i=0; i<sizeof(echoes)/sizeof(echoes[0]); i++) {
        struct stock_model m = {.echo=echoes[i]}; init(&m.base, SECURE_GPU);
        struct sgpu_report r; m.report=&r; struct sgpu_ops io=stock_ops(&m);
        assert(!sgpu_probe(&io, 3, fw, sizeof(fw), &r));
        assert(r.stage==SG_STOCK_TRANSITION && r.stock.requested && r.stock.attempted && r.stock.held);
        assert(r.stock.before==1 && r.stock.after==echoes[i] && r.trust==echoes[i] && r.trust_read);
        assert(r.stock.echo_zero==(i==0) && r.error==(i==0 ? SG_STOCK_HELD : SG_FAULT));
        assert(m.trust_writes==1 && m.echo_reads==1 && m.base.reset_count==1);
        assert(r.memory_retained && !m.base.frees && !r.restored && !r.smmu_restored);
        assert(!r.gpu_quiescent && r.power_pending==13 && r.markers==16 && !r.pixels && !m.base.blits);
        assert(r.rollback_failure.kind==SG_FAIL_NONE);
        if (i) {
            assert(r.failure.kind==SG_FAIL_READBACK && r.failure.offset==0x3d000);
            assert(r.failure.old==1 && r.failure.written==0 && r.failure.want==0 && r.failure.mask==~0u);
            assert(r.failure.got==echoes[i] && r.failure.saved_count==13);
        } else assert(r.failure.kind==SG_FAIL_NONE);
        destroy(&m.base); cases++;
    }
    const uint32_t before[] = {0, 2, 3, 0x80000001u, ~0u};
    for (unsigned i=0; i<sizeof(before)/sizeof(before[0]); i++) {
        struct stock_model m={0}; init(&m.base, NONE);
        m.base.regs[SG_GPU][SG_TRUST/4]=before[i];
        struct sgpu_report r; m.report=&r; struct sgpu_ops io=stock_ops(&m);
        assert(sgpu_probe(&io, 3, fw, sizeof(fw), &r)==(i==0));
        assert(!m.trust_writes && !r.stock.attempted && !r.stock.held && !r.pixels && !m.base.blits);
        assert(r.stock.before==before[i] && r.stock.echo_zero==(i==0));
        assert(r.restored && r.memory_retained && !m.base.frees);
        if(i) assert(r.error==SG_NEEDS_UNSECURE && r.failure.got==before[i]);
        destroy(&m.base); cases++;
    }
    for (unsigned i=0; i<sizeof(echoes)/sizeof(echoes[0]); i++) {
        if(echoes[i]==1) continue;
        struct stock_model m={.changed_old=echoes[i],.change_old=true}; init(&m.base, SECURE_GPU);
        struct sgpu_report r; m.report=&r; struct sgpu_ops io=stock_ops(&m);
        assert(!sgpu_probe(&io,3,fw,sizeof(fw),&r));
        assert(r.stock.attempted && r.stock.held && !r.stock.echo_zero && !m.trust_writes);
        assert(m.trust_reads==2 && r.failure.kind==SG_FAIL_GUARD && r.failure.got==echoes[i]);
        assert(r.memory_retained && !r.restored && r.power_pending==13 && !m.base.frees);
        destroy(&m.base); cases++;
    }
    for (unsigned late=1; late<=15; late++) {
        struct stock_model m={.late=late}; init(&m.base, SECURE_GPU);
        struct sgpu_report r; m.report=&r; struct sgpu_ops io=stock_ops(&m);
        assert(!sgpu_probe(&io, 3, fw, sizeof(fw), &r));
        assert(m.checkpoints==1 && !m.trust_writes && !r.stock.attempted && !r.pixels);
        assert(!r.stock.echo_zero && r.error && m.base.us<2000000);
        destroy(&m.base); cases++;
    }
    const enum injection failures[] = {BAD_FW, ALLOC_FAIL, BAD_PA, DUP_PA, MAP_FAIL,
        CX_TIMEOUT, GX_TIMEOUT, TCU_TIMEOUT, RCG_TIMEOUT, NO_AON, BUSY_GPU,
        BAD_LAYOUT, NO_S1, MATCH_CONFLICT, CB_CONFLICT, WRITE_DENIED,
        TLB_TIMEOUT, NO_CONSUME, NO_MARKER, GPU_FAULT, UNSTOPPABLE,
        NO_CLEAN, NO_INVALIDATE, WAIT_JITTER, BAD_RING_LOW, BAD_RING_HIGH,
        BAD_PM4_LOW, BAD_PM4_HIGH, BAD_PFP_LOW, BAD_PFP_HIGH};
    for(unsigned i=0;i<sizeof(failures)/sizeof(failures[0]);i++) {
        struct stock_model m={0}; init(&m.base, failures[i]);
        struct sgpu_report r; m.report=&r; struct sgpu_ops io=stock_ops(&m);
        assert(!sgpu_probe(&io, 3, fw, failures[i]==BAD_FW ? 1 : sizeof(fw), &r));
        assert(!m.trust_writes && !r.stock.attempted && !r.pixels && !m.base.blits);
        destroy(&m.base); cases++;
    }
    for(uint32_t mode=0;mode<=4;mode++) for(uint32_t opt=0;opt<=3;opt++) {
        if(mode==3 && opt==1) continue;
        struct stock_model m={0}; init(&m.base, SECURE_GPU);
        struct sgpu_report r; m.report=&r; struct sgpu_ops io=stock_ops(&m); io.stock_unsecure=opt;
        bool ok=sgpu_probe(&io, mode, fw, sizeof(fw), &r);
        assert(ok==(mode==0 || (!opt && (mode==1 || mode==2))));
        assert(!m.trust_writes && !r.stock.attempted && !r.pixels);
        if(mode==0 || (opt && (opt!=1 || mode!=3))) assert(!m.base.maps && !m.base.allocs && !m.base.writes);
        destroy(&m.base); cases++;
    }
    printf("PASS stock transition: %u scenarios; one checked zero write, no post-attempt IO, no pixels\n", cases);
    return 0;
}
