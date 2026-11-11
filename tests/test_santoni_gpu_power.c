/* Failure-site coverage for the ACTUAL shipped core. Reuse the existing MMIO,
 * cache and page-table model; the injections below are hypotheses, not claims
 * about Qualcomm hardware. No device access or kernel build is performed. */
#define main sgpu_existing_model_main
#include "test_santoni_gpu_mock.c"
#undef main

enum failure_mode { FM_NONE, FM_WRITE, FM_POLL, FM_DEFERRED_CFG, FM_ALIASED_CFG,
    FM_WAIT_FIELDS, FM_COLLAPSE_BIT };
struct site { enum sgpu_block block; uint32_t off, mask, want; };
struct failure_model {
    struct model base; /* existing callbacks receive this first member */
    struct sgpu_report *report;
    struct site site;
    enum failure_mode mode;
    bool armed, status_ready;
    uint32_t old, written, got, forward_traces, rollback_traces, gx_collapses;
    struct sgpu_failure at_trace;
};
_Static_assert(offsetof(struct failure_model, base) == 0, "model callback ABI");

static uint32_t failure_read(void *ctx, enum sgpu_block b, uint32_t off)
{
    struct failure_model *m = ctx;
    uint32_t got = read32(&m->base, b, off);
    if (m->mode == FM_POLL && m->armed && m->status_ready &&
        b == m->site.block && off == m->site.off)
        got = (got & ~m->site.mask) | ((~m->site.want) & m->site.mask);
    return got;
}

static void failure_write(void *ctx, enum sgpu_block b, uint32_t off, uint32_t value)
{
    struct failure_model *m = ctx;
    uint32_t old = *reg(&m->base, b, off);
    /* Vendor KGSL closes clocks before rails. Check the probe-owned GFX3D
     * enable has been restored before recollapsing GX, retaining its memory
     * bits until after that domain transition. Original branches are OFF. */
    if (b == SG_CC && off == 0x1c && (value & 1) && !(old & 1)) {
        assert(!(m->base.regs[SG_CC][0x20 / 4] & 1));
        assert((m->base.regs[SG_CC][0x20 / 4] & 0x6000) == 0x6000);
        m->gx_collapses++;
    }
    if (m->mode == FM_POLL && m->armed) {
        if (m->site.block == SG_TCU && b == SG_VOTE && off == 0xc)
            m->status_ready = true;
        else if (b == m->site.block && off == m->site.off) {
            if (off == 0 && m->site.mask == 1) m->status_ready |= (value & 1) != 0;
            else if (off == 0) m->status_ready |= (value & 2) != 0;
            else if (off == 0x44 || off == 0x1c) m->status_ready |= !(value & 1);
            else m->status_ready |= (value & 1) != 0;
        }
    }
    if (m->armed && m->mode != FM_NONE && m->mode != FM_POLL &&
        b == m->site.block && off == m->site.off &&
        (value & m->site.mask) == m->site.want) {
        m->old = old;
        m->written = value;
        if (m->mode == FM_WRITE || m->mode == FM_DEFERRED_CFG) m->base.writes++;
        else if (m->mode == FM_ALIASED_CFG) write32(&m->base, b, off, value & ~1u);
        else if (m->mode == FM_WAIT_FIELDS)
            write32(&m->base, b, off, (value & ~0x00fff000u) | (old & 0x00fff000u));
        else if (m->mode == FM_COLLAPSE_BIT) write32(&m->base, b, off, value | 1u);
        m->got = *reg(&m->base, b, off);
        return;
    }
    write32(&m->base, b, off, value);
}

static void failure_trace(void *ctx, const char *s, uint32_t a, uint32_t b, uint32_t c)
{
    struct failure_model *m = ctx;
    if (strcmp(s, "FAIL stage/kind/block") == 0) {
        assert(!m->forward_traces++);
        m->at_trace = m->report->failure;
        assert(a == m->at_trace.stage && b == m->at_trace.kind && c == m->at_trace.block);
        m->armed = false; /* cleanup changes the register, not the saved evidence */
    }
    if (strcmp(s, "ROLLBACK_FAIL stage/kind/block") == 0) m->rollback_traces++;
    assert(strncmp(s, "before ", 7) != 0 || strncmp(s, "before powered", 14) == 0 ||
        strncmp(s, "before ME_INIT", 14) == 0 || strncmp(s, "before TRUST", 12) == 0);
}

static void failure_init(struct failure_model *m, struct sgpu_report *report)
{
    memset(m, 0, sizeof(*m));
    init(&m->base, NONE);
    m->base.regs[SG_CC][0x44 / 4] = 0x00222801;
    m->base.regs[SG_CC][0x1c / 4] = 0x00222801;
    m->base.regs[SG_CC][1] = 0; /* exact observed CX/GX/CFG, other state is modeled */
    m->report = report;
}

static struct sgpu_ops failure_ops(struct failure_model *m)
{
    struct sgpu_ops io = ops(&m->base);
    io.ctx = m;
    io.read32 = failure_read;
    io.write32 = failure_write;
    io.trace = failure_trace;
    return io;
}

static void assert_power_exit(struct failure_model *m, const struct sgpu_report *r)
{
    assert(r->stage == SG_POWER && r->error == SG_POWER_TIMEOUT);
    assert(!r->markers && !r->pixels && !r->trust_read && !r->trust);
    assert(!r->memory_retained && m->base.frees == 1 && !m->base.exposed);
    assert(!m->base.mapped[SG_GPU] && !m->base.mapped[SG_SMMU] && !m->base.packets);
    assert(r->failure.stage == SG_POWER && m->forward_traces == 1);
    assert(memcmp(&r->failure, &m->at_trace, sizeof(r->failure)) == 0);
    assert(m->base.us < 1500000);
    assert(r->restored ? r->power_pending == 0 : r->power_pending != 0);
}

int main(void)
{
    uint8_t fw[64];
    firmware(fw);
    struct sgpu_report r;
    unsigned cases = 0;
    const struct site owners[] = {
        {SG_CC, 0x44, 2, 0}, {SG_CC, 0x44, 4, 0},
        {SG_CC, 0x1c, 2, 0}, {SG_CC, 0x1c, 4, 0}, {SG_CC, 0, 1, 0}, {SG_CC, 0x20, 1, 0}
    };
    for (unsigned i = 0; i < sizeof(owners) / sizeof(owners[0]); i++) {
        struct failure_model m; failure_init(&m, &r);
        m.base.regs[SG_CC][owners[i].off / 4] |= owners[i].mask;
        uint32_t got = m.base.regs[SG_CC][owners[i].off / 4];
        struct sgpu_ops io = failure_ops(&m);
        assert(!sgpu_probe(&io, 3, fw, sizeof(fw), &r));
        assert_power_exit(&m, &r);
        assert(r.failure.kind == SG_FAIL_OWNER && r.failure.offset == owners[i].off);
        assert(r.failure.mask == ((owners[i].off == 0x44 || owners[i].off == 0x1c) ? 6u : 1u) && !r.failure.want);
        assert(r.failure.got == got && r.failure.old == got && !r.failure.saved_count);
        assert(!m.base.writes && r.restored && !r.rollback_failure.kind);
        destroy(&m.base); cases++;
    }
    const struct site writes[] = {
        {SG_CC, 0, 2, 2}, {SG_CC, 4, 0x371f, 1}, {SG_MISC, 0xc, 1, 0},
        {SG_CC, 0x44, 0x00fff001, 0x00282000}, {SG_CC, 0x20, 0x6000, 0x6000},
        {SG_CC, 0x1c, 0x00fff001, 0x00285000}, {SG_VOTE, 0xc, 0xe, 0xe},
        {SG_CC, 0x20, 1, 1}, {SG_CC, 0x28, 1, 1}, {SG_CC, 0x30, 1, 1},
        {SG_CC, 0x34, 1, 1}, {SG_CC, 0x40, 1, 1}, {SG_CC, 0x4c, 1, 1}
    };
    for (unsigned i = 0; i < sizeof(writes) / sizeof(writes[0]); i++) {
        struct failure_model m; failure_init(&m, &r);
        m.mode = FM_WRITE; m.armed = true; m.site = writes[i];
        struct sgpu_ops io = failure_ops(&m);
        assert(!sgpu_probe(&io, 3, fw, sizeof(fw), &r));
        assert_power_exit(&m, &r);
        assert(r.failure.kind == SG_FAIL_READBACK && r.failure.block == writes[i].block);
        assert(r.failure.offset == writes[i].off && r.failure.mask == writes[i].mask);
        assert(r.failure.want == writes[i].want && r.failure.saved_count == i + 1);
        assert(r.failure.old == m.old && r.failure.written == m.written && r.failure.got == m.got);
        assert(!r.failure.elapsed_us && !r.failure.budget_us);
        assert(r.restored == (i <= 5)); /* after GX is awake, an unread GPU must stay powered */
        assert(r.rollback_failure.kind == (r.restored ? SG_FAIL_NONE : SG_FAIL_GUARD));
        destroy(&m.base); cases++;
    }
    const struct site polls[] = {
        {SG_CC, 0, B(31), 0}, {SG_CC, 0, 1, 0},
        {SG_CC, 0x44, B(31), B(31)}, {SG_CC, 0x1c, B(31), B(31)},
        {SG_TCU, 0x10, B(31), 0}, {SG_TCU, 0x18, B(31), 0}, {SG_TCU, 0x20, B(31), 0},
        {SG_CC, 0x20, 0xf0000000u, 0}, {SG_CC, 0x28, 0xf0000000u, 0},
        {SG_CC, 0x30, 0xf0000000u, 0}, {SG_CC, 0x34, 0xf0000000u, 0},
        {SG_CC, 0x40, 0xf0000000u, 0}, {SG_CC, 0x4c, 0xf0000000u, 0}
    };
    for (unsigned i = 0; i < sizeof(polls) / sizeof(polls[0]); i++) {
        struct failure_model m; failure_init(&m, &r);
        m.mode = FM_POLL; m.armed = true; m.site = polls[i];
        struct sgpu_ops io = failure_ops(&m);
        assert(!sgpu_probe(&io, 3, fw, sizeof(fw), &r));
        assert_power_exit(&m, &r);
        assert(r.failure.kind == SG_FAIL_POLL && r.failure.block == polls[i].block);
        assert(r.failure.offset == polls[i].off && r.failure.mask == polls[i].mask);
        assert(r.failure.want == polls[i].want && (r.failure.got & polls[i].mask) != polls[i].want);
        assert(r.failure.budget_us == 10000 && r.failure.elapsed_us == 10000);
        assert(r.restored == (i <= 2));
        assert(r.rollback_failure.kind == (r.restored ? SG_FAIL_NONE : SG_FAIL_GUARD));
        destroy(&m.base); cases++;
    }
    for (enum failure_mode mode = FM_DEFERRED_CFG; mode <= FM_COLLAPSE_BIT; mode++) {
        struct failure_model m; failure_init(&m, &r);
        m.mode = mode; m.armed = true;
        m.site = writes[mode <= FM_ALIASED_CFG ? 1 : 3];
        struct sgpu_ops io = failure_ops(&m);
        assert(!sgpu_probe(&io, 3, fw, sizeof(fw), &r));
        assert_power_exit(&m, &r);
        assert(r.failure.kind == SG_FAIL_READBACK && r.failure.offset == m.site.off);
        assert(r.failure.got == m.got && r.failure.written == m.written);
        if (mode == FM_WAIT_FIELDS) assert(!(r.failure.got & 1));
        if (mode == FM_COLLAPSE_BIT) assert((r.failure.got & 0x00fff000) == r.failure.want);
        assert(r.restored && !r.rollback_failure.kind);
        destroy(&m.base); cases++;
    }
    for (unsigned mode = 0; mode <= 3; mode++) {
        struct failure_model m; failure_init(&m, &r);
        struct sgpu_ops io = failure_ops(&m);
        assert(sgpu_probe(&io, mode, fw, sizeof(fw), &r));
        assert(!r.failure.kind && !r.rollback_failure.kind && !m.forward_traces && !m.rollback_traces);
        if (mode) assert(r.restored && m.gx_collapses == 1);
        if (mode < 2) assert(!m.base.allocs && !m.base.packets && !m.base.mapped[SG_SMMU]);
        if (!mode) assert(!m.base.maps && !m.base.writes);
        if (mode >= 2) assert(r.markers == 16 && r.memory_retained && !m.base.frees);
        assert(r.trust_read == (mode == 3));
        assert(r.pixels == (mode == 3 ? 256u : 0u));
        assert(m.base.regs[SG_CC][1] == 0 && m.base.regs[SG_VOTE][3] == B(7));
        assert(m.base.regs[SG_CC][0x1c / 4] == 0x00222801);
        assert(m.base.regs[SG_CC][0x44 / 4] == 0x00222801);
        destroy(&m.base); cases++;
    }
    printf("PASS %u power scenarios: owners=6 readbacks=13 polls=13; immutable evidence; clocks before GX collapse\n", cases);
    return 0;
}
