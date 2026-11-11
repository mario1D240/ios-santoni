/* Compile against <=0185 and current source with the SAME read-as-zero GMEM
 * model. Reproduce the supplied hardware fail tuple, then require no access
 * at all to that unused clock. This is not a hardware execution oracle. */
#define main sgpu_existing_model_main
#define SANTONI_GPU_ALLOW_LEGACY_GMEM 1
#define SANTONI_GPU_ALLOW_LEGACY_HWCG 1 /* mode1 never reaches internal clock setup */
#define SANTONI_GPU_ALLOW_LEGACY_CP 1 /* mode1 never reaches CP stop/start */
#include "../test_santoni_gpu_mock.c"
#undef main

struct gmem_model { struct model base; unsigned gmem_reads, gmem_writes; };
static uint32_t gmem_read(void *ctx, enum sgpu_block b, uint32_t off)
{
    struct gmem_model *m = ctx;
    if (b == SG_CC && off == 0x24) {
        assert(m->base.mapped[b]);
        m->gmem_reads++;
        return 0;
    }
    return read32(&m->base, b, off);
}
static void gmem_write(void *ctx, enum sgpu_block b, uint32_t off, uint32_t value)
{
    struct gmem_model *m = ctx;
    if (b == SG_CC && off == 0x24) {
        assert(m->base.mapped[b]);
        m->gmem_writes++;
        m->base.writes++;
        return;
    }
    write32(&m->base, b, off, value);
}

int main(void)
{
    struct gmem_model m = {0};
    init(&m.base, NONE);
    m.base.regs[SG_CC][0x44 / 4] = m.base.regs[SG_CC][0x1c / 4] = 0x00222801;
    m.base.regs[SG_CC][1] = 0;
    struct sgpu_ops io = ops(&m.base);
    io.ctx=&m; io.read32=gmem_read; io.write32=gmem_write;
    struct sgpu_report r;
    bool passed = sgpu_probe(&io, 1, NULL, 0, &r);
#ifdef EXPECT_LEGACY_GMEM_FAILURE
    assert(!passed && r.stage == SG_POWER && r.error == SG_POWER_TIMEOUT);
    assert(r.failure.kind == SG_FAIL_READBACK && r.failure.block == SG_CC);
    assert(r.failure.offset == 0x24 && r.failure.mask == 1 && r.failure.want == 1);
    assert(!r.failure.old && r.failure.written == 1 && !r.failure.got);
    assert(r.failure.saved_count == 14 && !r.failure.elapsed_us && !r.failure.budget_us);
    assert(m.gmem_reads == 4 && m.gmem_writes == 2 && !m.base.mapped[SG_GPU]);
    puts("PASS legacy mode1 reproduces stage2/error4/readback24/saved14 hardware tuple");
#else
    assert(passed && r.stage == SG_REGISTERS && r.error == SG_OK);
    assert(!r.failure.kind && !r.rollback_failure.kind && m.base.mapped[SG_GPU]);
    assert(!m.gmem_reads && !m.gmem_writes);
    puts("PASS current mode1 avoids unused GMEM clock entirely; same modeled hardware state");
#endif
    assert(r.restored && !r.memory_retained && !r.markers && !r.pixels && !r.trust_read);
    assert(!m.base.allocs && !m.base.frees && !m.base.packets && !m.base.mapped[SG_SMMU]);
    assert(m.base.regs[SG_CC][0x44 / 4] == 0x00222801 && m.base.regs[SG_CC][0x1c / 4] == 0x00222801);
    assert(!m.base.regs[SG_CC][1] && m.base.regs[SG_VOTE][3] == B(7));
    destroy(&m.base);
    return 0;
}
