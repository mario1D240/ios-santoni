/* Differential MMIO oracle: compile the SAME fixture against selected patch
 * revisions. Only forward operations are emitted, excluding rollback. The
 * wrapper requires an exact GMEM-only delta separately from safety checks. */
#define main sgpu_existing_model_main
#define SANTONI_GPU_ALLOW_LEGACY_GMEM 1 /* only this differential fixture runs the old driver */
#define SANTONI_GPU_ALLOW_LEGACY_HWCG 1 /* clock completion is checked separately */
#define SANTONI_GPU_ALLOW_LEGACY_CP 1 /* the bit28 regression is pinned independently */
#include "../test_santoni_gpu_mock.c"
#undef main

struct forward_model { struct model base; struct sgpu_report *report; unsigned mode; bool active; };
static bool recording(struct forward_model *m) {
#ifdef SANTONI_GPU_TRACE_CLEANUP
    (void)m; return true;
#else
    return m->active && m->report->stage != SG_COMPLETE;
#endif
}

static bool forward_map(void *ctx, enum sgpu_block b, uint32_t pa, uint32_t n)
{
    struct forward_model *m = ctx;
    if (recording(m)) printf("MAP %u %08x %08x\n", b, pa, n);
    return map(&m->base, b, pa, n);
}
static uint32_t forward_read(void *ctx, enum sgpu_block b, uint32_t off)
{
    struct forward_model *m = ctx;
    uint32_t value = read32(&m->base, b, off);
    if (recording(m)) printf("R32 %u %08x %08x\n", b, off, value);
    return value;
}
static uint64_t forward_read64(void *ctx, enum sgpu_block b, uint32_t off)
{
    struct forward_model *m = ctx;
    uint64_t value = read64(&m->base, b, off);
    if (recording(m)) printf("R64 %u %08x %016llx\n", b, off, (unsigned long long)value);
    return value;
}
static void forward_write(void *ctx, enum sgpu_block b, uint32_t off, uint32_t value)
{
    struct forward_model *m = ctx;
    if (recording(m)) printf("W32 %u %08x %08x\n", b, off, value);
#if defined(SANTONI_GPU_STOCK_ONLY_TRACE) || defined(SANTONI_GPU_STOCK_PIXEL_TRACE)
    if (b == SG_GPU && off == SG_TRUST) {
        assert(value == 0 && m->report->stock.attempted);
        *reg(&m->base, b, off) = 0;
        return;
    }
#endif
    write32(&m->base, b, off, value);
}
static void forward_write64(void *ctx, enum sgpu_block b, uint32_t off, uint64_t value)
{
    struct forward_model *m = ctx;
    if (recording(m)) printf("W64 %u %08x %016llx\n", b, off, (unsigned long long)value);
    write64(&m->base, b, off, value);
}
static void forward_wait(void *ctx, uint32_t us)
{
    struct forward_model *m = ctx;
    if (recording(m)) printf("WAIT %u\n", us);
    mock_wait_us(&m->base, us);
}
static void forward_clean(void *ctx, const void *va, uint32_t n)
{
    struct forward_model *m = ctx;
    if (recording(m)) printf("CLEAN %u %u\n", (unsigned)((const uint8_t *)va - m->base.cpu), n);
    clean(&m->base, va, n);
}
static void forward_invalidate(void *ctx, const void *va, uint32_t n)
{
    struct forward_model *m = ctx;
    if (recording(m)) printf("INVALIDATE %u %u\n", (unsigned)((const uint8_t *)va - m->base.cpu), n);
    invalidate(&m->base, va, n);
}
static void forward_trace(void *ctx, const char *s, uint32_t a, uint32_t b, uint32_t c)
{
    (void)a; (void)b; (void)c;
    struct forward_model *m = ctx;
    if (m->mode == 1 && strcmp(s, "GPU VBIF/AON delta/status") == 0) m->active = false;
}

int main(void)
{
    uint8_t fw[64]; firmware(fw);
    for (unsigned mode = 1; mode <= 3; mode++) {
        struct sgpu_report report;
        struct forward_model m = {.report=&report, .mode=mode, .active=true};
        init(&m.base, NONE);
        m.base.regs[SG_CC][0x44 / 4] = m.base.regs[SG_CC][0x1c / 4] = 0x00222801;
        m.base.regs[SG_CC][1] = 0;
        struct sgpu_ops io = ops(&m.base);
        io.ctx=&m; io.map=forward_map; io.read32=forward_read; io.read64=forward_read64;
        io.write32=forward_write; io.write64=forward_write64; io.wait_us=forward_wait;
        io.clean=forward_clean; io.invalidate=forward_invalidate; io.trace=forward_trace;
        printf("MODE %u\n", mode);
#ifdef SANTONI_GPU_STOCK_ONLY_TRACE
        if (mode == 3) {
            io.stock_unsecure = 1;
            m.base.regs[SG_GPU][SG_TRUST / 4] = 1;
            assert(!sgpu_probe(&io, mode, fw, sizeof(fw), &report));
            assert(report.error == SG_STOCK_HELD && report.stock.echo_zero && report.stock.held);
            destroy(&m.base);
            continue;
        }
#endif
#ifdef SANTONI_GPU_STOCK_PIXEL_TRACE
        if (mode == 3) {
            io.stock_unsecure = io.stock_pixels = 1;
            m.base.regs[SG_GPU][SG_TRUST / 4] = 1;
            assert(!sgpu_probe(&io, mode, fw, sizeof(fw), &report));
            assert(report.pixel.passed && report.pixels == 256 && report.error == SG_STOCK_HELD);
            destroy(&m.base);
            continue;
        }
#endif
        assert(sgpu_probe(&io, mode, fw, sizeof(fw), &report));
        destroy(&m.base);
    }
    return 0;
}
