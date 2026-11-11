/* Actual reconstructed 0220 functions; modeled DMA/cache/clock only. */
#define _POSIX_C_SOURCE 200112L
#include "santoni_gpu_core.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct sgpu_render_arena arena;
static struct sgpu_render_memory memory;
static struct sgpu_ops ops;
static uint64_t pa[SGPU_RENDER_MAX_PAGES];
static uint32_t commands[SGPU_RENDER_WORDS];
static unsigned cleans, invalidates, reads, waits, fence_reads, ready, cache_fault;
static uint32_t cb, global, irq, status, fence_value;
static uint64_t clock_us;
static bool stopped_clock, expired_clock;
static uint32_t source_handle, destination_handle;
static struct sgpu_render_plane sp, dp;

static uint32_t read32(void *ctx, enum sgpu_block block, uint32_t offset)
{
    assert(ctx == &arena); reads++;
    if (block == SG_GPU && offset == SG_STATUS) return status;
    if (block == SG_GPU && offset == SG_INT_STATUS) return irq;
    if (block == SG_SMMU && offset == SG_CB_FSR) return cb;
    assert(block == SG_SMMU && offset == 0x48); return global;
}
static uint64_t now(void *ctx) { assert(ctx == &arena); return clock_us; }
static void wait_us(void *ctx, uint32_t us)
{
    assert(ctx == &arena && us == 100); waits++;
    if (!stopped_clock) clock_us += expired_clock ? SGPU_RENDER_WAIT_US : us;
}
static void clean(void *ctx, const void *bytes, uint32_t length)
{
    assert(ctx == &arena && arena.exposed && arena.busy);
    assert(length); (void)bytes; cleans++;
    if (cache_fault == cleans) assert(arena.bo[0].last_seq == arena.busy);
}
static void invalidate(void *ctx, const void *bytes, uint32_t length)
{
    assert(ctx == &arena && arena.busy); invalidates++;
    if (bytes == memory.tables + 6 * SGPU_PAGE) {
        assert(length == 64); fence_reads++;
        if (ready && fence_reads >= ready) *(uint32_t *)(void *)bytes = fence_value ? fence_value : arena.busy;
    } else {
        assert(bytes == memory.pixels + arena.bo[1].physical * SGPU_PAGE);
        assert(length == arena.bo[1].pages * SGPU_PAGE);
    }
}
static void reset(unsigned pages)
{
    free(memory.tables); free(memory.pixels);
    memset(&arena, 0, sizeof(arena)); memset(&memory, 0, sizeof(memory));
    void *tables = NULL, *pixels = NULL;
    assert(!posix_memalign(&tables, SGPU_PAGE, SGPU_RENDER_TABLE_PAGES * SGPU_PAGE));
    assert(!posix_memalign(&pixels, SGPU_PAGE, pages * SGPU_PAGE));
    memory.tables = tables; memory.pixels = pixels;
    assert(memory.tables && memory.pixels);
    memory.pages = pages; memory.pa = pa;
    memset(memory.tables, 0x55, SGPU_RENDER_TABLE_PAGES * SGPU_PAGE);
    memset(memory.pixels, 0xa5, pages * SGPU_PAGE);
    for (unsigned i = 0; i < SGPU_RENDER_TABLE_PAGES; i++) memory.table_pa[i] = SGPU_DMA_MIN + i * SGPU_PAGE;
    /* Physical pages have holes. CPU and GPU aliases remain contiguous. */
    for (unsigned i = 0; i < pages; i++) pa[i] = SGPU_DMA_MIN + 0x100000 + i * 2 * SGPU_PAGE;
    ops = (struct sgpu_ops){.ctx = &arena, .read32 = read32, .now_us = now,
        .wait_us = wait_us, .clean = clean, .invalidate = invalidate};
    cleans = invalidates = reads = waits = fence_reads = cache_fault = 0;
    ready = 1; cb = 0x400; global = irq = fence_value = 0; status = 0x800001c1;
    clock_us = 1000; stopped_clock = expired_clock = false;
    memset(commands, 0xa5, sizeof(commands));
}
static void prepare(unsigned pages, uint32_t bytes)
{
    reset(pages); assert(sgpu_render_init(&arena, &memory, &ops));
    source_handle = sgpu_render_new(&arena, 0x100000001ull, bytes);
    destination_handle = sgpu_render_new(&arena, 0x100000001ull, bytes);
    assert(source_handle && destination_handle);
    sp = (struct sgpu_render_plane){source_handle, 0, 16, 16, 64, SG_RENDER_RGBA8};
    dp = sp; dp.handle = destination_handle;
}
static uint32_t begin(void)
{
    return sgpu_render_begin(&arena, 0x100000001ull, &sp, &dp, commands, SGPU_RENDER_WORDS);
}
static void denied(void)
{
    struct sgpu_render_arena saved = arena;
    uint32_t old[SGPU_RENDER_WORDS]; memcpy(old, commands, sizeof(old));
    assert(!begin()); assert(!memcmp(old, commands, sizeof(old)));
    assert(!memcmp(&saved, &arena, sizeof(arena))); assert(!cleans);
}
static uint64_t *l3(void) { return (uint64_t *)(void *)(memory.tables + 2 * SGPU_PAGE); }

static void layouts(void)
{
    prepare(1920, 3932160);
    sp.width = dp.width = 720; sp.height = dp.height = 1280;
    sp.stride = dp.stride = 3072; sp.format = dp.format = SG_RENDER_BGRA8;
    assert(begin() == 73); assert(cleans == 4); assert(sgpu_render_wait(&arena));
    uint32_t fixed[SGPU_RENDER_WORDS];
    assert(sgpu_blit_commands(fixed, SGPU_RENDER_WORDS, SGPU_MARKER_VA + 768) == 73);
    /* Differential command scope: each exact old -> new value is intentional. */
    unsigned changed = 0;
    for (unsigned i = 0; i < 73;) {
        uint32_t h = fixed[i++], count = h >> 28 == 4 ? h & 127 : h & 0x3fff;
        if (h >> 28 == 4) {
            unsigned reg = (h >> 8) & 0x3ffff;
            if (reg == 0x2107 || reg == 0x2110) {
                assert(fixed[i + 1] == (reg == 0x2107 ? SGPU_SOURCE_VA : SGPU_DEST_VA));
                assert(fixed[i + 3] == 0x00100001);
#if defined(SGPU_RENDER_VA)
                fixed[i + 1] = reg == 0x2107 ? 0x01201000 : 0x015c2000;
#else
                fixed[i + 1] = reg == 0x2107 ? 0x01001000 : 0x013c2000;
#endif
                fixed[i + 3] = 0xf0000030; changed += 2;
            }
        } else if (((h >> 16) & 0x7f) == 0x2c) {
            assert(fixed[i + 2] == 0x000f000f && fixed[i + 4] == 0x000f000f);
            fixed[i + 2] = fixed[i + 4] = 0x04ff02cf; changed += 2;
        } else if (((h >> 16) & 0x7f) == 0x46) {
            assert(fixed[i + 1] == 0x01030300);
#if defined(SGPU_RENDER_VA)
            fixed[i + 1] = 0x01200000;
#else
            fixed[i + 1] = 0x01000000;
#endif
            changed++;
            if (fixed[i] == 4) { assert(fixed[i + 3] == 0xa5052d01); fixed[i + 3] = 1; changed++; }
        }
        i += count;
    }
    assert(changed == 9 && !memcmp(fixed, commands, 73 * sizeof(uint32_t)));
    assert(arena.completed == 1 && !arena.busy && arena.exposed);
    assert(!l3()[arena.bo[0].first + arena.bo[0].pages]);
    assert(!l3()[arena.bo[1].first + arena.bo[1].pages]);
    assert(arena.bo[0].pages == 960 && arena.bo[1].pages == 960);
    /* Reuse only after completion, preserve channels and both row paddings. */
    sp.stride = dp.stride = 2880;
    assert(begin() == 73); assert(sgpu_render_wait(&arena)); assert(arena.completed == 2);
    dp.format = SG_RENDER_RGBA8; assert(!begin()); dp.format = sp.format;
    assert(!sgpu_render_free(&arena, 0x100000001ull, source_handle));
    assert(arena.bo[0].quarantine && l3()[arena.bo[0].first]);
}
static void invalid_inputs(void)
{
    prepare(32, 4096);
    struct sgpu_render_plane saved = sp;
    for (unsigned which = 0; which < 13; which++) {
        sp = saved;
        switch (which) {
        case 0: sp.width = 0; break; case 1: sp.height = 0; break;
        case 2: sp.width = 4097; break; case 3: sp.height = UINT32_MAX; break;
        case 4: sp.stride = 63; break; case 5: sp.stride = UINT32_MAX; break;
        case 6: sp.offset = 1; break; case 7: sp.offset = UINT32_MAX; break;
        case 8: sp.offset = 4096; break; case 9: sp.stride = 320; break;
        case 10: sp.format = 3; break; case 11: sp.handle = destination_handle; break;
        case 12: sp.width = 15; break;
        }
        denied();
    }
    sp = saved;
    assert(!sgpu_render_begin(&arena, 1, &sp, &dp, commands, SGPU_RENDER_WORDS));
    assert(!sgpu_render_begin(&arena, 0x100000001ull, &sp, &dp, commands, SGPU_RENDER_WORDS - 1));
    assert(!sgpu_render_begin(&arena, 0x100000001ull, &sp, &dp, (uint32_t *)(void *)memory.tables, SGPU_RENDER_WORDS));
    assert(!sgpu_render_begin(&arena, 0x100000001ull, &sp, &dp, (uint32_t *)(void *)memory.pixels, SGPU_RENDER_WORDS));
    arena.submitted = UINT32_MAX; denied(); arena.submitted = 0;
    uint64_t old = l3()[arena.bo[0].first];
    l3()[arena.bo[0].first] = 0; denied(); l3()[arena.bo[0].first] = old;
    old = l3()[arena.bo[0].first + arena.bo[0].pages];
    l3()[arena.bo[0].first + arena.bo[0].pages] = pa[3] | 3; denied();
    l3()[arena.bo[0].first + arena.bo[0].pages] = old;
    uint64_t saved_pa = pa[0]; pa[0] = 0; denied(); pa[0] = saved_pa;
    pa[31] = pa[30]; denied(); pa[31] = SGPU_DMA_MIN + 0x100000 + 31 * 2 * SGPU_PAGE;
    memory.tables[0] = 0; denied();
}
static void lifetime(void)
{
    prepare(32, 4096);
    uint8_t *p = NULL; assert(sgpu_render_cpu(&arena, 0x100000001ull, source_handle, 0, 4096, &p));
    assert(p == memory.pixels); assert(!sgpu_render_cpu(&arena, 1, source_handle, 0, 4096, &p));
    assert(!sgpu_render_cpu(&arena, 0x100000001ull, source_handle, 4095, 2, &p));
    assert(sgpu_render_free(&arena, 0x100000001ull, source_handle));
    assert(!sgpu_render_cpu(&arena, 0x100000001ull, source_handle, 0, 4, &p));
    sp.handle = source_handle = sgpu_render_new(&arena, 0x100000001ull, 4096);
    assert(source_handle == 3); /* no stale handle revival */
    assert(begin()); assert(!sgpu_render_cpu(&arena, 0x100000001ull, source_handle, 0, 4, &p));
    assert(!begin()); assert(!sgpu_render_new(&arena, 0x100000001ull, 4096));
    assert(sgpu_render_wait(&arena));
    assert(sgpu_render_cpu(&arena, 0x100000001ull, source_handle, 0, 4, &p));
    assert(!sgpu_render_init(&arena, &memory, &ops));
    assert(!sgpu_render_new(&arena, 0x100000001ull, 4096));
}
static void failures(void)
{
    for (unsigned kind = 0; kind < 10; kind++) {
        prepare(32, 4096); assert(begin());
        switch (kind) {
        case 0: ready = 0; stopped_clock = true; break;
        case 1: ready = 0; expired_clock = true; break;
        case 2: cb = 2; break; case 3: irq = 0x200; break; case 4: global = 8; break;
        case 5: fence_value = 2; stopped_clock = true; break;
        case 6: status = 2; stopped_clock = true; break;
        case 7: l3()[arena.bo[0].first] = 0; break;
        case 8: l3()[arena.bo[1].first + arena.bo[1].pages] = 3; break;
        case 9: pa[31] = 0; break;
        }
        assert(!sgpu_render_wait(&arena));
        assert(arena.busy == 1 && !arena.completed && arena.exposed);
        assert(arena.bo[0].quarantine && arena.bo[1].quarantine);
        uint32_t error = arena.error;
        assert(error == (kind == 2 || kind == 3 || kind == 4 ? SG_RENDER_FAULT :
            kind >= 7 ? SG_RENDER_BAD_MAPPING : SG_RENDER_TIMEOUT));
        sgpu_render_abort(&arena, SG_RENDER_FAULT); assert(arena.error == error);
        assert(!sgpu_render_free(&arena, 0x100000001ull, destination_handle));
        assert(!begin()); assert(!sgpu_render_wait(&arena));
        if (kind == 0 || kind == 5 || kind == 6) assert(fence_reads == 2001 && waits == 2000);
        if (kind == 1) assert(fence_reads == 2 && waits == 1);
    }
}
static void memory_guards(void)
{
    for (unsigned kind = 0; kind < 9; kind++) {
        reset(32); struct sgpu_render_memory m = memory;
        switch (kind) {
        case 0: m.pages = 0; break; case 1: m.pages = SGPU_RENDER_MAX_PAGES + 1; break;
        case 2: m.table_pa[6] = m.table_pa[0]; break; case 3: pa[31] = pa[30]; break;
        case 4: pa[0] = m.table_pa[6]; break; case 5: pa[31] = SGPU_DMA_END; break;
        case 6: m.pixels++; break; case 7: m.tables = m.pixels; break;
        case 8: ops.clean = NULL; break;
        }
        assert(!sgpu_render_init(&arena, &m, &ops)); assert(!arena.initialized);
        assert(memory.tables[0] == 0x55);
    }
}
int main(void)
{
    layouts(); invalid_inputs(); lifetime(); failures(); memory_guards();
    prepare(32, 4096); assert(begin());
    uint32_t fixed[100]; unsigned n = sgpu_blit_commands(fixed, 100, SGPU_MARKER_VA + 768);
    unsigned deltas = 0;
    for (unsigned i = 0; i < n; i++) if (fixed[i] != commands[i]) deltas++;
    assert(deltas == 5); /* two bases, two event addresses, one fence sequence */
    assert(cleans == 4); assert(sgpu_render_wait(&arena)); assert(invalidates == 2 && reads == 4);
    printf("PASS render0220: full padded BGRA, malformed/missing/late mappings, ownership, cache/fence, timeout quarantine; %u command words\n", n);
    printf("ABI arena=%zu memory=%zu bo=%zu plane=%zu ops=%zu; bo=%zu next_handle=%zu busy=%zu error=%zu initialized=%zu\n",
        sizeof(arena), sizeof(memory), sizeof(struct sgpu_render_bo), sizeof(sp), sizeof(ops),
        offsetof(struct sgpu_render_arena, bo), offsetof(struct sgpu_render_arena, next_handle),
        offsetof(struct sgpu_render_arena, busy), offsetof(struct sgpu_render_arena, error),
        offsetof(struct sgpu_render_arena, initialized));
    free(memory.tables); free(memory.pixels); return 0;
}
