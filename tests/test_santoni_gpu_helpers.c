/* Include the ACTUAL reconstructed source to exercise private helper guards.
 * This is a host test, not a production source rewrite or kernel build. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "santoni_gpu_core.c"

struct harness { uint32_t value, reads, writes, waits; uint64_t us, jitter; bool denied, clock; };
static uint32_t helper_read(void *ctx, enum sgpu_block b, uint32_t off)
{
    (void)b; (void)off;
    struct harness *h = ctx; h->reads++;
    if (h->clock && b == SG_CC && off == 0x20)
        return (h->value & ~0x80000000u) | ((h->value & 1u) ? 0 : 0x80000000u);
    return h->value;
}
static void helper_write(void *ctx, enum sgpu_block b, uint32_t off, uint32_t value)
{
    (void)b; (void)off;
    struct harness *h = ctx; h->writes++;
    if (!h->denied) h->value = h->clock ? value & ~0x80000000u : value;
}
static uint64_t helper_now(void *ctx) { return ((struct harness *)ctx)->us; }
static void helper_wait(void *ctx, uint32_t us)
{
    struct harness *h = ctx; h->waits++; h->us += us + h->jitter;
}
static void helper_trace(void *ctx, const char *s, uint32_t a, uint32_t b, uint32_t c)
{
    (void)ctx; (void)a; (void)b; (void)c;
    assert(strncmp(s, "before ", 7) != 0); /* failure records must not add an 11s pause */
}

int main(void)
{
    struct harness h = {0};
    struct sgpu_ops io = {.ctx=&h, .read32=helper_read, .write32=helper_write,
        .now_us=helper_now, .wait_us=helper_wait, .trace=helper_trace};
    struct sgpu_report r = {.stage=SG_POWER};
    struct probe p = {.ops=&io, .report=&r};
    assert(!poll(&p, SG_CC, 0, 1, 0, POLL_US + 1));
    assert(r.failure.kind == SG_FAIL_GUARD && r.failure.budget_us == POLL_US + 1);
    assert(!h.reads && !h.writes && !h.waits);
    struct sgpu_failure first = r.failure;
    assert(!poll(&p, SG_CC, 4, 1, 1, 0));
    assert(memcmp(&first, &r.failure, sizeof(first)) == 0);

    h = (struct harness){0}; r = (struct sgpu_report){.stage=SG_POWER};
    p.saved_count = COUNT(p.saved) - 1;
    assert(change(&p, SG_CC, 0x20, 1, 1) && p.saved_count == COUNT(p.saved));
    assert(!change(&p, SG_CC, 0x20, 0x6000, 0x6000));
    assert(r.failure.kind == SG_FAIL_GUARD && r.failure.saved_count == COUNT(p.saved));
    assert(h.writes == 1 && h.reads == 3);
    p.saved_count = COUNT(p.saved) + 1;
    assert(!change(&p, SG_CC, 0x28, 1, 1) && h.writes == 1);

    h = (struct harness){.denied=true}; r = (struct sgpu_report){.stage=SG_POWER};
    p.saved_count = 0;
    assert(!change(&p, SG_CC, 0x20, 1, 1));
    assert(r.failure.kind == SG_FAIL_READBACK && r.failure.old == 0);
    assert(r.failure.written == 1 && r.failure.got == 0 && r.failure.saved_count == 1);
    first = r.failure;
    p.restoring = true;
    assert(!poll(&p, SG_CC, 4, 1, 1, 0));
    assert(r.rollback_failure.kind == SG_FAIL_POLL && r.rollback_failure.offset == 4);
    assert(memcmp(&first, &r.failure, sizeof(first)) == 0);

    h = (struct harness){.clock=true}; r = (struct sgpu_report){.stage=SG_POWER};
    p.restoring = false; p.saved_count = 0;
    assert(change(&p, SG_CC, 0x20, 0x6000, 0x6000));
    assert(change(&p, SG_CC, 0x20, 1, 1));
    assert(p.saved_count == 2 && p.saved[0].mask == 0x6000 && p.saved[1].mask == 1);
    assert((p.saved[0].value & 0x6001) == 0 && (p.saved[1].value & 0x6001) == 0x6000);
    p.restoring = true;
    assert(sgpu_restore_power(&p) && !p.saved_count && h.value == 0);

    const uint32_t budgets[] = {0, 1, 99, 100, 9999, 10000, POLL_US, POLL_US + 1};
    for (unsigned i = 0; i < COUNT(budgets); i++) {
        h = (struct harness){0}; r = (struct sgpu_report){.stage=SG_POWER}; p.restoring = false;
        assert(!poll(&p, SG_CC, 0, 1, 1, budgets[i]));
        assert(r.failure.kind == (budgets[i] > POLL_US ? SG_FAIL_GUARD : SG_FAIL_POLL));
        assert(r.failure.budget_us == budgets[i] && h.waits <= POLL_US / 100);
        assert(!h.writes && h.us <= POLL_US);
    }
    h = (struct harness){.jitter=100000000000ull};
    r = (struct sgpu_report){.stage=SG_POWER};
    assert(!poll(&p, SG_CC, 0, 1, 1, 10000));
    assert(r.failure.elapsed_us == ~0u && r.failure.budget_us == 10000 && h.waits == 1);
    puts("PASS helper guards, journal capacity, timeout boundaries and first-failure isolation");
    return 0;
}
