/* Exercise extracted production SCM policy/entry/worker with a scripted SMC.
 * No SMC instruction is compiled into or executed by this host harness.
 * Call/time limits prove bounded callback re-entry, not a firmware return.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "santoni_gpu_core.h"

#ifndef __unused
#define __unused __attribute__((unused))
#endif
typedef int wait_result_t;
typedef void *DTEntry;
enum { kSuccess = 0 };
static struct { uint32_t mode, stock_unsecure, stock_pixels, g3, session, user, user_test; } sg;
/* This fixture keeps the independently tested launcher disabled. Its existing
 * off-role getters return true; no launcher service or child is simulated. */
static bool santoni_gpu_user_launch_options_ok(uint32_t mode) { (void)mode; return true; }
static bool santoni_gpu_user_launch_worker_ready(uint32_t mode) { (void)mode; return true; }
static void sgpu_session_loop(void) { assert(!"session loop unexpectedly reached by SCM fixture"); }
/* New render role stays off in this SCM-only fixture. Actual allocation,
 * dispatch and enabled/disabled roles have their own live-native contracts. */
static const uint32_t sgpu_render_enabled=0;
static bool sgpu_render_options(uint32_t mode) { (void)mode; return true; }
static bool sgpu_ui_options(uint32_t mode) { (void)mode; return true; } /* UI role disabled */
static bool sgpu_graphics_options(uint32_t mode) { (void)mode; return true; } /* graphics role disabled */
static void sgpu_render_worker(const struct sgpu_ops *ops,const uint8_t *fw,size_t bytes,
    struct sgpu_report *report)
{ (void)ops;(void)fw;(void)bytes;(void)report;assert(!"render reached SCM fixture"); }
static bool sgpu_smc_frame(void *, bool, uint64_t[8]);
static uint64_t now_us(void *);
static void sgpu_kernel_wait_us(void *, uint32_t);
static void trace(void *, const char *, uint32_t, uint32_t, uint32_t);
static bool PE_parse_boot_argn(const char *, void *, unsigned);
static int capture_printf(const char *, ...) __attribute__((format(printf, 1, 2)));
static void thread_terminate_self(void);
static bool sgpu_pas_cache_preflight(uint32_t mode);
static void sgpu_zap_allocation_preflight(uint32_t);
static int SecureDTLookupEntry(void *, const char *, DTEntry *);
static int SecureDTGetProperty(DTEntry, const char *, const void **, unsigned *);
static bool io_map(void *, enum sgpu_block, uint32_t, uint32_t);
static uint32_t sgpu_io_read32(void *, enum sgpu_block, uint32_t);
static uint64_t sgpu_io_read64(void *, enum sgpu_block, uint32_t);
static void sgpu_io_write32(void *, enum sgpu_block, uint32_t, uint32_t);
static void sgpu_io_write64(void *, enum sgpu_block, uint32_t, uint64_t);
static bool allocate(void *, struct sgpu_memory *);
static void release(void *, struct sgpu_memory *);
static void clean(void *, const void *, uint32_t);
static void sgpu_cache_invalidate(void *, const void *, uint32_t);
static void sgpu_failure_summary(const char *, const struct sgpu_failure *);
#define printf capture_printf
#include "santoni_gpu_scm_actual.h"
#undef printf

/* Layout consumed by the actual-binary wiring checker, on 64-bit hosts/XNU. */
_Static_assert(sizeof(struct sgpu_scm_budget) == 16, "SCM shared budget layout");
_Static_assert(sizeof(struct sgpu_scm_result) == 96, "SCM raw result layout");
_Static_assert(offsetof(struct sgpu_scm_result, raw) == 24, "SCM raw frame offset");
_Static_assert(sizeof(struct sgpu_scm_report) == 496, "SCM report layout");
_Static_assert(offsetof(struct sgpu_scm_report, probe64) == 16, "SCM probe64 offset");
_Static_assert(offsetof(struct sgpu_scm_report, probe32) == 112, "SCM probe32 offset");
_Static_assert(offsetof(struct sgpu_scm_report, availability) == 208, "SCM availability offset");
_Static_assert(offsetof(struct sgpu_scm_report, support) == 304, "SCM support offset");
_Static_assert(offsetof(struct sgpu_scm_report, failure) == 400, "SCM first failure offset");

struct step {
    bool wide, transport;
    uint64_t input[8], output[8], delay;
};
struct script {
    struct step steps[70];
    unsigned count, calls, waits, traces;
    uint64_t now, slept, trace_cost;
};
static struct script device;
static uint32_t zap, opt_in, stock_arg, cache_arg, last_stock, pixel_arg, last_pixels;
static uint32_t g3_arg, last_g3;
static bool zap_present = true, scm_present = true;
static unsigned parses, terminated, allocations, gpu_calls, dt_reads, diagnostics, cases;
static char last_diagnostic[1024];

static void reset(void)
{
    memset(&device, 0, sizeof(device));
    zap = opt_in = 1;
    stock_arg = cache_arg = last_stock = 0;
    pixel_arg = last_pixels = 0;
    g3_arg = last_g3 = 0;
    zap_present = scm_present = true;
    parses = terminated = allocations = gpu_calls = dt_reads = diagnostics = 0;
    last_diagnostic[0] = 0;
}

static void frame(uint64_t a[8], uint32_t fn, uint32_t arg)
{
    memset(a, 0, 8 * sizeof(*a));
    a[0] = fn; a[1] = 1; a[2] = arg;
}

static struct step *add_step(struct script *s, bool wide, const uint64_t input[8],
    int32_t status, uint64_t service, uint64_t delay)
{
    assert(s->count < sizeof(s->steps) / sizeof(s->steps[0]));
    struct step *p = &s->steps[s->count++];
    p->wide = wide; p->transport = true; p->delay = delay;
    memcpy(p->input, input, sizeof(p->input));
    p->output[0] = (uint64_t)(int64_t)status;
    p->output[1] = service;
    return p;
}

static void query_step(struct script *s, bool wide, uint32_t fn, uint32_t arg,
    int32_t status, uint64_t service, uint64_t delay)
{
    uint64_t a[8]; frame(a, fn | (wide ? SGPU_SCM_64 : 0), arg);
    (void)add_step(s, wide, a, status, service, delay);
}

static bool script_smc(void *ctx, bool wide, uint64_t a[8])
{
    struct script *s = ctx;
    assert(s->calls < s->count); /* any forbidden follow-up is a failure */
    const struct step *p = &s->steps[s->calls++];
    assert(wide == p->wide);
    for (unsigned i = 0; i < 7; i++) assert(a[i] == p->input[i]);
    s->now += p->delay;
    memcpy(a, p->output, sizeof(p->output));
    return p->transport;
}
static uint64_t script_now(void *ctx) { return ((struct script *)ctx)->now; }
static void script_wait(void *ctx, uint32_t us)
{
    struct script *s = ctx; s->waits++; s->slept += us; s->now += us;
}
static void script_trace(void *ctx, const char *label, uint32_t a, uint32_t b, uint32_t c)
{
    (void)a; (void)b; (void)c;
    struct script *s = ctx; s->traces++;
    s->now += strncmp(label, "before ", 7) == 0 ? 11000000u : s->trace_cost;
}
static struct sgpu_scm_ops ops_for(struct script *s)
{
    return (struct sgpu_scm_ops){.ctx=s, .smc=script_smc, .now_us=script_now,
        .wait_us=script_wait, .trace=script_trace};
}
static void success_tail(struct script *s, bool wide)
{
    query_step(s, wide, SGPU_SCM_INFO, SGPU_SCM_PAS_SUPPORTED, 0, 1, 100);
    query_step(s, wide, SGPU_SCM_PAS_SUPPORTED, SGPU_SCM_GPU_PAS_ID, 0, 1, 100);
}
static bool probe(struct script *s, struct sgpu_scm_report *r)
{
    struct sgpu_scm_ops ops = ops_for(s);
    bool ok = sgpu_scm_probe(&ops, 3, 1, 1, r);
    assert(s->calls == s->count);
    cases++;
    return ok;
}

static void conventions_and_service_status(void)
{
    struct sgpu_scm_report r;
    reset(); query_step(&device, true, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST, 0, 1, 100);
    success_tail(&device, true);
    assert(probe(&device, &r) && r.convention == SGPU_SCM_SMC64 && r.supported);
    assert(r.support.elapsed_us == 300 && !r.failed_phase && r.probe64.calls == 1);
    for (unsigned reason = 0; reason < 3; reason++) {
        reset();
        query_step(&device, true, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST,
            reason == 0 ? 0 : reason == 1 ? -1 : -4, 0, 100);
        query_step(&device, false, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST, 0, 1, 100);
        success_tail(&device, false);
        assert(probe(&device, &r) && r.convention == SGPU_SCM_SMC32);
        assert(r.support.elapsed_us == 400 && r.probe32.calls == 1);
    }
    for (int status = -5; status <= -2; status++) {
        if (status == -4) continue;
        reset(); query_step(&device, true, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST, status, 1, 100);
        assert(!probe(&device, &r) && r.failed_phase == SGPU_SCM_PROBE64);
        assert(r.failure.error == SGPU_SCM_REMOTE_ERROR && !r.failure.unresolved);
        assert((int32_t)r.failure.raw[0] == status && !r.probe32.started);
    }
    reset(); query_step(&device, true, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST, 0, 2, 100);
    assert(!probe(&device, &r) && r.failure.error == SGPU_SCM_BAD_CONVENTION);
    reset(); query_step(&device, true, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST, 0, 0, 100);
    query_step(&device, false, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST, 0, 0, 100);
    assert(!probe(&device, &r) && r.failed_phase == SGPU_SCM_PROBE32 && !r.availability.started);
    for (unsigned phase = 0; phase < 2; phase++) {
        reset(); query_step(&device, true, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST, 0, 1, 100);
        query_step(&device, true, SGPU_SCM_INFO, SGPU_SCM_PAS_SUPPORTED, 0, phase ? 1 : 0, 100);
        if (phase) query_step(&device, true, SGPU_SCM_PAS_SUPPORTED, 13, 0, 0, 100);
        assert(!probe(&device, &r) && r.failure.error == SGPU_SCM_NOT_SUPPORTED);
        assert(r.failed_phase == (phase ? SGPU_SCM_SUPPORT : SGPU_SCM_AVAILABILITY));
        assert(!r.supported && !r.failure.unresolved);
    }
}

static void frame_resume_and_busy_restart(void)
{
    struct sgpu_scm_report r;
    for (unsigned wide = 0; wide < 2; wide++) {
        reset();
        if (!wide) query_step(&device, true, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST, 0, 0, 100);
        uint64_t a[8]; frame(a, SGPU_SCM_INFO_FAST | (wide ? SGPU_SCM_64 : 0), SGPU_SCM_INFO_FAST);
        struct step *p = add_step(&device, wide, a, 1, 0x9911, 100);
        for (unsigned i = 2; i < 7; i++) p->output[i] = (wide ? 0x1122334400000000ull : 0x1100) + i;
        p = add_step(&device, wide, p->output, -12, 0, 100);
        p->output[6] = 0xdead; /* terminal EBUSY must not resume this session */
        (void)add_step(&device, wide, a, 0, 1, 100);
        success_tail(&device, wide);
        assert(probe(&device, &r));
        const struct sgpu_scm_result *negotiation = wide ? &r.probe64 : &r.probe32;
        assert(negotiation->interruptions == 1 && negotiation->busy_retries == 1);
        assert(negotiation->calls == 3 && device.waits == 1 && device.slept == 30000);
        assert(r.support.elapsed_us == (wide ? 30500u : 30600u));
    }
}

static void shared_limits_and_uncertainty(void)
{
    struct sgpu_scm_report r;
    uint64_t a[8];
    reset(); frame(a, SGPU_SCM_INFO_FAST | SGPU_SCM_64, SGPU_SCM_INFO_FAST);
    for (unsigned i = 0; i < 64; i++) {
        struct step *p = add_step(&device, true, a, i == 63 ? 0 : 1, i == 63 ? 1 : 99, 0);
        p->output[6] = i + 1; memcpy(a, p->output, sizeof(a));
    }
    assert(!probe(&device, &r) && device.calls == 64);
    assert(r.probe64.error == SGPU_SCM_OK && r.failed_phase == SGPU_SCM_AVAILABILITY);
    assert(r.failure.error == SGPU_SCM_CALL_LIMIT && !r.availability.started && !r.failure.unresolved);
    reset(); frame(a, SGPU_SCM_INFO_FAST | SGPU_SCM_64, SGPU_SCM_INFO_FAST);
    for (unsigned i = 0; i < 64; i++) {
        struct step *p = add_step(&device, true, a, 1, i + 20, 0);
        p->output[6] = i + 1; memcpy(a, p->output, sizeof(a));
    }
    assert(!probe(&device, &r) && r.failure.error == SGPU_SCM_CALL_LIMIT && r.failure.unresolved);
    assert(r.failure.interruptions == 64 && r.failure.raw[6] == 64 && !r.probe32.started);
    reset();
    query_step(&device, true, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST, 0, 0, 600000);
    query_step(&device, false, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST, 0, 1, 400000);
    assert(!probe(&device, &r) && r.failed_phase == SGPU_SCM_PROBE32);
    assert(r.failure.error == SGPU_SCM_TIME_LIMIT && r.failure.elapsed_us == 1000000 && !r.failure.unresolved);
    for (unsigned late = 0; late < 2; late++) {
        reset(); query_step(&device, true, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST,
            late ? -4 : 1, 1, 1000000);
        assert(!probe(&device, &r) && r.failure.error == SGPU_SCM_TIME_LIMIT);
        assert(r.failure.unresolved == !late && !r.probe32.started);
    }
    reset(); device.trace_cost = 250000;
    query_step(&device, true, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST, 0, 1, 10);
    assert(!probe(&device, &r) && r.failed_phase == SGPU_SCM_AVAILABILITY);
    assert(r.failure.error == SGPU_SCM_TIME_LIMIT && !r.failure.started);
    reset();
    for (unsigned i = 0; i < 21; i++) query_step(&device, true, SGPU_SCM_INFO_FAST,
        SGPU_SCM_INFO_FAST, -12, 0, 0);
    assert(!probe(&device, &r) && r.failure.error == SGPU_SCM_BUSY_LIMIT);
    assert(device.waits == 20 && r.failure.busy_retries == 20 && !r.failure.unresolved);
    reset();
    for (unsigned i = 0; i < 19; i++) query_step(&device, true, SGPU_SCM_INFO_FAST,
        SGPU_SCM_INFO_FAST, -12, 0, 0);
    query_step(&device, true, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST, 0, 0, 0);
    query_step(&device, false, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST, -12, 0, 0);
    query_step(&device, false, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST, -12, 0, 0);
    assert(!probe(&device, &r) && r.failed_phase == SGPU_SCM_PROBE32);
    assert(r.failure.error == SGPU_SCM_BUSY_LIMIT && device.waits == 20 && r.probe32.busy_retries == 1);
    reset(); query_step(&device, true, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST, -12, 0, 970000);
    assert(!probe(&device, &r) && r.failure.error == SGPU_SCM_TIME_LIMIT && device.waits == 0);
    reset(); query_step(&device, true, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST, 0, 1, 100);
    device.steps[0].transport = false; device.steps[0].output[6] = 0x1234;
    assert(!probe(&device, &r) && r.failure.error == SGPU_SCM_TRANSPORT_FAILED && r.failure.unresolved);
    assert(r.failure.raw[6] == 0x1234 && !r.probe32.started);
    reset(); query_step(&device, true, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST, 0, 1, 100);
    device.steps[0].output[0] = 0x1122334400000000ull;
    assert(!probe(&device, &r) && r.failure.error == SGPU_SCM_TRANSPORT_FAILED && r.failure.unresolved);
}

static void rejects(void)
{
    struct sgpu_scm_result r;
    struct sgpu_scm_report report;
    struct sgpu_scm_budget budget = {0};
    reset(); struct sgpu_scm_ops ops = ops_for(&device);
    uint64_t a[8]; frame(a, SGPU_SCM_INFO_FAST | SGPU_SCM_64, SGPU_SCM_INFO_FAST);
    for (unsigned mode = 0; mode <= 4; mode++) for (unsigned z = 0; z <= 2; z++)
        for (unsigned opt = 0; opt <= 2; opt++) {
            if (mode == 3 && z == 1 && opt == 1) continue;
            assert(!sgpu_scm_readonly_transport(&ops, mode, z, opt, a, &budget, &r));
            assert(r.error == SGPU_SCM_REJECTED && !r.started && device.calls == 0);
            assert(!sgpu_scm_probe(&ops, mode, z, opt, &report) && !report.attempted);
            cases++;
        }
    for (unsigned i = 1; i < 8; i++) {
        uint64_t bad[8]; memcpy(bad, a, sizeof(bad)); bad[i] += 1;
        assert(!sgpu_scm_readonly_transport(&ops, 3, 1, 1, bad, &budget, &r)); cases++;
    }
    const uint32_t forbidden[] = {0x02000201,0x02000202,0x02000205,0x02000206,
        0x82000207,0x0200010a,0x80000601};
    for (unsigned i = 0; i < sizeof(forbidden)/sizeof(forbidden[0]); i++) {
        for (unsigned wide = 0; wide < 2; wide++) {
            uint64_t bad[8]; frame(bad, forbidden[i] | (wide ? SGPU_SCM_64 : 0), 13);
            assert(!sgpu_scm_readonly_transport(&ops, 3, 1, 1, bad, &budget, &r)); cases++;
        }
    }
    const uint64_t bad_fn[] = {0x100000000ull | a[0], a[0] ^ SGPU_SCM_64 ^ 0x80000000};
    for (unsigned i = 0; i < 2; i++) {
        uint64_t bad[8]; memcpy(bad, a, sizeof(bad)); bad[0] = bad_fn[i];
        assert(!sgpu_scm_readonly_transport(&ops, 3, 1, 1, bad, &budget, &r)); cases++;
    }
    assert(!sgpu_scm_readonly_transport(NULL, 3, 1, 1, a, &budget, &r));
    assert(!sgpu_scm_readonly_transport(&ops, 3, 1, 1, NULL, &budget, &r));
    assert(!sgpu_scm_readonly_transport(&ops, 3, 1, 1, a, NULL, &r));
    assert(!sgpu_scm_readonly_transport(&ops, 3, 1, 1, a, &budget, NULL));
    for (unsigned missing = 0; missing < 3; missing++) {
        struct sgpu_scm_ops bad = ops;
        if (missing == 0) bad.smc = NULL;
        if (missing == 1) bad.now_us = NULL;
        if (missing == 2) bad.wait_us = NULL;
        assert(!sgpu_scm_probe(&bad, 3, 1, 1, &report));
        assert(!sgpu_scm_readonly_transport(&bad, 3, 1, 1, a, &budget, &r));
    }
    assert(device.calls == 0 && device.waits == 0 && device.traces == 0);
}

static void immutable_failure(void)
{
    struct sgpu_scm_report report = {0};
    struct sgpu_scm_result first = {.error=SGPU_SCM_REMOTE_ERROR, .unresolved=true};
    first.raw[0] = (uint64_t)(int64_t)-3; first.raw[6] = 0x1111;
    sgpu_scm_failure(&report, SGPU_SCM_PROBE64, &first, SGPU_SCM_BAD_CONVENTION);
    struct sgpu_scm_report original = report;
    struct sgpu_scm_result second = {.error=SGPU_SCM_TIME_LIMIT}; second.raw[6] = 0x2222;
    sgpu_scm_failure(&report, SGPU_SCM_SUPPORT, &second, SGPU_SCM_NOT_SUPPORTED);
    assert(memcmp(&original, &report, sizeof(report)) == 0); cases++;
}

static void worker_gates(void)
{
    for (uint32_t mode = 0; mode <= 4; mode++) for (uint32_t z = 0; z <= 2; z++)
        for (uint32_t opt = 0; opt <= 2; opt++) {
            if (mode == 3 && z == 1 && opt == 1) continue;
            reset(); zap = z; opt_in = opt; sg.mode = mode;
            assert(!sgpu_scm_capability_probe(mode) && device.calls == 0);
            if (mode != 3) assert(parses == 0);
            parses = 0; sgpu_kernel_thread(NULL, 0);
            assert(allocations == 1 && gpu_calls == 1 && terminated == 1 && device.calls == 0);
            cases++;
        }
    for (unsigned missing = 0; missing < 2; missing++) {
        reset(); if (missing) zap_present = false; else scm_present = false;
        assert(!sgpu_scm_capability_probe(3) && device.calls == 0); cases++;
    }
    for (unsigned pass = 0; pass < 2; pass++) {
        reset(); sg.mode = 3;
        query_step(&device, true, SGPU_SCM_INFO_FAST, SGPU_SCM_INFO_FAST, pass ? 0 : -3, 1, 100);
        if (pass) success_tail(&device, true);
        sgpu_kernel_thread(NULL, 0);
        assert(terminated == 1 && allocations == 0 && gpu_calls == 0 && dt_reads == 0);
        assert(device.calls == device.count && diagnostics >= 3);
        assert(strstr(last_diagnostic, pass ? "pass=1" : "pass=0"));
        assert(strstr(last_diagnostic, "NO PAS LOAD")); cases++;
    }
}

static void stock_worker_gates(void)
{
    for(unsigned mode=0; mode<=4; mode++) for(unsigned z=0; z<=2; z++)
        for(unsigned scm=0; scm<=2; scm++) for(unsigned cache=0; cache<=2; cache++) {
            reset(); sg.mode=mode; stock_arg=1; zap=z; opt_in=scm; cache_arg=cache;
            bool allowed=mode==3 && !z && !scm && !cache;
            sgpu_kernel_thread(NULL, 0);
            assert(terminated==1 && device.calls==0);
            assert(gpu_calls==(unsigned)allowed && allocations==(unsigned)allowed);
            assert(sg.stock_unsecure==(unsigned)allowed && last_stock==(unsigned)allowed);
            cases++;
        }
    for(unsigned invalid=2; invalid<=3; invalid++) {
        reset(); sg.mode=3; stock_arg=invalid; zap=opt_in=0;
        sgpu_kernel_thread(NULL, 0);
        assert(terminated==1 && !gpu_calls && !allocations && !device.calls && !sg.stock_unsecure);
        cases++;
    }
}

static void pixel_worker_gates(void)
{
    for(unsigned mode=0;mode<=4;mode++) for(unsigned stock=0;stock<=2;stock++)
        for(unsigned pixels=1;pixels<=2;pixels++) {
            reset(); sg.mode=mode; stock_arg=stock; pixel_arg=pixels; zap=opt_in=0;
            bool enabled=mode==3 && stock==1 && pixels==1;
            sgpu_kernel_thread(NULL,0);
            assert(terminated==1 && !device.calls);
            assert(gpu_calls==(unsigned)enabled && allocations==(unsigned)enabled);
            assert(last_pixels==(unsigned)enabled);
            cases++;
        }
}

static void g3_worker_gates(void)
{
    for(unsigned mode=0;mode<=4;mode++) for(unsigned stock=0;stock<3;stock++)
        for(unsigned pixels=0;pixels<3;pixels++) for(unsigned option=1;option<3;option++) {
            reset();sg.mode=mode;stock_arg=stock;pixel_arg=pixels;g3_arg=option;zap=opt_in=0;
            bool allowed=mode==3&&stock==1&&pixels==1&&option==1;
            sgpu_kernel_thread(NULL,0);
            assert(terminated==1&&!device.calls&&gpu_calls==(unsigned)allowed&&last_g3==(unsigned)allowed);
            cases++;
        }
    for(unsigned z=0;z<3;z++) for(unsigned scm=0;scm<3;scm++) for(unsigned cache=0;cache<3;cache++) {
        reset();sg.mode=3;stock_arg=pixel_arg=g3_arg=1;zap=z;opt_in=scm;cache_arg=cache;
        bool allowed=!z&&!scm&&!cache;sgpu_kernel_thread(NULL,0);
        assert(terminated==1&&!device.calls&&gpu_calls==(unsigned)allowed&&last_g3==(unsigned)allowed);cases++;
    }
}

/* Platform stubs for the actual adapter entry and worker, not policy copies. */
static bool sgpu_smc_frame(void *ctx, bool wide, uint64_t a[8])
{ (void)ctx; return script_smc(&device, wide, a); }
static uint64_t now_us(void *ctx) { (void)ctx; return device.now; }
static void sgpu_kernel_wait_us(void *ctx, uint32_t us) { (void)ctx; script_wait(&device, us); }
static void trace(void *ctx, const char *s, uint32_t a, uint32_t b, uint32_t c)
{ (void)ctx; script_trace(&device, s, a, b, c); }
static bool PE_parse_boot_argn(const char *name, void *out, unsigned n)
{
    parses++; assert(n == 4);
    if (strcmp(name, "santonigpu_user") == 0 || strcmp(name, "santonigpu_user_test") == 0) {
        *(uint32_t *)out=0; return true;
    }
    if (strcmp(name, "santonigpu_session") == 0) { *(uint32_t *)out=0; return true; }
    if (strcmp(name, "santonigpu_submit") == 0) { *(uint32_t *)out=g3_arg; return true; }
    if (strcmp(name, "santonigpu_pixels") == 0) { *(uint32_t *)out=pixel_arg; return true; }
    if (strcmp(name, "santonigpu_stock") == 0) { *(uint32_t *)out=stock_arg; return true; }
    if (strcmp(name, "santonigpu_cache") == 0) { *(uint32_t *)out=cache_arg; return true; }
    if (strcmp(name, "santonigpu_zap") == 0) {
        if (zap_present) *(uint32_t *)out = zap;
        return zap_present;
    }
    assert(strcmp(name, "santonigpu_scm") == 0);
    if (scm_present) *(uint32_t *)out = opt_in;
    return scm_present;
}
static int capture_printf(const char *fmt, ...)
{
    diagnostics++; va_list args; va_start(args, fmt);
    int n = vsnprintf(last_diagnostic, sizeof(last_diagnostic), fmt, args);
    va_end(args); return n;
}
static void thread_terminate_self(void) { terminated++; }
static bool sgpu_pas_cache_preflight(uint32_t mode) { (void)mode; return false; }
static void sgpu_zap_allocation_preflight(uint32_t mode) { (void)mode; allocations++; }
static int SecureDTLookupEntry(void *x, const char *name, DTEntry *out)
{ (void)x; (void)name; (void)out; dt_reads++; return -1; }
static int SecureDTGetProperty(DTEntry x, const char *name, const void **out, unsigned *n)
{ (void)x; (void)name; (void)out; (void)n; dt_reads++; return -1; }
static bool io_map(void *x, enum sgpu_block b, uint32_t p, uint32_t n)
{ (void)x; (void)b; (void)p; (void)n; return false; }
static uint32_t sgpu_io_read32(void *x, enum sgpu_block b, uint32_t o)
{ (void)x; (void)b; (void)o; return 0; }
static uint64_t sgpu_io_read64(void *x, enum sgpu_block b, uint32_t o)
{ (void)x; (void)b; (void)o; return 0; }
static void sgpu_io_write32(void *x, enum sgpu_block b, uint32_t o, uint32_t v)
{ (void)x; (void)b; (void)o; (void)v; }
static void sgpu_io_write64(void *x, enum sgpu_block b, uint32_t o, uint64_t v)
{ (void)x; (void)b; (void)o; (void)v; }
static bool allocate(void *x, struct sgpu_memory *m) { (void)x; (void)m; return false; }
static void release(void *x, struct sgpu_memory *m) { (void)x; (void)m; }
static void clean(void *x, const void *p, uint32_t n) { (void)x; (void)p; (void)n; }
static void sgpu_cache_invalidate(void *x, const void *p, uint32_t n) { (void)x; (void)p; (void)n; }
static void sgpu_failure_summary(const char *name, const struct sgpu_failure *f)
{ (void)name; (void)f; }
bool sgpu_probe(const struct sgpu_ops *ops, uint32_t mode, const uint8_t *blob,
    size_t size, struct sgpu_report *report)
{ (void)mode; (void)blob; (void)size; last_stock=ops->stock_unsecure; last_pixels=ops->stock_pixels; last_g3=ops->g3; gpu_calls++; memset(report, 0, sizeof(*report)); return false; }
bool sgpu_session_start(const struct sgpu_ops *ops,uint32_t mode,const uint8_t *blob,
    size_t size,struct sgpu_report *report)
{ (void)ops;(void)mode;(void)blob;(void)size;(void)report;assert(!"unexpected session startup");return false; }
void sgpu_session_failure_result(struct sgpu_session_result *out)
{ (void)out;assert(!"unexpected session report"); }

int main(void)
{
    /* Independent constants verified against downstream SCM headers/callers. */
    assert(SGPU_SCM_INFO_FAST == 0x82000601u && SGPU_SCM_INFO == 0x02000601u);
    assert(SGPU_SCM_PAS_SUPPORTED == 0x02000207u && SGPU_SCM_64 == 0x40000000u);
    assert(SGPU_SCM_GPU_PAS_ID == 13 && SGPU_SCM_MAX_CALLS == 64 && SGPU_SCM_MAX_BUSY == 20);
    assert(SGPU_SCM_BUDGET_US == 1000000 && SGPU_SCM_BUSY_DELAY_US == 30000);
    conventions_and_service_status();
    frame_resume_and_busy_restart();
    shared_limits_and_uncertainty();
    rejects(); immutable_failure(); worker_gates(); stock_worker_gates(); pixel_worker_gates();
    g3_worker_gates();
    printf("PASS actual SCM scalar policy/entry/worker: %u cases; mock SMC only\n", cases);
    return 0;
}
