/* Actual adapter trace and launcher getters, then the actual bounded EL0
 * probe under a synthetic readiness schedule. No hardware timing claim. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "santoni_gpu_launch.h"

static const char *keys[] = {"santonigpu_user_exec", "santonigpu_stock",
    "santonigpu_pixels", "santonigpu_submit", "santonigpu_session",
    "santonigpu_user", "santonigpu_user_test", "santonigpu_zap",
    "santonigpu_scm", "santonigpu_cache"};
static uint32_t options[10];
static bool absent, suffix_missing, bad_suffix;
static unsigned parses, prints, waits;
static uint64_t trace_delay, readiness_at;
static struct { uint32_t mode; } sg;
static char output[256];

static bool PE_parse_boot_argn(const char *key, void *out, int size)
{
    assert(++parses <= 32);
    if (!strcmp(key, "launchdsuffix")) {
        assert(size == 64);
        if (suffix_missing) return false;
        strcpy(out, bad_suffix ? "debug" : "release"); return true;
    }
    assert(size == 4 && *(uint32_t *)out == 0);
    for (unsigned i = 0; i < 10; i++) if (!strcmp(key, keys[i])) {
        if (i == 0 && absent) return false;
        *(uint32_t *)out = options[i]; return true;
    }
    assert(false); return false;
}
static int trace_printf(const char *format, ...)
{
    va_list ap; va_start(ap, format);
    int result = vsnprintf(output, sizeof(output), format, ap);
    va_end(ap); prints++; return result;
}
static void sgpu_kernel_wait_us(void *ctx, uint32_t delay)
{
    assert(ctx == NULL && delay == 11000000u);
    waits++; trace_delay += delay;
}
#define printf trace_printf
#include "actual_readiness.h"
#undef printf

/* Reuse the existing syscall fixture. Its OPEN_DELAY condition is supplied
 * by this test's synthetic worker publication time, rather than three sleeps. */
#include "readiness_probe_fixture.h"

static void reset(void)
{
    memset(options, 0, sizeof(options));
    for (unsigned i = 0; i < 6; i++) options[i] = 1;
    absent = suffix_missing = bad_suffix = false;
    memset(&launch, 0, sizeof(launch));
    launch.stage = LAUNCH_READY; launch.mounted = true; sg.mode = 3;
    parses = prints = waits = 0; trace_delay = 0;
}
static void check(bool pause, const char *message)
{
#ifdef READINESS_BASELINE
    pause = true;
#endif
    parses = prints = waits = 0; trace_delay = 0;
    unsigned char saved[sizeof(launch)]; memcpy(saved, &launch, sizeof(launch));
    uint32_t saved_options[10]; memcpy(saved_options, options, sizeof(options));
    uint32_t mode = sg.mode;
    trace((void *)(uintptr_t)0xabcdef, message, 0x80000001, 0xffffffff, 0x76543210);
    assert(prints == 1);
    char expected[256]; snprintf(expected, sizeof(expected),
        "SANTONI GPU: %s [80000001 ffffffff 76543210]\n", message);
    assert(!strcmp(output, expected));
    bool before = strncmp(message, "before ", 7) == 0;
    assert(waits == (unsigned)(before && pause));
    assert(trace_delay == (before && pause ? 11000000u : 0u));
    assert(!memcmp(saved, &launch, sizeof(launch)) && sg.mode == mode);
    assert(!memcmp(saved_options, options, sizeof(options)));
    if (!before) assert(parses == 0);
}
static void scheduled_probe(void)
{
    reset();
    for (unsigned i = 0; i < 6; i++) { parses = 0; trace(NULL, "before synthetic stage", i, 0, 0); }
    readiness_at = 40000000u + trace_delay;
    memset(&m, 0, sizeof(m)); m.scenario = OPEN_DELAY; m.pid = 7; m.idle = 1;
    struct sgpu_probe_report result;
    int passed = sgpu_user_probe_run(&result);
#ifdef READINESS_BASELINE
    assert(readiness_at == 106000000u && !passed && result.error == P_DEADLINE);
    assert(result.sent == 0 && !m.opened && m.waits == 1000);
#else
    assert(readiness_at == 40000000u && passed && result.pass == 1);
    assert(result.sent == 32 && result.verified == 32 && result.negative == 7);
    assert(m.fd_closed && m.closes == 1 && m.clock < 100000000u);
#endif
}
int main(void)
{
    reset(); check(false, "before powered GPU");
    for (unsigned mode = 0; mode < 5; mode++) { reset(); sg.mode = mode; check(mode != 3, "before "); }
    for (unsigned enabled = 0; enabled < 3; enabled++) { reset(); options[0] = enabled; check(enabled != 1, "before "); }
    reset(); absent = true; check(true, "before ");
    for (unsigned i = 1; i < 10; i++) {
        reset(); options[i] = i < 6 ? 0 : 1; check(true, "before ");
        reset(); options[i] = 2; check(true, "before ");
    }
    for (unsigned stage = 0; stage < 4; stage++) { reset(); launch.stage = stage; check(stage != LAUNCH_READY, "before "); }
    reset(); launch.mounted = false; check(true, "before ");
    reset(); bad_suffix = true; check(true, "before ");
    reset(); suffix_missing = true; check(true, "before ");
    const char *messages[] = {"", "before", "Before ", "after powered GPU", "x before "};
    for (unsigned i = 0; i < 5; i++) { reset(); check(false, messages[i]); }
    scheduled_probe();
    puts("PASS 40 trace/role cases and actual probe synthetic startup schedule");
    return 0;
}
