#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

typedef uintptr_t vm_offset_t;
typedef uintptr_t vm_map_address_t;
typedef uint32_t ppnum_t;
#define SGPU_PAGE 4096u
#define KMA_DATA 1u
#define KMA_ZERO 2u
#define KERN_SUCCESS 0
#define VM_KERN_MEMORY_IOKIT 7u
#define VM_WIMG_DEFAULT 2u
#define VM_WIMG_WCOMB 6u
static int kernel_map, kernel_pmap, page_shift = 12;
static uint64_t page_size = 4096;
static uint8_t *owned[2], *aperture[2];
static uint64_t physical[2] = {0x100000, 0x200000};
static uint32_t attributes[2][2][16], active[2];
static unsigned allocations, frees, queries, transitions, views, cleans, lookups, parses;
static unsigned fail_alloc, fail_query, fail_transition, fail_view, fail_lookup;
static uint32_t cache_arg, zap_arg, scm_arg;
static unsigned cases;

static int slot_for_va(uint64_t va, unsigned *page, unsigned *alias)
{
    for (unsigned i = 0; i < 2; i++) for (unsigned a = 0; a < 2; a++) {
        uintptr_t base = (uintptr_t)(a ? aperture[i] : owned[i]);
        if (va >= base && va < base + 65536) {
            *page = (unsigned)((va - base) / SGPU_PAGE); *alias = a;
            return (int)i;
        }
    }
    return -1;
}

static int slot_for_pa(uint64_t pa, unsigned *page)
{
    for (unsigned i = 0; i < 2; i++) if (pa >= physical[i] && pa < physical[i] + 65536) {
        *page = (unsigned)((pa - physical[i]) / SGPU_PAGE); return (int)i;
    }
    return -1;
}

static int kmem_alloc_contig(int map, vm_offset_t *va, uint32_t size,
    vm_offset_t mask, ppnum_t maximum, ppnum_t alignment, unsigned flags, unsigned tag)
{
    (void)map;
    unsigned i = allocations++;
    assert(i < 2 && size == 8192 && mask == 4095 && maximum == 0xfffff);
    assert(alignment == (i ? 255u : 0u) && flags == (KMA_DATA | KMA_ZERO));
    assert(tag == VM_KERN_MEMORY_IOKIT);
    if (allocations == fail_alloc) return 1;
    active[i] = size; memset(owned[i], 0, size); *va = (vm_offset_t)owned[i];
    return 0;
}

static ppnum_t pmap_find_phys(int map, uint64_t va)
{
    (void)map; unsigned page, alias; lookups++;
    int i = slot_for_va(va, &page, &alias);
    if (i < 0 || lookups == fail_lookup) return 0;
    return (ppnum_t)(physical[i] / SGPU_PAGE + page);
}

static vm_map_address_t phystokv(uint64_t pa)
{
    unsigned page; int i = slot_for_pa(pa, &page); assert(i >= 0);
    return (vm_map_address_t)(aperture[i] + page * SGPU_PAGE);
}

static void kmem_free(int map, vm_offset_t va, uint32_t bytes)
{
    (void)map; unsigned page, alias; int i = slot_for_va(va, &page, &alias);
    assert(i >= 0 && !page && !alias && active[i] == bytes);
    for (unsigned p = 0; p < bytes / SGPU_PAGE; p++)
        assert(attributes[i][0][p] == VM_WIMG_DEFAULT && attributes[i][1][p] == VM_WIMG_DEFAULT);
    active[i] = 0; frees++;
}

static bool pmap_santoni_pas_cache_control(ppnum_t pn, unsigned expected, unsigned replacement)
{
    unsigned page; int i = slot_for_pa((uint64_t)pn * SGPU_PAGE, &page); assert(i >= 0);
    assert(active[i] && expected == attributes[i][0][page] && expected == attributes[i][1][page]);
    if (expected == replacement) { queries++; return queries != fail_query; }
    transitions++;
    if (replacement == VM_WIMG_WCOMB) assert(cleans > 0 && queries >= 2);
    attributes[i][0][page] = attributes[i][1][page] = replacement;
    return transitions != fail_transition; /* failure may already have changed the page */
}

static bool sgpu_pas_cache_view(vm_offset_t va, uint64_t pa, uint32_t attribute)
{
    unsigned page, alias; int i = slot_for_va(va, &page, &alias); views++;
    if (i < 0 || views == fail_view) return false;
    return physical[i] + page * SGPU_PAGE == pa &&
        attributes[i][alias][page] == (attribute == 0xff ? VM_WIMG_DEFAULT : VM_WIMG_WCOMB);
}

static void CleanPoC_DcacheRegion_Force(vm_offset_t va, size_t bytes)
{
    unsigned page, alias; int i = slot_for_va(va, &page, &alias);
    assert(i >= 0 && !page && !alias && bytes == active[i]);
    for (unsigned p = 0; p < bytes / SGPU_PAGE; p++)
        assert(attributes[i][0][p] == VM_WIMG_DEFAULT && attributes[i][1][p] == VM_WIMG_DEFAULT);
    cleans++;
}

static bool PE_parse_boot_argn(const char *name, void *out, unsigned bytes)
{
    assert(bytes == 4); parses++;
    if (!strcmp(name, "santonigpu_cache")) *(uint32_t *)out = cache_arg;
    else if (!strcmp(name, "santonigpu_zap")) *(uint32_t *)out = zap_arg;
    else { assert(!strcmp(name, "santonigpu_scm")); *(uint32_t *)out = scm_arg; }
    return true;
}

static void trace(void *ctx, const char *message, uint32_t a, uint32_t b, uint32_t c)
{ (void)ctx; (void)message; assert(a == 8192 && b == 8192 && c == 0x100000); }
static void host_barrier(void) {}
#include "santoni_gpu_pas_cache_actual.h"

static void reset(void)
{
    memset(&sgpu_cache_trial, 0, sizeof(sgpu_cache_trial));
    allocations = frees = queries = transitions = views = cleans = lookups = parses = 0;
    fail_alloc = fail_query = fail_transition = fail_view = fail_lookup = 0;
    cache_arg = zap_arg = 1; scm_arg = 0;
    for (unsigned i = 0; i < 2; i++) {
        active[i] = 0;
        for (unsigned a = 0; a < 2; a++) for (unsigned p = 0; p < 16; p++)
            attributes[i][a][p] = VM_WIMG_DEFAULT;
    }
}

static void lifecycle(void)
{
    reset(); assert(sgpu_pas_cache_preflight(3));
    assert(!sgpu_cache_trial.forward_error && !sgpu_cache_trial.cleanup_error);
    assert(allocations == 2 && frees == 2 && transitions == 8 && cleans == 2);
    unsigned calls = allocations; sgpu_pas_cache_trial_run(&sgpu_cache_trial);
    assert(allocations == calls); cases++;
    for (unsigned fail = 1; fail <= 2; fail++) {
        reset(); fail_alloc = fail; sgpu_pas_cache_trial_run(&sgpu_cache_trial);
        assert(sgpu_cache_trial.forward_error == fail && !sgpu_cache_trial.cleanup_error);
        assert(!transitions && frees == fail - 1); cases++;
    }
    for (unsigned fail = 1; fail <= 4; fail++) {
        reset(); fail_query = fail; sgpu_pas_cache_trial_run(&sgpu_cache_trial);
        assert(sgpu_cache_trial.forward_error == (fail <= 2 ? 3u : 4u));
        assert(!sgpu_cache_trial.cleanup_error && frees == 2); cases++;
    }
    for (unsigned fail = 1; fail <= 8; fail++) {
        reset(); fail_transition = fail; sgpu_pas_cache_trial_run(&sgpu_cache_trial);
        assert(sgpu_cache_trial.cleanup_error && frees == 1);
        assert(sgpu_cache_trial.metadata.uncertain || sgpu_cache_trial.image.uncertain);
        assert(sgpu_cache_trial.forward_error == (fail <= 2 ? 3u : fail <= 4 ? 4u : 0u));
        cases++;
    }
    for (unsigned fail = 1; fail <= 32; fail++) {
        reset(); fail_view = fail; sgpu_pas_cache_trial_run(&sgpu_cache_trial);
        assert(sgpu_cache_trial.forward_error || sgpu_cache_trial.cleanup_error); cases++;
    }
}

static void exposure_and_malformed(void)
{
    reset(); struct sgpu_pas_cached_span span = {0};
    assert(sgpu_pas_allocate(&span.memory, 8192, SGPU_PAGE));
    assert(sgpu_pas_cached_prepare(&span));
    span.memory.exposed = true;
    unsigned before = transitions + views + lookups + frees;
    assert(!sgpu_pas_cached_prepare(&span));
    assert(!sgpu_pas_cached_views(&span.memory, 0, 0x44));
    assert(!sgpu_pas_cached_release(&span));
    assert(transitions + views + lookups + frees == before); cases++;
    for (unsigned field = 0; field < 8; field++) {
        reset(); span = (struct sgpu_pas_cached_span){0};
        if (field == 0) span.memory.bytes = 65537;
        if (field == 1) span.memory.bytes = UINT32_MAX;
        if (field == 2) span.converted_pages = UINT32_MAX;
        if (field == 3) span.memory.va = 1;
        if (field == 4) span.memory.pa = 1;
        if (field == 5) span.uncertain = true;
        if (field == 6) span.memory.exposed = true;
        if (field == 7) {
            span.memory.va = (vm_offset_t)owned[0]; span.memory.pa = physical[0];
            span.memory.bytes = 69632;
        }
        assert(!sgpu_pas_cached_prepare(&span) && !sgpu_pas_cached_release(&span));
        assert(!transitions && !views && !lookups && !frees); cases++;
    }
    reset(); sgpu_cache_trial.metadata.memory.va = 1;
    sgpu_pas_cache_trial_run(&sgpu_cache_trial);
    assert(sgpu_cache_trial.forward_error == 6 && !allocations && !frees); cases++;
    reset(); fail_lookup = 6; sgpu_pas_cache_trial_run(&sgpu_cache_trial);
    assert(sgpu_cache_trial.forward_error && !transitions && frees == 2); cases++;
}

static void gates(void)
{
    for (unsigned mode = 0; mode < 5; mode++) for (unsigned cache = 0; cache < 3; cache++)
        for (unsigned zap = 0; zap < 3; zap++) for (unsigned scm = 0; scm < 3; scm++) {
            if (mode == 3 && cache == 1 && zap == 1 && scm == 0) continue;
            reset(); cache_arg = cache; zap_arg = zap; scm_arg = scm;
            bool handled = sgpu_pas_cache_preflight(mode);
            assert(handled == (mode == 3 && cache == 1));
            assert(!allocations && !transitions && !frees);
            if (mode != 3) assert(!parses);
            cases++;
        }
}

int main(void)
{
    for (unsigned i = 0; i < 2; i++) {
        FILE *f = tmpfile(); assert(f && !ftruncate(fileno(f), 65536));
        owned[i] = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(f), 0);
        aperture[i] = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_SHARED, fileno(f), 0);
        assert(owned[i] != MAP_FAILED && aperture[i] != MAP_FAILED); fclose(f);
    }
    lifecycle(); exposure_and_malformed(); gates();
    for (unsigned i = 0; i < 2; i++) { munmap(owned[i], 65536); munmap(aperture[i], 65536); }
    printf("PASS actual PAS cache lifetime/opt-in contracts: %u cases; no SMC\n", cases);
}
