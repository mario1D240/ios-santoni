/* Host kernel-VM stubs around the actual adapter's PAS preparation functions.
 * The runner includes the reconstructed functions, not a duplicate allocator.
 * Synthetic ELF bytes only: no device firmware, SMC or guessed carveout.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdalign.h>

typedef uintptr_t vm_offset_t;
typedef uint32_t ppnum_t;
typedef int DTEntry;
#define SGPU_PAGE 4096u
#define KMA_DATA 1u
#define KMA_ZERO 2u
#define KERN_SUCCESS 0
#define VM_KERN_MEMORY_IOKIT 7u
#define kSuccess 0
static int kernel_map, kernel_pmap, page_shift = 12;
static uint64_t page_size = 4096;
static alignas(4096) uint8_t storage[2][65536];
static uint64_t physical[2];
static unsigned allocations, frees, lookups, arg_reads, dt_reads;
static unsigned fail_allocation, bad_page, bad_page_kind, enabled, missing_property;
static int bad_va;
static uint32_t allocated_bytes[2], expected_masks[2];
static uint8_t metadata[6685], segment[5205];

static void reset(void)
{
    memset(storage, 0xa5, sizeof(storage));
    physical[0] = 0x100000; physical[1] = 0x200000;
    allocations = frees = lookups = arg_reads = dt_reads = 0;
    fail_allocation = bad_page = bad_page_kind = enabled = missing_property = 0;
    bad_va = 0; page_shift = 12; page_size = SGPU_PAGE;
    memset(allocated_bytes, 0, sizeof(allocated_bytes));
    memset(expected_masks, 0, sizeof(expected_masks));
}

static int kmem_alloc_contig(int map, vm_offset_t *va, uint32_t size,
    vm_offset_t mask, ppnum_t max, ppnum_t pmask, unsigned flags, unsigned tag)
{
    (void)map;
    assert(size && size <= 65536 && !(size % SGPU_PAGE));
    assert(mask == 4095 && max == 0xfffff);
    assert(flags == (KMA_DATA | KMA_ZERO) && tag == VM_KERN_MEMORY_IOKIT);
    unsigned index = allocations++;
    assert(index < 2);
    assert(pmask == expected_masks[index]);
    if (allocations == fail_allocation) return 1;
    allocated_bytes[index] = size;
    memset(storage[index], 0, size);
    *va = (vm_offset_t)storage[index];
    if (bad_va == 1) (*va)++;
    if (bad_va == 2) *va = 0;
    if (bad_va == 3) *va = ~(vm_offset_t)4095;
    return KERN_SUCCESS;
}

static ppnum_t pmap_find_phys(int map, uint64_t va)
{
    (void)map;
    lookups++;
    for (unsigned i = 0; i < 2; i++) {
        uint64_t base = (vm_offset_t)storage[i];
        if (va >= base && va < base + sizeof(storage[i])) {
            unsigned page = (unsigned)((va - base) / SGPU_PAGE);
            if (bad_page && page + 1 == bad_page) {
                if (!bad_page_kind) return 0;
                return (ppnum_t)(physical[i] / SGPU_PAGE + page +
                    (bad_page_kind == 1 ? 1 : -1));
            }
            return (ppnum_t)(physical[i] / SGPU_PAGE + page);
        }
    }
    return 0;
}

static void kmem_free(int map, vm_offset_t va, uint32_t bytes)
{
    (void)map;
    assert(bytes && !(bytes % SGPU_PAGE));
    bool found = bad_va != 0;
    for (unsigned i = 0; i < 2; i++)
        if (va == (vm_offset_t)storage[i]) {
            assert(bytes == allocated_bytes[i]);
            allocated_bytes[i] = 0; found = true;
        }
    assert(found);
    frees++;
}

static bool PE_parse_boot_argn(const char *name, void *value, unsigned bytes)
{
    assert(!strcmp(name, "santonigpu_zap") && bytes == 4);
    arg_reads++; *(uint32_t *)value = enabled; return enabled != 0;
}

static int SecureDTLookupEntry(void *root, const char *path, DTEntry *entry)
{
    (void)root; assert(!strcmp(path, "/chosen"));
    dt_reads++; *entry = 1; return missing_property == 3 ? 1 : kSuccess;
}

static int SecureDTGetProperty(DTEntry entry, const char *name,
    const void **value, unsigned *bytes)
{
    assert(entry == 1); dt_reads++;
    if (!strcmp(name, "santoni-gpu-zap-mdt")) {
        *value = metadata + 1; *bytes = 6684;
        return missing_property == 1 ? 1 : kSuccess;
    }
    assert(!strcmp(name, "santoni-gpu-zap-b02"));
    *value = segment + 1; *bytes = 5204;
    return missing_property == 2 ? 1 : kSuccess;
}

/* Written by the Python runner from checked incremental patches. */
#include "santoni_gpu_pas_actual.h"

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}

static void put32(uint8_t *p, uint32_t v)
{
    put16(p, (uint16_t)v); put16(p + 2, (uint16_t)(v >> 16));
}

static void firmware(void)
{
    expected_masks[1] = 255;
    uint8_t *m = metadata + 1;
    memset(metadata, 0, sizeof(metadata));
    memcpy(m, "\177ELF\001\001\001", 7);
    put16(m + 16, 2); put16(m + 18, 164); put32(m + 20, 1);
    put32(m + 28, 52); put16(m + 40, 52); put16(m + 42, 32); put16(m + 44, 3);
    /* Ignore one non-load header and one hash PT_LOAD, still use index .b02. */
    put32(m + 52 + 32, 1); put32(m + 52 + 32 + 20, 8192);
    put32(m + 52 + 32 + 24, 0x02200000);
    uint8_t *ph = m + 52 + 64;
    put32(ph, 1); put32(ph + 12, 0x5000); put32(ph + 16, 5204);
    put32(ph + 20, 5204); put32(ph + 24, 0x08000007); put32(ph + 28, 0x100000);
    for (unsigned i = 0; i < sizeof(segment); i++) segment[i] = (uint8_t)(i % 251);
}

static void allocation_cases(void)
{
    struct sgpu_pas_memory m = {0};
    reset();
    assert(sgpu_pas_allocate(&m, 6684, SGPU_PAGE));
    assert(m.va == (vm_offset_t)storage[0] && m.pa == 0x100000 && m.bytes == 8192);
    assert(lookups >= 2 && !m.exposed);
    m.exposed = true;
    assert(!sgpu_pas_release(&m) && frees == 0 && m.va);
    m.exposed = false; /* host-only reset, not evidence of PAS shutdown */
    assert(sgpu_pas_release(&m) && frees == 1 && !m.va && !m.bytes && !m.pa);
    assert(sgpu_pas_release(&m) && frees == 1);
    for (unsigned field = 0; field < 4; field++) {
        reset(); m = (struct sgpu_pas_memory){0};
        if (field == 0) m.va = 1;
        if (field == 1) m.pa = 1;
        if (field == 2) m.bytes = 1;
        if (field == 3) m.exposed = true;
        assert(!sgpu_pas_allocate(&m, 8192, SGPU_PAGE) && !allocations);
    }
    const uint32_t bad_sizes[] = {0, 65537, UINT32_MAX};
    for (unsigned i = 0; i < sizeof(bad_sizes) / sizeof(bad_sizes[0]); i++) {
        reset(); m = (struct sgpu_pas_memory){0};
        assert(!sgpu_pas_allocate(&m, bad_sizes[i], SGPU_PAGE) && !allocations);
    }
    const uint32_t bad_alignments[] = {0, 1, 2048, 4097, 8193, 0x200000, UINT32_MAX};
    for (unsigned i = 0; i < sizeof(bad_alignments) / sizeof(bad_alignments[0]); i++) {
        reset(); m = (struct sgpu_pas_memory){0};
        assert(!sgpu_pas_allocate(&m, 8192, bad_alignments[i]) && !allocations);
    }
    reset(); m = (struct sgpu_pas_memory){0}; page_shift = 14;
    assert(!sgpu_pas_allocate(&m, 8192, SGPU_PAGE) && !allocations);
    page_shift = 12; page_size = 16384;
    assert(!sgpu_pas_allocate(&m, 8192, SGPU_PAGE) && !allocations);
    reset(); assert(!sgpu_pas_allocate(NULL, 8192, SGPU_PAGE) && !allocations);
    assert(!sgpu_pas_release(NULL));
    reset(); m = (struct sgpu_pas_memory){0}; fail_allocation = 1;
    assert(!sgpu_pas_allocate(&m, 8192, SGPU_PAGE) && allocations == 1 && !frees && !m.va);
    for (unsigned page = 1; page <= 16; page++) {
        reset(); m = (struct sgpu_pas_memory){0}; bad_page = page;
        assert(!sgpu_pas_allocate(&m, 65536, SGPU_PAGE) && frees == 1 && !m.va && !m.pa);
    }
    for (unsigned kind = 1; kind <= 2; kind++) {
        reset(); m = (struct sgpu_pas_memory){0}; bad_page = 16; bad_page_kind = kind;
        assert(!sgpu_pas_allocate(&m, 65536, SGPU_PAGE) && frees == 1 && !m.va);
    }
    for (int invalid = 1; invalid <= 3; invalid++) {
        reset(); m = (struct sgpu_pas_memory){0}; bad_va = invalid;
        assert(!sgpu_pas_allocate(&m, 8192, SGPU_PAGE) && !m.va);
        assert(frees == (invalid == 2 ? 0u : 1u));
        assert(!lookups);
    }
    const uint64_t bad_pas[] = {0, 0x101000, 0xfffff000, 0x100000000ull};
    for (unsigned i = 0; i < sizeof(bad_pas) / sizeof(bad_pas[0]); i++) {
        reset(); m = (struct sgpu_pas_memory){0}; physical[0] = bad_pas[i];
        expected_masks[0] = 255;
        assert(!sgpu_pas_allocate(&m, 8192, 0x100000) && frees == 1 && !m.va);
    }
    reset(); m = (struct sgpu_pas_memory){0}; physical[0] = 0xfffff000;
    assert(!sgpu_pas_allocate(&m, 8192, SGPU_PAGE) && frees == 1 && !m.va);
    reset(); m = (struct sgpu_pas_memory){0}; physical[0] = 0xffffe000;
    assert(sgpu_pas_allocate(&m, 8192, SGPU_PAGE));
    assert(sgpu_pas_release(&m));
    reset(); m = (struct sgpu_pas_memory){0};
    expected_masks[0] = 255;
    assert(sgpu_pas_allocate(&m, 65536, 0x100000) && m.bytes == 65536);
    assert(sgpu_pas_release(&m));
}

static void preparation_cases(void)
{
    struct sgpu_zap_layout layout;
    struct sgpu_zap_buffers b = {0};
    reset(); firmware();
    assert(sgpu_zap_layout(metadata + 1, 6684, 5204, &layout));
    assert(layout.memory_bytes == 8192 && layout.alignment == 0x100000);
    assert(sgpu_zap_prepare(metadata + 1, 6684, segment + 1, 5204, &b));
    assert(allocations == 2 && !frees && b.metadata.bytes == 8192 && b.image.bytes == 8192);
    assert(!memcmp((void *)b.metadata.va, metadata + 1, 6684));
    assert(!memcmp((void *)b.image.va, segment + 1, 5204));
    for (unsigned i = 6684; i < b.metadata.bytes; i++) assert(storage[0][i] == 0);
    for (unsigned i = 5204; i < b.image.bytes; i++) assert(storage[1][i] == 0);
    assert(!sgpu_zap_prepare(metadata + 1, 6684, segment + 1, 5204, &b) && allocations == 2);
    assert(sgpu_pas_release(&b.image) && sgpu_pas_release(&b.metadata));
    reset(); firmware(); b = (struct sgpu_zap_buffers){0}; fail_allocation = 2;
    assert(!sgpu_zap_prepare(metadata + 1, 6684, segment + 1, 5204, &b));
    assert(allocations == 2 && frees == 1 && !b.metadata.va && !b.image.va);
    reset(); firmware(); b = (struct sgpu_zap_buffers){0};
    assert(!sgpu_zap_prepare(metadata + 1, 6684, NULL, 5204, &b) && !allocations);
    assert(!sgpu_zap_layout(NULL, 6684, 5204, &layout));
    assert(!sgpu_zap_layout(metadata + 1, 6684, 5204, NULL));
    assert(!sgpu_zap_layout(metadata + 1, 51, 5204, &layout));
    assert(!sgpu_zap_layout(metadata + 1, 16385, 5204, &layout));
    assert(!sgpu_zap_layout(metadata + 1, 6684, 0, &layout));
    assert(!sgpu_zap_layout(metadata + 1, 6684, 65537, &layout));
    /* Every malformed case must be rejected before an allocation or copy. */
    const struct { unsigned offset; uint32_t value; unsigned width; } bad[] = {
        {0, 0, 1}, {4, 2, 1}, {5, 2, 1}, {6, 0, 1}, {16, 1, 2}, {18, 40, 2},
        {20, 0, 4}, {40, 51, 2}, {42, 31, 2}, {44, 0, 2}, {44, 65, 2},
        {28, 51, 4}, {28, 6684, 4}, {28, UINT32_MAX, 4},
        {116, 0, 4}, {128, 0x5001, 4}, {128, 0xfffff000, 4},
        {132, 5203, 4}, {132, 5205, 4}, {136, 5203, 4}, {136, 65537, 4},
        {140, 7, 4}, {140, 0x02000007, 4}, {144, 0x100001, 4}, {144, 0x200000, 4},
        /* Turn hash entry .b01 into a second real load. */
        {108, 0x08000007, 4}, {44, 2, 2}
    };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        reset(); firmware(); b = (struct sgpu_zap_buffers){0};
        uint8_t *p = metadata + 1 + bad[i].offset;
        if (bad[i].width == 4) put32(p, bad[i].value);
        else if (bad[i].width == 2) put16(p, (uint16_t)bad[i].value);
        else *p = (uint8_t)bad[i].value;
        assert(!sgpu_zap_prepare(metadata + 1, 6684, segment + 1, 5204, &b) && !allocations);
    }
    reset(); firmware(); b = (struct sgpu_zap_buffers){0};
    memcpy(metadata + 1 + 84, metadata + 1 + 116, 32);
    memset(metadata + 1 + 116, 0, 32); /* valid single load, but .b01, not .b02 */
    assert(!sgpu_zap_prepare(metadata + 1, 6684, segment + 1, 5204, &b) && !allocations);
    reset(); firmware(); b = (struct sgpu_zap_buffers){0};
    put32(metadata + 1 + 136, 5205); /* one BSS byte plus all rounded padding */
    assert(sgpu_zap_prepare(metadata + 1, 6684, segment + 1, 5204, &b));
    assert(storage[1][5204] == 0);
    assert(sgpu_pas_release(&b.image) && sgpu_pas_release(&b.metadata));
    reset(); firmware(); b = (struct sgpu_zap_buffers){0};
    put32(metadata + 1 + 132, 5203); put32(metadata + 1 + 136, 5203);
    assert(sgpu_zap_prepare(metadata + 1, 6684, segment + 1, 5203, &b));
    assert(!memcmp(storage[1], segment + 1, 5203) && storage[1][5203] == 0);
    assert(sgpu_pas_release(&b.image) && sgpu_pas_release(&b.metadata));
}

static void opt_in_cases(void)
{
    for (unsigned mode = 0; mode <= 4; mode++) {
        reset(); firmware(); enabled = 1;
        sgpu_zap_allocation_preflight(mode);
        if (mode == 3) assert(arg_reads == 1 && allocations == 2 && frees == 2);
        else assert(!arg_reads && !dt_reads && !allocations);
    }
    const unsigned rejected[] = {0, 2, UINT32_MAX};
    for (unsigned i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
        reset(); firmware(); enabled = rejected[i];
        sgpu_zap_allocation_preflight(3);
        assert(arg_reads == 1 && !dt_reads && !allocations);
    }
    for (unsigned missing = 1; missing <= 3; missing++) {
        reset(); firmware(); enabled = 1; missing_property = missing;
        sgpu_zap_allocation_preflight(3);
        assert(!allocations && !frees);
    }
    reset(); firmware(); enabled = 1; fail_allocation = 2;
    sgpu_zap_allocation_preflight(3);
    assert(allocations == 2 && frees == 1);
}

int main(void)
{
    allocation_cases(); preparation_cases(); opt_in_cases();
    puts("PASS actual PAS allocation, ELF bounds, ownership, padding and opt-in contracts (NO SMC)");
    return 0;
}
