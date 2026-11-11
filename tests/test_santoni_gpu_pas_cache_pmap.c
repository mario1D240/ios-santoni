#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint64_t pmap_paddr_t, vm_map_address_t, vm_offset_t, pt_entry_t, tt_entry_t;
typedef uint32_t ppnum_t;
typedef uint16_t pp_attr_t;
typedef struct { unsigned pta_root_level, pta_max_level, page; } pt_attr_t;
typedef struct { uint64_t min, max; tt_entry_t *tte; } pmap;
static pmap map;
static pmap *kernel_pmap = &map;
static pt_attr_t geometry;
static uint64_t table[3][512], ordinary;
static uint32_t page_bytes = 4096;
static pp_attr_t pp_attr_table[4096];
static unsigned locked, writes, flushes, pv_updates, syncs, cache_syncs, attempts, cases;
static bool drop_write, refuse_cas;
#define PAGE_SIZE page_bytes
#define ARM_PGBYTES 4096u
#define PHYS_BASE 0x98000000ull
#define DATA_PA (PHYS_BASE + 0x4000)
#define TABLE_PA (PHYS_BASE + 0x100000)
#define APERTURE 0xfffffff080004000ull
#define VM_WIMG_DEFAULT 2u
#define VM_WIMG_WCOMB 6u
#define VM_WIMG_MASK 0x3fu
#define PP_ATTR_WIMG_MASK 0x3fu
#define PP_ATTR_WIMG(x) ((x) & PP_ATTR_WIMG_MASK)
#define ARM_TTE_TYPE_MASK 2ull
#define ARM_TTE_VALID 1ull
#define ARM_TTE_TYPE_TABLE 2ull
#define ARM_TTE_TABLE_MASK 0x0000fffffffff000ull
#define ARM_PTE_TYPE 3ull
#define ARM_PTE_HINT_MASK (1ull << 52)
#define ARM_PTE_ATTRINDXMASK (7ull << 2)
#define ARM_PTE_SHMASK (3ull << 8)
#define ARM_PTE_APMASK (3ull << 6)
#define ARM_PTE_AP(x) ((uint64_t)(x) << 6)
#define AP_RWNA 0u
#define PMAP_TT_L3_LEVEL 3u
#define PT_ENTRY_NULL NULL
#define ptoa(pn) ((uint64_t)(pn) << 12)
#define PN ((ppnum_t)(DATA_PA >> 12))

static bool pa_valid(uint64_t pa) { return pa >= PHYS_BASE && pa < PHYS_BASE + 0x1000000; }
static unsigned pa_index(uint64_t pa) { assert(pa_valid(pa)); return (unsigned)((pa - PHYS_BASE) >> 12); }
static const pt_attr_t *pmap_get_pt_attr(pmap *p) { assert(p == kernel_pmap); return &geometry; }
static unsigned pt_attr_page_size(const pt_attr_t *a) { return a->page; }
static unsigned ttn_index(const pt_attr_t *a, uint64_t va, unsigned level)
{ (void)a; assert(level >= 1 && level <= 3); return (unsigned)((va >> (12 + 9 * (3 - level))) & 511); }
static vm_map_address_t phystokv(uint64_t pa)
{
    if (pa == DATA_PA) return APERTURE;
    assert(pa >= TABLE_PA && pa < TABLE_PA + 3 * 4096 && !(pa & 4095));
    return (vm_map_address_t)(uintptr_t)table[(pa - TABLE_PA) / 4096];
}
static uint64_t pte_to_pa(uint64_t pte) { return pte & ARM_TTE_TABLE_MASK; }
static uint64_t wimg_to_pte(unsigned attr, uint64_t pa)
{ (void)pa; return attr == VM_WIMG_DEFAULT ? (2ull << 8) : (4ull | (3ull << 53)); }
static unsigned pmap_cache_attributes(ppnum_t pn)
{ unsigned v = pp_attr_table[pa_index(ptoa(pn))] & PP_ATTR_WIMG_MASK; return v ? v : VM_WIMG_DEFAULT; }
static void pvh_lock(unsigned pai) { assert(!locked && pai == pa_index(DATA_PA)); locked = 1; }
static void pvh_unlock(unsigned pai) { assert(locked && pai == pa_index(DATA_PA)); locked = 0; }
static bool OSCompareAndSwap16(pp_attr_t old, pp_attr_t value, pp_attr_t *location)
{
    assert(locked); attempts++;
    if (refuse_cas || *location != old) return false;
    *location = value; return true;
}
static void write_pte_strong(uint64_t *pte, uint64_t value)
{ assert(locked); writes++; if (!drop_write) *pte = value; }
static void flush_mmu_tlb_region_asid_async(uint64_t va, unsigned bytes, pmap *p, bool last)
{ assert(locked && writes && va == APERTURE && bytes == 4096 && p == kernel_pmap && last); flushes++; }
static bool pmap_update_cache_attributes_locked(ppnum_t pn, unsigned value, bool tlbi)
{
    assert(locked && flushes && pn == PN && tlbi); pv_updates++;
    ordinary = (ordinary & ~(ARM_PTE_ATTRINDXMASK | ARM_PTE_SHMASK)) | wimg_to_pte(value, DATA_PA);
    return true;
}
static void sync_tlb_flush(void) { assert(locked && pv_updates); syncs++; }
static void pmap_sync_wimg(ppnum_t pn, unsigned old, unsigned replacement)
{ assert(!locked && syncs && pn == PN && old != replacement); cache_syncs++; }
#include "santoni_gpu_pas_pmap_actual.h"

static uint64_t *leaf(void) { return &table[2][ttn_index(&geometry, APERTURE, 3)]; }
static void reset(void)
{
    geometry = (pt_attr_t){1, 3, 4096}; page_bytes = 4096;
    map = (pmap){APERTURE - 0x4000, APERTURE + 0x200000, table[0]};
    memset(table, 0, sizeof(table)); memset(pp_attr_table, 0, sizeof(pp_attr_table));
    table[0][ttn_index(&geometry, APERTURE, 1)] = (TABLE_PA + 4096) | 3;
    table[1][ttn_index(&geometry, APERTURE, 2)] = (TABLE_PA + 8192) | 3;
    ordinary = *leaf() = DATA_PA | ARM_PTE_TYPE | wimg_to_pte(VM_WIMG_DEFAULT, DATA_PA) | (1ull << 10) | (3ull << 53);
    pp_attr_table[pa_index(DATA_PA)] = 0x8000 | VM_WIMG_DEFAULT;
    locked = writes = flushes = pv_updates = syncs = cache_syncs = attempts = 0;
    drop_write = refuse_cas = false;
}

int main(void)
{
    reset(); uint64_t original = *leaf();
    assert(pmap_santoni_pas_cache_control(PN, 2, 2));
    assert(!writes && !attempts && !locked); cases++;
    assert(pmap_santoni_pas_cache_control(PN, 2, 6));
    assert(*leaf() == ordinary && pmap_cache_attributes(PN) == 6);
    assert((pp_attr_table[pa_index(DATA_PA)] & 0x8000) && cache_syncs == 1); cases++;
    assert(pmap_santoni_pas_cache_control(PN, 6, 2));
    assert(*leaf() == ordinary && *leaf() == original && cache_syncs == 2); cases++;
    for (unsigned bad = 0; bad < 12; bad++) {
        reset();
        if (bad == 0) table[0][ttn_index(&geometry, APERTURE, 1)] = 1; /* L1 block */
        if (bad == 1) table[1][ttn_index(&geometry, APERTURE, 2)] = 1; /* L2 block */
        if (bad == 2) table[1][ttn_index(&geometry, APERTURE, 2)] = 0;
        if (bad == 3) *leaf() |= ARM_PTE_HINT_MASK;
        if (bad == 4) *leaf() = (*leaf() & ~ARM_TTE_TABLE_MASK) | (DATA_PA + 4096);
        if (bad == 5) *leaf() &= ~ARM_TTE_VALID;
        if (bad == 6) *leaf() |= ARM_PTE_AP(2);
        if (bad == 7) *leaf() ^= 4;
        if (bad == 8) pp_attr_table[pa_index(DATA_PA)] = 6;
        if (bad == 9) geometry.page = 16384;
        if (bad == 10) page_bytes = 16384;
        if (bad == 11) map.tte = NULL;
        assert(!pmap_santoni_pas_cache_control(PN, 2, 6));
        assert(!writes && !attempts && !cache_syncs && !locked); cases++;
    }
    reset(); assert(!pmap_santoni_pas_cache_control(0, 2, 6));
    assert(!pmap_santoni_pas_cache_control(PN, 7, 6));
    assert(!pmap_santoni_pas_cache_control(PN, 2, 7));
    assert(!writes && !attempts); cases++;
    reset(); refuse_cas = true;
    assert(!pmap_santoni_pas_cache_control(PN, 2, 6) && attempts == 64);
    assert(!writes && !locked); cases++;
    reset(); drop_write = true;
    assert(!pmap_santoni_pas_cache_control(PN, 2, 6));
    assert(pmap_cache_attributes(PN) == 6 && *leaf() != ordinary); cases++;
    printf("PASS actual PAS pmap contract: %u cases; no live page tables\n", cases);
}
