#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint64_t vm_offset_t, vm_map_address_t, pmap_paddr_t;
typedef struct { uint64_t pa, va, len; } ptov_table_entry;
typedef struct { uint64_t topOfKernelData; } boot_args;
#define PTOV_TABLE_SIZE 8
#define ARM64_GRANULE_ALLOW_BLOCK 1u
#define ARM64_GRANULE_ALLOW_HINT 2u
static ptov_table_entry ptov_table[PTOV_TABLE_SIZE];
static uint64_t gPhysBase = 0x98000000, gVirtBase = 0xfffffff007004000ull;
static uint64_t segLOWEST, end_kern, real_avail_end = 0xc0000000, physmap_end;
static unsigned ptov_index, regions, attrs[2], tree_updates;
enum { AP_RWNA = 0 };
#ifndef bzero
#define bzero(p,n) memset((p),0,(n))
#endif
static uint64_t phystokv(uint64_t pa) { return gVirtBase + pa - gPhysBase; }
static void arm_vm_physmap_slide(ptov_table_entry *entries, uint64_t va, uint64_t size, int ap, unsigned granule)
{
    assert(ap == AP_RWNA && regions < 2);
    attrs[regions++] = granule;
    entries[ptov_index] = (ptov_table_entry){va - gVirtBase + gPhysBase, va, size};
    ptov_index++;
}
static void arm_vm_page_granular_RWNX(uint64_t va, unsigned long size, unsigned granule)
{ assert(va == end_kern && size == 0x100000 && granule == 3); tree_updates++; }
static int cmp_ptov_entries(const void *a, const void *b)
{ const ptov_table_entry *x = a, *y = b; return x->len > y->len ? -1 : x->len < y->len; }
#include "santoni_gpu_pas_physmap_actual.h"

int main(void)
{
    segLOWEST = gVirtBase + 0x4000; end_kern = gVirtBase + 0xf00000;
    physmap_end = gVirtBase + 0x80000000;
    boot_args args = {.topOfKernelData=0x99000000};
    arm_vm_physmap_init(&args);
    assert(regions == 2 && tree_updates == 1 && attrs[0] == 3);
#if defined(ARM64_BOARD_CONFIG_SANTONI)
    assert(attrs[1] == 0); /* only general-use RAM changes to unhinted leaves */
#else
    assert(attrs[1] == 3);
#endif
    assert(ptov_table[0].pa == args.topOfKernelData && ptov_table[0].len == 0x27000000);
    printf("PASS actual physical-aperture policy; other region and ADT policies preserved\n");
}
