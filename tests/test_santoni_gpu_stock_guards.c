/* Direct private-helper negatives, compiled from the actual reconstructed core. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "santoni_gpu_core.c"

static unsigned accesses;
static uint32_t forbidden_read(void *ctx, enum sgpu_block b, uint32_t off)
{ (void)ctx; (void)b; (void)off; accesses++; return 0; }
static void no_trace(void *ctx, const char *s, uint32_t a, uint32_t b, uint32_t c)
{ (void)ctx; (void)s; (void)a; (void)b; (void)c; }

int main(void)
{
    static _Alignas(SGPU_PAGE) uint8_t data[SGPU_POOL_BYTES];
    struct sgpu_ops io = {.stock_unsecure=1, .read32=forbidden_read, .trace=no_trace};
    for (unsigned bad=0; bad<19; bad++) {
        struct sgpu_report r = {.stage=SG_STOCK_TRANSITION, .markers=16};
        struct probe p = {.ops=&io, .report=&r, .gpu_live=true, .gpu_owned=true,
            .gpu_resumed=true, .smmu_live=true, .dma_exposed=true, .commands_started=true};
        p.memory.va=data;
        for(unsigned i=0;i<SGPU_POOL_PAGES;i++) p.memory.pa[i]=SGPU_DMA_MIN+i*SGPU_PAGE;
        uint32_t mode=3, wptr=75;
        io.stock_unsecure=1; accesses=0;
        switch(bad) {
        case 0: mode=2; break;
        case 1: io.stock_unsecure=0; break;
        case 2: io.stock_unsecure=2; break;
        case 3: p.gpu_live=false; break;
        case 4: p.gpu_owned=false; break;
        case 5: p.gpu_resumed=false; break;
        case 6: p.smmu_live=false; break;
        case 7: p.dma_exposed=false; break;
        case 8: p.commands_started=false; break;
        case 9: p.restoring=true; break;
        case 10: r.error=SG_MARKER_MISMATCH; break;
        case 11: r.failure.kind=SG_FAIL_POLL; break;
        case 12: r.markers=8; break;
        case 13: wptr=9; break;
        case 14: r.stock.attempted=true; break;
        case 15: p.memory.va=NULL; break;
        case 16: p.memory.pa[23]=0; break;
        case 17: p.memory.pa[23]=p.memory.pa[0]; break;
        case 18: p.memory.pa[23]++; break;
        }
        struct sgpu_failure first=r.failure;
        assert(!sgpu_stock_transition(&p, mode, wptr));
        assert(!accesses && !r.stock.echo_zero && !r.stock.held);
        if(bad==10) assert(r.error==SG_MARKER_MISMATCH);
        if(bad==11) assert(!memcmp(&first, &r.failure, sizeof(first)));
    }
    puts("PASS stock private guards: 19 negatives; no hardware access");
    return 0;
}
