/* Actual reconstructed private pixel helper: malformed entry stays read-free. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "santoni_gpu_core.c"

static unsigned accesses;
static uint32_t forbidden_read(void *ctx,enum sgpu_block block,uint32_t off)
{ (void)ctx;(void)block;(void)off; accesses++; return 0; }
static void no_trace(void *ctx,const char *s,uint32_t a,uint32_t b,uint32_t c)
{ (void)ctx;(void)s;(void)a;(void)b;(void)c; }

int main(void)
{
    static _Alignas(SGPU_PAGE) uint8_t data[SGPU_POOL_BYTES];
    for(unsigned bad=0;bad<26;bad++) {
        struct sgpu_ops io={.stock_unsecure=1,.stock_pixels=1,.read32=forbidden_read,.trace=no_trace};
        struct sgpu_report r={.stage=SG_STOCK_TRANSITION,.markers=16,.error=SG_STOCK_HELD};
        r.stock.attempted=r.stock.echo_zero=r.stock.held=r.pixel.requested=true;
        struct probe p={.ops=&io,.report=&r,.gpu_live=true,.gpu_owned=true,
            .gpu_resumed=true,.smmu_live=true,.dma_exposed=true,.commands_started=true};
        p.memory.va=data;
        for(unsigned i=0;i<SGPU_POOL_PAGES;i++) p.memory.pa[i]=SGPU_DMA_MIN+i*SGPU_PAGE;
        uint32_t mode=3,words=75,*wptr=&words; accesses=0;
        switch(bad) {
        case 0: mode=2;break;
        case 1: io.stock_unsecure=0;break;
        case 2: io.stock_unsecure=2;break;
        case 3: io.stock_pixels=0;break;
        case 4: io.stock_pixels=2;break;
        case 5: r.pixel.requested=false;break;
        case 6: r.pixel.started=true;break;
        case 7: r.stock.echo_zero=false;break;
        case 8: r.failure.kind=SG_FAIL_POLL;break;
        case 9: r.error=SG_FAULT;break;
        case 10: r.stock.attempted=false;break; /* error16 without attempted is invalid */
        case 11: r.error=0;break; /* attempted without its held outcome is invalid */
        case 12: p.gpu_live=false;break;
        case 13: p.gpu_owned=false;break;
        case 14: p.gpu_resumed=false;break;
        case 15: p.smmu_live=false;break;
        case 16: p.dma_exposed=false;break;
        case 17: p.commands_started=false;break;
        case 18: p.restoring=true;break;
        case 19: r.markers=8;break;
        case 20: wptr=NULL;break;
        case 21: words=9;break;
        case 22: p.memory.va=NULL;break;
        case 23: p.memory.pa[23]=0;break;
        case 24: p.memory.pa[23]=p.memory.pa[0];break;
        case 25: p.memory.pa[23]++;break;
        }
        struct sgpu_failure original=r.failure;
        bool started=r.pixel.started;
        assert(!sgpu_stock_pixels_test(&p,mode,wptr));
        assert(!accesses && r.pixel.started==started && !r.pixel.passed && !r.pixels);
        if(bad==8) assert(!memcmp(&original,&r.failure,sizeof(original)));
        if(bad==9) assert(r.error==SG_FAULT);
    }
    puts("PASS pixel private guards: 26 negatives, immutable forward errors");
    return 0;
}
