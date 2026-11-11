/* Actual controller functions; bootstrap/MMIO/DMA behavior are host models. */
#include "santoni_gpu_live_ui_model.h"
#include "santoni_gpu_graphics_hw.h"
#define HW_PTE_RO 0x0060000000000ec7ull
int main(int argc,char **argv)
{
    assert(argc==2);unsigned test=(unsigned)strtoul(argv[1],NULL,10);assert(test<17);
    assert(!sgpu_graphics_hw_begin(3,1) && !sgpu_graphics_hw_ready());
    struct live_model m={0};init(&m.session.base,SECURE_GPU);
    void *tables=NULL,*pixels=NULL;
    assert(!posix_memalign(&tables,SGPU_PAGE,7*SGPU_PAGE));
    assert(!posix_memalign(&pixels,SGPU_PAGE,2*SGPU_RENDER_BYTES));
    m.memory=(struct sgpu_render_memory){.tables=tables,.pixels=pixels,.pa=m.pages,.pages=SGPU_RENDER_LIVE_PAGES};
    m.tables_dma=calloc(1,7*SGPU_PAGE);m.pixels_dma=calloc(1,2*SGPU_RENDER_BYTES);assert(m.tables_dma && m.pixels_dma);
    for(unsigned i=0;i<7;i++)m.memory.table_pa[i]=0xa0000000ull+i*2*SGPU_PAGE;
    for(unsigned i=0;i<SGPU_RENDER_LIVE_PAGES;i++)m.pages[i]=0xa1000000ull+i*2*SGPU_PAGE;
    struct sgpu_ops io=ops(&m.session.base);io.ctx=&m;io.trace=live_trace;
    io.read32=live_read;io.read64=live_read64;io.write32=live_write;io.clean=live_clean;
    io.invalidate=live_invalidate;io.wait_us=live_wait;io.now_us=live_now;
    io.stock_unsecure=io.stock_pixels=io.g3=io.session=1;
    struct sgpu_report boot={0};struct sgpu_render_live_result result={0};uint8_t fw[64];firmware(fw);
    assert(sgpu_render_live_start(&io,3,1,fw,sizeof(fw),&m.memory,&boot,&result));
    m.ui=true; /* reset/verify TLB handoffs in the independently modeled hardware */
    if(test==1 || test==2 || test==3) {
        uint32_t mode=test==1?1:test==2?2:3,enabled=test==3?0:1;
        assert(!sgpu_graphics_hw_begin(mode,enabled) && m.live_writes==10);goto done;
    }
    if(test==4)m.pages[SGPU_RENDER_LIVE_PAGES-1]=0;
    if(test==6)m.injection=2;
    if(test==7)m.injection=3;
    if(test==8)m.injection=4;
    if(test==9)m.injection=1;
    if(test==13)m.injection=32;
    bool began=sgpu_graphics_hw_begin(3,1);
    if(test==4 || (test>=6 && test<=9) || test==13) {
        assert(!began && !sgpu_graphics_hw_ready());struct sgpu_graphics_hw_result state;
        sgpu_graphics_hw_snapshot(&state);assert(state.failed && state.error);goto done;
    }
    assert(began && sgpu_graphics_hw_ready() && m.live_writes==18);
    uint64_t *legacy=(uint64_t *)(void *)(m.session.base.dma+2*SGPU_PAGE);
    assert((legacy[(SGPU_RING_VA-SGPU_VA_BASE)/SGPU_PAGE]&~0x0000fffffffff000ull)==HW_PTE_RO);
    for(unsigned i=1;i<SGPU_RENDER_MAX_PAGES;i++)assert(!sgpu_graphics_hw_pte(SGPU_RENDER_VA+i*SGPU_PAGE));
    assert(sgpu_graphics_hw_fence_pa()==m.memory.table_pa[6] && !sgpu_graphics_hw_fence());
    assert(!sgpu_graphics_hw_begin(3,1));
    uint32_t va=SGPU_RENDER_VA+4*SGPU_PAGE;uint64_t pages[2]={0xa3000000,0xa3002000};
    unsigned before=m.live_writes;
    if(test==5)m.pages[0]^=SGPU_PAGE;
    if(test==10)pages[0]=m.memory.table_pa[0];
    if(test==11)pages[1]=pages[0];
    if(test==12)((uint64_t *)(void *)((uint8_t *)tables+2*SGPU_PAGE))[6]=0xa3000ec7;
    if(test==14)*reg(&m.session.base,SG_SMMU,SG_CB_FSR)=2;
    if(test==14) {assert(sgpu_graphics_hw_faulted() && !sgpu_graphics_hw_ready());goto done;}
    if(test==16) {
        assert(!sgpu_graphics_hw_map(va,pages,0,HW_PTE_RO,va));
        assert(!sgpu_graphics_hw_map(SGPU_RENDER_VA,pages,1,HW_PTE_RO,SGPU_RENDER_VA+SGPU_PAGE));
        assert(!sgpu_graphics_hw_map(va,pages,1,0,va+SGPU_PAGE));
        assert(m.live_writes==before);goto done;
    }
    bool mapped=sgpu_graphics_hw_map(va,pages,2,HW_PTE_RO,va+3*SGPU_PAGE);
    assert(!mapped && m.live_writes==before); /* mismatched guard before any write */
    mapped=sgpu_graphics_hw_map(va,pages,2,HW_PTE_RO,va+2*SGPU_PAGE);
    if(test==5 || test==10 || test==11 || test==12) {assert(!mapped && m.live_writes==before);goto done;}
    assert(mapped && m.live_writes==before+8);
    assert(sgpu_graphics_hw_pte(va)==(pages[0]|HW_PTE_RO) && sgpu_graphics_hw_pte(va+SGPU_PAGE)==(pages[1]|HW_PTE_RO));
    assert(!sgpu_graphics_hw_pte(va+2*SGPU_PAGE));
    assert(sgpu_graphics_hw_idle() && !sgpu_graphics_hw_faulted());
    assert(sgpu_graphics_hw_unmap(va,2,va+2*SGPU_PAGE) && m.live_writes==before+16);
    assert(!sgpu_graphics_hw_pte(va) && !sgpu_graphics_hw_pte(va+SGPU_PAGE));
done:
    assert(!m.session.base.frees);
    printf("PASS graphics HW case=%u; actual controller, MMIO/bootstrap modeled\n",test);
    free(m.tables_dma);free(m.pixels_dma);free(tables);free(pixels);return 0;
}
