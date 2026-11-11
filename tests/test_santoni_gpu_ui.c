/* Actual core with independently modeled DMA/table/TLB/ring behavior. */
#include "santoni_gpu_live_ui_model.h"

int main(int argc,char **argv)
{
    assert(argc==2);unsigned test=(unsigned)strtoul(argv[1],NULL,10);
    struct live_model m={0};init(&m.session.base,SECURE_GPU);
    void *tables=NULL,*pixels=NULL;
    assert(!posix_memalign(&tables,SGPU_PAGE,7*SGPU_PAGE));
    assert(!posix_memalign(&pixels,SGPU_PAGE,2*SGPU_RENDER_BYTES));
    m.memory=(struct sgpu_render_memory){.tables=tables,.pixels=pixels,.pa=m.pages,.pages=SGPU_RENDER_LIVE_PAGES};
    m.tables_dma=calloc(1,7*SGPU_PAGE);m.pixels_dma=calloc(1,2*SGPU_RENDER_BYTES);
    assert(m.tables_dma && m.pixels_dma);
    for(unsigned i=0;i<7;i++)m.memory.table_pa[i]=0xa0000000ull+i*2*SGPU_PAGE;
    for(unsigned i=0;i<SGPU_RENDER_LIVE_PAGES;i++)m.pages[i]=0xa1000000ull+i*2*SGPU_PAGE;
    for(unsigned b=0;b<2;b++) {
        void *src=NULL;assert(!posix_memalign(&src,SGPU_PAGE,SGPU_RENDER_BYTES));m.import_cpu[b]=src;
        m.import_dma[b]=calloc(1,SGPU_RENDER_BYTES);assert(m.import_dma[b]);
        for(unsigned i=0;i<SGPU_RENDER_BYTES/SGPU_PAGE;i++)
            m.import_pa[b][i]=0xa2000000ull+b*0x1000000ull+i*2*SGPU_PAGE;
    }
    struct sgpu_ops io=ops(&m.session.base);io.ctx=&m;io.trace=live_trace;
    io.read32=live_read;io.read64=live_read64;io.write32=live_write;io.clean=live_clean;
    io.invalidate=live_invalidate;io.wait_us=live_wait;io.now_us=live_now;
    io.stock_unsecure=io.stock_pixels=io.g3=io.session=1;
    struct sgpu_report boot={0};struct sgpu_render_live_result result={0};uint8_t fw[64];firmware(fw);
    assert(!sgpu_ui_start(1));
    assert(sgpu_render_live_start(&io,3,1,fw,sizeof(fw),&m.memory,&boot,&result));
    assert(!sgpu_ui_start(0));
    assert(sgpu_ui_start(1));
    assert(!sgpu_ui_start(1));
    m.ui=true;
    /* The caller's returned boot report is not runtime state. Poisoning it
     * must not alter the persistent session/UI reports. */
    memset(&boot,0xff,sizeof(boot));
    const uint8_t *out=NULL;uint32_t stride=0;
    assert(!sgpu_ui_frame(&out,&stride));
    struct sgpu_ui_image image={m.import_cpu[0],m.import_pa[0],SGPU_RENDER_BYTES/SGPU_PAGE,
        SGPU_RENDER_BYTES,SGPU_RENDER_WIDTH,SGPU_RENDER_HEIGHT,SGPU_RENDER_STRIDE};
    if(test==1)image.stride-=64;
    if(test==2)m.import_pa[0][image.pages-1]=0;
    if(test==3)m.import_pa[0][image.pages-1]=m.import_pa[0][0];
    if(test==4)m.import_pa[0][image.pages-1]=m.memory.table_pa[6];
    if(test==5)m.import_pa[0][image.pages-1]=m.session.base.pa[23];
    if(test==6)m.import_pa[0][image.pages-1]=m.pages[SGPU_RENDER_LIVE_PAGES-1];
    if(test==7)image.pages--;
    if(test==8)image.va++;
    if(test==9)image.bytes--;
    if(test==10)m.injection=8; /* absent sequence fence */
    if(test==11)m.injection=2; /* stop write rejected */
    if(test==12)m.injection=6; /* TLBSYNC stays busy */
    if(test==13)m.injection=18; /* actual global fault after GPU execution */
    if(test==14)m.injection=16; /* actual CB fault, distinct from status0x400 */
    if(test==15)m.injection=37; /* CP/RBBM never returns idle */
    if(test==16)image.width--;
    if(test==17)image.height--;
    if(test==18)m.import_pa[0][image.pages-1]=SGPU_DMA_END;
    unsigned before=m.live_writes;
    unsigned frames=test==0?64:test==19?2:1;
    for(unsigned frame=0;frame<frames;frame++) {
        unsigned b=frame&1;
        if(test==0){image.va=m.import_cpu[b];image.pa=m.import_pa[b];}
        for(unsigned i=0;i<SGPU_RENDER_BYTES;i++)m.import_cpu[b][i]=(uint8_t)(i*13+frame*29);
        int rc=sgpu_ui_copy(&image,&out,&stride);
        if(test==0 || (test==19 && frame==0)) {
            assert(rc==1 && out && stride==3072);
            assert(sgpu_ui_frame(&out,&stride));
            for(unsigned y=0;y<1280;y++)
                assert(!memcmp(out+y*stride,m.import_cpu[b]+y*stride,720*4));
            assert(!m.session.base.frees);
            assert(m.full_blits==frame+3);
            unsigned start=10+frame*9;
            const unsigned delta[][3]={{SG_GPU,SG_ME_CNTL,3},{SG_SMMU,SG_S2CR0,SG_S2CR_FAULT},
                {SG_SMMU,SG_CB,0x1126},{SG_SMMU,SG_CB_TLBIASID,1},{SG_SMMU,SG_CB_TLBSYNC,0},
                {SG_SMMU,SG_CB,0x1127},{SG_SMMU,SG_S2CR0,0},{SG_GPU,SG_ME_CNTL,0}};
            for(unsigned i=0;i<8;i++)
                assert(m.delta[start+i].block==delta[i][0] && m.delta[start+i].offset==delta[i][1] && m.delta[start+i].value==delta[i][2]);
            assert(m.delta[start+8].block==SG_GPU && m.delta[start+8].offset==SG_RB_WPTR);
            if(test==19)m.pages[0]^=SGPU_PAGE; /* old source PA after RO import */
        } else if((test>=10 && test<=15) || test==19) {
            assert(rc==-1 && !out && !stride);
            assert(!sgpu_ui_frame(&out,&stride));
            struct sgpu_ui_result first={0},again={0};sgpu_ui_snapshot(&first);
            assert(first.failed && !first.ready && first.error);
            if(test==11)assert(first.phase==SG_LIVE_HALT && first.failure.kind==SG_FAIL_READBACK &&
                first.failure.offset==SG_ME_CNTL && first.failure.mask==0xfffffff3u &&
                first.failure.want==3 && first.failure.got==0);
            unsigned writes=m.live_writes;
            assert(!sgpu_ui_copy(&image,&out,&stride));
            sgpu_ui_snapshot(&again);assert(!memcmp(&first,&again,sizeof(first)));
            assert(writes==m.live_writes && !m.session.base.frees);
        } else assert(!rc && !out && !stride && m.live_writes==before);
    }
    if(test==0)assert(m.wraps>=4 && m.full_blits==66);
    printf("PASS UI core case=%u frames=%u wraps=%u; host hardware model only\n",test,frames,m.wraps);
    for(unsigned b=0;b<2;b++){free(m.import_cpu[b]);free(m.import_dma[b]);}
    free(tables);free(pixels);free(m.tables_dma);free(m.pixels_dma);destroy(&m.session.base);
    return 0;
}
