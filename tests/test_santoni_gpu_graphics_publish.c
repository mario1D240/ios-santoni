/* Actual controller publication, with independent CPU/DMA views and table
 * walks. Bootstrap/MMIO/cache/GPU execution remain explicit host models. */
#include "santoni_gpu_live_ui_model.h"
#include "santoni_gpu_graphics_hw.h"

#define HW_RO 0x0060000000000ec7ull
#define HW_RW 0x0060000000000e47ull
static bool publishing;
static unsigned scenario,posts,executed,wraps;
static uint32_t wanted_sequence,wanted_roots,destination;

static void execute_ib(struct live_model *m,uint32_t va,uint32_t bytes)
{
    assert(bytes==16);
    const uint32_t *ib=(const uint32_t *)(const void *)live_address(m,va,bytes,false);
    assert(ib && !live_address(m,va,bytes,true));
    assert(ib[0]==0x703d8003 && ib[1]==destination && !ib[2]);
    live_store(m,ib[1],ib[3]);executed++;
}
static void execute_ring(struct live_model *m,uint32_t end)
{
    struct model *b=&m->session.base;
    const uint32_t *ring=(const uint32_t *)(const void *)live_address(m,SGPU_RING_VA,SGPU_PAGE,false);
    assert(ring && !live_address(m,SGPU_RING_VA,4,true));
    unsigned first=b->last,roots=0,events=0,waits=0;
    if(end<first) {
        assert(ring[first]==sgpu_packet7(0x10,SGPU_PAGE/4-first-1));
        for(unsigned i=first+1;i<SGPU_PAGE/4;i++)assert(!ring[i]);
        first=0;wraps++;
    }
    for(unsigned i=first;i<end;) {
        uint32_t h=ring[i++],count=h&0x3fff,op=(h>>16)&127;
        assert(h==sgpu_packet7(op,count) && count<=end-i);
        if(op==0x3f) {
            assert(count==3 && !ring[i+1] && ring[i+2]==4 && !events && !waits);
            execute_ib(m,ring[i],ring[i+2]*4);roots++;
        } else if(op==0x46) {
            assert(count==4 && ring[i]==4 && ring[i+1]==SGPU_RENDER_VA && !ring[i+2]);
            assert(ring[i+3]==wanted_sequence && roots==wanted_roots && !events && !waits);
            if(scenario!=26)live_store(m,ring[i+1],ring[i+3]+(scenario==27));
            events++;
        } else {
            assert(op==0x26 && !count && events==1 && !waits);waits++;
        }
        i+=count;
    }
    assert(roots==wanted_roots && events==1 && waits==1);
    b->last=end;*reg(b,SG_GPU,SG_RB_RPTR)=end;
    *reg(b,SG_GPU,SG_STATUS)=scenario==24?2:0;
    if(scenario==25)*reg(b,SG_SMMU,SG_CB_FSR)=2;
}
static void publish_write(void *ctx,enum sgpu_block block,uint32_t off,uint32_t value)
{
    struct live_model *m=ctx;
    if(!publishing || block!=SG_GPU || off!=SG_RB_WPTR) {live_write(ctx,block,off,value);return;}
    assert(value && value<SGPU_PAGE/4);posts++;
    *reg(&m->session.base,block,off)=value+(scenario==22);
    if(scenario==22 || scenario==23)return;
    execute_ring(m,value);
}
static void publish_clean(void *ctx,const void *address,uint32_t bytes)
{
    struct live_model *m=ctx;
    live_clean(ctx,address,bytes);
    if(publishing && address==m->session.base.cpu+3*SGPU_PAGE) {
        if(scenario==29)((uint64_t *)(void *)(m->memory.tables+2*SGPU_PAGE))[4]^=SGPU_PAGE;
        if(scenario==30)*reg(&m->session.base,SG_GPU,SG_ME_CNTL)=15;
    }
}
int main(int argc,char **argv)
{
    assert(argc==2);scenario=(unsigned)strtoul(argv[1],NULL,10);assert(scenario<31);
    struct live_model m={0};init(&m.session.base,SECURE_GPU);
    void *tables=NULL,*pixels=NULL;
    assert(!posix_memalign(&tables,SGPU_PAGE,7*SGPU_PAGE));
    assert(!posix_memalign(&pixels,SGPU_PAGE,2*SGPU_RENDER_BYTES));
    m.memory=(struct sgpu_render_memory){.tables=tables,.pixels=pixels,.pa=m.pages,.pages=SGPU_RENDER_LIVE_PAGES};
    m.tables_dma=calloc(1,7*SGPU_PAGE);m.pixels_dma=calloc(1,2*SGPU_RENDER_BYTES);assert(m.tables_dma && m.pixels_dma);
    for(unsigned i=0;i<7;i++)m.memory.table_pa[i]=0xa0000000ull+i*2*SGPU_PAGE;
    for(unsigned i=0;i<SGPU_RENDER_LIVE_PAGES;i++)m.pages[i]=0xa1000000ull+i*2*SGPU_PAGE;
    struct sgpu_ops io=ops(&m.session.base);io.ctx=&m;io.trace=live_trace;
    io.read32=live_read;io.read64=live_read64;io.write32=publish_write;io.clean=publish_clean;
    io.invalidate=live_invalidate;io.wait_us=live_wait;io.now_us=live_now;
    io.stock_unsecure=io.stock_pixels=io.g3=io.session=1;
    struct sgpu_report boot={0};struct sgpu_render_live_result result={0};uint8_t fw[64];firmware(fw);
    assert(sgpu_render_live_start(&io,3,1,fw,sizeof(fw),&m.memory,&boot,&result));m.ui=true;
    assert(sgpu_graphics_hw_begin(3,1));
    uint32_t source=SGPU_RENDER_VA+4*SGPU_PAGE;destination=SGPU_RENDER_VA+8*SGPU_PAGE;
    for(unsigned i=0;i<2;i++) {
        assert(!posix_memalign((void **)&m.import_cpu[i],SGPU_PAGE,SGPU_PAGE));
        m.import_dma[i]=calloc(1,SGPU_PAGE);assert(m.import_dma[i]);m.import_pa[i][0]=0xa3000000+i*2*SGPU_PAGE;
        uint32_t va=i?destination:source;
        assert(sgpu_graphics_hw_map(va,&m.import_pa[i][0],1,i?HW_RW:HW_RO,va+SGPU_PAGE));
    }
    uint32_t *ib=(uint32_t *)(void *)m.import_cpu[0];
    ib[0]=0x703d8003;ib[1]=destination;ib[2]=0;ib[3]=0xa505cafe;
    sgpu_graphics_hw_clean(ib,16);
    struct sgpu_graphics_command commands[SGPU_GRAPHICS_IBS+1];
    for(unsigned i=0;i<SGPU_GRAPHICS_IBS+1;i++)commands[i]=(struct sgpu_graphics_command){source,16};
    uint32_t count=scenario==1?SGPU_GRAPHICS_IBS:1,sequence=1;
    if(scenario==3)count=0;
    if(scenario==4)count=SGPU_GRAPHICS_IBS+1;
    if(scenario==5)sequence=0;
    if(scenario==7)commands[0].bytes=0;
    if(scenario==8)commands[0].gpu_va++;
    if(scenario==9)commands[0].bytes++;
    if(scenario==10)commands[0].bytes=SGPU_GRAPHICS_IB_BYTES+4;
    if(scenario==11)commands[0].gpu_va=SGPU_RENDER_VA;
    if(scenario==12)commands[0].gpu_va=SGPU_RENDER_VA+SGPU_RENDER_MAX_PAGES*SGPU_PAGE;
    if(scenario==13)commands[0].gpu_va=source+2*SGPU_PAGE;
    if(scenario==14)commands[0].gpu_va=source+SGPU_PAGE-8;
    if(scenario==15)commands[0].gpu_va=destination;
    if(scenario==16)((uint64_t *)(void *)(tables+2*SGPU_PAGE))[4]^=SGPU_PAGE;
    if(scenario==17)m.pages[SGPU_RENDER_LIVE_PAGES-1]^=SGPU_PAGE;
    if(scenario==18)*reg(&m.session.base,SG_GPU,SG_TRUST)=1;
    if(scenario==19)*reg(&m.session.base,SG_GPU,SG_ME_CNTL)=15;
    if(scenario==20)(*reg(&m.session.base,SG_GPU,SG_RB_RPTR))++;
    if(scenario==21)*reg(&m.session.base,SG_SMMU,SG_CB)=0x1126;
    publishing=true;wanted_sequence=sequence;wanted_roots=count;
    uint64_t before=live_now(&m);
    bool published=sgpu_graphics_hw_publish(scenario==6?NULL:commands,count,sequence);
    if(scenario>=3 && scenario<=21) {assert(!published && !posts);goto done;}
    if(scenario==29 || scenario==30) {assert(!published && !posts && !sgpu_graphics_hw_ready());goto done;}
    if(scenario>=22 && scenario<=24) {
        assert(!published && posts==1 && !sgpu_graphics_hw_ready());
        assert(live_now(&m)-before<=2*SGPU_RENDER_WAIT_US+1000);
        struct sgpu_graphics_hw_result state,again;sgpu_graphics_hw_snapshot(&state);
        assert(state.failed && state.error && state.pending==sequence);
        assert(!sgpu_graphics_hw_unmap(source,1,source+SGPU_PAGE));
        assert(!sgpu_graphics_hw_publish(commands,1,sequence+1));sgpu_graphics_hw_snapshot(&again);
        assert(again.error==state.error && !memcmp(&again.failure,&state.failure,sizeof(state.failure)));
        goto done;
    }
    assert(published && posts==1 && executed==count);
    if(scenario==25) {assert(sgpu_graphics_hw_faulted() && !sgpu_graphics_hw_ready());goto done;}
    /* CPU's fence is stale until the exact DMA invalidation occurs. */
    assert(!sgpu_graphics_hw_fence());sgpu_graphics_hw_invalidate_fence();
    assert(sgpu_graphics_hw_fence()==(scenario==26?0:sequence+(scenario==27)));
    if(scenario==26 || scenario==27)goto done;
    assert(!sgpu_graphics_hw_publish(commands,count,sequence+1));
    assert(!sgpu_graphics_hw_unmap(source,1,source+SGPU_PAGE));
    assert(sgpu_graphics_hw_idle());
    if(scenario==2) {
        for(sequence=2;sequence<=151;sequence++) {
            wanted_sequence=sequence;wanted_roots=count=sequence&1?SGPU_GRAPHICS_IBS:1;
            assert(sgpu_graphics_hw_publish(commands,count,sequence));
            sgpu_graphics_hw_invalidate_fence();assert(sgpu_graphics_hw_fence()==sequence && sgpu_graphics_hw_idle());
        }
        assert(wraps>=3 && posts==151);
    }
    uint32_t value=0;memcpy(&value,m.import_dma[1],4);assert(value==0xa505cafe);
    assert(sgpu_graphics_hw_unmap(source,1,source+SGPU_PAGE));
    assert(sgpu_graphics_hw_unmap(destination,1,destination+SGPU_PAGE));
done:
    assert(!m.session.base.frees);
    printf("PASS actual graphics publication case=%u posts=%u IBs=%u wraps=%u; hardware modeled\n",scenario,posts,executed,wraps);
    for(unsigned i=0;i<2;i++){free(m.import_cpu[i]);free(m.import_dma[i]);}
    free(m.tables_dma);free(m.pixels_dma);free(tables);free(pixels);return 0;
}
