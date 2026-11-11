/* Actual kernel core + separate CPU/DMA views; no device access. */
#define main sgpu_old_mock_main
#include "test_santoni_gpu_mock.c"
#undef main

struct g3_model {
    struct model base;
    struct sgpu_report *report;
    bool started, ended;
    unsigned submitted, injection;
};
static void g3_trace(void *ctx,const char *s,uint32_t a,uint32_t b,uint32_t c)
{
    struct g3_model *m=ctx;(void)a;(void)b;(void)c;
    if (!strncmp(s,"before G3",9)) {
        assert(m->report->g3.started && m->report->pixel.passed);
        m->started=true;
        if(m->injection==1) *reg(&m->base,SG_GPU,SG_TRUST)=1;
        if(m->injection==2) *reg(&m->base,SG_GPU,SG_INT_STATUS)=2;
        if(m->injection==3) ((uint64_t *)(void *)(m->base.cpu+2*SGPU_PAGE))[257]=3;
    }
    if(!strcmp(s,"stock pixel test ended; state HELD until reboot; no cleanup")) m->ended=true;
}
static uint32_t g3_read(void *ctx,enum sgpu_block b,uint32_t off)
{ struct g3_model *m=ctx;assert(!m->ended);return read32(&m->base,b,off); }
static void g3_write(void *ctx,enum sgpu_block b,uint32_t off,uint32_t v)
{
    struct g3_model *m=ctx;assert(!m->ended);
    if(b==SG_GPU && off==SG_TRUST) {
        assert(v==0 && m->report->stock.attempted && !m->started);
        *reg(&m->base,b,off)=0;return;
    }
    if(!m->started) { write32(&m->base,b,off,v);return; }
    assert(b==SG_GPU && off==SG_RB_WPTR && v==159+11*m->submitted);
    assert(m->report->g3.submitted==m->submitted+1 && m->report->stock.held);
    m->submitted++;*reg(&m->base,b,off)=v;
    if(m->injection==4) { *reg(&m->base,SG_GPU,SG_STATUS)=2;return; }
    uint32_t *ring=(uint32_t *)(void *)gpu_address(&m->base,SGPU_RING_VA,SGPU_PAGE,false);
    assert(ring && m->base.last+11==v);
    uint32_t *batch=ring+m->base.last;
    assert(batch[0]==sgpu_packet7(0x3f,3) && !batch[2] && batch[3]==17);
    assert(batch[4]==sgpu_packet7(0x26,0) && batch[5]==sgpu_packet7(0x46,4));
    assert(batch[6]==4 && !batch[8] && batch[9]==m->submitted && batch[10]==sgpu_packet7(0x26,0));
    uint32_t *ib=(uint32_t *)(void *)gpu_address(&m->base,batch[1],68,false);
    assert(ib && !gpu_address(&m->base,batch[1],4,true));
    assert(!gpu_address(&m->base,batch[1]+SGPU_PAGE,4,false));
    for(unsigned i=0;i<4;i++) {
        assert(ib[4*i]==sgpu_packet7(0x3d,3) && !ib[4*i+2]);
        assert(!gpu_address(&m->base,(ib[4*i+1]&~4095u)+SGPU_PAGE,4,false));
        gpu_write(&m->base,ib[4*i+1],ib[4*i+3]^(m->injection==6?1u:0u));
    }
    assert(ib[16]==sgpu_packet7(0x26,0));
    if(m->injection!=5) gpu_write(&m->base,batch[7],batch[9]);
    if(m->injection==7) gpu_write(&m->base,ib[1]+16,0);
    if(m->injection==8) *reg(&m->base,SG_SMMU,SG_CB_FSR)=2;
    if(m->injection==9) *reg(&m->base,b,off)=v+1;
    m->base.last=v;*reg(&m->base,SG_GPU,SG_RB_RPTR)=v;*reg(&m->base,SG_GPU,SG_STATUS)=0;
}

int main(void)
{
    uint8_t fw[64];firmware(fw);
    for(unsigned injection=0;injection<10;injection++) {
        struct g3_model m={.injection=injection};init(&m.base,SECURE_GPU);
        struct sgpu_report r;m.report=&r;struct sgpu_ops io=ops(&m.base);
        io.ctx=&m;io.read32=g3_read;io.write32=g3_write;io.trace=g3_trace;
        io.stock_unsecure=io.stock_pixels=io.g3=1;
        assert(!sgpu_probe(&io,3,fw,sizeof(fw),&r));
        assert(r.g3.requested && r.g3.started && m.ended && r.pixel.passed && r.pixels==256);
        assert(r.g3.passed==(injection==0));
        assert(r.g3.submitted==(injection==0?2u:injection<=3?0u:1u));
        assert(r.g3.completed==(injection==0?2u:0u));
        assert(r.g3.writes==(injection==0?8u:0u));
        assert(r.memory_retained && !r.restored && !r.gpu_quiescent && !r.smmu_restored);
        assert(r.power_pending==13 && m.base.frees==0 && m.base.reset_count==1);
        assert(r.error==(injection==0?SG_STOCK_HELD:injection<=1?SG_BAD_SMMU:
            injection==2||injection==8||injection==9?SG_FAULT:injection==3?SG_BAD_MEMORY:
            injection==4||injection==5?SG_COMMAND_TIMEOUT:SG_MARKER_MISMATCH));
        assert(!r.rollback_failure.kind && m.base.us<1000000);
        destroy(&m.base);
    }
    for(unsigned mode=0;mode<=4;mode++) for(unsigned stock=0;stock<3;stock++)
        for(unsigned pixels=0;pixels<3;pixels++) for(unsigned option=1;option<3;option++) {
            if(mode==3 && stock==1 && pixels==1 && option==1) continue;
            struct model m;init(&m,NONE);struct sgpu_ops io=ops(&m);struct sgpu_report r;
            io.stock_unsecure=stock;io.stock_pixels=pixels;io.g3=option;
            assert(sgpu_probe(&io,mode,fw,sizeof(fw),&r)==(mode==0));
            assert(!m.allocs && !m.maps && !m.writes);destroy(&m);
        }
    puts("PASS G3: two owned IB submissions, 8 writes, 9 failures, 89 invalid modes; retention");
}
