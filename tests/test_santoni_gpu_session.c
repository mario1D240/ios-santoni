/* Actual core with separate CPU/PoC views; each invocation has a fresh session. */
#define main old_gpu_mock_main
#include "test_santoni_gpu_mock.c"
#undef main

struct session_model {
    struct model base;
    bool ib_path, active;
    unsigned injection, ibs, accesses, clocks;
};
static void (*session_callback_check)(void);
static void session_trace(void *ctx,const char *text,uint32_t a,uint32_t b,uint32_t c)
{
    struct session_model *m=ctx;(void)a;(void)b;(void)c;
    if(session_callback_check)session_callback_check();
    if (!strncmp(text,"before G3",9)) m->ib_path=true;
}
static uint32_t session_read(void *ctx,enum sgpu_block block,uint32_t off)
{
    struct session_model *m=ctx;m->accesses++;
    if(session_callback_check)session_callback_check();
    if (m->active && m->injection==1 && block==SG_GPU && off==SG_TRUST) return 1;
    return read32(&m->base,block,off);
}
static uint64_t session_read64(void *ctx,enum sgpu_block block,uint32_t off)
{ struct session_model *m=ctx;m->accesses++;if(session_callback_check)session_callback_check();return read64(&m->base,block,off); }
static void session_write(void *ctx,enum sgpu_block block,uint32_t off,uint32_t value)
{
    struct session_model *m=ctx;m->accesses++;
    if(session_callback_check)session_callback_check();
    if (block==SG_GPU && off==SG_TRUST) { assert(value==0);*reg(&m->base,block,off)=0;return; }
    if (!m->ib_path) { write32(&m->base,block,off,value);return; }
    assert(block==SG_GPU && off==SG_RB_WPTR && value==m->base.last+11);
    uint32_t *ring=(uint32_t *)(void *)gpu_address(&m->base,SGPU_RING_VA,SGPU_PAGE,false);
    assert(ring);uint32_t *batch=ring+m->base.last;
    assert(batch[0]==sgpu_packet7(0x3f,3) && !batch[2] && batch[3]==17);
    assert(batch[4]==sgpu_packet7(0x26,0) && batch[5]==sgpu_packet7(0x46,4));
    assert(batch[6]==4 && !batch[8] && batch[9]==m->ibs+1 && batch[10]==sgpu_packet7(0x26,0));
    uint32_t *ib=(uint32_t *)(void *)gpu_address(&m->base,batch[1],68,false);
    assert(ib && !gpu_address(&m->base,batch[1],4,true));
    assert(!gpu_address(&m->base,batch[1]+SGPU_PAGE,4,false));
    m->ibs++;*reg(&m->base,block,off)=value;
    if (m->active && (m->injection==4 || m->injection==12)) return;
    for (unsigned i=0;i<4;i++) {
        assert(ib[i*4]==sgpu_packet7(0x3d,3) && !ib[i*4+2]);
        gpu_write(&m->base,ib[i*4+1],ib[i*4+3] ^ (m->active && m->injection==6 ? 1u:0u));
    }
    assert(ib[16]==sgpu_packet7(0x26,0));
    if (!(m->active && m->injection==5))
        gpu_write(&m->base,batch[7],batch[9]+(m->active && m->injection==10 ? 1u:0u));
    if (m->active && m->injection==7) gpu_write(&m->base,ib[1]+16,0);
    if (m->active && m->injection==3) *reg(&m->base,SG_SMMU,SG_CB_FSR)=2;
    if (m->active && m->injection==9) *reg(&m->base,block,off)=value+1;
    m->base.last=value;*reg(&m->base,SG_GPU,SG_RB_RPTR)=value;*reg(&m->base,SG_GPU,SG_STATUS)=0;
}
static void session_clean(void *ctx,const void *p,uint32_t n)
{
    struct session_model *m=ctx;m->accesses++;clean(&m->base,p,n);
    if(session_callback_check)session_callback_check();
    if (m->active && m->injection==11) m->base.us+=SGPU_SESSION_BUDGET_US+1;
}
static void session_invalidate(void *ctx,const void *p,uint32_t n)
{
    struct session_model *m=ctx;m->accesses++;
    if(session_callback_check)session_callback_check();
    if (!(m->active && m->injection==8)) invalidate(&m->base,p,n);
}
static void session_wait(void *ctx,uint32_t us)
{ struct session_model *m=ctx;if(session_callback_check)session_callback_check();if (!(m->active && m->injection==12)) mock_wait_us(&m->base,us); }
static uint64_t session_now(void *ctx)
{
    struct session_model *m=ctx;m->clocks++;
    if(session_callback_check)session_callback_check();
    if (m->active && m->injection==13 && m->clocks>4) return 0;
    return now(&m->base);
}
static bool boot_session(struct session_model *m,struct sgpu_report *out,unsigned option)
{
    uint8_t fw[64];firmware(fw);
    struct sgpu_ops io=ops(&m->base);
    io.ctx=m;io.trace=session_trace;io.read32=session_read;io.read64=session_read64;
    io.write32=session_write;io.clean=session_clean;io.invalidate=session_invalidate;
    io.wait_us=session_wait;io.now_us=session_now;
    io.stock_unsecure=io.stock_pixels=io.g3=1;io.session=option;
    bool ok=sgpu_session_start(&io,3,fw,sizeof(fw),out);
    memset(&io,0xcc,sizeof(io));memset(fw,0xdd,sizeof(fw));
    return ok; /* later requests must not reference io, fw or out */
}
static void clobber_stack(void)
{ volatile unsigned char buf[4096];for(unsigned i=0;i<sizeof(buf);i++)buf[i]=0x66; }

int main(int argc,char **argv)
{
    assert(argc==2);unsigned injection=(unsigned)strtoul(argv[1],NULL,10);
    const enum injection startup_bad[]={ALLOC_FAIL,BAD_PA,DUP_PA,MAP_FAIL,BAD_LAYOUT};
    struct session_model m={0};
    init(&m.base,injection>=20 && injection<25 ? startup_bad[injection-20] : SECURE_GPU);
    struct sgpu_report startup={0};
    if(injection>=100) {
        assert(!boot_session(&m,&startup,injection-100));
        assert(!m.base.allocs && !m.accesses);destroy(&m.base);return 0;
    }
    if(injection>=20 && injection<25) {
        assert(!boot_session(&m,&startup,1));
        struct sgpu_session_result failure={0};sgpu_session_failure_result(&failure);
        assert(failure.error && failure.phase==SG_SESSION_BOOT);
        unsigned before=m.accesses;assert(!boot_session(&m,&startup,1));assert(m.accesses==before);
        assert(!sgpu_session_prepare());destroy(&m.base);return 0;
    }
    assert(boot_session(&m,&startup,1));
    assert(startup.g3.passed && startup.g3.completed==2 && startup.g3.writes==8);
    assert(startup.pixels==256 && startup.memory_retained && !startup.restored && startup.power_pending==13);
    struct sgpu_report saved=startup;
    assert(!boot_session(&m,&startup,1));assert(!memcmp(&saved,&startup,sizeof(saved)));
    memset(&startup,0xcc,sizeof(startup));clobber_stack();
    m.active=true;m.injection=injection;m.clocks=0;
    if(injection==2) ((uint64_t *)(void *)(m.base.cpu+2*SGPU_PAGE))[257]=3;
    m.base.us=100000;
    if(injection>=30 && injection<=50) {
        const unsigned checks[][2]={{SG_GPU,SG_RB_RPTR},{SG_GPU,SG_RB_WPTR},{SG_GPU,SG_ME_CNTL},
            {SG_GPU,SG_INT_MASK},{SG_GPU,SG_RB_BASE},{SG_GPU,SG_RB_BASE_HI},{SG_GPU,SG_RB_CNTL},
            {SG_GPU,SG_PM4_BASE},{SG_GPU,SG_PM4_BASE+4},{SG_GPU,SG_PFP_BASE},{SG_GPU,SG_PFP_BASE+4},
            {SG_SMMU,SG_CB},{SG_SMMU,SG_S2CR0},{SG_SMMU,SG_GR1_CBA2R0},{SG_SMMU,SG_GR1_CBAR0},
            {SG_SMMU,SG_CB_TTBCR},{SG_SMMU,SG_CB_TTBCR2},{SG_SMMU,SG_CB_MAIR0},{SG_SMMU,SG_CB_MAIR0+4},
            {SG_SMMU,SG_CB_TTBR0},{SG_SMMU,SG_CB_TTBR0+4}};
        *reg(&m.base,(enum sgpu_block)checks[injection-30][0],checks[injection-30][1])^=1;
    }
    struct sgpu_session_queue q={0};assert(sgpu_session_queue_init(&q));
    unsigned max=injection==16?2:injection?1:32;
    for(unsigned n=0;n<max;n++) {
        if(injection==16)m.injection=n?4:0;
        uint32_t values[4]={n*4+1,n*4+2,n*4+3,n*4+4},id=0;
        assert(sgpu_session_enqueue(&q,1,1,values,&id)==SG_SESSION_OK && id==n+1);
        memset(values,0xab,sizeof(values)); /* immutable queue snapshot */
        struct sgpu_session_request request;assert(sgpu_session_take(&q,&request));
        struct sgpu_session_result result={0};
        bool prepared=sgpu_session_prepare();
        if(injection==1 || injection==2 || injection==13 || injection>=30) assert(!prepared);
        if(prepared) {
            if(injection==14) {
                unsigned before=m.accesses;
                assert(sgpu_session_close(&q,1)==SG_SESSION_OK);
                assert(!sgpu_session_commit(&q,id));sgpu_session_stop();
                assert(m.accesses==before && q.status.cancelled==1 && !q.status.committed);
                destroy(&m.base);return 0;
            }
            assert(sgpu_session_commit(&q,id));
            if(injection==15)assert(sgpu_session_close(&q,1)==SG_SESSION_OK);
            bool ok=sgpu_session_execute(request.value,&result);
            assert(ok==(injection==0 || injection==15 || (injection==16 && !n)));
        } else {
            assert(injection==1 || injection==2 || injection==13 || injection>=30);
            sgpu_session_failure_result(&result);
        }
        assert(sgpu_session_finish(&q,id,&result));
        if(!injection) assert(result.writes==4 && result.sequence==n+3 && result.wptr==181+11*n);
    }
    if(!injection) {
        assert(q.status.completed==32 && q.status.writes==128 && q.status.last_sequence==34 && q.status.wptr==522);
        assert(q.status.state==SG_SESSION_CLOSED && q.status.reason==SG_SESSION_QUOTA);
        uint32_t id=0,v[4]={0};assert(sgpu_session_enqueue(&q,1,1,v,&id)!=SG_SESSION_OK && !id);
    } else if(injection==15) {
        assert(q.status.state==SG_SESSION_CLOSED && q.status.reason==SG_SESSION_CLOSE && q.status.completed==1);
    } else {
        assert(q.status.state==SG_SESSION_FAULTED && q.status.failed==1 && q.status.error);
        if(injection==16)assert(q.status.completed==1 && q.status.first_failed_id==2 && q.status.wptr==181);
    }
    sgpu_session_stop();unsigned before=m.accesses;
    struct sgpu_session_result again={0};uint32_t v[4]={0};
    assert(!sgpu_session_prepare() && !sgpu_session_execute(v,&again));
    assert(m.accesses==before && !m.base.frees && m.base.reset_count==1);
    assert(m.accesses<20000);
    printf("PASS session case=%u completed=%u writes=%u callbacks=%u retained; no device\n",
        injection,q.status.completed,q.status.writes,m.accesses);
    destroy(&m.base);return 0;
}
