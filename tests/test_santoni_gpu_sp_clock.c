/* Captured-readback and vendor-RMW oracles. These test the actual patched core,
 * not physical HWCG-policy acceptance or recovery of the iOS boot/UI. */
#define main sgpu_existing_model_main
#include "test_santoni_gpu_mock.c"
#undef main

struct sp_model {
    struct model base;
    uint32_t observed_top, corrupt;
    unsigned policy_writes, release_writes;
};

static void sp_write(void *ctx,enum sgpu_block block,uint32_t off,uint32_t value)
{
    struct sp_model *m=ctx;
    if (block==SG_GPU && off==SG_CLOCK_CNTL && m->base.resume_step==3) {
        uint32_t old=*reg(&m->base,block,off);
        assert(value==(old&~0xffu)); /* exact vendor release: preserve every upper bit */
        m->release_writes++;
        write32(&m->base,block,off,value);
        if (m->corrupt) *reg(&m->base,block,off)^=m->corrupt;
        return;
    }
    write32(&m->base,block,off,value);
    if (block==SG_GPU && off==SG_CLOCK_CNTL && value==0xaaa8aa00u) {
        m->policy_writes++;
        *reg(&m->base,block,off)=m->observed_top;
    }
}

int main(void)
{
    uint8_t fw[64]; firmware(fw);
    struct sgpu_report r;
#ifdef EXPECT_LEGACY_SP_FAILURE
    struct sp_model m={.observed_top=0xaaa82a00u}; init(&m.base,NONE);
    struct sgpu_ops io=ops(&m.base); io.ctx=&m; io.write32=sp_write;
    assert(!sgpu_probe(&io,2,fw,sizeof(fw),&r));
    assert(r.stage==SG_TRANSLATION && r.error==SG_FAULT && r.failure.kind==SG_FAIL_READBACK);
    assert(r.failure.offset==SG_CLOCK_CNTL && r.failure.mask==~0u && r.failure.want==0xaaa8aa00u);
    assert(r.failure.old==0x55 && r.failure.written==0xaaa8aa00u && r.failure.got==0xaaa82a00u);
    assert(!r.failure.elapsed_us && !r.failure.budget_us && r.failure.saved_count==13);
    assert(r.restored && !r.memory_retained && !r.power_pending && !m.base.packets);
    destroy(&m.base);
    puts("PASS captured 545038a TOP echo failure oracle (not a physical reproduction)");
#else
    unsigned cases=0;
    const uint32_t readings[]={0xaaa8aa00u,0xaaa82a00u,0x135724ffu,0xfedcba55u};
    for (unsigned i=0;i<sizeof(readings)/sizeof(readings[0]);i++) {
        struct sp_model m={.observed_top=readings[i]}; init(&m.base,NONE);
        struct sgpu_ops io=ops(&m.base); io.ctx=&m; io.write32=sp_write;
        assert(sgpu_probe(&io,2,fw,sizeof(fw),&r));
        assert(m.policy_writes==2 && m.release_writes==2);
        assert(m.base.regs[SG_GPU][SG_CLOCK_CNTL/4]==(readings[i]&~0xffu));
        assert(r.markers==16 && !r.pixels && !r.trust_read && r.restored && r.memory_retained);
        destroy(&m.base); cases++;
    }
    /* Both low-byte denial and ANY upper-bit corruption of final RMW must fail.
     * In particular bit15 remains checked in final preservation, not ignored. */
    for (unsigned bit=0;bit<32;bit++) {
        struct sp_model m={.observed_top=0xaaa82a00u,.corrupt=1u<<bit}; init(&m.base,NONE);
        struct sgpu_ops io=ops(&m.base); io.ctx=&m; io.write32=sp_write;
        assert(!sgpu_probe(&io,2,fw,sizeof(fw),&r));
        assert(m.policy_writes==1 && m.release_writes==1 && !m.base.packets && !m.base.reset_count);
        assert(r.error==SG_FAULT && r.failure.offset==SG_CLOCK_CNTL && r.failure.mask==~0u);
        assert(r.failure.old==0xaaa82a00u && r.failure.written==0xaaa82a00u && r.failure.want==0xaaa82a00u);
        assert(r.failure.got==(0xaaa82a00u^(1u<<bit)) && !r.restored && !r.memory_retained);
        assert(!r.gpu_quiescent && r.power_pending==13 && m.base.frees==1);
        destroy(&m.base); cases++;
    }
    printf("PASS %u SP clock scenarios; captured readback, exact RMW and all 32 final-echo bits\n",cases);
#endif
    return 0;
}
