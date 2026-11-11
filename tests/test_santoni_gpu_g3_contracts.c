/* Actual private G3 bookkeeping/validator, no MMIO or mock policy copy. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "santoni_gpu_core.c"

static _Alignas(SGPU_PAGE) uint8_t pool[SGPU_POOL_BYTES];
static struct sgpu_memory memory;
static struct sgpu_g3 arena;
static unsigned cases;
static uint32_t ib,data,fence;
static void init_contract(void)
{
    memory.va=pool;
    for(unsigned i=0;i<SGPU_POOL_PAGES;i++) memory.pa[i]=SGPU_DMA_MIN+i*8192;
    uint8_t fw[16]={0};struct sgpu_firmware f={.pm4=fw,.pfp=fw,.pm4_bytes=16,.pfp_bytes=16};
    assert(sgpu_tables_build(&memory,&f));assert(sgpu_g3_init(&arena,&memory,9));
}
static uint32_t *commands(void)
{ return (uint32_t *)(void *)(pool+sgpu_g3_lookup(&arena,1,ib)->physical[0]*SGPU_PAGE); }
static void setup(void)
{
    init_contract();
    ib=sgpu_g3_new(&arena,1,128,SG_G3_IB);data=sgpu_g3_new(&arena,1,16,SG_G3_DATA);
    fence=sgpu_g3_new(&arena,1,64,SG_G3_FENCE);assert(ib&&data&&fence);
    uint32_t *p=commands();p[0]=sgpu_packet7(0x3d,3);p[1]=sgpu_g3_va(sgpu_g3_lookup(&arena,1,data));
    p[2]=0;p[3]=0xabc;p[4]=sgpu_packet7(0x26,0);arena.sealed=true;
}
int main(void)
{
    uint32_t batch[SG_G3_BATCH_WORDS];
    for(unsigned bad=0;bad<25;bad++) {
        setup();uint32_t owner=1,ih=ib,dh=data,fh=fence,words=5;uint32_t *p=commands();
        switch(bad) {
        case 0: owner=0;break;case 1: owner=2;break;case 2: ih=0;break;
        case 3: dh=ib;break;case 4: fh=data;break;case 5: words=0;break;
        case 6: words=65;break;case 7: words=3;break;
        case 8: p[0]^=0x8000;break;case 9: p[0]=sgpu_packet7(0x3f,3);break;
        case 10: p[1]++;break;case 11: p[1]+=16;break;case 12: p[2]=1;break;
        case 13: p[1]=sgpu_g3_va(sgpu_g3_lookup(&arena,1,fence));break;
        case 14: p[0]=sgpu_packet7(0x26,0);words=1;break;
        case 15: arena.failed=true;break;case 16: arena.busy=1;break;
        case 17: arena.submitted=UINT32_MAX;break;case 18: arena.sealed=false;break;
        case 19: arena.bo[1].owner=2;break;case 20: arena.bo[0].retired=true;break;
        case 21: ((uint64_t *)(void *)(pool+2*SGPU_PAGE))[arena.bo[0].first+1]=3;break;
        case 22: ((uint64_t *)(void *)(pool+2*SGPU_PAGE))[arena.bo[0].first]^=128;break;
        case 23: memory.pa[arena.bo[1].physical[0]]=0;break;
        case 24: arena.bo[1].quarantine=true;break;
        }
        struct sgpu_g3 before=arena;memset(batch,0xa5,sizeof(batch));uint32_t copy[SG_G3_BATCH_WORDS];memcpy(copy,batch,sizeof(copy));
        assert(!sgpu_g3_begin(&arena,owner,ih,dh,fh,words,batch));
        assert(!memcmp(&arena,&before,sizeof(arena)) && !memcmp(batch,copy,sizeof(batch)));cases++;
    }
    setup();
    assert(sgpu_g3_begin(&arena,1,ib,data,fence,5,batch));
    assert(arena.busy==1 && arena.submitted==1 && !arena.completed);
    for(unsigned i=0;i<3;i++) assert(arena.bo[i].last_seq==1);
    assert(batch[0]==sgpu_packet7(0x3f,3) && batch[9]==1);
    assert(!sgpu_g3_complete(&arena,2,fence,1));assert(!sgpu_g3_complete(&arena,1,data,1));
    assert(!sgpu_g3_complete(&arena,1,fence,0));assert(!sgpu_g3_complete(&arena,1,fence,2));
    assert(sgpu_g3_complete(&arena,1,fence,1));assert(!sgpu_g3_complete(&arena,1,fence,1));
    assert(sgpu_g3_begin(&arena,1,ib,data,fence,5,batch));assert(batch[9]==2);
    assert(!sgpu_g3_complete(&arena,1,fence,1));assert(sgpu_g3_complete(&arena,1,fence,2));cases++;
    for(unsigned pending=0;pending<2;pending++) {
        setup();assert(sgpu_g3_begin(&arena,1,ib,data,fence,5,batch));
        if(!pending) assert(sgpu_g3_complete(&arena,1,fence,1));
        uint8_t saved[SGPU_POOL_BYTES];memcpy(saved,pool,sizeof(saved));
        assert(!sgpu_g3_free(&arena,2,data));assert(!sgpu_g3_free(&arena,1,data));
        assert(arena.bo[1].retired && arena.bo[1].quarantine && !sgpu_g3_lookup(&arena,1,data));
        assert(arena.failed==(bool)pending && !memcmp(saved,pool,sizeof(saved)));
        assert(!sgpu_g3_new(&arena,1,4,SG_G3_DATA));cases++;
    }
    setup();assert(sgpu_g3_begin(&arena,1,ib,data,fence,5,batch));
    uint8_t saved[SGPU_POOL_BYTES];memcpy(saved,pool,sizeof(saved));sgpu_g3_abort(&arena);
    assert(arena.failed && arena.busy==1 && !memcmp(saved,pool,sizeof(saved)));
    for(unsigned i=0;i<3;i++) assert(arena.bo[i].quarantine);
    assert(!sgpu_g3_complete(&arena,1,fence,1));cases++;
    init_contract();uint32_t first=sgpu_g3_new(&arena,1,SGPU_PAGE+1,SG_G3_DATA);
    assert(first && arena.bo[0].pages==2 && sgpu_g3_mapping(&arena,&arena.bo[0]));
    assert(!sgpu_g3_free(&arena,2,first));assert(sgpu_g3_free(&arena,1,first));
    uint32_t next=sgpu_g3_new(&arena,1,SGPU_PAGE+1,SG_G3_DATA);
    assert(next!=first && !sgpu_g3_lookup(&arena,1,first));cases++;
    for(unsigned i=0;i<5;i++) assert(sgpu_g3_new(&arena,2,4,SG_G3_DATA));
    struct sgpu_g3 before=arena;assert(!sgpu_g3_new(&arena,2,4,SG_G3_DATA));
    assert(!memcmp(&arena,&before,sizeof(before)));cases++;
    init_contract();assert(!sgpu_g3_new(&arena,0,4,SG_G3_DATA));
    assert(!sgpu_g3_new(&arena,1,0,SG_G3_DATA));assert(!sgpu_g3_new(&arena,1,UINT32_MAX,SG_G3_DATA));
    assert(!sgpu_g3_new(&arena,1,4,0));assert(!sgpu_g3_new(&arena,1,4,4));
    assert(!sgpu_g3_new(&arena,1,SGPU_POOL_BYTES,SG_G3_DATA));
    arena.next_handle=UINT32_MAX;assert(!sgpu_g3_new(&arena,1,4,SG_G3_DATA));cases++;
    init_contract();((uint64_t *)(void *)(pool+2*SGPU_PAGE))[256]=3;
    assert(!sgpu_g3_init(&arena,&memory,9));cases++;
    init_contract();((uint64_t *)(void *)(pool+2*SGPU_PAGE))[1]=memory.pa[9]|PTE_RO;
    assert(!sgpu_g3_init(&arena,&memory,9));cases++;
    printf("PASS G3 contracts: %u groups; owned guards, exact IB whitelist, immutable rejects, sequence and quarantine\n",cases);
}
