#include "santoni_gpu_pm4.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Header oracle is KGSL's nibble parity table, independent of the parser loop. */
static uint32_t parity(uint32_t v)
{return (0x9669u>>((v^(v>>4)^(v>>8)^(v>>12)^(v>>16)^(v>>20)^(v>>24)^(v>>28))&15))&1;}
static uint32_t packet7(uint32_t op,uint32_t n)
{return 0x70000000u|n|(parity(n)<<15)|(op<<16)|(parity(op)<<23);}
static uint32_t packet4(uint32_t reg,uint32_t n)
{return 0x40000000u|n|(parity(n)<<7)|(reg<<8)|(parity(reg)<<27);}
int main(int argc,char **argv)
{
    assert(argc==2);unsigned test=(unsigned)strtoul(argv[1],NULL,10);assert(test<46);
    uint32_t *a=calloc(1,SGPU_GRAPHICS_IB_BYTES),*b=calloc(1,SGPU_GRAPHICS_IB_BYTES);assert(a && b);
    struct sgpu_graphics_snapshot snapshots[2]={
        {SGPU_RENDER_VA+SGPU_PAGE,SGPU_RENDER_VA+0x400000,SGPU_PAGE,a},
        {SGPU_RENDER_VA+0x30000,SGPU_RENDER_VA+0x500000,SGPU_PAGE,b}};
    struct sgpu_graphics_range ranges[3]={
        {1,snapshots[0].source_va,SGPU_PAGE,SGPU_GRAPHICS_RO},
        {2,SGPU_RENDER_VA+0x20000,SGPU_PAGE,SGPU_GRAPHICS_RW},
        {3,snapshots[1].source_va,SGPU_PAGE,SGPU_GRAPHICS_RO}};
    struct sgpu_pm4_rule rules[3]={
        {.reg=0x2180,.allowed_bits=UINT32_MAX,.required_mask=UINT32_MAX,.required_value=0x86000000,.kind=SG_PM4_VALUE},
        {.reg=0x2108,.allowed_bits=UINT32_MAX,.alignment=4,.minimum_bytes=8,.kind=SG_PM4_READ64},
        {.reg=0x2111,.allowed_bits=UINT32_MAX,.alignment=4,.minimum_bytes=8,.kind=SG_PM4_WRITE64}};
    struct sgpu_pm4_policy policy={.rules=rules,.count=3};
    struct sgpu_graphics_command roots[SGPU_GRAPHICS_IBS]={{snapshots[0].gpu_va,16}};
    unsigned nroots=1,nranges=3;
    a[0]=packet7(0x3d,3);a[1]=ranges[1].gpu_va;a[2]=0;a[3]=0x31337;
    b[0]=packet7(0x10,0);
    bool success=true,already=false;
    if(test==1){a[0]=0xffffffff;success=false;}
    if(test==2){roots[0].bytes=12;success=false;}
    if(test==3){a[0]^=1u<<23;success=false;}
    if(test==4){a[0]|=1u<<24;success=false;}
    if(test>=5 && test<=9) {
        const unsigned ops[5]={0x66,0x5f,0x53,0x31,0x3c};
        a[0]=packet7(ops[test-5],3);success=false;
    }
    if(test==10){a[1]=ranges[0].gpu_va;success=false;}
    if(test==11){a[1]=snapshots[0].gpu_va;success=false;}
    if(test==12){a[1]=SGPU_RING_VA;success=false;}
    if(test==13){a[0]=packet7(0x3d,4);a[1]=ranges[1].gpu_va+ranges[1].bytes-4;a[4]=0;roots[0].bytes=20;success=false;}
    if(test==14){nranges=0;success=false;}
    if(test==15){ranges[2].gpu_va=ranges[1].gpu_va;success=false;}
    if(test>=16 && test<=18) {
        a[0]=packet4(test==16?0x2108:0x2111,2);a[1]=test==17?ranges[1].gpu_va:ranges[0].gpu_va;
        a[2]=0;roots[0].bytes=12;success=test!=18;
    }
    if(test>=19 && test<=24) {
        uint32_t reg=test==19?0x2181:0x2180;
        if(test>=22) {
            reg=test==22?SG_ME_CNTL/4:test==23?SG_VBIF_VERSION/4:SG_TRUST/4;
            rules[0].reg=reg;rules[0].required_mask=0;
        }
        a[0]=packet4(reg,1);a[1]=0x86000000+(test==21);roots[0].bytes=8;success=test==20;
    }
    if((test>=25 && test<=29) || test==34 || test==35) {
        a[0]=packet7(0x3f,3);a[1]=snapshots[1].source_va;a[2]=0;a[3]=1;
        if(test==25){a[1]=SGPU_RING_VA;success=false;}
        if(test==27){a[2]=1;success=false;}
        if(test==28){a[3]=SGPU_PAGE/4+1;success=false;}
        if(test==29){b[0]=packet7(0x3f,3);b[1]=snapshots[0].source_va;b[2]=0;b[3]=4;a[3]=4;success=false;}
        if(test==34)a[1]=snapshots[1].gpu_va;
        if(test==35){already=true;success=false;}
    }
    if(test>=30 && test<=33) {
        a[0]=packet7(0x43,3);a[1]=(2u<<24)|(1u<<16)|1u;a[2]=snapshots[1].source_va;a[3]=0;
        if(test==31){a[1]=1u<<18;a[2]=0;}
        if(test==32){a[1]|=1u<<20;success=false;}
        if(test==33){a[1]|=1u<<29;success=false;}
    }
    if(test==36) {
        for(unsigned i=0;i<8;i++) {
            a[i*4]=packet7(0x3f,3);a[i*4+1]=snapshots[0].source_va+(i+1)*16;
            a[i*4+2]=0;a[i*4+3]=i==7?1:4;
        }
        a[32]=packet7(0x10,0);success=false;
    }
    if(test==37) {
        snapshots[0].bytes=SGPU_GRAPHICS_IB_BYTES;ranges[0].bytes=SGPU_GRAPHICS_IB_BYTES;
        for(unsigned i=0;i<SGPU_PM4_NODES;i++) {
            a[i*4]=packet7(0x3f,3);a[i*4+1]=snapshots[1].source_va;a[i*4+2]=0;a[i*4+3]=1;
        }
        roots[0].bytes=SGPU_PM4_NODES*16;success=false;
    }
    if(test==38) {
        snapshots[0].bytes=SGPU_GRAPHICS_IB_BYTES;ranges[0].bytes=SGPU_GRAPHICS_IB_BYTES;
        for(unsigned i=0;i<SGPU_GRAPHICS_IB_BYTES/4;i++)a[i]=packet7(0x10,0);
        unsigned end=SGPU_GRAPHICS_IB_BYTES/4-4;
        a[end]=packet7(0x3f,3);a[end+1]=snapshots[1].source_va;a[end+2]=0;a[end+3]=1;
        nroots=SGPU_GRAPHICS_IBS;for(unsigned i=0;i<nroots;i++)roots[i]=(struct sgpu_graphics_command){snapshots[0].gpu_va,SGPU_GRAPHICS_IB_BYTES};
        success=false;
    }
    if(test==39){policy.draw=true;a[0]=packet7(0x38,4);a[1]=4|(2u<<6);a[2]=1;a[3]=3;a[4]=0;roots[0].bytes=20;}
    if(test==40) {
        a[0]=packet7(0x3f,3);a[1]=snapshots[0].source_va+28;a[2]=0;a[3]=1;
        a[4]=packet7(0x3d,3);a[5]=ranges[1].gpu_va;a[6]=0;a[7]=packet7(0x10,0);
        roots[0].bytes=32;success=false; /* non-cyclic overlapping code/data interval */
    }
    if(test==41){a[0]=packet7(0x38,4);a[1]=4|(2u<<6);a[2]=1;a[3]=3;a[4]=0;roots[0].bytes=20;success=false;}
    if(test==42 || test==43) {
        rules[1].shift=test==42?4:12;rules[1].alignment=16;
        a[0]=packet4(0x2108,2);a[1]=test==42?ranges[0].gpu_va>>4:0xf0000000;a[2]=0;roots[0].bytes=12;
        success=test==42;
    }
    if(test==44){ranges[2].handle=ranges[1].handle;success=false;}
    if(test==45) {
        for(unsigned i=0;i<7;i++) {
            a[i*4]=packet7(0x3f,3);a[i*4+1]=snapshots[0].source_va+(i+1)*16;
            a[i*4+2]=0;a[i*4+3]=i==6?1:4;
        }
        a[28]=packet7(0x10,0);
    }
    bool result=already?sgpu_pm4_validate(&policy,snapshots,2,roots,nroots,ranges,nranges):
        sgpu_pm4_prepare(&policy,snapshots,2,roots,nroots,ranges,nranges);
    assert(result==success);
    if(success) {
        if(test==26 || test==34)assert(a[1]==snapshots[1].gpu_va);
        if(test==30)assert(a[2]==snapshots[1].gpu_va);
        uint32_t *saved=malloc(SGPU_GRAPHICS_IB_BYTES);assert(saved);memcpy(saved,a,SGPU_GRAPHICS_IB_BYTES);
        assert(sgpu_pm4_validate(&policy,snapshots,2,roots,nroots,ranges,nranges));
        assert(!memcmp(saved,a,SGPU_GRAPHICS_IB_BYTES));free(saved);
    }
    printf("PASS PM4 case=%u expected=%u; private commands only, no hardware\n",test,success);
    free(a);free(b);return 0;
}
