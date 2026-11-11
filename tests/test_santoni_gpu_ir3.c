/* Actual capture bytes plus isolated malformed encodings/metadata. GPU, PA
 * and runtime responses are not modeled here; this never runs a GPU. */
#include "santoni_gpu_ir3.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "santoni_gpu_ir3_captured.h"
static void put(uint32_t *words,unsigned at,uint64_t value)
{words[at*2]=(uint32_t)value;words[at*2+1]=(uint32_t)(value>>32);}
static uint64_t mul(unsigned dst,unsigned a,unsigned b,unsigned repeat,unsigned flags)
{return UINT64_C(0x4070000000000000)|((uint64_t)dst<<32)|a|((uint64_t)b<<16)|((uint64_t)repeat<<40)|flags;}
static uint64_t mad(unsigned dst,unsigned a,unsigned b,unsigned c,unsigned repeat)
{return UINT64_C(0x6380000000000000)|((uint64_t)dst<<32)|a|((uint64_t)b<<47)|((uint64_t)c<<16)|((uint64_t)repeat<<40);}
static void only(uint32_t *words,uint64_t value)
{memset(words,0,16384);put(words,0,value);put(words,1,UINT64_C(0x0300000000000000));}
static void high_inputs(struct sgpu_ir3_limits *l,unsigned first,unsigned count)
{for(unsigned s=first;s<first+count;s++)l->inputs[s/64]|=UINT64_C(1)<<(s%64);}
int main(int argc,char **argv)
{
    assert(argc==4);unsigned test=(unsigned)strtoul(argv[1],NULL,10),kind=(unsigned)strtoul(argv[3],NULL,10);
    assert(test<86 && kind<5 && (!test || kind==4));
    uint32_t code[4096]={0},before[4096];
    memcpy(code,captured_ir3_shaders[kind],128);
    struct sgpu_ir3_limits limits={.constant_scalars=20,.samplers=1,.textures=1,.varying_scalars=2,.inputs={3,0,0,0}};
    struct sgpu_ir3_result result,original;memset(&result,0xa5,sizeof(result));original=result;
    uint32_t available=128;bool good=test==0 || test==36 || test==46 || test==47 || test==48 || test==51 || test==52 ||
        test==59 || test==61 || test==64 || test==67 || test==72 || test==75 || test==77 || test==79 || test==80;
    const uint32_t *words=code;struct sgpu_ir3_limits *l=&limits;struct sgpu_ir3_result *r=&result;
    switch(test) {
    case 0:break;
    case 1:code[9]&=~0x10000000u;break;
    case 2:code[9]&=~0x10000000u;code[11]|=0x10000000u;break;
    case 3:code[3]&=~0x8000u;break;
    case 4:code[1]|=0x8000u;break;
    case 5:limits.varying_scalars=1;break;
    case 6:limits.varying_scalars=0;break;
    case 7:limits.varying_scalars=129;break;
    case 8:limits.inputs[0]=1;break;
    case 9:code[0]|=0x400u;break;
    case 10:code[2]=0x2002u;break;
    case 11:code[0]=0x2800u;break;
    case 12:code[0]=0x1000u;break;
    case 13:code[0]|=0x01000000u;break;
    case 14:code[1]|=0x100u;break;
    case 15:code[1]=(code[1]&~255u)|244u;break;
    case 16:code[0]=(code[0]&65535u)|(243u<<16);high_inputs(l,243,1);break;
    case 17:code[3]|=0x800u;break;
    case 18:code[5]=0x00000400u;break;
    case 19:code[9]=(code[9]&~255u)|242u;break;
    case 20:code[8]=(code[8]&~255u)|242u;high_inputs(l,242,2);break;
    case 21:code[8]=(code[8]&65535u)|(0x2c01u<<16);break;
    case 22:code[8]=(code[8]&65535u)|(0x2802u<<16);break;
    case 23:code[8]=(code[8]&65535u)|(0x6801u<<16);break;
    case 24:code[9]|=0x80000u;break;
    case 25:code[9]&=~0x300u;break;
    case 26:code[9]|=0x4000u;break;
    case 27:code[7]&=~0xf00u;break;
    case 28:code[7]=(code[7]&~255u)|242u;break;
    case 29:code[12]=1;break;
    case 30:code[10]=code[11]=0;break;
    case 31:available=127;break;
    case 32:words=(const uint32_t *)((const uint8_t *)code+1);break;
    case 33:words=NULL;break;
    case 34:l=NULL;break;
    case 35:r=NULL;break;
    case 36:put(code,4,UINT64_C(0x1300000000000000));code[10]=code[11]=0;break;
    case 37:code[9]=(code[9]&~255u)|4u;code[9]&=~0x10000000u;break;
    case 38:code[9]=(code[9]&~255u)|6u;code[9]&=~0x10000000u;break;
    case 39:code[9]=(code[9]&~255u)|4u;code[8]=0x28010000u;code[9]&=~0x10000b00u;break;
    case 40:only(code,mad(242,0x1004,0,0x1004,3));break;
    case 41:only(code,mad(8,0x17ff,0,0x1004,3)|(UINT64_C(1)<<43));limits.constant_scalars=2048;break;
    case 42:only(code,mad(8,0x1004,0,0x17ff,3)|(UINT64_C(1)<<29));limits.constant_scalars=2048;break;
    case 43:only(code,mad(8,0x1004,242,0x1004,3)|(UINT64_C(1)<<15));high_inputs(l,242,2);break;
    case 44:only(code,mad(8,242,0,0x1004,3)|(UINT64_C(1)<<43));high_inputs(l,242,2);break;
    case 45:only(code,mad(8,0x1004,0,242,3)|(UINT64_C(1)<<29));high_inputs(l,242,2);break;
    case 46:only(code,mad(8,0x17fc,0,0x17fc,3)|(UINT64_C(1)<<43)|(UINT64_C(1)<<29));limits.constant_scalars=2048;break;
    case 47:only(code,mad(8,0x17fc,240,0x17fc,3)|(UINT64_C(1)<<43)|(UINT64_C(1)<<29)|(UINT64_C(1)<<15));limits.constant_scalars=2048;high_inputs(l,240,4);break;
    case 48:only(code,mul(240,0,0x2801,3,0));break;
    case 49:only(code,mul(241,0,0x2801,3,0));break;
    case 50:only(code,mul(8,0x17ff,0x2801,3,0)|(UINT64_C(1)<<43));limits.constant_scalars=2048;break;
    case 51:only(code,mul(8,0x17fc,0x2801,3,0)|(UINT64_C(1)<<43));limits.constant_scalars=2048;break;
    case 52:only(code,mul(8,240,0x2801,3,0)|(UINT64_C(1)<<43));high_inputs(l,240,4);break;
    case 53:only(code,mul(8,241,0x2801,3,0)|(UINT64_C(1)<<43));high_inputs(l,241,3);break;
    case 54:only(code,mul(8,4,0x2801,3,0)|(UINT64_C(1)<<43));high_inputs(l,4,1);break;
    case 55:only(code,mad(8,0x1004,0,0x1004,3)^(UINT64_C(1)<<55));break;
    case 56:only(code,mad(8,0x1004,0,0x1004,0)|(UINT64_C(1)<<15));break;
    case 57:only(code,mad(8,0x800,0,0x1004,1));break;
    case 58:only(code,mad(8,0x1004,0,0x1800,1));break;
    case 59:code[0]=0x207eu;code[2]=0x207fu;limits.varying_scalars=128;break;
    case 60:code[2]=0x2080u;limits.varying_scalars=128;break;
    case 61:code[0]|=240u<<16;code[2]|=240u<<16;high_inputs(l,240,2);break;
    case 62:code[0]|=240u<<16;code[2]|=240u<<16;high_inputs(l,240,1);break;
    case 63:code[1]&=~0x100000u;break;
    case 64:memset(code,0,sizeof(code));code[2047]=0x03000000u;available=8192;break;
    case 65:memset(code,0,sizeof(code));code[2049]=0x03000000u;available=8208;break;
    case 66:put(code,4,UINT64_C(0x204cc00400000000));put(code,5,UINT64_C(0x1300000000000000));break;
    case 67:put(code,4,mul(4,0,0x2801,0,0)|(UINT64_C(1)<<60));break;
    case 68:put(code,4,UINT64_C(0xa0c01f0400000005));put(code,5,UINT64_C(0x1300000000000000));break;
    case 69:put(code,4,UINT64_C(0x0000070000000000));put(code,5,UINT64_C(0xa0c01f1000000009));put(code,6,UINT64_C(0x1300000000000000));break;
    case 70:put(code,4,UINT64_C(0xa0c01f1000000005));break;
    case 71:put(code,5,UINT64_C(0xa0c01f1000000005));put(code,6,UINT64_C(0x0300000000000000));break;
    case 72:only(code,mul(8,0,0x2801,3,0));break;
    case 73:only(code,mul(8,240,0x2801,3,0)|(UINT64_C(1)<<43));high_inputs(l,240,3);break;
    case 74:only(code,mul(1,0,0x2801,3,0)|(UINT64_C(1)<<43));high_inputs(l,2,2);break;
    case 75:only(code,mul(8,0,0x2801,3,0));limits.constant_scalars=0;break;
    case 76:only(code,mul(8,0x100,0x2801,3,0));break;
    case 77:memset(code,0,sizeof(code));put(code,0,UINT64_C(0x0300000000000000));high_inputs(l,243,1);break;
    case 78:put(code,4,UINT64_C(0x204cc00200000000));put(code,5,UINT64_C(0x1300000000000000));break;
    case 79:put(code,4,mul(2,0,0x2801,0,0)|(UINT64_C(1)<<60));break;
    case 80:put(code,4,UINT64_C(0xa0c01f1000000005));put(code,5,UINT64_C(0x1300000000000000));break;
    case 81:code[0]|=0x10000000u;break;
    case 82:code[5]=0x00000300u;break;
    case 83:only(code,mad(8,0,0,0x1004,3)|(UINT64_C(1)<<43));break;
    case 84:put(code,3,UINT64_C(0xa0c01f0200000005));put(code,4,UINT64_C(0x1300000000000000));code[10]=code[11]=0;break;
    case 85:put(code,4,UINT64_C(0x0000070000000000));put(code,5,UINT64_C(0x204cc00200000000));put(code,6,UINT64_C(0x1300000000000000));break;
    }
    memcpy(before,code,sizeof(code));struct sgpu_ir3_limits saved=limits;
    bool accepted=sgpu_ir3_subset(words,available,l,r);
    if(accepted!=good)fprintf(stderr,"case%u: accepted=%u expected=%u\n",test,accepted,good);
    assert(accepted==good);
    assert(!memcmp(code,before,sizeof(code)) && !memcmp(&limits,&saved,sizeof(limits)));
    if(!good)assert(!memcmp(&result,&original,sizeof(result)));
    else {
        assert(result.extent==(test==64?8192u:128u));
        if(!test) {
            const unsigned instructions[]={3,5,13,4,6},steps[]={3,5,21,5,14},registers[]={1,1,3,2,3};
            assert(result.instructions==instructions[kind] && result.steps==steps[kind] && result.registers==registers[kind]);
            assert(result.samples==(kind==2 || kind==4?1u:0u));
            assert(result.synchronizations==(kind==2 || kind==4?1u:0u));
            assert(result.input_reads[0]==(kind==2 || kind==3 || kind==4?3u:0u));
            assert(result.bary_instructions==(kind==4?2u:0u) && result.input_released==(kind==4));
            assert(result.varying_reads[0]==(kind==4?3u:0u) && !result.varying_reads[1]);
            assert(result.bary_inputs[0]==(kind==4?3u:0u));
            const uint64_t constant_reads[]={0,0,0x70003,16,0};
            assert(result.constant_reads[0]==constant_reads[kind]);
            for(unsigned i=1;i<32;i++)assert(!result.constant_reads[i]);
            if(kind==3)assert(result.written[0]==60u && result.defined[0]==63u && result.constant_scalars==5);
            if(kind==4)assert(result.written[0]==4092u && result.defined[0]==4095u && !result.constant_scalars);
        }
        if(test==46 || test==47 || test==51)assert(result.constant_scalars==2048 && result.steps==5 && result.constant_reads[31]==(UINT64_C(15)<<60));
        if(test==47 || test==48 || test==52)assert(result.registers==61);
        if(test==59)assert(result.varying_reads[1]==(UINT64_C(3)<<62));
        if(test==61)assert(result.bary_inputs[3]==(UINT64_C(3)<<48));
        if(test==72 || test==75)assert(result.input_reads[0]==1 && result.written[0]==0xf00u);
    }
    puts("PASS bounded actual IR3 v4; GPU/hardware/production admission absent");return 0;
}
