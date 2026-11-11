/* Actual production packager + actual default-refusing kernel PM4 on real Mesa
 * captured commands. Memory/transport are host models; no GPU runs. */
#define _POSIX_C_SOURCE 200112L
#include "commands.h"
#include "santoni_gpu_pm4.h"
#include "santoni_gpu_raster.h"
#include "santoni_gpu_raster_batch.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "santoni_gpu_raster_captured.h"
struct buffer {uint32_t original,handle,va,bytes,span,flags;uint8_t *cpu,*saved;};
struct model {struct buffer bo[64];bool used[2048];unsigned seed_count,next,seed,submits,frees;};
static struct buffer *find(struct model *m,uint32_t h)
{for(unsigned i=0;i<m->next;i++)if(m->bo[i].handle==h)return &m->bo[i];return NULL;}
static void allocate(struct buffer *b)
{b->span=(b->bytes+4095)&~4095u;assert(!posix_memalign((void **)&b->cpu,4096,b->span));memset(b->cpu,0,b->span);}
static unsigned mutation;
static void damage(struct sgpu_graphics_snapshot *,unsigned,const struct sgpu_graphics_range *,unsigned,struct sgpu_graphics_command *,unsigned);
static bool call(void *context,uint32_t selector,const uint64_t *in,uint32_t ni,uint64_t *out,uint32_t no,
    const void *wire,size_t size)
{
    struct model *m=context;
    if(selector==SG_GFX_INFO) {uint64_t info[10]={1,4096,0x05000500,139264,SGPU_RENDER_VA,0x800000,0x7fe000,65536,0,0};
        assert(!ni && no==10);memcpy(out,info,sizeof(info));return true;}
    if(selector==SG_GFX_NEW) {
        assert(ni==2 && no==4 && m->next<64);struct buffer *b=&m->bo[m->next];
        if(m->seed<m->seed_count) {assert(b->bytes==in[0] && b->flags==in[1]);m->seed++;}
        else {
            b->bytes=(uint32_t)in[0];b->flags=(uint32_t)in[1];allocate(b);
            unsigned count=b->span/4096,first=1;
            for(;first+count<2048;first++) {unsigned i=0;while(i<=count && !m->used[first+i])i++;if(i>count)break;}
            assert(first+count<2048);for(unsigned i=0;i<=count;i++)m->used[first+i]=true;
            b->va=SGPU_RENDER_VA+first*4096;
        }
        b->handle=++m->next;out[0]=out[3]=b->handle;out[1]=b->va;out[2]=b->bytes;return true;
    }
    if(selector==SG_GFX_SUBMIT) {
        assert(!ni && no==1 && size==sizeof(struct sgpu_graphics_wire_submit));m->submits++;
        const struct sgpu_graphics_wire_submit *s=wire;
        assert(s->version==1 && s->ibs<=8 && s->handles<=56 && !s->reserved);
        struct sgpu_graphics_snapshot snapshots[8]={0};struct sgpu_graphics_command roots[8]={0};
        struct sgpu_graphics_range ranges[56]={0};unsigned ns=0;
        for(unsigned i=0;i<s->handles;i++) {struct buffer *b=find(m,s->handle[i]);assert(b);ranges[i]=(struct sgpu_graphics_range){b->handle,b->va,b->bytes,b->flags};}
        for(unsigned i=0;i<s->ibs;i++) {
            struct buffer *b=find(m,s->ib[i].handle);assert(b && b->handle>m->seed_count && b->flags==SGFX_READ);
            unsigned j=0;for(;j<ns;j++)if(snapshots[j].source_va==b->va)break;
            if(j==ns) {
                uint32_t *copy=malloc(b->bytes);assert(copy);memcpy(copy,b->cpu,b->bytes);
                /* Fresh modeled private spans, not a fixed +4MiB address
                 * which could overlap a full-screen owner target. */
                unsigned count=(b->bytes+4095)/4096,first=1;
                for(;first+count<2048;first++) {unsigned k=0;while(k<=count && !m->used[first+k])k++;if(k>count)break;}
                assert(first+count<2048);for(unsigned k=0;k<=count;k++)m->used[first+k]=true;
                snapshots[ns]=(struct sgpu_graphics_snapshot){b->va,SGPU_RENDER_VA+first*4096,b->bytes,copy};ns++;
            }
            roots[i]=(struct sgpu_graphics_command){snapshots[j].gpu_va+s->ib[i].offset,s->ib[i].bytes};
        }
        struct sgpu_raster_context *context=calloc(1,sizeof(*context));assert(context);
        bool accepted=sgpu_raster_prepare_batch(context,SGPU_GRAPHICS_VM_LEGACY,snapshots,ns,roots,s->ibs,ranges,s->handles);
        if(!accepted)fprintf(stderr,"draft raster prepare refused error=%u draws=%u clears=%u target=%ux%u stage0=%u/%u stage1=%u/%u\n",
            context->error,context->draws,context->clears,context->width,context->height,
            context->stage[0].object_ready,context->stage[0].load_ready,context->stage[1].object_ready,context->stage[1].load_ready);
        assert(accepted);
        uint32_t *saved[8];for(unsigned i=0;i<ns;i++) {saved[i]=malloc(snapshots[i].bytes);assert(saved[i]);memcpy(saved[i],snapshots[i].words,snapshots[i].bytes);}
        damage(snapshots,ns,ranges,s->handles,roots,s->ibs);
        bool verified=sgpu_raster_validate_batch(context,SGPU_GRAPHICS_VM_LEGACY,snapshots,ns,roots,s->ibs,ranges,s->handles);
        if(verified!=(mutation==0))fprintf(stderr,"bad quad result case=%u valid=%u error=%u\n",mutation,verified,context->error);
        assert(verified==(mutation==0));
        for(unsigned i=0;i<ns;i++) {if(!mutation)assert(!memcmp(saved[i],snapshots[i].words,snapshots[i].bytes));free(saved[i]);}
        printf("restricted draft approved immutable commands: draws=%u clears=%u target=%ux%u pitch=%u; GPU_execution=0 hardware_verified=0\n",
            context->draws,context->clears,context->width,context->height,context->pitch);
        free(context);
        for(unsigned i=0;i<ns;i++)free(snapshots[i].words);
        return false;
    }
    assert(selector==SG_GFX_FREE || selector==SG_GFX_CPU_PREP);
    if(selector==SG_GFX_FREE)m->frees++;
    assert(ni==1 && !no);return true;
}
static bool map(void *context,uint32_t handle,uint8_t **cpu,uint64_t *bytes)
{struct buffer *b=find(context,handle);assert(b);*cpu=b->cpu;*bytes=b->span;return true;}
static void unmap(void *context,uint32_t handle,uint8_t *cpu)
{struct buffer *b=find(context,handle);assert(b && b->cpu==cpu);}
static void close_model(void *context) {(void)context;}

static uint32_t h7(uint32_t op,uint32_t n) {
    return 0x70000000u|n|((1u^(unsigned)__builtin_parity(n))<<15)|(op<<16)|((1u^(unsigned)__builtin_parity(op))<<23);
}
static uint32_t *register_word(struct sgpu_graphics_snapshot *s,unsigned ns,uint32_t wanted) {
    for(unsigned j=0;j<ns;j++)for(unsigned i=0;i<s[j].bytes/4;i++) {
        uint32_t h=s[j].words[i],n=h&127,reg=(h>>8)&0x3ffff;
        if((h>>28)==4 && n && n<=s[j].bytes/4-i-1 && wanted>=reg && wanted-reg<n)return &s[j].words[i+1+wanted-reg];
    }
    assert(false);return NULL;
}
static uint32_t *shader_words(struct sgpu_graphics_snapshot *s,unsigned ns,uint32_t reg) {
    uint32_t va=*register_word(s,ns,reg);
    for(unsigned j=0;j<ns;j++)if(va>=s[j].gpu_va && va-s[j].gpu_va<=s[j].bytes && 128<=s[j].bytes-(va-s[j].gpu_va))
        return &s[j].words[(va-s[j].gpu_va)/4];
    assert(false);return NULL;
}
static uint32_t *state_packet(struct sgpu_graphics_snapshot *s,unsigned ns,unsigned block,unsigned type,unsigned dst) {
    for(unsigned j=0;j<ns;j++)for(unsigned i=0;i+3<s[j].bytes/4;i++) {
        uint32_t h=s[j].words[i],p=s[j].words[i+1];
        if((h>>28)==7 && ((h>>16)&127)==0x30 && ((p>>18)&15)==block &&
            (s[j].words[i+2]&3)==type && (p&0x3fff)==dst)return &s[j].words[i];
    }
    assert(false);return NULL;
}
static void damage(struct sgpu_graphics_snapshot *s,unsigned ns,const struct sgpu_graphics_range *ranges,unsigned nr,
    struct sgpu_graphics_command *roots,unsigned ni) {
    uint32_t *p;
    switch(mutation) {
    case 0:return;
    case 1:*register_word(s,ns,0xe294)=0xffffffffu;break;
    case 2:*register_word(s,ns,0xe593)=0xf00;break;
    case 3:*register_word(s,ns,0xe5a3)=0;break;
    case 4:*register_word(s,ns,0xe592)=1;break;
    case 5:*register_word(s,ns,0xe280)=0x10004;break;
    case 6:*register_word(s,ns,0xe787)=0xfcfcfc;break;
    case 7:*register_word(s,ns,0xe5c0)&=~0x10000u;break;
    case 8:*register_word(s,ns,0xe29d)=0xff00;break;
    case 9:*register_word(s,ns,0xe384)=0x404;break;
    case 10:*register_word(s,ns,0xe150)=0x7e0;break;
    case 11:*register_word(s,ns,0xe151)=0;break;
    case 12:*register_word(s,ns,0xe5c9)=0x100;break;
    case 13:*register_word(s,ns,0xe1a9)=0xffff0000;break;
    case 14:*register_word(s,ns,0xe157)=0x7e0;break;
    case 15:*register_word(s,ns,0xe182)=0;break;
    case 16:*register_word(s,ns,0xe144)=0xc8;break;
    case 17:*register_word(s,ns,0xe005)=0xc8;break;
    case 18:*register_word(s,ns,0xe788)=0x0200fcfc;break;
    case 19:p=state_packet(s,ns,8,1,1);*p=h7(0x10,*p&0x3fff);break;
    case 20:shader_words(s,ns,0xe5c3)[2]=0x2002;break;
    case 21:shader_words(s,ns,0xe5c3)[3]&=~0x8000u;break;
    case 22:shader_words(s,ns,0xe5c3)[0]|=1u<<16;break;
    case 23:p=shader_words(s,ns,0xe5ac);p[5]=(p[5]&~255u)|5u;break;
    case 24:shader_words(s,ns,0xe5c3)[9]&=~0x10000000u;break;
    case 25:shader_words(s,ns,0xe5c3)[8]|=0x04000000u;break;
    case 26:shader_words(s,ns,0xe5c3)[5]=0x400;break;
    case 27:shader_words(s,ns,0xe5ac)[5]&=~0x300u;break;
    case 28:p=shader_words(s,ns,0xe5ac);p[5]|=1u<<15;break;
    case 29: {
        p=register_word(s,ns,0xe155);bool found=false;
        for(unsigned i=0;i<nr;i++)if(*p>=ranges[i].gpu_va && *p-ranges[i].gpu_va<ranges[i].bytes) {
            assert(ranges[i].bytes>=64);*p=ranges[i].gpu_va+((ranges[i].bytes-64)&~63u);found=true;break;
        }
        assert(found);break;
    }
    case 30:p=state_packet(s,ns,4,1,0);p[8]+=12288;break;
    case 31:p=state_packet(s,ns,4,1,0);p[8]=*register_word(s,ns,0xe155);break;
    case 32: {
        uint32_t *word=register_word(s,ns,0xe1b3);bool found=false;
        for(unsigned j=0;j<ns;j++)for(unsigned i=0;i<s[j].bytes/4;i++) {
            uint32_t h=s[j].words[i],n=h&127,reg=(h>>8)&0x3ffff;
            if((h>>28)==4 && n && reg<=0xe1b3 && 0xe1b3-reg<n && &s[j].words[i+1+0xe1b3-reg]==word) {
                s[j].words[i]=h7(0x10,n);found=true;break;
            }
        }
        assert(found);break;
    }
    case 33:*register_word(s,ns,0xe7c1)=1;break;
    case 34:*register_word(s,ns,0xe5c3)=*register_word(s,ns,0xe5ac);break;
    case 35:*register_word(s,ns,0xe5c0)&=~0xfc00u;break;
    case 36:*register_word(s,ns,0xe40a)+=16380;break;
    case 37:p=state_packet(s,ns,4,0,0);p[4]|=3u<<5;break;
    case 38:p=state_packet(s,ns,4,1,0);p[4]|=1;break;
    case 39:*register_word(s,ns,0xe146)=2;break;
    case 40:p=state_packet(s,ns,8,1,1);p[1]=(p[1]&~0x3fffu)|2;break;
    case 41:shader_words(s,ns,0xe5c3)[0]=0x2001;break;
    case 42:shader_words(s,ns,0xe5c3)[1]|=0x8000;break;
    case 43:p=shader_words(s,ns,0xe5ac);memset(p+4,0,120);p[5]=0x03000000;break;
    case 44:p=shader_words(s,ns,0xe5ac);memcpy(p,shader_words(s,ns,0xe5c3),128);break;
    case 45:*register_word(s,ns,0xe5cb)=0;break;
    case 46:*register_word(s,ns,0xe15c)=*register_word(s,ns,0xe155);break;
    case 47:*register_word(s,ns,0xe151)&=~1u;break;
    case 48:*register_word(s,ns,0xe29d)=0xff01;break;
    case 49:*register_word(s,ns,0xe7c3)=0;break;
    case 50: {
        /* Execute the ACTUAL relocated draw child without its restore root.
         * Derive its address/extent from the immutable IB packet, never a
         * guessed snapshot index or hardcoded length. Cold context required. */
        assert(ni && ni<=SGPU_GRAPHICS_IBS);bool found=false;
        for(unsigned j=0;j<ns && !found;j++)for(unsigned i=0;i+3<s[j].bytes/4;i++) {
            uint32_t h=s[j].words[i],op=(h>>16)&127;
            if((h>>28)==7 && (op==0x3f || op==0x37) && (h&0x3fff)==3) {
                assert(!s[j].words[i+2]);roots[0].gpu_va=s[j].words[i+1];roots[0].bytes=s[j].words[i+3]*4;found=true;break;
            }
        }
        assert(found);break;
    }
    default:assert(false);
    }
}

int main(int argc,char **argv)
{
    assert(argc==4);mutation=(unsigned)strtoul(argv[3],NULL,10);assert(mutation<51);unsigned expected=(unsigned)strtoul(argv[2],NULL,10);
    uint32_t header[8];memcpy(header,captured_raster_header,sizeof(header));
    assert(header[0]==0x50434753 && header[1]==1 && header[2]<=56 && header[3]<=8 && header[6]==505);
    struct model m={.seed_count=header[2]};struct sgpu_graphics_wire_ib roots[8]={0};
    memcpy(roots,captured_raster_roots,header[3]*sizeof(roots[0]));
    for(unsigned i=0;i<m.seed_count;i++) {
        uint32_t values[4];memcpy(values,captured_raster_buffers[i],sizeof(values));struct buffer *b=&m.bo[i];
        *b=(struct buffer){.original=values[0],.va=values[1],.bytes=values[2],.flags=values[3]};
        assert(b->bytes && b->bytes<=0x7fe000 && (b->flags==1 || b->flags==2) && b->va>=SGPU_RENDER_VA+4096 && !(b->va&4095));
        allocate(b);
        for(unsigned j=0;j<sizeof(captured_raster_runs)/sizeof(captured_raster_runs[0]);j++) {
            const struct captured_raster_run *r=&captured_raster_runs[j];if(r->buffer!=i)continue;
            assert(r->word<=b->bytes/4 && r->words<=b->bytes/4-r->word);
            for(unsigned k=0;k<r->words;k++)((uint32_t *)(void *)b->cpu)[r->word+k]=r->value;
        }
        b->saved=malloc(b->bytes);assert(b->saved);memcpy(b->saved,b->cpu,b->bytes);
        unsigned first=(b->va-SGPU_RENDER_VA)/4096,count=b->span/4096;assert(first+count<2048);
        for(unsigned j=0;j<=count;j++) {assert(!m.used[first+j]);m.used[first+j]=true;}
    }
    struct sgfx_client client={0};struct sgfx_transport transport={&m,call,map,unmap,close_model};assert(sgfx_init(&client,&transport));
    uint32_t handles[56];for(unsigned i=0;i<m.seed_count;i++) {struct sgfx_bo *b=sgfx_new(&client,m.bo[i].bytes,m.bo[i].flags);assert(b);handles[i]=b->handle;}
    for(unsigned i=0;i<header[3];i++) {
        bool found=false;for(unsigned j=0;j<m.seed_count;j++)if(m.bo[j].original==roots[i].handle) {roots[i].handle=m.bo[j].handle;found=true;break;}
        assert(found);
    }
    struct sgfx_command_result result;assert(!sgfx_submit_commands(&client,roots,header[3],handles,m.seed_count,&result));
    assert(m.submits==1 && !m.frees && client.failed && !result.submitted && result.error==SGFX_CMD_IO && result.command_buffers==expected);
    for(unsigned i=0;i<m.seed_count;i++)assert(!memcmp(m.bo[i].cpu,m.bo[i].saved,m.bo[i].bytes));
    printf("PASS actual captured packager: BOs=%u snapshots=%u appended_or_free_data_safe=1 prototype_policy_accepted=1 GPU_executed=0 hardware_verified=0\n",m.seed_count,result.command_buffers);
    sgfx_close(&client);for(unsigned i=0;i<m.next;i++) {free(m.bo[i].cpu);free(m.bo[i].saved);}return 0;
}
