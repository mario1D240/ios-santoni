#include "commands.h"
#include <stdlib.h>
#include <string.h>
#define CMD_DEPTH 8u
#define CMD_NODES 512u
struct command_copy {
    struct sgfx_bo *source,*mirror;
    uint32_t *words;
    uint32_t mirror_bytes;
    bool root;
};
struct command_interval {uint32_t copy,offset,bytes;};
struct command_reloc {uint32_t *low,copy,offset,flags;};
struct command_walk {
    struct sgfx_client *client;
    struct sgfx_command_result *result;
    const uint32_t *handles;
    uint32_t handle_count,copy_count,depth,nodes,words,relocs,data_count;
    struct command_copy copy[SGPU_GRAPHICS_UAPI_IBS];
    struct command_interval active[CMD_DEPTH],visited[CMD_NODES];
    struct command_interval data[CMD_NODES];
    struct command_reloc reloc[CMD_NODES];
};
static bool command_fail(struct command_walk *w,uint32_t error)
{if(!w->result->error)w->result->error=error;return false;}
static struct sgfx_bo *command_bo(struct command_walk *w,uint32_t handle)
{
    bool listed=false;
    for(unsigned i=0;i<w->handle_count;i++)if(w->handles[i]==handle)listed=true;
    if(!listed || !handle)return NULL;
    for(unsigned i=0;i<SGPU_GRAPHICS_UAPI_HANDLES;i++)if(w->client->bo[i].handle==handle)return &w->client->bo[i];
    return NULL;
}
static uint32_t command_copy(struct command_walk *w,struct sgfx_bo *bo)
{
    for(unsigned i=0;i<w->copy_count;i++)if(w->copy[i].source==bo)return i;
    if(w->copy_count==SGPU_GRAPHICS_UAPI_IBS || !bo || !bo->cpu || !bo->bytes ||
        bo->bytes>w->client->info[7] || bo->bytes>UINT32_MAX-4 || (bo->bytes&3)) {command_fail(w,SGFX_CMD_LIMIT);return UINT32_MAX;}
    uint32_t *words=malloc((size_t)bo->bytes+4);
    if(!words) {command_fail(w,SGFX_CMD_MEMORY);return UINT32_MAX;}
    memcpy(words,bo->cpu,bo->bytes);
    unsigned i=w->copy_count++;w->copy[i]=(struct command_copy){bo,NULL,words,bo->bytes,false};return i;
}
static uint32_t command_parity(uint32_t value)
{uint32_t p=1;for(;value;value>>=1)p^=value&1;return p;}
static bool command_header(uint32_t h,uint32_t *type,uint32_t *op,uint32_t *count)
{
    *type=h>>28;
    if(*type==4) {
        *count=h&127;*op=(h>>8)&0x3ffff;
        return *count && h==(0x40000000u|*count|(command_parity(*count)<<7)|(*op<<8)|(command_parity(*op)<<27));
    }
    if(*type==7) {
        *count=h&0x3fff;*op=(h>>16)&127;
        return h==(0x70000000u|*count|(command_parity(*count)<<15)|(*op<<16)|(command_parity(*op)<<23));
    }
    return false;
}
static bool command_walk(struct command_walk *,uint32_t,uint32_t,uint32_t);
static bool command_child(struct command_walk *w,uint32_t *low,uint32_t high,uint32_t words)
{
    if(high || !words || words>w->client->info[7]/4 || (*low&3))return command_fail(w,SGFX_CMD_ADDRESS);
    uint32_t bytes=words*4;struct sgfx_bo *bo=NULL;
    for(unsigned i=0;i<w->handle_count;i++) {
        struct sgfx_bo *candidate=command_bo(w,w->handles[i]);
        if(candidate && *low>=candidate->gpu_va && *low-candidate->gpu_va<=candidate->bytes &&
            bytes<=candidate->bytes-(*low-candidate->gpu_va)) {bo=candidate;break;}
    }
    if(!bo)return command_fail(w,SGFX_CMD_ADDRESS);
    uint32_t copy=command_copy(w,bo),offset=*low-bo->gpu_va;
    if(copy==UINT32_MAX)return false;
    if(w->relocs==CMD_NODES)return command_fail(w,SGFX_CMD_LIMIT);
    w->reloc[w->relocs++]=(struct command_reloc){low,copy,offset,0};
    return command_walk(w,copy,offset,bytes);
}
/* Mesa25.0.7 fd5_program.c/fd5_emit.c, and adreno_pm4.xml CP_LOAD_STATE4:
 * shader units are16 64-bit instructions (ir3_compiler.c instr_align=16);
 * constants are vec4s. These are size/relocation checks, not IR3 validation.
 * Data is never parsed as PM4 or overwritten to manufacture a NOP root. */
static bool command_blob(struct command_walk *w,uint32_t *low,uint32_t high,uint32_t bytes,uint32_t flags)
{
    if(high || (*low&3)!=flags)return command_fail(w,SGFX_CMD_ADDRESS);
    uint32_t va=*low&~3u;struct sgfx_bo *bo=NULL;
    for(unsigned i=0;i<w->handle_count;i++) {
        struct sgfx_bo *candidate=command_bo(w,w->handles[i]);
        if(candidate && va>=candidate->gpu_va && va-candidate->gpu_va<candidate->bytes &&
            (!bytes || bytes<=candidate->bytes-(va-candidate->gpu_va))) {bo=candidate;break;}
    }
    if(!bo)return command_fail(w,SGFX_CMD_ADDRESS);
    uint32_t offset=va-bo->gpu_va;
    if(!bytes) {
        bytes=bo->bytes-offset; /* SP shader object: protect the entire remaining BO. */
        if(bytes<128)return command_fail(w,SGFX_CMD_ADDRESS);
    }
    uint32_t copy=command_copy(w,bo);
    if(copy==UINT32_MAX)return false;
    if(w->data_count==CMD_NODES || w->relocs==CMD_NODES)return command_fail(w,SGFX_CMD_LIMIT);
    for(unsigned i=0;i<w->nodes;i++)if(w->visited[i].copy==copy &&
        offset<w->visited[i].offset+w->visited[i].bytes && w->visited[i].offset<offset+bytes)
        return command_fail(w,SGFX_CMD_PACKET);
    w->data[w->data_count++]=(struct command_interval){copy,offset,bytes};
    w->reloc[w->relocs++]=(struct command_reloc){low,copy,offset,flags};
    return true;
}
static bool command_state4(struct command_walk *w,uint32_t *p,uint32_t count)
{
    if(count<3 || (p[0]&0xc000u) || p[2])return command_fail(w,SGFX_CMD_PACKET);
    uint32_t source=(p[0]>>16)&3,block=(p[0]>>18)&15,units=p[0]>>22,type=p[1]&3;
    uint32_t destination=p[0]&0x3fff;
    if(block==0 || block==4) {
        /* Pinned Mesa fd5_emit.c emit_textures: direct VS/FS samplers have
         * four words/unit, texture descriptors twelve. Only descriptors are
         * immutable command state; pixel BOs remain same-owner resources.
         * Never copy an entire surface into the small private IB allocation. */
        if(source || destination || !units || units>16 || type>1 || p[1]!=type ||
            count!=3+units*(type?12u:4u))return command_fail(w,SGFX_CMD_PACKET);
        if(!type)return true;
        for(unsigned unit=0;unit<units;unit++) {
            const uint32_t *texture=&p[3+unit*12];
            /* a5xx.xml TEX_CONST4 low5 bits are alignment, CONST5 bits0..16
             * are BASE_HI, while upper bits hold DEPTH (not address flags).
             * Full format/tiling/layer/pitch bounds belong to kernel policy. */
            if((texture[4]&31u) || (texture[5]&0x1ffffu))return command_fail(w,SGFX_CMD_ADDRESS);
            bool owned=false;
            for(unsigned i=0;i<w->handle_count;i++) {
                struct sgfx_bo *bo=command_bo(w,w->handles[i]);
                if(bo && texture[4]>=bo->gpu_va && texture[4]-bo->gpu_va<bo->bytes)owned=true;
            }
            if(!owned)return command_fail(w,SGFX_CMD_ADDRESS);
        }
        return true;
    }
    if(!units || (block!=8 && block!=12) || type>1 ||
        units>0x4000u-destination || (!type && destination))return command_fail(w,SGFX_CMD_PACKET);
    uint32_t bytes=units*(type?16u:128u);
    if(source==0) {
        /* The initial Mesa recipe uses indirect shaders. Inline constants
         * already belong to the private command snapshot. */
        return type==1 && p[1]==1 && count==3+bytes/4?true:command_fail(w,SGFX_CMD_PACKET);
    }
    if(source!=2 || count!=3 || bytes>w->client->info[7] ||
        (!type && (p[1]&127u)) || (type && ((destination|units)&3)))
        return command_fail(w,SGFX_CMD_PACKET);
    return command_blob(w,&p[1],p[2],bytes,type);
}
static bool command_registers(struct command_walk *w,uint32_t reg,uint32_t *p,uint32_t count)
{
    /* A505 register WORD indices from Mesa's a5xx.xml. Only the two
     * shader-object pointers are relocated; the kernel checks all registers. */
    for(unsigned i=0;i<count;i++) {
        uint32_t current=reg+i;
        if(current==0xe5ad || current==0xe5c4)return command_fail(w,SGFX_CMD_PACKET);
        if(current==0xe5ac || current==0xe5c3) {
            if(i+1>=count || (p[i]&127u) || !command_blob(w,&p[i],p[i+1],0,0))
                return command_fail(w,SGFX_CMD_ADDRESS);
            i++;
        }
    }
    return true;
}
static bool command_walk(struct command_walk *w,uint32_t copy,uint32_t offset,uint32_t bytes)
{
    struct command_copy *c=&w->copy[copy];
    if((offset|bytes)&3 || !bytes || offset>c->source->bytes || bytes>c->source->bytes-offset)
        return command_fail(w,SGFX_CMD_INPUT);
    if(w->depth==CMD_DEPTH || w->nodes==CMD_NODES || bytes/4>w->client->info[7]/4*SGPU_GRAPHICS_UAPI_IBS-w->words)
        return command_fail(w,SGFX_CMD_LIMIT);
    for(unsigned i=0;i<w->depth;i++)if(w->active[i].copy==copy &&
        offset<w->active[i].offset+w->active[i].bytes && w->active[i].offset<offset+bytes)
        return command_fail(w,SGFX_CMD_CYCLE);
    for(unsigned i=0;i<w->data_count;i++)if(w->data[i].copy==copy &&
        offset<w->data[i].offset+w->data[i].bytes && w->data[i].offset<offset+bytes)
        return command_fail(w,SGFX_CMD_PACKET);
    struct command_interval interval={copy,offset,bytes};
    w->active[w->depth++]=interval;w->visited[w->nodes++]=interval;w->words+=bytes/4;
    uint32_t *p=c->words+offset/4;
    for(unsigned pos=0;pos<bytes/4;) {
        uint32_t type,op,count;
        if(!command_header(p[pos],&type,&op,&count) || count>bytes/4-pos-1)return command_fail(w,SGFX_CMD_PACKET);
        uint32_t *payload=&p[pos+1];
        if(type==4) {
            if(!command_registers(w,op,payload,count))return false;
        } else if(op==0x30) {
            if(!command_state4(w,payload,count))return false;
        } else if(op==0x37 || op==0x3f) {
            if(count!=3)return command_fail(w,SGFX_CMD_PACKET);
            if(!command_child(w,&payload[0],payload[1],payload[2]))return false;
        } else if(type==7 && op==0x43) {
            if(!count || count%3)return command_fail(w,SGFX_CMD_PACKET);
            for(unsigned i=0;i<count;i+=3) {
                uint32_t control=payload[i],words=control&0xffff;
                if(control&~0x1f0fffffu)return command_fail(w,SGFX_CMD_PACKET);
                if((control&(3u<<17)) || !words) {
                    if(words || payload[i+1] || payload[i+2])return command_fail(w,SGFX_CMD_PACKET);
                } else if(!command_child(w,&payload[i+1],payload[i+2],words))return false;
            }
        } else if(type==7 && (op==0x57 || op==0x3a || op==0x32)) {
            return command_fail(w,SGFX_CMD_PACKET); /* unsupported conditional/chain command pointers */
        }
        /* Kernel policies still check every register/opcode/data address and
         * shader. Direct VS/FS texture framing above is not content approval;
         * indirect textures, UBO/SSBO and other state blocks remain refused. */
        pos+=count+1;
    }
    w->depth--;return true;
}
static bool command_nop_root(struct command_walk *w,uint32_t copy,uint32_t *offset)
{
    uint32_t at=0,end=w->copy[copy].source->bytes;
    while(at<end) {
        uint32_t next=at;
        for(unsigned i=0;i<w->nodes;i++)if(w->visited[i].copy==copy &&
            at<w->visited[i].offset+w->visited[i].bytes && w->visited[i].offset<at+4)
            if(next<w->visited[i].offset+w->visited[i].bytes)next=w->visited[i].offset+w->visited[i].bytes;
        for(unsigned i=0;i<w->data_count;i++)if(w->data[i].copy==copy &&
            at<w->data[i].offset+w->data[i].bytes && w->data[i].offset<at+4)
            if(next<w->data[i].offset+w->data[i].bytes)next=w->data[i].offset+w->data[i].bytes;
        if(next==at) {w->copy[copy].words[at/4]=0x70108000u;*offset=at;return true;}
        at=next;
    }
    /* A data-only BO can be fully occupied. Append the synthetic NOP in a
     * fresh mirror byte span instead of corrupting shader/constant bytes. */
    if((uint64_t)end+4>w->client->info[7])return command_fail(w,SGFX_CMD_LIMIT);
    w->copy[copy].words[end/4]=0x70108000u;w->copy[copy].mirror_bytes=end+4;*offset=end;return true;
}
uint32_t sgfx_submit_commands(struct sgfx_client *c,const struct sgpu_graphics_wire_ib *roots,uint32_t nr,
    const uint32_t *handles,uint32_t nh,struct sgfx_command_result *result)
{
    if(!result)return 0;
    memset(result,0,sizeof(*result));
    if(!c || !c->initialized || c->failed || c->closed || !roots || !handles || !nr || nr>SGPU_GRAPHICS_UAPI_IBS ||
        !nh || nh>SGPU_GRAPHICS_UAPI_HANDLES) {result->error=SGFX_CMD_INPUT;return 0;}
    if(c->submitted!=c->completed && !sgfx_wait(c,c->submitted)) {result->error=SGFX_CMD_IO;return 0;}
    struct command_walk *w=calloc(1,sizeof(*w));
    if(!w) {result->error=SGFX_CMD_MEMORY;return 0;}
    w->client=c;w->result=result;w->handles=handles;w->handle_count=nh;
    struct sgpu_graphics_wire_ib input[SGPU_GRAPHICS_UAPI_IBS],output[SGPU_GRAPHICS_UAPI_IBS];
    uint32_t ids[SGPU_GRAPHICS_UAPI_HANDLES],root_copy[SGPU_GRAPHICS_UAPI_IBS],count=nr,seq=0;
    memcpy(input,roots,nr*sizeof(*roots));memcpy(ids,handles,nh*sizeof(*handles));w->handles=ids;
    for(unsigned i=0;i<nh;i++) {
        if(!command_bo(w,ids[i])) {command_fail(w,SGFX_CMD_INPUT);goto done;}
        for(unsigned j=0;j<i;j++)if(ids[i]==ids[j]) {command_fail(w,SGFX_CMD_INPUT);goto done;}
    }
    for(unsigned i=0;i<nr;i++) {
        struct sgfx_bo *bo=command_bo(w,input[i].handle);
        if(!bo) {command_fail(w,SGFX_CMD_INPUT);goto done;}
        root_copy[i]=command_copy(w,bo);
        if(root_copy[i]==UINT32_MAX)goto done;
        w->copy[root_copy[i]].root=true;
    }
    for(unsigned i=0;i<nr;i++)if(!command_walk(w,root_copy[i],input[i].offset,input[i].bytes))goto done;
    if(nh+w->copy_count>SGPU_GRAPHICS_UAPI_HANDLES) {command_fail(w,SGFX_CMD_LIMIT);goto done;}
    for(unsigned i=0;i<w->copy_count;i++)if(!w->copy[i].root) {
        if(count==SGPU_GRAPHICS_UAPI_IBS) {command_fail(w,SGFX_CMD_LIMIT);goto done;}
        uint32_t offset;if(!command_nop_root(w,i,&offset))goto done;
        output[count++]=(struct sgpu_graphics_wire_ib){i,offset,4}; /* copy index until mirrors exist */
    }
    result->command_buffers=w->copy_count;result->roots=count;
    for(unsigned i=0;i<w->copy_count;i++) {
        w->copy[i].mirror=sgfx_new(c,w->copy[i].mirror_bytes,SGFX_READ);
        if(!w->copy[i].mirror) {command_fail(w,SGFX_CMD_IO);goto done;}
        ids[nh+i]=w->copy[i].mirror->handle;
    }
    for(unsigned i=0;i<w->relocs;i++)*w->reloc[i].low=(w->copy[w->reloc[i].copy].mirror->gpu_va+w->reloc[i].offset)|w->reloc[i].flags;
    for(unsigned i=0;i<w->copy_count;i++)memcpy(w->copy[i].mirror->cpu,w->copy[i].words,w->copy[i].mirror_bytes);
    for(unsigned i=0;i<nr;i++)output[i]=(struct sgpu_graphics_wire_ib){w->copy[root_copy[i]].mirror->handle,input[i].offset,input[i].bytes};
    for(unsigned i=nr;i<count;i++)output[i].handle=w->copy[output[i].handle].mirror->handle;
    result->sequence=seq=sgfx_submit(c,output,count,ids,nh+w->copy_count);
    if(!seq) {command_fail(w,SGFX_CMD_IO);goto done;}
    result->submitted=true;
    if(!sgfx_wait(c,seq)) {command_fail(w,SGFX_CMD_IO);goto done;}
    result->completed=true;
done:
    for(unsigned i=0;i<w->copy_count;i++) {
        if(w->copy[i].mirror && !c->failed && !c->closed && c->submitted==c->completed)
            if(!sgfx_free(c,w->copy[i].mirror->handle))command_fail(w,SGFX_CMD_IO);
        free(w->copy[i].words); /* CPU heap was never GPU mapped */
    }
    free(w);return result->error?0:seq;
}
