/* Real userspace packager + unchanged kernel parser. GPU/IOKit are modeled;
 * valid state packaging must STILL be refused by the current kernel policy. */
#define main command_fixture_main
#include "test_santoni_graphics_commands.c"
#undef main
static unsigned state_case,state_attempts;
static struct sgfx_bo *state_root,*state_shader,*state_constants;
static uint8_t shader_original[256],constants_original[64];
static uint32_t state_packet4(uint32_t reg,uint32_t count)
{
    unsigned a=1,b=1;
    for(unsigned n=reg;n;n>>=1)a^=n&1;
    for(unsigned n=count;n;n>>=1)b^=n&1;
    return 0x40000000u|(reg<<8)|(a<<27)|count|(b<<7);
}
static bool state_call(void *context,uint32_t selector,const uint64_t *in,uint32_t ni,
    uint64_t *out,uint32_t no,const void *wire,size_t bytes)
{
    struct peer *p=context;
    if(selector==SG_GFX_SUBMIT) {
        const struct sgpu_graphics_wire_submit *r=wire;state_attempts++;
        struct peer_bo *root=bo(p,r->ib[0].handle);
        assert(root && root->flags==SGFX_READ && root->handle>3);
        const uint32_t *words=(const uint32_t *)(const void *)root->memory;
        struct peer_bo *shader=NULL,*constants=NULL;
        for(unsigned i=1;i<r->ibs;i++) {
            struct peer_bo *b=bo(p,r->ib[i].handle);assert(b && b->flags==SGFX_READ);
            assert(r->ib[i].bytes==4 && r->ib[i].offset<=b->bytes-4);
            uint32_t nop;memcpy(&nop,b->memory+r->ib[i].offset,4);assert(nop==packet7(0x10,0));
            uint32_t offset=state_case==2?128:0;
            if(b->va+offset==words[2]) {
                assert(b->handle>3 && !memcmp(b->memory+offset,shader_original+offset,128));
                assert(r->ib[i].offset+4<=offset || r->ib[i].offset>=offset+128);
                shader=b;
            }
            if(!memcmp(b->memory,constants_original,64))constants=b;
        }
        assert(shader && shader->bytes==state_shader->bytes+(state_case==2?0u:4u));
        assert(!memcmp(state_shader->cpu,shader_original,state_shader->bytes));
        assert(!memcmp(state_constants->cpu,constants_original,64));
        uint32_t shader_offset=state_case==2?128:0;
        if(state_case==2)assert(shader->bytes==256);
        /* Shader LOAD_STATE4 is first; preserved flags and copied VA required. */
        assert(words[0]==packet7(0x30,3));
        assert(words[2]==shader->va+shader_offset && words[3]==0);
        if(state_case!=3) {
            assert(words[4]==state_packet4(state_case==1?0xe5c3:0xe5ac,2));
            assert(words[5]==shader->va+shader_offset && words[6]==0);
        }
        unsigned at=state_case==3?4:7;
        assert(words[at]==packet7(0x30,state_case==4?19:3));
        if(state_case==4) {
            assert(words[at+2]==1 && !words[at+3]);
            assert(!memcmp(words+at+4,constants_original,64));
        } else {
            assert(constants && constants->bytes==68);
            assert(words[at+2]==(constants->va|1u) && !words[at+3]);
        }
        /* Keep default-off raster/shader authority in the actual parser. */
        bool result=call(context,selector,in,ni,out,no,wire,bytes);
        assert(!result && p->submits==1 && !p->writes);return result;
    }
    return call(context,selector,in,ni,out,no,wire,bytes);
}
int main(int argc,char **argv)
{
    assert(argc==2);state_case=(unsigned)strtoul(argv[1],NULL,10);assert(state_case<26);
    struct peer p={0};struct sgfx_client c={0};
    struct sgfx_transport transport={&p,state_call,map,unmap,close_peer};assert(sgfx_init(&c,&transport));
    state_root=sgfx_new(&c,256,SGFX_READ);
    state_shader=sgfx_new(&c,state_case==2 || state_case==25?256:128,SGFX_READ);
    state_constants=sgfx_new(&c,64,SGFX_READ);assert(state_root && state_shader && state_constants);
    for(unsigned i=0;i<sizeof(shader_original);i++)shader_original[i]=(uint8_t)(i*13+7);
    for(unsigned i=0;i<sizeof(constants_original);i++)constants_original[i]=(uint8_t)(i*3+11);
    memcpy(state_shader->cpu,shader_original,state_shader->bytes);memcpy(state_constants->cpu,constants_original,64);
    uint32_t *r=(uint32_t *)(void *)state_root->cpu;
    unsigned block=state_case==1?12:8,offset=state_case==2?128:0;
    r[0]=packet7(0x30,3);r[1]=(1u<<22)|(block<<18)|(2u<<16);r[2]=state_shader->gpu_va+offset;r[3]=0;
    r[4]=state_packet4(state_case==1?0xe5c3:0xe5ac,2);r[5]=r[2];r[6]=0;
    unsigned at=state_case==3?4:7;
    r[at]=packet7(0x30,3);r[at+1]=(4u<<22)|(block<<18)|(2u<<16);r[at+2]=state_constants->gpu_va|1u;r[at+3]=0;
    unsigned length=at+4;
    if(state_case==4) {
        r[at]=packet7(0x30,19);r[at+1]&=~(2u<<16);r[at+2]=1;
        memcpy(r+at+4,constants_original,64);length+=16;
    }
    uint32_t handles[3]={state_root->handle,state_shader->handle,state_constants->handle};unsigned nh=3;
    if(state_case==5)r[3]=1;
    if(state_case==6)r[2]+=4;
    if(state_case==7)r[1]+=1u<<22; /* shader read exceeds the owned BO */
    if(state_case==8)r[2]=SGPU_RENDER_VA; /* unowned/private window */
    if(state_case==9)r[1]&=~(0x3ffu<<22);
    if(state_case==10)r[1]|=1u<<14;
    if(state_case==11)r[1]=(1u<<22)|(13u<<18)|(2u<<16); /* compute refused */
    if(state_case==12)r[2]|=2;
    if(state_case==13)r[1]=(r[1]&~(3u<<16))|(1u<<16);
    if(state_case==14) {r[1]&=~(3u<<16);r[2]=0;} /* direct shaders not in initial recipe */
    if(state_case==15) {handles[1]=state_constants->handle;nh=2;}
    if(state_case==16)r[at+2]=state_constants->gpu_va|2u; /* UBO descriptor has nested pointers */
    if(state_case==17)r[at+1]=(1u<<22)|(block<<18)|(2u<<16); /* indirect constants need vec4 upload grouping */
    if(state_case==18)r[at+3]=1;
    if(state_case==19) {r[0]=state_packet4(0xe5ad,1);r[1]=0;length=2;}
    if(state_case==20) {r[0]=state_packet4(0xe5ac,1);r[1]=state_shader->gpu_va;length=2;}
    if(state_case==21)r[6]=1;
    if(state_case==22) {
        /* A later nested command may not reinterpret protected shader data. */
        r[length]=packet7(0x3f,3);r[length+1]=state_shader->gpu_va;r[length+2]=0;r[length+3]=1;length+=4;
    }
    if(state_case==23) {r[2]=state_root->gpu_va;r[5]=r[2];} /* shader/code overlap */
    if(state_case==24) {r[1]|=1;}
    if(state_case==25) {r[1]+=1u<<22;r[2]+=128;r[5]=r[2];} /* late-offset span crossing */
    struct sgpu_graphics_wire_ib root={state_root->handle,0,length*4};struct sgfx_command_result result;
    assert(!sgfx_submit_commands(&c,&root,1,handles,nh,&result));
    if(state_case<5) {
        assert(state_attempts==1 && result.error==SGFX_CMD_IO && c.failed && !result.submitted && !p.frees);
        assert(result.command_buffers==(state_case==4?2u:3u));
    } else assert(!state_attempts && !p.submits && !c.failed && result.error && !p.frees);
    sgfx_close(&c);for(unsigned i=0;i<p.next;i++)free(p.bo[i].memory);
    printf("PASS state packaging case=%u; kernel GLES refusal retained; no GPU execution\n",state_case);
    return 0;
}
