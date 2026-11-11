/* Direct A505 texture state framing and owner binding in the actual packager.
 * Actual reconstructed kernel PM4 must STILL refuse every textured submit. */
#define main command_fixture_main
#include "test_santoni_graphics_commands.c"
#undef main
static unsigned texture_case,attempts;
static struct sgfx_bo *pixel,*root_bo;
static bool texture_call(void *ctx,uint32_t selector,const uint64_t *in,uint32_t ni,uint64_t *out,uint32_t no,
    const void *wire,size_t size)
{
    struct peer *p=ctx;
    if(selector==SG_GFX_NEW && in[0]>4096) {
        assert(ni==2 && no==4 && p->next<64 && in[0]==131072);
        struct peer_bo *b=&p->bo[p->next];b->handle=++p->next;b->va=SGPU_RENDER_VA+0x200000;
        b->bytes=(uint32_t)in[0];b->flags=(uint32_t)in[1];b->live=true;
        assert(!posix_memalign((void **)&b->memory,4096,b->bytes));memset(b->memory,0x55,b->bytes);
        out[0]=out[3]=b->handle;out[1]=b->va;out[2]=b->bytes;return true;
    }
    if(selector==SG_GFX_SUBMIT) {
        attempts++;const struct sgpu_graphics_wire_submit *request=wire;
        assert(request->ibs==1 && request->handles==4 && request->ib[0].handle==4);
        struct peer_bo *mirror=bo(p,4);assert(mirror && mirror->flags==SGFX_READ);
        assert(mirror->bytes==root_bo->bytes && !memcmp(mirror->memory,root_bo->cpu,root_bo->bytes));
        const uint32_t *words=(const uint32_t *)(const void *)mirror->memory;
        if(texture_case!=2)assert(words[16]==pixel->gpu_va+(texture_case==17?32u:0u));
        bool accepted=call(ctx,selector,in,ni,out,no,wire,size);
        assert(!accepted && p->submits==1 && !p->writes);return false;
    }
    return call(ctx,selector,in,ni,out,no,wire,size);
}
static bool texture_map(void *ctx,uint32_t handle,uint8_t **out,uint64_t *size)
{struct peer_bo *b=bo(ctx,handle);assert(b && b->live);*out=b->memory;*size=b->bytes>4096?b->bytes:4096;return true;}
int main(int argc,char **argv)
{
    assert(argc==2);texture_case=(unsigned)strtoul(argv[1],NULL,10);assert(texture_case<22);
    struct peer p={0};struct sgfx_client client={0};
    struct sgfx_transport transport={&p,texture_call,texture_map,unmap,close_peer};assert(sgfx_init(&client,&transport));
    root_bo=sgfx_new(&client,1024,SGFX_READ);
    pixel=sgfx_new(&client,texture_case==3?131072:4096,SGFX_WRITE);
    struct sgfx_bo *dummy=sgfx_new(&client,4,SGFX_READ);assert(root_bo && pixel && dummy);
    uint32_t *words=(uint32_t *)(void *)root_bo->cpu,block=texture_case==1?0:4;
    /* Mesa fd5_emit.c emit_textures: four sampler/twelve descriptor words.
     * Pixel address is fresh from this modeled owner allocation, not a dump. */
    words[0]=packet7(0x30,7);words[1]=(1u<<22)|(block<<18);words[2]=words[3]=0;
    words[4]=0;words[5]=8192;words[6]=words[7]=0;
    words[8]=packet7(0x30,15);words[9]=words[1];words[10]=1;words[11]=0;
    uint32_t *descriptor=words+12;
    descriptor[0]=0x0c006880;descriptor[1]=16u|(16u<<15);descriptor[2]=0x20008002;descriptor[3]=2;
    descriptor[4]=pixel->gpu_va;descriptor[5]=1u<<17;
    unsigned bytes=96,nh=3;uint32_t handles[3]={root_bo->handle,pixel->handle,dummy->handle};
    switch(texture_case) {
    case 0:case 1:case 3:break;
    case 2:bytes=32;break;
    case 4:words[9]|=2u<<16;break;
    case 5:words[9]|=1;break;
    case 6:words[9]&=~(0x3ffu<<22);break;
    case 7:
        for(unsigned i=1;i<17;i++)memcpy(descriptor+i*12,descriptor,48);
        words[8]=packet7(0x30,3+17*12);words[9]=(17u<<22)|(block<<18);bytes=(8+1+3+17*12)*4;break;
    case 8:words[8]=packet7(0x30,14);bytes-=4;break;
    case 9:descriptor[5]|=1;break;
    case 10:descriptor[4]|=4;break;
    case 11:descriptor[4]=SGPU_RENDER_VA;break;
    case 12:handles[1]=dummy->handle;nh=2;break;
    case 13:words[10]=2;break;
    case 14:words[11]=1;break;
    case 15:words[2]=0x100;break;
    case 16:descriptor[4]=pixel->gpu_va+pixel->bytes;break;
    case 17:descriptor[4]+=32;break;
    case 18:descriptor[5]=2u<<17;break; /* framing is NOT content approval */
    case 19:words[4]|=3u<<5;break; /* no border-mode approval in the packager */
    case 20:words[9]=(1u<<22)|(5u<<18);break;
    case 21:words[0]=packet7(0x30,3);bytes=16;break;
    }
    struct sgpu_graphics_wire_ib root={root_bo->handle,0,bytes};struct sgfx_command_result result;
    assert(!sgfx_submit_commands(&client,&root,1,handles,nh,&result));
    bool framed=texture_case<4 || (texture_case>=17 && texture_case<=19);
    if(framed)assert(attempts==1 && client.failed && !p.frees && result.error==SGFX_CMD_IO &&
        result.command_buffers==1 && result.roots==1 && !result.submitted);
    else assert(!attempts && !client.failed && !p.submits && result.error && !p.frees);
    sgfx_close(&client);for(unsigned i=0;i<p.next;i++)free(p.bo[i].memory);
    printf("PASS actual texture framing case=%u; kernel GLES refused; no GPU execution\n",texture_case);return 0;
}
