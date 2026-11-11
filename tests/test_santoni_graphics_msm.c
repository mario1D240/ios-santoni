/* Actual Mesa UAPI translation + command packager + kernel PM4. Peer is modeled. */
#define main command_fixture_main
#include "test_santoni_graphics_commands.c"
#undef main
#include "msm.h"
#include "msm_drm.h"
#include <errno.h>
int main(int argc,char **argv)
{
    assert(argc==2);unsigned test=(unsigned)strtoul(argv[1],NULL,10);assert(test<17);
    struct peer p={0};struct sgfx_client c={0};struct sgfx_transport transport={&p,call,map,unmap,close_peer};assert(sgfx_init(&c,&transport));
    assert(!sgfx_msm_render_ready(&c));
    struct drm_msm_param param={.pipe=MSM_PIPE_3D0,.param=MSM_PARAM_GPU_ID};
    assert(sgfx_msm_command(&c,DRM_MSM_GET_PARAM,&param,sizeof(param))==0 && param.value==505);
    param.param=MSM_PARAM_GMEM_SIZE;assert(!sgfx_msm_command(&c,DRM_MSM_GET_PARAM,&param,sizeof(param)) && param.value==139264);
    param.param=MSM_PARAM_MAX_FREQ;assert(sgfx_msm_command(&c,DRM_MSM_GET_PARAM,&param,sizeof(param))==-EOPNOTSUPP);
    param.param=MSM_PARAM_GPU_ID;param.pad=1;assert(sgfx_msm_command(&c,DRM_MSM_GET_PARAM,&param,sizeof(param))==-EINVAL);
    struct drm_msm_gem_new new={.size=128,.flags=MSM_BO_WC|MSM_BO_GPU_READONLY};
    assert(!sgfx_msm_command(&c,DRM_MSM_GEM_NEW,&new,sizeof(new)));uint32_t root=new.handle;
    assert(!sgfx_msm_command(&c,DRM_MSM_GEM_NEW,&new,sizeof(new)));uint32_t leaf=new.handle;
    new.size=4;new.flags=MSM_BO_WC;assert(!sgfx_msm_command(&c,DRM_MSM_GEM_NEW,&new,sizeof(new)));uint32_t dest=new.handle;
    struct drm_msm_gem_info info={.handle=root,.info=MSM_INFO_GET_OFFSET};
    assert(!sgfx_msm_command(&c,DRM_MSM_GEM_INFO,&info,sizeof(info)) && info.value==(uint64_t)root<<32);
    uint32_t *r=sgfx_msm_map(&c,info.value),*l=(uint32_t *)(void *)(bo(&p,leaf)->memory+64);assert(r);
    assert(!sgfx_msm_map(&c,info.value+1));
    r[0]=packet7(0x3f,3);r[1]=bo(&p,leaf)->va+64;r[2]=0;r[3]=4;
    l[0]=packet7(0x3d,3);l[1]=bo(&p,dest)->va;l[2]=0;l[3]=0xa505cafe;
    struct drm_msm_gem_submit_bo bos[3]={{MSM_SUBMIT_BO_READ,root,0},{MSM_SUBMIT_BO_READ,leaf,0},{MSM_SUBMIT_BO_WRITE,dest,0}};
    struct drm_msm_gem_submit_cmd cmds[2]={{.type=MSM_SUBMIT_CMD_BUF,.submit_idx=0,.size=16},
        {.type=MSM_SUBMIT_CMD_IB_TARGET_BUF,.submit_idx=1,.submit_offset=64,.size=16}};
    struct drm_msm_gem_submit submit={.flags=MSM_PIPE_3D0,.nr_bos=3,.nr_cmds=2,.bos=(uintptr_t)bos,.cmds=(uintptr_t)cmds};
    if(test!=1)c.info[9]=1; /* explicit synthetic renderer capability; real kernel stays0 */
    if(test==2)submit.flags|=MSM_SUBMIT_SUDO;
    if(test==3)submit.flags|=MSM_SUBMIT_FENCE_FD_OUT;
    if(test==4)submit.queueid=1;
    if(test==5)submit.in_syncobjs=0x1000;
    if(test==6)cmds[0].submit_idx=3;
    if(test==7)cmds[0].nr_relocs=1;
    if(test==8)cmds[0].submit_offset=1;
    if(test==9)bos[1].handle=99;
    if(test==10)bos[1].handle=root;
    if(test==11)bos[0].flags=MSM_SUBMIT_BO_WRITE;
    if(test==12)cmds[0].type=MSM_SUBMIT_CMD_CTX_RESTORE_BUF;
    if(test==13)submit.nr_bos=57;
    if(test==14)submit.nr_cmds=9;
    if(test==15)submit.cmds++;
    if(test==16)cmds[1].size=128;
    int result=sgfx_msm_command(&c,DRM_MSM_GEM_SUBMIT,&submit,sizeof(submit));
    if(test) {assert(result<0 && !p.submits);goto done;}
    assert(!result && submit.fence==1 && p.submits==1 && p.writes==1 && p.frees==2);
    struct drm_msm_wait_fence fence={.fence=1};assert(!sgfx_msm_command(&c,DRM_MSM_WAIT_FENCE,&fence,sizeof(fence)));
    fence.fence=2;assert(sgfx_msm_command(&c,DRM_MSM_WAIT_FENCE,&fence,sizeof(fence))==-EINVAL);
    struct drm_msm_gem_cpu_prep prep={.handle=dest,.op=MSM_PREP_READ};assert(!sgfx_msm_command(&c,DRM_MSM_GEM_CPU_PREP,&prep,sizeof(prep)));
    assert(!sgfx_msm_gem_close(&c,root));assert(!sgfx_msm_map(&c,(uint64_t)root<<32));
done:
    sgfx_close(&c);for(unsigned i=0;i<p.next;i++)free(p.bo[i].memory);
    printf("PASS actual MSM bridge case=%u; kernel PM4 executed, platform/GPU modeled\n",test);return 0;
}
