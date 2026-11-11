/* Host capture integrity, using actual client/MSM/libdrm code and memory model. */
#include "santoni_drm.h"
#include "xf86drm.h"
#include "msm_drm.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
unsigned sgfx_capture_count(void);
int main(int argc,char **argv)
{
    assert(argc==2);unsigned test=(unsigned)strtoul(argv[1],NULL,10);assert(test<9);
    if(test==7) {assert(!sgfx_ios_connect_renderer(NULL));assert(!sgfx_capture_count());return 0;}
    int fd=test==6?sgfx_drm_open_renderer():sgfx_drm_open();assert(fd>=65536);
    if(test==8) {assert(sgfx_drm_open_renderer()==-EACCES);assert(!sgfx_capture_count());assert(!sgfx_drm_close(fd));return 0;}
    struct drm_msm_gem_new request={.size=128,.flags=MSM_BO_WC|MSM_BO_GPU_READONLY};
    assert(!drmCommandWriteRead(fd,DRM_MSM_GEM_NEW,&request,sizeof(request)));
    uint32_t handle=request.handle;uint32_t *words=sgfx_drm_bo_map(fd,(uint64_t)handle<<32,128);assert(words);
    words[0]=0x70108000u; /* The producer records bytes; it never parses/executes NOP. */
    struct drm_msm_gem_submit_bo bo={.handle=handle,.flags=MSM_SUBMIT_BO_READ};
    struct drm_msm_gem_submit_cmd command={.type=MSM_SUBMIT_CMD_BUF,.size=4};
    struct drm_msm_gem_submit submit={.flags=MSM_PIPE_3D0,.nr_bos=1,.nr_cmds=1,.bos=(uintptr_t)&bo,.cmds=(uintptr_t)&command};
    switch(test) {
    case 1:command.size=132;break;
    case 2:command.submit_offset=1;break;
    case 3:command.nr_relocs=1;break;
    case 4:bo.handle=UINT32_MAX;break;
    case 5:submit.flags|=MSM_SUBMIT_FENCE_FD_OUT;break;
    }
    int result=drmCommandWriteRead(fd,DRM_MSM_GEM_SUBMIT,&submit,sizeof(submit));
    bool accepted=test==0 || test==6;
    assert((result==0)==accepted);assert(sgfx_capture_count()==(accepted?1u:0u));
    if(accepted) {assert(submit.fence==1);uint32_t submitted=0,completed=0;
        assert(sgfx_drm_status(fd,&submitted,&completed) && submitted==1 && completed==1);}
    assert(!sgfx_drm_close(fd));puts("PASS capture transport; NO GPU/HARDWARE execution");return 0;
}
