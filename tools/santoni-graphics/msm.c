/* No Linux DRM device is opened. Only the checked IOKit BO/IB protocol runs.
 * Header/API source: Mesa25.0.7 742a20f48c59e8649533c84c4d49dd95b403f5da.
 * Rendering admission still requires the kernel's explicit GLES capability. */
#include "msm.h"
#include "msm_drm.h"
#include <errno.h>
#include <string.h>
static struct sgfx_bo *msm_bo(struct sgfx_client *c,uint32_t handle)
{
    if(!c || !c->initialized || c->failed || c->closed || !handle)return NULL;
    for(unsigned i=0;i<SGPU_GRAPHICS_UAPI_HANDLES;i++)if(c->bo[i].handle==handle)return &c->bo[i];
    return NULL;
}
bool sgfx_msm_render_ready(const struct sgfx_client *c)
{return c && c->initialized && !c->failed && !c->closed && c->info[2]==0x05000500u && c->info[3]==139264 && (c->info[9]&1);}
static bool msm_time(const struct drm_msm_timespec *t)
{return t->tv_sec>=0 && t->tv_nsec>=0 && t->tv_nsec<1000000000;}
int sgfx_msm_gem_close(struct sgfx_client *c,uint32_t handle)
{return !msm_bo(c,handle)?-EINVAL:sgfx_free(c,handle)?0:-EIO;}
void *sgfx_msm_map(struct sgfx_client *c,uint64_t offset)
{
    if(offset&0xffffffffu)return NULL;
    struct sgfx_bo *b=msm_bo(c,(uint32_t)(offset>>32));return b?b->cpu:NULL;
}
int sgfx_msm_command(struct sgfx_client *c,unsigned long index,void *data,size_t size)
{
    if(!c || !c->initialized || c->failed || c->closed)return -ENODEV;
    if(!data)return -EINVAL;
    switch(index) {
    case DRM_MSM_GET_PARAM: {
        if(size!=sizeof(struct drm_msm_param))return -EINVAL;
        struct drm_msm_param *p=data;
        if(p->pipe!=MSM_PIPE_3D0 || p->pad || p->len)return -EINVAL;
        switch(p->param) {
        case MSM_PARAM_GPU_ID:p->value=505;break;
        case MSM_PARAM_CHIP_ID:p->value=c->info[2];break;
        case MSM_PARAM_GMEM_SIZE:p->value=c->info[3];break;
        case MSM_PARAM_GMEM_BASE:
            /* Verified production core programs UCHE_GMEM_RANGE_MIN_LO,
             * vendor word0xe8b x4=byte0x3a2c, to0x100000. This is GPU-local
             * GMEM addressing, not a guessed physical carveout or BO PA. */
            p->value=0x100000;break;
        case MSM_PARAM_PRIORITIES:p->value=1;break;
        case MSM_PARAM_VA_SIZE:p->value=c->info[5];break;
        default:return -EOPNOTSUPP; /* do not invent clock/fault/timestamp measurements */
        }
        return 0;
    }
    case DRM_MSM_GEM_NEW: {
        if(size!=sizeof(struct drm_msm_gem_new))return -EINVAL;
        struct drm_msm_gem_new *p=data;uint32_t cache=p->flags&MSM_BO_CACHE_MASK;
        if(!p->size || p->size>c->info[6] || p->size>UINT32_MAX ||
            (p->flags&~(MSM_BO_GPU_READONLY|MSM_BO_SCANOUT|MSM_BO_CACHE_MASK)) ||
            (cache!=MSM_BO_WC && cache!=MSM_BO_CACHED))return -EINVAL;
        if(c->submitted!=c->completed && !sgfx_wait(c,c->submitted))return -EIO;
        struct sgfx_bo *b=sgfx_new(c,(uint32_t)p->size,p->flags&MSM_BO_GPU_READONLY?SGFX_READ:SGFX_WRITE);
        if(!b)return c->failed?-EIO:-ENOMEM;
        p->handle=b->handle;return 0;
    }
    case DRM_MSM_GEM_INFO: {
        if(size!=sizeof(struct drm_msm_gem_info))return -EINVAL;
        struct drm_msm_gem_info *p=data;struct sgfx_bo *b=msm_bo(c,p->handle);
        if(!b || p->pad)return -EINVAL;
        if(p->info==MSM_INFO_GET_OFFSET && !p->len)p->value=(uint64_t)b->handle<<32;
        else if(p->info==MSM_INFO_GET_IOVA && !p->len)p->value=b->gpu_va;
        else if(p->info==MSM_INFO_SET_NAME && p->value && p->len && p->len<=32)return 0; /* optional debug name */
        else return -EOPNOTSUPP;
        return 0;
    }
    case DRM_MSM_GEM_CPU_PREP: {
        if(size!=sizeof(struct drm_msm_gem_cpu_prep))return -EINVAL;
        struct drm_msm_gem_cpu_prep *p=data;
        if(!msm_bo(c,p->handle) || !msm_time(&p->timeout) || !p->op || (p->op&~(MSM_PREP_READ|MSM_PREP_WRITE|MSM_PREP_NOSYNC)))return -EINVAL;
        if((p->op&MSM_PREP_NOSYNC) && c->submitted!=c->completed)return -EBUSY;
        return sgfx_cpu_prep(c,p->handle)?0:-EIO;
    }
    case DRM_MSM_GEM_CPU_FINI: {
        if(size!=sizeof(struct drm_msm_gem_cpu_fini))return -EINVAL;
        struct drm_msm_gem_cpu_fini *p=data;
        return msm_bo(c,p->handle)?0:-EINVAL; /* kernel submit cleans every listed BO */
    }
    case DRM_MSM_GEM_MADVISE: {
        if(size!=sizeof(struct drm_msm_gem_madvise))return -EINVAL;
        struct drm_msm_gem_madvise *p=data;
        if(!msm_bo(c,p->handle) || (p->madv!=MSM_MADV_WILLNEED && p->madv!=MSM_MADV_DONTNEED))return -EINVAL;
        p->retained=1;return 0; /* actual wired backing is retained until logical free/reboot */
    }
    case DRM_MSM_SUBMITQUEUE_NEW: {
        if(size!=sizeof(struct drm_msm_submitqueue))return -EINVAL;
        struct drm_msm_submitqueue *p=data;
        if(p->flags || p->prio)return -EOPNOTSUPP;
        p->id=0;return 0; /* one serialized owner/queue; no shared-context preemption */
    }
    case DRM_MSM_SUBMITQUEUE_CLOSE:
        return size==sizeof(uint32_t) && !*(uint32_t *)data?0:-EINVAL;
    case DRM_MSM_WAIT_FENCE: {
        if(size!=sizeof(struct drm_msm_wait_fence))return -EINVAL;
        struct drm_msm_wait_fence *p=data;
        if(p->queueid || p->flags || !p->fence || !msm_time(&p->timeout) || p->fence>c->submitted)return -EINVAL;
        if(p->fence<=c->completed)return 0;
        /* Submits below synchronously wait before returning. No caller can
         * create an unbounded wait or fake a sync-file/signaled fence. */
        return -ETIMEDOUT;
    }
    case DRM_MSM_GEM_SUBMIT: {
        if(size!=sizeof(struct drm_msm_gem_submit))return -EINVAL;
        struct drm_msm_gem_submit *p=data;
        if(!sgfx_msm_render_ready(c))return -EOPNOTSUPP;
        if(p->flags&~(MSM_PIPE_ID_MASK|MSM_SUBMIT_NO_IMPLICIT) || MSM_PIPE_ID(p->flags)!=MSM_PIPE_3D0 ||
            p->queueid || p->pad || p->in_syncobjs || p->out_syncobjs || p->nr_in_syncobjs ||
            p->nr_out_syncobjs || p->syncobj_stride || !p->nr_cmds || p->nr_cmds>SGPU_GRAPHICS_UAPI_IBS || !p->nr_bos ||
            p->nr_bos>SGPU_GRAPHICS_UAPI_HANDLES || !p->bos || !p->cmds ||
            (p->bos&7) || (p->cmds&7))return -EINVAL;
        const struct drm_msm_gem_submit_bo *bos=(const void *)(uintptr_t)p->bos;
        const struct drm_msm_gem_submit_cmd *cmds=(const void *)(uintptr_t)p->cmds;
        uint32_t handles[SGPU_GRAPHICS_UAPI_HANDLES];struct sgpu_graphics_wire_ib roots[SGPU_GRAPHICS_UAPI_IBS];unsigned nr=0;
        for(unsigned i=0;i<p->nr_bos;i++) {
            struct sgfx_bo *b=msm_bo(c,bos[i].handle);
            if(!b || !(bos[i].flags&(MSM_SUBMIT_BO_READ|MSM_SUBMIT_BO_WRITE)) || (bos[i].flags&~MSM_SUBMIT_BO_FLAGS) ||
                ((bos[i].flags&MSM_SUBMIT_BO_WRITE) && b->flags==SGFX_READ))return -EINVAL;
            handles[i]=b->handle;
            for(unsigned j=0;j<i;j++)if(handles[i]==handles[j])return -EINVAL;
        }
        for(unsigned i=0;i<p->nr_cmds;i++) {
            if(cmds[i].submit_idx>=p->nr_bos || cmds[i].pad || cmds[i].nr_relocs || cmds[i].relocs ||
                !cmds[i].size || ((cmds[i].submit_offset|cmds[i].size)&3))return -EINVAL;
            struct sgfx_bo *b=msm_bo(c,handles[cmds[i].submit_idx]);
            if(cmds[i].submit_offset>b->bytes || cmds[i].size>b->bytes-cmds[i].submit_offset)return -EINVAL;
            if(cmds[i].type==MSM_SUBMIT_CMD_BUF)roots[nr++]=(struct sgpu_graphics_wire_ib){b->handle,cmds[i].submit_offset,cmds[i].size};
            else if(cmds[i].type!=MSM_SUBMIT_CMD_IB_TARGET_BUF)return -EOPNOTSUPP;
        }
        if(!nr)return -EINVAL;
        struct sgfx_command_result result;
        uint32_t sequence=sgfx_submit_commands(c,roots,nr,handles,p->nr_bos,&result);
        if(!sequence)return result.error==SGFX_CMD_LIMIT?-E2BIG:result.error==SGFX_CMD_IO?-EIO:-EINVAL;
        p->fence=sequence;return 0;
    }
    default:return -EOPNOTSUPP;
    }
}
