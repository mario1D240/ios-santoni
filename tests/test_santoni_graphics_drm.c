/* Execute the real facade/adapter/command packager/kernel PM4. GPU modeled. */
#define main commands_fixture_main
#include "test_santoni_graphics_commands.c"
#undef main
#include "santoni_drm.h"
#include "xf86drm.h"
#include "msm_drm.h"
#include <errno.h>
#include <pthread.h>
static struct peer fixture;
static unsigned closes,connects,renderer_connects;
static bool raster;
static bool connection_fail;
static bool facade_call(void *ctx,uint32_t sel,const uint64_t *in,uint32_t ni,
    uint64_t *out,uint32_t no,const void *wire,size_t size)
{
    bool ok=call(ctx,sel,in,ni,out,no,wire,size);
    if(ok && sel==SG_GFX_INFO)out[9]=raster?1:0; /* explicit synthetic kernel capability */
    return ok;
}
static void facade_close(void *ctx) {(void)ctx;closes++;}
bool sgfx_ios_connect(struct sgfx_transport *t)
{connects++;if(connection_fail)return false;*t=(struct sgfx_transport){&fixture,facade_call,map,unmap,facade_close};return true;}
bool sgfx_ios_connect_renderer(struct sgfx_transport *t)
{renderer_connects++;if(connection_fail)return false;*t=(struct sgfx_transport){&fixture,facade_call,map,unmap,facade_close};return true;}
static void *duplicate_thread(void *arg)
{
    int fd=*(int *)arg;
    for(unsigned i=0;i<200;i++) {
        int copy=sgfx_drm_dup(fd);assert(copy>=65536);assert(!sgfx_drm_close(copy));
        assert(sgfx_drm_close(copy)==-EBADF);
    }
    return NULL;
}
int main(int argc,char **argv)
{
    assert(argc==2);unsigned test=(unsigned)strtoul(argv[1],NULL,10);assert(test<19);
    raster=test!=1;
    if(test>=13) {
        if(test==15)raster=false;
        if(test==16)connection_fail=true;
        if(test==17) {
            int admin=sgfx_drm_open();assert(admin>=65536 && connects==1 && !renderer_connects);
            assert(sgfx_drm_open_renderer()==-EACCES && !renderer_connects && !closes);
            uint32_t sub=0,done=0;assert(sgfx_drm_status(admin,&sub,&done));
            assert(!sgfx_drm_close(admin) && closes==1);return 0;
        }
        int lease=sgfx_drm_open_renderer();
        if(test==15 || test==16) {
            assert(lease==(test==15?-EOPNOTSUPP:-ENODEV) && renderer_connects==1 && !connects && closes==(test==15?1u:0u));
            connection_fail=false;raster=true;
            assert(sgfx_drm_open_renderer()==-ENODEV && sgfx_drm_open()==-ENODEV && renderer_connects==1 && !connects);
            return 0;
        }
        assert(lease>=65536 && renderer_connects==1 && !connects && !closes && !fixture.next && !fixture.submits);
        int child=sgfx_drm_open();assert(child>lease && renderer_connects==1 && !connects);
        if(test==18) {
            pthread_t threads[8];for(unsigned i=0;i<8;i++)assert(!pthread_create(&threads[i],NULL,duplicate_thread,&child));
            for(unsigned i=0;i<8;i++)assert(!pthread_join(threads[i],NULL));
        }
        assert(!sgfx_drm_close(child) && !closes);
        int after=sgfx_drm_open_renderer();assert(after>child && renderer_connects==1 && !connects);
        assert(!sgfx_drm_close(after) && !closes);
        uint32_t sub=99,done=99;assert(sgfx_drm_status(lease,&sub,&done) && !sub && !done);
        assert(!sgfx_drm_close(lease) && closes==1);
        assert(sgfx_drm_open_renderer()==-ENODEV && sgfx_drm_open()==-ENODEV && renderer_connects==1 && !connects);
        return 0;
    }
    assert(drmOpenWithType("kgsl",NULL,DRM_NODE_RENDER)==-EINVAL);
    assert(drmOpenWithType("msm",NULL,DRM_NODE_PRIMARY)==-EINVAL);
    int fd=drmOpenWithType("msm",NULL,DRM_NODE_RENDER);
    if(test==1) {
        assert(fd==-EOPNOTSUPP && connects==1 && closes==1 && !fixture.next && !fixture.submits);
        assert(sgfx_drm_open()==-ENODEV && connects==1);return 0;
    }
    assert(fd>=65536 && connects==1);int copy=sgfx_drm_dup(fd);assert(copy>fd);
    drmVersionPtr v=drmGetVersion(copy);assert(v && v->version_major==1 && v->version_minor==4 && !strcmp(v->name,"msm"));drmFreeVersion(v);
    uint64_t cap=123;assert(!drmGetCap(fd,DRM_CAP_SYNCOBJ,&cap) && !cap);
    assert(drmGetCap(fd,DRM_CAP_TIMESTAMP_MONOTONIC,&cap)==-EOPNOTSUPP);
    struct drm_msm_param param={.pipe=MSM_PIPE_3D0,.param=MSM_PARAM_GPU_ID};
    assert(!drmCommandWriteRead(fd,DRM_MSM_GET_PARAM,&param,sizeof(param)) && param.value==505);
    if(test==2) {
        int ts[30];for(unsigned i=0;i<30;i++)assert((ts[i]=sgfx_drm_dup(fd))>copy);
        assert(sgfx_drm_dup(fd)==-EMFILE);
        for(unsigned i=0;i<30;i++)assert(!sgfx_drm_close(ts[i]));
    }
    if(test==3) {
        pthread_t threads[8];for(unsigned i=0;i<8;i++)assert(!pthread_create(&threads[i],NULL,duplicate_thread,&fd));
        for(unsigned i=0;i<8;i++)assert(!pthread_join(threads[i],NULL));
    }
    if(test==12) {
        int root=sgfx_drm_open();assert(root>copy);
        assert(!sgfx_drm_close(copy) && !sgfx_drm_close(fd) && !closes);
        int fresh=sgfx_drm_open();assert(fresh>root && connects==1 && !closes);
        assert(!sgfx_drm_close(fresh) && !closes && !fixture.next && !fixture.submits);
        assert(!sgfx_drm_close(root) && closes==1 && sgfx_drm_open()==-ENODEV);
        return 0;
    }
    struct drm_msm_gem_new new={.size=16,.flags=MSM_BO_WC|MSM_BO_GPU_READONLY};
    assert(!drmCommandWriteRead(fd,DRM_MSM_GEM_NEW,&new,sizeof(new)));uint32_t root=new.handle;
    new.flags=MSM_BO_WC;assert(!drmCommandWriteRead(fd,DRM_MSM_GEM_NEW,&new,sizeof(new)));uint32_t dest=new.handle;
    new.flags=MSM_BO_WC|MSM_BO_GPU_READONLY;assert(!drmCommandWriteRead(fd,DRM_MSM_GEM_NEW,&new,sizeof(new)));
    uint32_t *r=sgfx_drm_bo_map(copy,(uint64_t)root<<32,16);assert(r);
    assert(!sgfx_drm_bo_map(fd,(uint64_t)root<<32,17));
    assert(!sgfx_drm_bo_map(fd,((uint64_t)root<<32)+1,4));
    assert(!sgfx_drm_bo_map(42,(uint64_t)root<<32,4));
    r[0]=packet7(0x3d,3);r[1]=bo(&fixture,dest)->va;r[2]=0;r[3]=0xa505cafe;
    struct drm_msm_gem_submit_bo bos[2]={{MSM_SUBMIT_BO_READ,root,0},{MSM_SUBMIT_BO_WRITE,dest,0}};
    struct drm_msm_gem_submit_cmd cmd={.type=MSM_SUBMIT_CMD_BUF,.submit_idx=0,.size=16};
    struct drm_msm_gem_submit sub={.flags=MSM_PIPE_3D0,.nr_bos=2,.nr_cmds=1,.bos=(uintptr_t)bos,.cmds=(uintptr_t)&cmd};
    if(test==4)sub.flags|=MSM_SUBMIT_SUDO;
    if(test==5)sub.flags|=MSM_SUBMIT_FENCE_FD_OUT;
    if(test==6)sub.queueid=1;
    if(test==7)cmd.nr_relocs=1;
    if(test==8)fixture.scenario=15;
    int submit=drmCommandWriteRead(copy,DRM_MSM_GEM_SUBMIT,&sub,sizeof(sub));
    if(test>=4 && test<=8)assert(submit<0 && (test==8 || !fixture.submits));
    else {
        assert(!submit && sub.fence==1 && fixture.submits==1 && fixture.writes==1);
        struct drm_msm_gem_cpu_prep prep={.handle=dest,.op=MSM_PREP_READ};
        assert(!drmCommandWrite(fd,DRM_MSM_GEM_CPU_PREP,&prep,sizeof(prep)));
        uint32_t *pixels=sgfx_drm_bo_map(fd,(uint64_t)dest<<32,4);assert(pixels && *pixels==0xa505cafe);
    }
    if(test==8) {
        unsigned count=fixture.submits;uint32_t submitted=99,completed=99;
        assert(!fixture.frees && !sgfx_drm_status(fd,&submitted,&completed) && submitted==99 && completed==99);
        assert(!sgfx_drm_bo_map(fd,(uint64_t)dest<<32,4));
        assert(drmCommandWriteRead(fd,DRM_MSM_GEM_SUBMIT,&sub,sizeof(sub))<0 && fixture.submits==count);
    }
    int prime=77;uint32_t sync=88;
    assert(drmPrimeHandleToFD(fd,root,0,&prime)==-EOPNOTSUPP && prime==77);
    assert(drmSyncobjCreate(fd,0,&sync)==-EOPNOTSUPP && sync==88);
    if(test==9) {
        struct drm_gem_close close={.handle=root,.pad=1};assert(drmIoctl(fd,DRM_IOCTL_GEM_CLOSE,&close)==-1 && errno==EINVAL);
        close.pad=0;assert(!drmIoctl(fd,DRM_IOCTL_GEM_CLOSE,&close));assert(!sgfx_drm_bo_map(fd,(uint64_t)root<<32,4));
    }
    if(test==10) {
        assert(drmCommandWriteRead(3,DRM_MSM_GET_PARAM,&param,sizeof(param))==-EBADF);
        assert(!drmGetVersion(3));assert(drmIoctl(3,DRM_IOCTL_GEM_CLOSE,&param)==-1 && errno==EBADF);
    }
    if(test==11) {
        assert(!sgfx_drm_close(copy));int fresh=sgfx_drm_dup(fd);assert(fresh>copy);
        assert(drmCommandWriteRead(copy,DRM_MSM_GET_PARAM,&param,sizeof(param))==-EBADF);copy=fresh;
    }
    sgfx_drm_bo_unmap(r,16);assert(!sgfx_drm_close(fd) && !closes);
    assert(!sgfx_drm_close(copy) && closes==1);
    assert(sgfx_drm_open()==-ENODEV && connects==1);
    for(unsigned i=0;i<fixture.next;i++)free(fixture.bo[i].memory);
    printf("PASS facade case=%u; actual PM4, GPU modeled\n",test);return 0;
}
