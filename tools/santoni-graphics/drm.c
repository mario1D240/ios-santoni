/* Mesa msm softpin/GMEM dialect over the real owner-bound IOKit transport.
 * All client operations, including submit snapshots and waits, are serialized.
 * Closing the final token is terminal: the kernel lease lasts until reboot. */
#include "santoni_drm.h"
#include "xf86drm.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
static pthread_mutex_t lock=PTHREAD_MUTEX_INITIALIZER;
static struct sgfx_client client;
static int tokens[32],next_token=65536;
static unsigned references;
static bool attempted,renderer_selected;
static bool live(int fd)
{
    for(unsigned i=0;i<32;i++)if(tokens[i] && tokens[i]==fd)return true;
    return false;
}
static int result(int value)
{if(value<0)errno=-value;return value;}
static int token_new(void)
{
    if(next_token==INT_MAX)return result(-EMFILE);
    for(unsigned i=0;i<32;i++)if(!tokens[i]) {
        tokens[i]=next_token++;references++;return tokens[i];
    }
    return result(-EMFILE);
}
static int open_locked(const struct sgfx_transport *transport,bool renderer)
{
    if(renderer && attempted && !renderer_selected)return result(-EACCES);
    if(!attempted) {
        attempted=true;renderer_selected=renderer;
        struct sgfx_transport ios;
        if(!transport) {
            if(!(renderer?sgfx_ios_connect_renderer(&ios):sgfx_ios_connect(&ios)))return result(-ENODEV);
            transport=&ios;
        }
        if(!sgfx_init(&client,transport)) {sgfx_close(&client);return result(-ENODEV);}
        /* No BO allocation, shader compile, MMIO or submit before admission. */
        if(!sgfx_msm_render_ready(&client)) {sgfx_close(&client);return result(-EOPNOTSUPP);}
    }
    if(!sgfx_msm_render_ready(&client))return result(-ENODEV);
    return token_new();
}
int sgfx_drm_open_transport(const struct sgfx_transport *transport)
{pthread_mutex_lock(&lock);int r=open_locked(transport,false);pthread_mutex_unlock(&lock);return r;}
int sgfx_drm_open(void) {return sgfx_drm_open_transport(NULL);}
int sgfx_drm_open_renderer(void)
{pthread_mutex_lock(&lock);int r=open_locked(NULL,true);pthread_mutex_unlock(&lock);return r;}
int sgfx_drm_dup(int fd)
{pthread_mutex_lock(&lock);int r=live(fd)?token_new():result(-EBADF);pthread_mutex_unlock(&lock);return r;}
int sgfx_drm_close(int fd)
{
    pthread_mutex_lock(&lock);int r=-EBADF;
    for(unsigned i=0;i<32;i++)if(tokens[i] && tokens[i]==fd) {
        tokens[i]=0;if(!--references)sgfx_close(&client);r=0;break;
    }
    pthread_mutex_unlock(&lock);return result(r);
}
bool sgfx_drm_status(int fd,uint32_t *submitted,uint32_t *completed)
{
    pthread_mutex_lock(&lock);bool ok=live(fd) && sgfx_msm_render_ready(&client);
    if(ok && submitted && completed) {*submitted=client.submitted;*completed=client.completed;}
    else ok=false;
    pthread_mutex_unlock(&lock);return ok;
}
void *sgfx_drm_bo_map(int fd,uint64_t offset,size_t length)
{
    pthread_mutex_lock(&lock);void *p=NULL;
    if(live(fd) && length)for(unsigned i=0;i<SGPU_GRAPHICS_UAPI_HANDLES;i++) {
        const struct sgfx_bo *b=&client.bo[i];
        if(b->handle && offset==(uint64_t)b->handle<<32 && length<=b->bytes) {
            p=sgfx_msm_map(&client,offset);break;
        }
    }
    if(!p)errno=live(fd)?EINVAL:EBADF;
    pthread_mutex_unlock(&lock);return p;
}
void sgfx_drm_bo_unmap(void *p,size_t length)
{(void)p;(void)length;} /* The managed CPU alias belongs to GEM_CLOSE/last close. */
int drmOpenWithType(const char *name,const char *busid,int type)
{
    if(!name || strcmp(name,"msm") || busid || type!=DRM_NODE_RENDER)return result(-EINVAL);
    return sgfx_drm_open();
}
drmVersionPtr drmGetVersion(int fd)
{
    pthread_mutex_lock(&lock);drmVersionPtr v=NULL;
    if(live(fd)) {
        v=calloc(1,sizeof(*v));
        if(v) {
            v->name=malloc(4);
            if(v->name) {
                memcpy(v->name,"msm",4);v->name_len=3;
                v->version_major=1;v->version_minor=4; /* pinned Mesa softpin + GMEM_BASE dialect */
            } else {free(v);v=NULL;}
        }
        if(!v)errno=ENOMEM;
    } else errno=EBADF;
    pthread_mutex_unlock(&lock);return v;
}
void drmFreeVersion(drmVersionPtr v)
{if(v) {free(v->name);free(v->date);free(v->desc);free(v);}}
int drmGetCap(int fd,uint64_t cap,uint64_t *value)
{
    pthread_mutex_lock(&lock);int r=0;
    if(!live(fd))r=-EBADF;
    else if(!value)r=-EINVAL;
    else if(cap==DRM_CAP_SYNCOBJ || cap==DRM_CAP_SYNCOBJ_TIMELINE || cap==DRM_CAP_PRIME)*value=0;
    else r=-EOPNOTSUPP;
    pthread_mutex_unlock(&lock);return result(r);
}
int drmCommandWriteRead(int fd,unsigned long index,void *data,unsigned long size)
{
    pthread_mutex_lock(&lock);
    int r=live(fd)?sgfx_msm_command(&client,index,data,size):-EBADF;
    pthread_mutex_unlock(&lock);return result(r);
}
int drmCommandWrite(int fd,unsigned long index,void *data,unsigned long size)
{return drmCommandWriteRead(fd,index,data,size);}
int drmIoctl(int fd,unsigned long request,void *arg)
{
    pthread_mutex_lock(&lock);int r;
    if(!live(fd))r=-EBADF;
    else if(!arg)r=-EINVAL;
    else if(request==DRM_IOCTL_GEM_CLOSE) {
        const struct drm_gem_close *p=arg;
        r=p->pad?-EINVAL:sgfx_msm_gem_close(&client,p->handle);
    } else r=-EOPNOTSUPP;
    pthread_mutex_unlock(&lock);
    if(r<0) {errno=-r;return -1;} /* drmIoctl follows ioctl's errno convention. */
    return 0;
}
static int unsupported(int fd)
{pthread_mutex_lock(&lock);int r=live(fd)?-EOPNOTSUPP:-EBADF;pthread_mutex_unlock(&lock);return result(r);}
int drmPrimeHandleToFD(int fd,uint32_t h,uint32_t flags,int *out)
{(void)h;(void)flags;(void)out;return unsupported(fd);}
int drmPrimeFDToHandle(int fd,int prime,uint32_t *out)
{(void)prime;(void)out;return unsupported(fd);}
int drmSyncobjCreate(int fd,uint32_t flags,uint32_t *out)
{(void)flags;(void)out;return unsupported(fd);}
int drmSyncobjDestroy(int fd,uint32_t h) {(void)h;return unsupported(fd);}
int drmSyncobjHandleToFD(int fd,uint32_t h,int *out)
{(void)h;(void)out;return unsupported(fd);}
int drmSyncobjFDToHandle(int fd,int obj,uint32_t *out)
{(void)obj;(void)out;return unsupported(fd);}
int drmSyncobjImportSyncFile(int fd,uint32_t h,int sync)
{(void)h;(void)sync;return unsupported(fd);}
int drmSyncobjExportSyncFile(int fd,uint32_t h,int *out)
{(void)h;(void)out;return unsupported(fd);}
int drmSyncobjReset(int fd,const uint32_t *h,uint32_t count)
{(void)h;(void)count;return unsupported(fd);}
int drmSyncobjWait(int fd,uint32_t *h,unsigned count,int64_t timeout,unsigned flags,uint32_t *signaled)
{(void)h;(void)count;(void)timeout;(void)flags;(void)signaled;return unsupported(fd);}
int drmSyncobjTimelineWait(int fd,uint32_t *h,uint64_t *points,unsigned count,int64_t timeout,unsigned flags,uint32_t *signaled)
{(void)h;(void)points;(void)count;(void)timeout;(void)flags;(void)signaled;return unsupported(fd);}
