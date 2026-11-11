/* Explicit loader startup prerequisite. A status observer never claims GPU
 * ownership. This bounds returning syscalls; it cannot time out a syscall that
 * never returns or a thread the kernel does not schedule. */
#include "santoni_drm.h"
#include <errno.h>
#include <time.h>
/* The kernel retains its40-second storage/input startup delay. Permit a
 * renderer loader that starts early to observe publication within a bounded
 * 60-second/600-poll window. This is not a scheduling or hardware guarantee. */
#define SGFX_STARTUP_NS 60000000000ull
#define SGFX_STARTUP_POLLS 600u
static bool monotonic_ns(uint64_t *out)
{
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC,&now) || now.tv_sec<0 || now.tv_nsec<0 || now.tv_nsec>=1000000000 ||
        (uint64_t)now.tv_sec>(UINT64_MAX-(uint64_t)now.tv_nsec)/1000000000ull)return false;
    *out=(uint64_t)now.tv_sec*1000000000ull+(uint64_t)now.tv_nsec;return true;
}
bool sgfx_ios_renderer_wait(void)
{
    uint64_t start,last,now;
    if(!monotonic_ns(&start) || start>UINT64_MAX-SGFX_STARTUP_NS)return false;
    last=start;uint64_t deadline=start+SGFX_STARTUP_NS;
    for(unsigned poll=0;poll<SGFX_STARTUP_POLLS;poll++) {
        if(!monotonic_ns(&now) || now<last || now>=deadline)return false;
        last=now;
        uint64_t status[SGPU_GRAPHICS_RENDERER_STATUS_WORDS]={0};
        int result=sgfx_ios_renderer_status(status);
        if(!monotonic_ns(&now) || now<last || now>=deadline)return false;
        last=now;
        if(result!=0 && result!=-ENODEV)return false;
        if(!result) {
            if(status[0]!=SGPU_GRAPHICS_UAPI_VERSION || status[1]!=1 || status[2]>1 || status[3] || status[4])return false;
            if(status[2]==1)return true;
        }
        const struct timespec pause={0,100000000};
        if(nanosleep(&pause,NULL))return false;
    }
    return false;
}
