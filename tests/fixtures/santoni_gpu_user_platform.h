/* Host contracts for XNU8796 conf/devfs/kauth/task APIs. Not kernel ABI proof. */
#ifndef SANTONI_GPU_USER_PLATFORM_H
#define SANTONI_GPU_USER_PLATFORM_H
#include <sys/types.h>
#include <errno.h>
#include <stdarg.h>
#include <stdatomic.h>
#include "santoni_gpu_launch.h"
/* These session/client harnesses keep the independent EL0 launcher disabled.
 * Use its reconstructed record type and preserve the launcher-off observation:
 * worker_ready may be true without a published executable or any trace event.
 * The actual enabled getters/publication are tested by the launcher suites. */
bool santoni_gpu_user_launch_worker_ready(uint32_t mode)
{ assert(!queue_depth && mode==3);return true; }
bool santoni_gpu_user_launch_mount_published(void)
{ assert(!queue_depth);return false; }
void santoni_gpu_user_launch_trace_snapshot(struct sgpu_launch_trace_diag *out)
{ assert(!queue_depth && out);memset(out,0,sizeof(*out)); }
typedef unsigned long u_long;
typedef char *caddr_t;
typedef void *task_t;
struct proc;
struct uio;
struct tty;
struct buf;
#undef major
#undef minor
#undef makedev
#define major(d) ((int)(((uint32_t)(d)>>24)&255u))
#define minor(d) ((int)((uint32_t)(d)&0xffffffu))
#define makedev(m,n) ((dev_t)(((uint32_t)(m)<<24)|(uint32_t)(n)))
#define UID_ROOT 0
#define DEVFS_CHAR 0
#define _IOWR(g,n,t) (0xc0000000u|((uint32_t)sizeof(t)<<16)|((uint32_t)(g)<<8)|(n))
struct cdevsw {
    int (*d_open)(dev_t,int,int,struct proc *);
    int (*d_close)(dev_t,int,int,struct proc *);
    int (*d_read)(dev_t,struct uio *,int);
    int (*d_write)(dev_t,struct uio *,int);
    int (*d_ioctl)(dev_t,u_long,caddr_t,int,struct proc *);
    int (*d_stop)(struct tty *,int);
    int (*d_reset)(int);
    struct tty **d_ttys;
    int (*d_select)(dev_t,int,void *,struct proc *);
    int (*d_mmap)(void);
    void (*d_strategy)(struct buf *);
    int (*d_reserved_1)(void);
    int (*d_reserved_2)(void);
    int d_type;
};
static int host_rdwrt(dev_t d,struct uio *u,int f) {(void)d;(void)u;(void)f;return ENODEV;}
static int host_stop(struct tty *t,int f) {(void)t;(void)f;return ENODEV;}
static int host_reset(int f) {(void)f;return ENODEV;}
static int host_select(dev_t d,int w,void *q,struct proc *p) {(void)d;(void)w;(void)q;(void)p;return ENODEV;}
static int host_empty(void) {return ENODEV;}
static void host_strategy(struct buf *b) {(void)b;}
#define eno_rdwrt host_rdwrt
#define eno_stop host_stop
#define eno_reset host_reset
#define eno_select host_select
#define eno_mmap host_empty
#define eno_strat host_strategy
#define eno_getc host_empty
#define eno_putc host_empty
static _Thread_local bool host_root=true;
static _Thread_local task_t host_task=(task_t)(uintptr_t)0x1010;
static _Atomic unsigned host_task_refs;
static unsigned host_namespace_calls, host_publication_failure;
static void (*host_task_hook)(void);
static task_t current_task(void) {assert(!queue_depth);if(host_task_hook)host_task_hook();return host_task;}
static void *kauth_cred_get(void) {assert(!queue_depth);return &host_root;}
static int kauth_cred_issuser(void *cred) {assert(!queue_depth && cred==&host_root);return host_root;}
static void task_reference(task_t task) {assert(!queue_depth && task);host_task_refs++;}
static void task_deallocate(task_t task) {assert(!queue_depth && task && host_task_refs);host_task_refs--;}
static int cdevsw_add(int number,const struct cdevsw *table)
{
    assert(!queue_depth && number==-1 && table && table->d_open && table->d_ioctl);
    host_namespace_calls++;return host_publication_failure==1 ? -1 : 77;
}
static void *devfs_make_node(dev_t dev,int type,unsigned uid,unsigned gid,int permissions,const char *format,...)
{
    assert(!queue_depth && dev==makedev(77,0) && type==DEVFS_CHAR && uid==0 && gid==0);
    assert(permissions==0600 && !strcmp(format,"santonigpu"));
    host_namespace_calls++;return host_publication_failure==2 ? NULL : (void *)(uintptr_t)0x4242;
}
#endif
