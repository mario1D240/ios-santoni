/* CPU/VFS/syscall contracts for the actual trace dispatcher and receiver.
 * The fd table, MAC policies, copying and vnode vector calls are modeled. */
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "santoni_gpu_launch.h"
#include "santoni_gpu_launch_trace.h"
#define VREG 1
#define VDIR 2
#define MOCKFS_FILE 2
#define FREAD 1
#define FWRITE 2
#define LCK_GRP_DECLARE(name,label) int name __attribute__((unused))
#define LCK_MTX_DECLARE(name,group) pthread_mutex_t name = PTHREAD_MUTEX_INITIALIZER
static pthread_mutex_t mockfs_santoni_diag_lock;
static _Thread_local bool diag_locked;
typedef struct vnode *vnode_t;
typedef struct proc *proc_t;
typedef struct vfs_context *vfs_context_t;
typedef struct trace_mount *mockfs_mount_t;
typedef struct trace_node *mockfs_fsnode_t;
struct trace_vfs_mount { void *mnt_data; };
struct vnode { int type,refs; void *data; struct trace_vfs_mount *mount;
    int (**op)(void *); unsigned rdev; };
struct trace_node { int type; struct trace_vfs_mount *mnt; };
struct trace_mount { int mockfs_mnt_mtx; uint64_t santoni_probe_kva;
    uint32_t santoni_probe_file_bytes,santoni_probe_span_bytes; bool santoni_probe_failed; };
struct proc { int pid,p_pgrpid; };
struct vfs_context { bool kernel,root; proc_t proc; };
struct vnop_open_args { vnode_t a_vp; int a_mode; vfs_context_t a_context; };
struct vnop_close_args { vnode_t a_vp; int a_fflag; vfs_context_t a_context; };
struct vnop_ioctl_args { vnode_t a_vp; uint64_t a_command; char *a_data;
    int a_fflag; vfs_context_t a_context; };
static struct {
    struct sgpu_launch_options options;
    const char *suffix;
    struct proc proc,other_proc;
    proc_t current;
    struct vfs_context ctx;
    struct trace_vfs_mount vfs,other_vfs;
    struct trace_mount mount;
    struct trace_node node;
    struct vnode vnode,other_vnode;
    vnode_t executable;
    unsigned gets,puts,prints,locks,unlocks;
    bool locked;
    char line[512];
} tm;
static proc_t current_proc(void) { return tm.current; }
static int proc_pid(proc_t p) { assert(p); return p->pid; }
static bool vfs_context_iskernel(vfs_context_t c) { assert(c); return c->kernel; }
static bool vfs_context_issuser(vfs_context_t c) { assert(c); return c->root; }
static proc_t vfs_context_proc(vfs_context_t c) { assert(c); return c->proc; }
static int vnode_vtype(vnode_t v) { assert(v); return v->type; }
static void *vnode_fsnode(vnode_t v) { assert(v); return v->data; }
static struct trace_vfs_mount *vnode_mount(vnode_t v) { assert(v); return v->mount; }
static vnode_t proc_getexecutablevnode(proc_t p)
{
    assert(p==tm.current && !tm.locked);
    tm.gets++;
    if (tm.executable) tm.executable->refs++;
    return tm.executable;
}
static unsigned dispatch_iocount;
static int vnode_put(vnode_t v)
{
    assert(v && v->refs>0 && !tm.locked);
    v->refs--; tm.puts++;
    if (!v->refs) dispatch_iocount=0;
    return 0;
}
static void lck_mtx_lock(void *lock)
{
    assert(!diag_locked);
    if (lock==&mockfs_santoni_diag_lock) {
        assert(!pthread_mutex_lock(lock)); diag_locked=true; return;
    }
    int *mount_lock=lock;
    assert(lock==&tm.mount.mockfs_mnt_mtx && !*mount_lock && !tm.locked);
    *mount_lock=1; tm.locked=true; tm.locks++;
}
static void lck_mtx_unlock(void *lock)
{
    if (lock==&mockfs_santoni_diag_lock) {
        assert(diag_locked); diag_locked=false; assert(!pthread_mutex_unlock(lock)); return;
    }
    int *mount_lock=lock;
    assert(!diag_locked && lock==&tm.mount.mockfs_mnt_mtx && *mount_lock && tm.locked);
    *mount_lock=0; tm.locked=false; tm.unlocks++;
}
static int err_open(struct vnop_open_args *a) { (void)a; return ENOTSUP; }
static int err_close(struct vnop_close_args *a) { (void)a; return ENOTSUP; }
static int err_ioctl(struct vnop_ioctl_args *a) { (void)a; return ENOTSUP; }
static int trace_printf(const char *format, ...) __attribute__((format(printf,1,2)));
static int trace_printf(const char *format, ...)
{
    assert(!diag_locked && !tm.locked && tm.gets==tm.puts+dispatch_iocount);
    va_list args; va_start(args,format);
    int n=vsnprintf(tm.line,sizeof(tm.line),format,args);
    va_end(args); assert(n>0 && n<(int)sizeof(tm.line)); tm.prints++; return n;
}
#define printf trace_printf
static bool PE_parse_boot_argn(const char *name, void *out, int bytes)
{
    if (!strcmp(name,"launchdsuffix")) {
        assert(bytes==64);
        if (!tm.suffix) return false;
        snprintf(out,(size_t)bytes,"%s",tm.suffix); return true;
    }
    assert(bytes==4);
    const uint32_t *value=NULL;
#define ARG(s,f) if (!strcmp(name,s)) value=&tm.options.f
    ARG("santonigpu",mode);
    ARG("santonigpu_user_exec",enabled);
    ARG("santonigpu_stock",stock);
    ARG("santonigpu_pixels",pixels);
    ARG("santonigpu_submit",submit);
    ARG("santonigpu_session",session);
    ARG("santonigpu_user",user);
    ARG("santonigpu_user_test",user_test);
    ARG("santonigpu_zap",zap);
    ARG("santonigpu_scm",scm);
    ARG("santonigpu_cache",cache);
#undef ARG
    assert(value); memcpy(out,value,4); return true;
}
/* Modeled Darwin services for the common syscall/file/vnode route. */
#include <limits.h>
#include <sys/types.h>
#include <strings.h>
#define v_type type
#define v_op op
#define v_rdev rdev
#define vc_ucred root
#define f_flag fp_glob->fg_flag
#define f_type fp_glob->fg_type
#define f_ops fp_glob->fg_ops
#ifndef __unused
#define __unused __attribute__((unused))
#endif
#define CONFIG_MACF 1
#define CONFIG_AUDIT 0
#define FALSE false
#define OS_FALLTHROUGH __attribute__((fallthrough))
#define AUDIT_ARG(...) ((void)0)
#define Z_WAITOK 0
#define IOC_IN 0x80000000UL
#define IOC_OUT 0x40000000UL
#define IOC_VOID 0x20000000UL
#define IOCPARM_LEN(c) (((c)>>16)&0x1fff)
#define IOCPARM_MAX 4096
#define DTYPE_SOCKET 2
#define DTYPE_PIPE 3
#define FP_CLOEXEC 1
#define FNONBLOCK 4
#undef FASYNC
#define FASYNC 8
#define FIONCLEX 0x20006602UL
#define FIOCLEX 0x20006601UL
#define FIONREAD 0x4004667fUL
#define FIONBIO 0x8004667eUL
#define FIOASYNC 0x8004667dUL
#define FIOSETOWN 0x8004667cUL
#define FIOGETOWN 0x4004667bUL
#define TIOCREVOKE 0x20007471UL
#define TIOCREVOKECLEAR 0x20007472UL
#define TIOCSPGRP 0x80047476UL
#define TIOCGPGRP 0x40047477UL
#define TIOCSCTTY 0x20007461UL
#define DKIOCSETBLOCKSIZE 0x80046418UL
#define FSIOC_AUTH_FS 0x80044a45UL
#define FIODTYPE 0x4004667aUL
#define VFIFO 7
#define VCHR 4
#define VBLK 3
#define major(r) ((r)>>24)
#define os_atomic_or(p,v,order) (*(p)|=(v))
#define os_atomic_andnot(p,v,order) (*(p)&=~(v))
#define ioctl sgpu_host_ioctl
/* Exact receiver definition follows this explicit service contract. */
static int mockfs_santoni_ioctl(struct vnop_ioctl_args *);
typedef bool boolean_t;
typedef uint64_t user_addr_t;
struct ioctl_args { int fd; u_long com; user_addr_t data; };
struct fileproc;
struct fileops { int (*fo_ioctl)(struct fileproc *,u_long,caddr_t,vfs_context_t); };
struct fileglob { int fg_flag,fg_type; bool fg_cred; off_t fg_offset;
    struct fileops *fg_ops; vnode_t data; };
struct fileproc { struct fileglob *fp_glob; int fp_flags; };
struct socket { int so_pgid; };
struct session { vnode_t s_ttyvp; unsigned s_ttyvid; };
struct pgrp { int unused; };
static struct { int d_type; } bdevsw[1],cdevsw[1];
static unsigned nblkdev=1,nchrdev=1;
static int mock_vector(void *a) { (void)a; abort(); }
static int other_vector(void *a) { (void)a; abort(); }
static int (*mock_ops[])(void *)={mock_vector};
static int (*other_ops[])(void *)={other_vector};
static int (**mockfs_vnodeop_p)(void *)=mock_ops;
static struct {
    bool fdlocked; int lookup_error,copyin_error,file_mac_error,vnode_mac_error,get_error;
    unsigned fdlocks,fdunlocks,lookups,drops,fprefs,copyins,copyouts,file_mac,vnode_mac;
    unsigned vnode_gets,vnop_calls,receiver_calls,device_calls;
    u_long command; int flags; char *user,*copied; size_t copy_bytes;
    struct fileproc fp; struct fileglob fg; struct fileops ops;
} dm;
static struct vfs_context *vfs_context_current(void) { return &tm.ctx; }
static bool proc_is64bit(proc_t p) { assert(p==tm.current); return true; }
static void *kalloc_data(size_t n,int flags) { (void)flags; return calloc(1,n); }
static void kfree_data(void *p,size_t n) { (void)n; free(p); }
static int copyin(user_addr_t source,void *dest,size_t size)
{
    dm.copyins++; assert((void *)(uintptr_t)source==dm.user && size==64);
    dm.copied=dest; dm.copy_bytes=size;
    if (dm.copyin_error) return dm.copyin_error;
    memcpy(dest,dm.user,size); return 0;
}
static int copyout(void *source,user_addr_t dest,size_t size)
{ (void)source; (void)dest; (void)size; dm.copyouts++; return 0; }
static void proc_fdlock(proc_t p)
{ assert(p==tm.current && !dm.fdlocked); dm.fdlocked=true; dm.fdlocks++; }
static void proc_fdunlock(proc_t p)
{ assert(p==tm.current && dm.fdlocked); dm.fdlocked=false; dm.fdunlocks++; }
static int fp_lookup(proc_t p,int fd,struct fileproc **out,int locked)
{
    assert(p==tm.current && fd==5 && locked==1 && dm.fdlocked); dm.lookups++;
    if (dm.lookup_error) return dm.lookup_error;
    *out=&dm.fp; dm.fprefs++; return 0;
}
static void fp_drop(proc_t p,int fd,struct fileproc *fp,int locked)
{ assert(p==tm.current && fd==5 && fp==&dm.fp && locked==1 && dm.fdlocked && dm.fprefs==1);
    dm.fprefs--; dm.drops++; }
static void *fp_get_data(struct fileproc *fp) { assert(fp==&dm.fp); return fp->fp_glob->data; }
static int mac_file_check_ioctl(bool cred,struct fileglob *fg,u_long cmd)
{ assert(cred==fg->fg_cred && fg==&dm.fg && cmd==dm.command && dm.fdlocked && dm.fprefs==1);
    dm.file_mac++; return dm.file_mac_error; }
static int vnode_getwithref(vnode_t vp)
{
    assert(vp==&tm.vnode && !dm.fdlocked && dm.fprefs==1 && !dispatch_iocount);
    dm.vnode_gets++;
    if (dm.get_error) return dm.get_error;
    vp->refs++; tm.gets++; dispatch_iocount=1; return 0;
}
static int mac_vnode_check_ioctl(vfs_context_t ctx,vnode_t vp,u_long cmd)
{ assert(ctx->root==dm.fg.fg_cred && vp==&tm.vnode && vp->refs==1 && cmd==dm.command);
    dm.vnode_mac++; return dm.vnode_mac_error; }
static int VNOP_IOCTL(vnode_t vp,u_long cmd,caddr_t data,int flags,vfs_context_t ctx)
{
    assert(vp==&tm.vnode && vp->refs==1 && !dm.fdlocked && dm.fprefs==1);
    assert(cmd==dm.command && data==dm.copied && data!=dm.user && dm.copy_bytes==64);
    dm.vnop_calls++; dm.flags=flags;
    if (vp->v_type==VREG && vp->v_op==mockfs_vnodeop_p) {
        dm.receiver_calls++;
        struct vnop_ioctl_args args={vp,cmd,data,flags,ctx};
        return mockfs_santoni_ioctl(&args);
    }
    dm.device_calls++; return 73;
}
static int vnode_size(vnode_t vp,off_t *out,vfs_context_t ctx)
{ (void)ctx; assert(vp==&tm.vnode); *out=16635; return 0; }
static struct proc *proc_find(int pid) { (void)pid; abort(); }
static void proc_rele(proc_t p) { (void)p; abort(); }
static struct pgrp *proc_pgrp(proc_t p,struct session **s) { (void)p; (void)s; abort(); }
static void session_lock(struct session *s) { (void)s; abort(); }
static void session_unlock(struct session *s) { (void)s; abort(); }
static unsigned vnode_vid(vnode_t v) { (void)v; abort(); }
static void pgrp_rele(struct pgrp *p) { (void)p; abort(); }
