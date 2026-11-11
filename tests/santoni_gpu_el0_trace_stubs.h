/* Explicit CPU/VFS contracts for the new trace receiver only. */
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
typedef struct trace_vnode *vnode_t;
typedef struct trace_proc *proc_t;
typedef struct trace_context *vfs_context_t;
typedef struct trace_mount *mockfs_mount_t;
typedef struct trace_node *mockfs_fsnode_t;
struct trace_vfs_mount { void *mnt_data; };
struct trace_vnode { int type,refs; void *data; struct trace_vfs_mount *mount; };
struct trace_node { int type; struct trace_vfs_mount *mnt; };
struct trace_mount { int mockfs_mnt_mtx; uint64_t santoni_probe_kva;
    uint32_t santoni_probe_file_bytes,santoni_probe_span_bytes; bool santoni_probe_failed; };
struct trace_proc { int pid; };
struct trace_context { bool kernel,root; proc_t proc; };
struct vnop_open_args { vnode_t a_vp; int a_mode; vfs_context_t a_context; };
struct vnop_close_args { vnode_t a_vp; int a_fflag; vfs_context_t a_context; };
struct vnop_ioctl_args { vnode_t a_vp; uint64_t a_command; char *a_data;
    int a_fflag; vfs_context_t a_context; };
static struct {
    struct sgpu_launch_options options;
    const char *suffix;
    struct trace_proc proc,other_proc;
    proc_t current;
    struct trace_context ctx;
    struct trace_vfs_mount vfs,other_vfs;
    struct trace_mount mount;
    struct trace_node node;
    struct trace_vnode vnode,other_vnode;
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
static void vnode_put(vnode_t v)
{
    assert(v && v->refs>0 && !tm.locked);
    v->refs--; tm.puts++;
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
    assert(!diag_locked && !tm.locked && tm.gets==tm.puts);
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
