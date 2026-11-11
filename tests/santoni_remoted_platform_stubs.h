/* Explicit host contracts for the new exec-local Santoni workaround.
 * These CPU/VFS/signature services do not emulate a device or authenticate files.
 */
#ifndef SANTONI_REMOTED_PLATFORM_STUBS_H
#define SANTONI_REMOTED_PLATFORM_STUBS_H
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

/* The CS bits used by the workaround match XNU8796 and the inspected kernel. */
#define CS_VALID 0x00000001u
#define CS_ADHOC 0x00000002u
#define CS_HARD 0x00000100u
#define CS_KILL 0x00000200u
#define CS_ENFORCEMENT 0x00001000u
#define CS_KILLED 0x01000000u
#define CS_PLATFORM_BINARY 0x04000000u
#define CS_SIGNED 0x20000000u
#define CS_ALLOWED_MACHO (CS_ADHOC | CS_HARD | CS_KILL)
#define VREG 1
#define VDIR 2
#define VCHR 4
#define MNT_RDONLY 0x1u
#define MNT_ROOTFS 0x4000u
#define TUNABLE(type, name, argument, initial) type name = initial
#define TRUE 1
#define FALSE 0
#define XNU_TARGET_OS_OSX 1
#define DEVELOPMENT 1
#define DEBUG 0
#define KERN_SUCCESS 0
#define KERN_FAILURE 5
#define IMGPF_SPAWN 2
#define PLATFORM_IOS 2
#define IPC_PORT_NULL 0
#define IPC_PORT_VALID(p) ((p) != IPC_PORT_NULL)
#define NULLVP NULL
#define CSSLOT_SIGNATURESLOT 0x10000
#define CSMAGIC_BLOBWRAPPER 0xfade0b01u
#define CS_CDHASH_LEN 20
#define CS_CDHASH_STRING_SIZE 41
#define SIGKILL 9
#define DBG_BSD_PROC 0
#define BSD_PROC_EXITREASON_CREATE 0
#define DBG_FUNC_NONE 0
#define OS_REASON_EXEC 1
#define OS_REASON_CODESIGNING 2
#define EXEC_EXIT_REASON_SECURITY_POLICY 1
#define EXEC_EXIT_REASON_WRONG_PLATFORM 2
#define EXEC_EXIT_REASON_TASKGATED_OTHER 3
#define EXEC_EXIT_REASON_MACHINE_THREAD 4
#define CODESIGNING_EXIT_REASON_TASK_ACCESS_PORT 5
#define CODESIGNING_EXIT_REASON_TASKGATED_INVALID_SIG 6
#define BSDDBG_CODE(a, b) 0
#define KERNEL_DEBUG_CONSTANT(...) ((void)0)
#define os_log(...) ((void)0)

typedef int kern_return_t;
typedef uintptr_t mach_port_t;
typedef int boolean_t;
struct mount { uint64_t flags; };
typedef struct mount *mount_t;
struct cs_blob {
    uint32_t csb_flags;
    unsigned char csb_platform_binary;
    const void *csb_mem_kaddr;
    size_t csb_mem_size;
    const void *csb_entitlements_blob;
    const void *csb_der_entitlements_blob;
};
struct vnode {
    int type;
    mount_t mount;
    const char *path;
    int path_error;
    int path_length;
    bool override_length;
    bool missing_nul;
    struct cs_blob *blob;
};
struct task { bool platform; bool enforced; };
struct proc {
    struct vnode *p_textvp;
    int64_t p_textoff;
    uint32_t flags;
    int pid;
    char p_name[32];
    struct task task;
    bool locked;
};
typedef struct proc *proc_t;
struct reason { unsigned ordinal; };
typedef struct reason *os_reason_t;
#define OS_REASON_NULL NULL
struct _posix_spawnattr { uint32_t psa_platform; };
struct image_params {
    uint32_t ip_flags;
    uint32_t ip_csflags;
    int ip_mac_return;
    os_reason_t ip_cs_error;
    struct _posix_spawnattr *ip_px_sa;
    struct vnode *ip_vp;
    int64_t ip_arch_offset;
    void *ip_new_thread;
};

static struct {
    unsigned api_calls, path_calls, flag_updates, platform_calls, lock_calls;
    unsigned unlock_calls, log_calls, platform_logs, kills, access_calls;
    int constraint_error, proc_error, thread_error, access_error, taskgated_error;
    uint32_t platform;
    mach_port_t access_port;
    bool cms;
    char platform_log[1024];
} services;
static proc_t target;
static struct reason reasons[16];
static unsigned reason_count;
static bool unentitled_ios_sim_launch;
static int platform_exec_logging;

static int csproc_get_platform_binary(struct proc *p);
static struct cs_blob *csproc_get_blob(struct proc *p);

static int proc_getpid(proc_t p) { services.api_calls++; return p->pid; }
static void proc_name(int pid, char *name, int size)
{
    services.api_calls++;
    assert(target != NULL && pid == target->pid && size == 32);
    memcpy(name, target->p_name, 32);
}
static uint32_t proc_getcsflags(proc_t p) { services.api_calls++; return p->flags; }
static int vnode_vtype(struct vnode *vp) { services.api_calls++; return vp->type; }
static mount_t vnode_mount(struct vnode *vp) { services.api_calls++; return vp->mount; }
static uint64_t vfs_flags(mount_t mp) { services.api_calls++; return mp->flags; }
static int vn_getpath(struct vnode *vp, char *path, int *len)
{
    services.api_calls++;
    services.path_calls++;
    assert(!target->locked);
    size_t n = strlen(vp->path) + 1;
    if (n > (size_t)*len) {
        *len = (int)n;
        return ENOSPC;
    }
    memcpy(path, vp->path, n);
    if (vp->missing_nul) path[n - 1] = 'x';
    *len = vp->override_length ? vp->path_length : (int)n;
    return vp->path_error;
}
static struct cs_blob *ubc_cs_blob_get(struct vnode *vp, int a, int b, int64_t off)
{
    services.api_calls++;
    assert(vp != NULL && a == -1 && b == -1 && off == 0);
    return vp->blob;
}
static void proc_lock(proc_t p)
{
    assert(!p->locked);
    p->locked = true;
    services.lock_calls++;
}
static void proc_unlock(proc_t p)
{
    assert(p->locked);
    p->locked = false;
    services.unlock_calls++;
}
static void proc_csflags_set(proc_t p, uint32_t flags)
{
    if (flags == CS_PLATFORM_BINARY) assert(p->locked);
    services.flag_updates++;
    p->flags |= flags;
}
static void proc_csflags_update(proc_t p, uint32_t flags)
{
    assert(p->locked);
    p->flags = flags;
}
static struct task *proc_task(proc_t p) { return &p->task; }
static struct task *proc_get_task_raw(proc_t p) { return &p->task; }
static struct task *get_task_map(struct task *t) { return t; }
static void task_set_platform_binary(struct task *t, boolean_t enabled)
{
    assert(t == &target->task && !target->locked && enabled == TRUE);
    services.platform_calls++;
    t->platform = true;
}
static void vm_map_switch_protect(struct task *t, boolean_t enabled)
{ (void)t; (void)enabled; }
static void vm_map_cs_enforcement_set(struct task *t, boolean_t enabled)
{ t->enforced = enabled; }
static os_reason_t os_reason_create(int ns, int code)
{
    (void)ns; (void)code;
    assert(reason_count < 16);
    reasons[reason_count].ordinal = reason_count + 1;
    return &reasons[reason_count++];
}
static int mac_proc_check_launch_constraints(proc_t p, struct image_params *img,
    os_reason_t *reason)
{
    (void)p; (void)img;
    *reason = services.constraint_error ? os_reason_create(1, 1) : NULL;
    return services.constraint_error;
}
static uint32_t proc_platform(proc_t p) { (void)p; return services.platform; }
static bool IOVnodeHasEntitlement(struct vnode *vp, int64_t off, const char *name)
{ (void)vp; (void)off; (void)name; return false; }
static int task_get_task_access_port(struct task *t, mach_port_t *port)
{
    (void)t;
    services.access_calls++;
    *port = services.access_port;
    return services.access_error;
}
static int __EXEC_WAITING_ON_TASKGATED_CODE_SIGNATURE_UPCALL__(mach_port_t port, int pid)
{ (void)port; (void)pid; return services.taskgated_error; }
static int ubc_cs_generation_check(struct vnode *vp) { (void)vp; return 0; }
static int ubc_cs_blob_revalidate(struct vnode *vp, struct cs_blob *blob,
    struct image_params *img, int flags, uint32_t platform)
{ (void)vp; (void)blob; (void)img; (void)flags; (void)platform; return 0; }
static const void *csblob_find_blob_bytes(const uint8_t *data, size_t size,
    unsigned slot, unsigned magic)
{ (void)data; (void)size; (void)slot; (void)magic; return services.cms ? data : NULL; }
static void proc_getcdhash(proc_t p, uint8_t *hash) { (void)p; memset(hash, 0, 20); }
static void cdhash_to_string(char *out, const uint8_t *hash)
{ (void)hash; memset(out, '0', 40); out[40] = 0; }
static int proc_process_signature(proc_t p, os_reason_t *reason)
{
    (void)p;
    if (services.proc_error) *reason = os_reason_create(1, 1);
    return services.proc_error;
}
static int thread_process_signature(void *thread, struct task *task)
{ (void)thread; (void)task; return services.thread_error; }
static void psignal_vfork_with_reason(proc_t p, struct task *task, void *thread,
    int sig, os_reason_t reason)
{ (void)p; (void)task; (void)thread; assert(sig == SIGKILL && reason != NULL); services.kills++; }
static void psignal_with_reason(proc_t p, int sig, os_reason_t reason)
{ (void)p; assert(sig == SIGKILL && reason != NULL); services.kills++; }
static void ipc_port_release_send(mach_port_t port) { (void)port; }
static int host_kernel_printf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    services.log_calls++;
    if (strncmp(format, "SANTONI PLATFORM:", 17) == 0) {
        services.platform_logs++;
        vsnprintf(services.platform_log, sizeof(services.platform_log), format, args);
    }
    va_end(args);
    return 0;
}
#define printf host_kernel_printf
#endif
