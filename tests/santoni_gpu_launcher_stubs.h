/* Host contracts for the actual reconstructed launcher/VFS functions.
 * These are explicit CPU/VFS models, not a kernel or hardware simulation. */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <assert.h>
#include <stdarg.h>
#include "santoni_gpu_launch.h"
#ifndef __unused
#define __unused __attribute__((unused))
#endif
#define TRUE 1
#define FALSE 0
#define NULLVP NULL
#define MFSNAMELEN 16
#define UID_ROOT 0
#define DEVFS_CHAR 1
#define KMA_DATA 1
#define KMA_NOPAGEWAIT 2
#define VM_KERN_MEMORY_IOKIT 1
#define KERN_SUCCESS 0
#define MNT_RDONLY 1u
#define MNT_NOSUID 2u
#define MNT_NOATIME 4u
#define MNT_UPDATE 8u
#define MNT_RELOAD 16u
#define MNT_ROOTFS 32u
#define MNT_NOEXEC 64u
#define MNT_FORCE 128u
#define MNTK_KERNEL_MOUNT 1u
#define FORCECLOSE 1
#define Z_WAITOK 1
#define Z_ZERO 2
#define Z_NOFAIL 4
#define LCK_ATTR_NULL NULL
#define VREG 1
#define VDIR 2
#define VNFS_CANTCACHE 1
#define VNFS_NOCACHE 2
#define VNCREATE_FLAVOR 1
#define VCREATESIZE sizeof(struct vnode_fsparam)
#define MOCKFS_ROOT 0
#define MOCKFS_DEV 1
#define MOCKFS_FILE 2
#define LOOKUP 0
#define VREAD 0400
#define VWRITE 0200
#define VEXEC 0100
#define RB_SINGLE 1
#define CONFIG_MEMORYSTATUS 0
#define DEBUG 0
#define DEVELOPMENT 1
#define VM_FLAGS_ANYWHERE 0
#define VM_KERN_MEMORY_NONE 0
#define USER_ADDR_NULL 0
#define USER_ADDR_ALIGN(x,n) (((x)+(n)-1)&~((n)-1))
#define VATTR_RETURN(v,f,x) ((v)->f=(x))
typedef uint64_t vm_offset_t, vm_size_t, user_addr_t, user64_addr_t;
typedef uint64_t mach_vm_offset_t, mach_vm_size_t;
typedef uint32_t user32_addr_t;
typedef int kern_return_t, boolean_t, lck_mtx_t;
typedef void *vm_map_t, *DTEntry, *memory_object_control_t;
typedef struct model_proc { int pid; } *proc_t;
typedef struct model_context { bool kernel; } *vfs_context_t;
typedef struct mount *mount_t;
typedef struct vnode *vnode_t;
typedef struct mockfs_fsnode *mockfs_fsnode_t;
typedef struct mockfs_mount *mockfs_mount_t;
struct vnode { void *v_data; int v_type; mount_t mp; int refs;
    struct specinfo { uint64_t si_devsize; } *v_specinfo; };
struct mount { uint32_t mnt_flag, mnt_kern_flag; void *mnt_data;
    vnode_t mnt_devvp; const char *name; };
struct mockfs_fsnode { uint8_t type; uint64_t size; mount_t mnt; vnode_t vp;
    mockfs_fsnode_t parent, child_a, child_b; };
struct mockfs_mount { lck_mtx_t mockfs_mnt_mtx; mockfs_fsnode_t mockfs_root;
    boolean_t mockfs_memory_backed, mockfs_physical_memory;
    uint32_t mockfs_memdev_base; uint64_t mockfs_memdev_size;
    uint64_t santoni_probe_kva; uint32_t santoni_probe_file_bytes, santoni_probe_span_bytes;
    boolean_t santoni_probe_failed; };
struct vnode_fsparam { mount_t vnfs_mp; int vnfs_vtype; const char *vnfs_str;
    vnode_t vnfs_dvp; void *vnfs_fsnode, *vnfs_vops; int vnfs_markroot, vnfs_marksystem;
    int vnfs_rdev; uint64_t vnfs_filesize; void *vnfs_cnp; int vnfs_flags; };
struct componentname { int cn_nameiop, cn_namelen; char *cn_nameptr; };
struct vnop_lookup_args { vnode_t a_dvp; vnode_t *a_vpp;
    struct componentname *a_cnp; vfs_context_t a_context; };
struct vnode_attr { uint64_t va_nlink, va_mode, va_uid, va_gid, va_fileid;
    uint64_t va_total_size, va_total_alloc, va_data_size, va_data_alloc; };
struct vnop_getattr_args { vnode_t a_vp; struct vnode_attr *a_vap; };
struct execve_args { user_addr_t fname, argp, envp; };
struct cdevsw { void *d_open,*d_close,*d_read,*d_write,*d_ioctl,*d_stop,*d_reset;
    void *d_ttys,*d_select,*d_mmap,*d_strategy,*d_reserved_1,*d_reserved_2; int d_type; };
#define eno_opcl NULL
#define eno_rdwrt NULL
#define eno_ioctl NULL
#define eno_stop NULL
#define eno_reset NULL
#define eno_select NULL
#define eno_mmap NULL
#define eno_strat NULL
#define eno_getc NULL
#define eno_putc NULL
enum { kSuccess=0 };
static int kernel_map_storage, kernel_pmap_storage, mockfs_mtx_grp;
static void *kernel_map=&kernel_map_storage,*kernel_pmap=&kernel_pmap_storage;
static void *mockfs_vnodeop_p;
static unsigned page_shift=12, page_size=4096;
static int boothowto;
static vnode_t rootvnode;
static struct model_proc model_proc={1};
static struct model_context model_context={true};
static struct {
    struct sgpu_launch_options options;
    const char *suffix;
    unsigned allocations,frees,dt,root_lookups,nodes,mounts,clean,pager,creates,puts;
    unsigned locked,lock_init,lock_destroy,tree_alloc,tree_free,execs,vflushes;
    int dt_fail,alloc_fail,major_fail,node_fail,mount_fail,pager_fail,ubc_fail,create_fail;
    int noncontig,missing_last,tree_fail,adopt_fail,exec_fail,copyout_fail;
    uint64_t kva,pa;
    unsigned char *probe,*memory;
    struct mount root_mount,probe_mount;
    unsigned char scratch[4096];
    char exec_paths[3][128],exec_arg[3][8];
} model;
static void panic(const char *s,...) __attribute__((noreturn));
static void panic(const char *s,...) { fprintf(stderr,"unexpected modeled panic: %s\n",s); abort(); }
static proc_t current_proc(void) { return &model_proc; }
static int proc_pid(proc_t p) { return p->pid; }
static bool proc_is64bit(proc_t p __unused) { return true; }
static vm_map_t current_map(void) { return kernel_map; }
static uint64_t vm_map_page_size(vm_map_t p __unused) { return 4096; }
static int mach_vm_allocate_kernel(vm_map_t p __unused,mach_vm_offset_t *out,
    mach_vm_size_t n,int f __unused,int tag __unused)
{ assert(n==4096); *out=(uintptr_t)model.scratch; return 0; }
static int copyout(const void *p,user_addr_t out,size_t n)
{ if (model.copyout_fail) return EFAULT; assert(out>=(uintptr_t)model.scratch &&
    out+n<=(uintptr_t)model.scratch+4096); memcpy((void *)(uintptr_t)out,p,n); return 0; }
static void set_security_token(proc_t p) { assert(p->pid==1); }
static int execve(proc_t p,struct execve_args *a,int *rv __unused)
{ assert(p->pid==1 && !a->envp && model.execs<3); unsigned i=model.execs++;
    snprintf(model.exec_paths[i],128,"%s",(char *)(uintptr_t)a->fname);
    user64_addr_t *argv=(void *)(uintptr_t)a->argp; assert(argv[0]==a->fname && !argv[2]);
    if (argv[1]) snprintf(model.exec_arg[i],8,"%s",(char *)(uintptr_t)argv[1]);
    return i==0?model.exec_fail:0; }
#define strlcpy model_strlcpy
#define strlcat model_strlcat
static size_t model_strlcpy(char *d,const char *s,size_t n)
{ size_t len=strlen(s); if(n) snprintf(d,n,"%s",s); return len; }
static size_t model_strlcat(char *d,const char *s,size_t n)
{ size_t len=strlen(d),more=strlen(s); if(len<n) snprintf(d+len,n-len,"%s",s); return len+more; }
static int PE_parse_boot_argn(const char *,void *,int);
static mount_t vnode_mount(vnode_t v) { return v->mp; }
static void vfs_name(mount_t m,char *s) { model.root_lookups++; snprintf(s,MFSNAMELEN,"%s",m->name); }
static int SecureDTLookupEntry(void *x __unused,const char *s,DTEntry *out)
{ assert(!strcmp(s,"/chosen")); model.dt++; *out=&model; return model.dt_fail; }
static int SecureDTGetProperty(DTEntry x,const char *s,const void **out,unsigned *n)
{ assert(x==&model && !strcmp(s,"santoni-gpu-el0-probe")); model.dt++;
    *out=model.probe;*n=16635; return model.dt_fail; }
static kern_return_t kmem_alloc_contig(void *m,vm_offset_t *out,vm_size_t n,
    unsigned a,unsigned b,unsigned c,unsigned flags,unsigned tag)
{ assert(m==kernel_map && n==20480 && !a && !b && !c &&
    flags==(KMA_DATA|KMA_NOPAGEWAIT) && tag==VM_KERN_MEMORY_IOKIT);
    model.allocations++; *out=model.alloc_fail?0:model.kva; return model.alloc_fail; }
static uint64_t pmap_find_phys(void *p,uint64_t kva)
{ assert(p==kernel_pmap && kva>=model.kva && kva<model.kva+20480);
    unsigned off=(unsigned)(kva-model.kva);
    if(model.missing_last && off==16384) return 0;
    return (model.pa+off+(model.noncontig && off==4096?4096:0))>>12; }
static void kmem_free(void *p,uint64_t kva,uint64_t n)
{ assert(p==kernel_map && kva==model.kva && n==20480); model.frees++; }
void CleanPoC_DcacheRegion_Force(vm_offset_t kva,size_t n)
{ assert(kva==model.kva && n==20480 && !model.nodes && !model.mounts);
    assert(!memcmp(model.memory,model.probe,16635));
    for(unsigned i=16635;i<20480;i++) assert(!model.memory[i]); model.clean++; }
static unsigned makedev(int major,int minor) { assert(major==42 && !minor);return 42; }
static int cdevsw_add(int n,const struct cdevsw *sw __unused)
{ assert(n==-1); return model.major_fail?-1:42; }
static void *devfs_make_node(unsigned dev,int type,unsigned uid,unsigned gid,
    unsigned mode,const char *s)
{ assert(dev==42 && type==DEVFS_CHAR && !uid && !gid && mode==0600 &&
    !strcmp(s,"sgpu/.mountpoint") && model.clean==1);model.nodes++; return model.node_fail?NULL:&model; }
static vfs_context_t vfs_context_kernel(void) { return &model_context; }
static bool vfs_context_iskernel(vfs_context_t c) { return c->kernel; }
static int kernel_mount(const char *,vnode_t,vnode_t,const char *,void *,size_t,int,uint32_t,vfs_context_t);
static void *model_kalloc(size_t n,int f __unused)
{ model.tree_alloc++; if(model.tree_fail && model.tree_alloc==(unsigned)model.tree_fail)return NULL;return calloc(1,n); }
#define kalloc_type(t,f) ((t *)model_kalloc(sizeof(t),f))
#define kfree_type(t,p) do { model.tree_free++; free(p); } while(0)
static void lck_mtx_init(int *m,void *g __unused,void *a __unused) { *m=0; model.lock_init++; }
static void lck_mtx_destroy(int *m,void *g __unused) { assert(!*m);model.lock_destroy++; }
static void lck_mtx_lock(int *m) { assert(!*m && !model.locked);*m=1;model.locked=1; }
static void lck_mtx_unlock(int *m) { assert(*m && model.locked);*m=0;model.locked=0; }
static int vnode_create(int f,size_t n,struct vnode_fsparam *p,vnode_t *out)
{ assert(f==VNCREATE_FLAVOR && n==VCREATESIZE && model.locked);model.creates++;
    if(model.create_fail)return ENOMEM;*out=calloc(1,sizeof(**out));
    (*out)->v_data=p->vnfs_fsnode;(*out)->v_type=p->vnfs_vtype;(*out)->mp=p->vnfs_mp;(*out)->refs=1;return 0; }
static int vnode_get(vnode_t v) { assert(model.locked); v->refs++;return 0; }
static void vnode_put(vnode_t v) { assert(!model.locked && v->refs>0);v->refs--;model.puts++; }
static memory_object_control_t ubc_getobject(vnode_t v __unused,int x) { assert(!x);return model.ubc_fail?NULL:&model; }
static int pager_map_to_phys_contiguous(memory_object_control_t c,uint64_t off,uint64_t kva,uint64_t n)
{ assert(c==&model && !off && kva==model.kva && n==20480 && model.clean==1 && !model.frees && model.locked);
    model.pager++;return model.pager_fail; }
static int vflush(mount_t m __unused,void *v __unused,int flags __unused) { model.vflushes++;return EBUSY; }
static int mockfs_fsnode_create(mount_t,uint8_t,mockfs_fsnode_t *);
static int mockfs_fsnode_destroy(mockfs_fsnode_t);
static int mockfs_fsnode_adopt(mockfs_fsnode_t,mockfs_fsnode_t);
static int mockfs_fsnode_orphan(mockfs_fsnode_t);
static int mockfs_fsnode_child_by_type(mockfs_fsnode_t,uint8_t,mockfs_fsnode_t *);
static int mockfs_fsnode_vnode(mockfs_fsnode_t,vnode_t *);
