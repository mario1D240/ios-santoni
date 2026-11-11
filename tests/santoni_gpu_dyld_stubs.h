#include <stdint.h>
#include <stddef.h>
struct proc;struct task;
typedef struct proc *proc_t;typedef struct task *task_t;
typedef uint64_t user_addr_t;
#define ENOPOLICY 103
#define EFAULT 14
#ifdef __cplusplus
extern "C" {
#endif
proc_t current_proc(void);
task_t current_task(void);
int proc_pid(proc_t);
unsigned proc_getuid(proc_t);
int PE_parse_boot_argn(const char *,void *,unsigned);
uint64_t santoni_gpu_graphics_dyld_flags(proc_t);
int copyin(user_addr_t,void *,size_t);
int copyout(const void *,user_addr_t,size_t);
int printf(const char *,...);
int fixture_dyld_printf(const char *,...);
int fixture_policy(proc_t,int,user_addr_t);
unsigned santoni_gpu_dyld_trace_begin(proc_t,unsigned);
void santoni_gpu_dyld_trace_event(proc_t,unsigned,unsigned,int);
void fixture_reset_trace(void);
void proc_selfname(char *,int);
int32_t OSAddAtomic(int32_t,volatile int32_t *);
int OSCompareAndSwap(uint32_t,uint32_t,volatile uint32_t *);
#ifdef __cplusplus
}
bool gfx_renderer_task(task_t);
#endif
