/* Included after actual reconstructed sleh functions and explicit host stubs.
 * Tests exception routing and observation; no real exception/kernel executes. */
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

typedef uint32_t exception_type_t, fault_status_t, vm_prot_t;
typedef uint64_t mach_exception_data_type_t, vm_offset_t;
typedef unsigned mach_msg_type_number_t;
typedef int kern_return_t, expected_fault_handler_t;
typedef struct { uint64_t pc,sp,lr,far;uint32_t esr,cpsr;bool wide; } arm_saved_state_t;
struct vm_map { void *pmap; };
typedef struct vm_map *vm_map_t;
struct host_thread { int iotier_override;vm_map_t map;
    struct { int trr_fault_state; } t_rr_state;
    struct { uint32_t recover_esr;uint64_t recover_far;arm_saved_state_t *upcb; } machine;
};
typedef struct host_thread *thread_t;
typedef void *proc_t;
static struct vm_map user_map;
static vm_map_t kernel_map;
static struct host_thread thread;
static int init_object, other_object;
static void *initproc, *caller;
static uint32_t mode,enabled;
static bool have_mode,have_enabled,mounted,ready,interrupt_context;
static unsigned parse_calls,mount_calls,ready_calls,lines,triages,vm_calls,fast_calls;
static int fast_result,vm_result;
static exception_type_t delivered_exc;
static mach_exception_data_type_t delivered_code,delivered_address;
static char output[768];
static jmp_buf terminal;
#define PSR64_IS_USER(cpsr) ((cpsr)==0)
#define TRUE true
#define FALSE false
#define EXC_BAD_ACCESS 1
#define EXC_ARM_DA_ALIGN 0x101
#define EXC_ARM_SP_ALIGN 0x103
#define KERN_SUCCESS 0
#define KERN_FAILURE 5
#define KERN_ABORTED 14
#define KERN_INVALID_ADDRESS 1
#define KERN_MEMORY_ERROR 10
#define THROTTLE_LEVEL_NONE 0
#define TRR_FAULT_NONE 0
#define VM_PROT_EXECUTE 4
#define VM_KERN_MEMORY_NONE 0
#define THREAD_ABORTSAFE 0
#define FSC_ACCESS_FLAG_FAULT_L3 3
#define ESR_EC_MASK 0xfc000000u
#define ESR_EC_DABORT_EL0 0x24u
#define ESR_EC_SHIFT 26
#define __improbable(v) (v)
#define assertf(v,...) assert(v)

static bool is_saved_state64(const arm_saved_state_t *s) { return s->wide; }
static uint32_t get_saved_state_cpsr(const arm_saved_state_t *s) { return s->cpsr; }
static uint64_t get_saved_state_pc(const arm_saved_state_t *s) { return s->pc; }
static uint64_t get_saved_state_sp(const arm_saved_state_t *s) { return s->sp; }
static uint64_t get_saved_state_lr(const arm_saved_state_t *s) { return s->lr; }
static uint64_t get_saved_state_far(const arm_saved_state_t *s) { return s->far; }
static uint32_t get_saved_state_esr(const arm_saved_state_t *s) { return s->esr; }
static void set_saved_state_esr(arm_saved_state_t *s,uint32_t v) { s->esr=v; }
static void set_saved_state_far(arm_saved_state_t *s,uint64_t v) { s->far=v; }
static void *current_proc(void) { return caller; }
static int proc_isinitproc(proc_t p) { return p==initproc; }
static thread_t current_thread(void) { return &thread; }
static bool PE_parse_boot_argn(const char *name,void *out,int bytes) {
    assert(bytes==4);parse_calls++;
    if(!strcmp(name,"santonigpu")) { if(have_mode)memcpy(out,&mode,4);return have_mode; }
    assert(!strcmp(name,"santonigpu_user_exec"));
    if(have_enabled)memcpy(out,&enabled,4);return have_enabled;
}
static bool santoni_gpu_user_launch_mount_published(void) { mount_calls++;return mounted; }
static bool santoni_gpu_user_launch_worker_ready(uint32_t n) { assert(n==3);ready_calls++;return ready; }
static int host_printf(const char *fmt,...) __attribute__((format(printf,1,2)));
static int host_printf(const char *fmt,...) {
    va_list ap;va_start(ap,fmt);size_t used=strlen(output);
    int n=vsnprintf(output+used,sizeof(output)-used,fmt,ap);va_end(ap);
    assert(n>=0 && (size_t)n<sizeof(output)-used);lines++;return n;
}
static void panic_with_thread_kernel_state(const char *text,arm_saved_state_t *s) __attribute__((noreturn));
static void panic_with_thread_kernel_state(const char *text,arm_saved_state_t *s) { (void)text;(void)s;longjmp(terminal,2); }
static void panic(const char *text,...) __attribute__((noreturn));
static void panic(const char *text,...) { (void)text;longjmp(terminal,2); }
static void exception_triage(exception_type_t exc,mach_exception_data_type_t *codes,unsigned count) __attribute__((noreturn));
static void exception_triage(exception_type_t exc,mach_exception_data_type_t *codes,unsigned count) {
    assert(count==2);delivered_exc=exc;delivered_code=codes[0];delivered_address=codes[1];triages++;longjmp(terminal,1);
}
static void thread_exception_return(void) __attribute__((noreturn));
static void thread_exception_return(void) { longjmp(terminal,3); }
static bool ml_at_interrupt_context(void) { return interrupt_context; }
static bool is_vm_fault(fault_status_t f) { return f==1 || f==3; }
static bool is_translation_fault(fault_status_t f) { return f==1; }
static bool is_alignment_fault(fault_status_t f) { return f==0x21; }
static bool is_parity_error(fault_status_t f) { return f==0x18; }
static void thread_reset_pcs_done_faulting(thread_t t) { t->t_rr_state.trr_fault_state=TRR_FAULT_NONE; }
static uint64_t tbi_clear(uint64_t v) { return v&0x00ffffffffffffffull; }
static int arm_fast_fault(void *pmap,uint64_t address,uint32_t protection,bool af,bool user) {
    (void)pmap;(void)address;(void)protection;(void)af;assert(user);fast_calls++;return fast_result;
}
static int vm_fault(vm_map_t map,uint64_t addr,uint32_t prot,bool wiring,int memory,int abortsafe,void *pmap,int offset) {
    assert(map==&user_map && !wiring && memory==0 && abortsafe==0 && !pmap && !offset);
    (void)addr;(void)prot;vm_calls++;return vm_result;
}
#define printf host_printf
#include "santoni_gpu_user_fault_actual.h"
#undef printf

static arm_saved_state_t state;
static void reset(void) {
    state=(arm_saved_state_t){.pc=0x100001638,.sp=0x16ffffff000,.lr=0x10000261c,
        .far=0x16ffffff044,.esr=0x92000021,.wide=true};
    thread=(struct host_thread){.map=&user_map,.machine={.upcb=&state}};
    caller=initproc=&init_object;mode=3;enabled=1;
    have_mode=have_enabled=mounted=ready=true;interrupt_context=false;
    parse_calls=mount_calls=ready_calls=lines=triages=vm_calls=fast_calls=0;
    output[0]=0;vm_result=KERN_MEMORY_ERROR;fast_result=KERN_INVALID_ADDRESS;
    santoni_gpu_user_fault_reported=0;
}
static void route(unsigned kind,fault_status_t fault) {
    if(kind==0)handle_pc_align(&state);
    else if(kind==1)handle_sp_align(&state);
    else handle_user_abort(&state,state.esr,state.far,fault,0,0);
}
#define CHECK(v) do { if(!(v)) { fprintf(stderr,"fault contract line %d: %s\n",__LINE__,#v);return 1; } } while(0)
static int run(unsigned test) {
    reset();arm_saved_state_t before=state;
    if(test<14) {
        if(test==0)state.wide=false;
        if(test==1)state.cpsr=4;
        if(test==2)initproc=NULL;
        if(test==3)caller=&other_object;
        if(test==4)have_mode=false;
        if(test==5)mode=1;
        if(test==6)mode=2;
        if(test==7)mode=4;
        if(test==8)have_enabled=false;
        if(test==9)enabled=0;
        if(test==10)enabled=2;
        if(test==11)mounted=false;
        if(test==12)ready=false;
        santoni_gpu_user_fault(test==13?NULL:&state,1,0x101,state.far);
        CHECK(!lines && !santoni_gpu_user_fault_reported);
        if(test<=3 || test==13)CHECK(!parse_calls && !mount_calls && !ready_calls);
        return 0;
    }
    if(test==14) {
        santoni_gpu_user_fault(&state,1,0x101,0xfedcba9876543210ull);
        CHECK(lines==2 && santoni_gpu_user_fault_reported==1);
        CHECK(!strcmp(output,"SANTONI GPU: USER FAULT pc=0000000100001638 sp=0000016ffffff000 lr=000000010000261c\n"
            "SANTONI GPU: USER FAULT esr=92000021 far=0000016ffffff044 exc=1 code=0000000000000101 address=fedcba9876543210\n"));
        CHECK(!memcmp(&state,&before,sizeof(state)) && !triages);
        state.pc++;santoni_gpu_user_fault(&state,1,0x102,0);CHECK(lines==2);
        return 0;
    }
    unsigned kind=test==15?0:test==16?1:2;
    fault_status_t fault=test==17?0x21:1;
    if(test==19)vm_result=KERN_SUCCESS;
    if(test==20)vm_result=KERN_ABORTED;
    if(test==21) { fault=3;fast_result=KERN_SUCCESS; }
    if(test==22) { state.cpsr=4;kind=1; }
    if(test==23) { interrupt_context=true; }
    before=state;
    int stop=setjmp(terminal);
    if(!stop)route(kind,fault);
    if(test>=19 && test<=21)CHECK(!stop && !lines && !triages && !santoni_gpu_user_fault_reported);
    else if(test>=22)CHECK(stop==2 && !lines && !triages && !santoni_gpu_user_fault_reported);
    else {
        CHECK(stop==1 && lines==2 && triages==1 && delivered_exc==EXC_BAD_ACCESS);
        CHECK(delivered_code==(test<=15 || test==17?EXC_ARM_DA_ALIGN:test==16?EXC_ARM_SP_ALIGN:KERN_MEMORY_ERROR));
        CHECK(delivered_address==(test==15?state.pc:test==16?state.sp:state.far));
    }
    CHECK(!memcmp(&state,&before,sizeof(state)));
    return 0;
}
#ifndef SANTONI_FAULT_BASELINE
int main(void) {
    for(unsigned i=0;i<24;i++) { if(run(i))return 1;printf("PASS user-fault-%u\n",i); }
    return 0;
}
#else
int main(void) {
    for(unsigned kind=0;kind<3;kind++) {
        reset();int stop=setjmp(terminal);
        if(!stop)route(kind,0x21);
        CHECK(stop==1 && !lines && triages==1);
        printf("PASS user-fault-baseline-%u\n",kind);
    }
    return 0;
}
#endif
