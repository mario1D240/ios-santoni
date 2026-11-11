/* Actual session adapter loop/producer with real pthread scheduling and a
 * faithful register-wait/unlock/block wake-token model. No XNU ABI claim. */
#include "santoni_gpu_session_model.h"
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <stdarg.h>
#ifndef __unused
#define __unused __attribute__((unused))
#endif
typedef int wait_result_t;
typedef pthread_t thread_t;
/* XNU8796 osfmk/kern/kern_types.h: THREAD_WAITING is -1, not 1
 * (1 is THREAD_TIMED_OUT). Preserve the actual signed wait_result_t ABI. */
enum { KERN_SUCCESS=0, THREAD_UNINT=0, THREAD_WAITING=-1 };
#define THREAD_CONTINUE_NULL NULL
#define LCK_GRP_DECLARE(name, label) int name __attribute__((unused))
#define LCK_MTX_DECLARE(name, group) pthread_mutex_t name=PTHREAD_MUTEX_INITIALIZER
static pthread_mutex_t *queue_lock_address;
static _Thread_local unsigned queue_depth;
static void lck_mtx_lock(pthread_mutex_t *lock)
{ assert(!pthread_mutex_lock(lock));if(lock==queue_lock_address)queue_depth++; }
static void lck_mtx_unlock(pthread_mutex_t *lock)
{ if(lock==queue_lock_address){assert(queue_depth==1);queue_depth--;}assert(!pthread_mutex_unlock(lock)); }
static pthread_mutex_t event_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t event_cond=PTHREAD_COND_INITIALIZER;
static unsigned wake_generation, registrations, blocks, force_wakes;
static _Thread_local unsigned wait_generation;
static bool fail_start;
static void (*producer_fn)(void *,wait_result_t);
static pthread_t producer_thread;
static wait_result_t assert_wait(void *event,unsigned mode)
{
    assert(event && mode==THREAD_UNINT);
    lck_mtx_lock(&event_lock);wait_generation=wake_generation;registrations++;
    if(force_wakes) {force_wakes--;wake_generation++;}
    lck_mtx_unlock(&event_lock);return THREAD_WAITING;
}
static void thread_wakeup(void *event)
{
    assert(event);lck_mtx_lock(&event_lock);wake_generation++;
    pthread_cond_broadcast(&event_cond);lck_mtx_unlock(&event_lock);
}
static void thread_block(void *continuation)
{
    assert(!continuation);sched_yield();lck_mtx_lock(&event_lock);blocks++;
    while(wait_generation==wake_generation) assert(!pthread_cond_wait(&event_cond,&event_lock));
    lck_mtx_unlock(&event_lock);
}
static void *run_producer(void *arg) {producer_fn(arg,0);return NULL;}
static int kernel_thread_start(void (*fn)(void *,wait_result_t),void *arg,thread_t *out)
{
    if(fail_start)return 1;
    producer_fn=fn;assert(!pthread_create(out,NULL,run_producer,arg));producer_thread=*out;return KERN_SUCCESS;
}
static void thread_deallocate(thread_t worker) {(void)worker;}
static void thread_terminate_self(void) {pthread_exit(NULL);}
static uint64_t now_us(void *ctx)
{ (void)ctx;struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000+t.tv_nsec/1000; }
static void sgpu_kernel_wait_us(void *ctx,uint32_t us)
{(void)ctx;assert(us==10000);struct timespec t={.tv_nsec=100000};nanosleep(&t,NULL);}
static void sgpu_failure_summary(const char *s,const struct sgpu_failure *f) {(void)s;(void)f;}
static struct {uint32_t mode,g3,stock_unsecure,stock_pixels,session,user,user_test;} sg;
#ifdef SGPU_USER_VERSION
#include "fixtures/santoni_gpu_user_platform.h"
#endif
static uint32_t option;
static unsigned scenario;
static bool PE_parse_boot_argn(const char *name,void *out,unsigned length)
{assert(!strcmp(name,"santonigpu_session") && length==4);memcpy(out,&option,4);return true;}
static bool adapter_execute(const uint32_t value[4],struct sgpu_session_result *out)
{
    bool ok=sgpu_session_execute(value,out);
    if(scenario==10 && ok) out->writes=0; /* rejected internal completion record */
    return ok;
}
static bool adapter_commit(struct sgpu_session_queue *q,uint32_t id)
{
    if(scenario==11) return false; /* unexpected internal commitment rejection */
    return sgpu_session_commit(q,id);
}
#define sgpu_session_execute adapter_execute
#define sgpu_session_commit adapter_commit
#include "santoni_gpu_session_adapter_actual.h"
#undef sgpu_session_commit
#undef sgpu_session_execute
static pthread_t owner_thread;
static bool close_injected;
static void check_worker_and_lock(void)
{
    assert(pthread_equal(owner_thread,pthread_self()));
    assert(!queue_depth); /* other producers may legitimately hold the mutex */
    /* Close at an actual worker callback, before commitment or after it.
     * This executes the real adapter's cancellation/finish paths, not a
     * second implementation of its loop. The GPU callback remains outside
     * the mutex; only the CPU close operation takes it. */
    if ((scenario==6 || scenario==7) && !close_injected) {
        lck_mtx_lock(&sgpu_session_lock);
        uint32_t id=session_queue.status.active;
        uint32_t want=scenario==6 ? SG_REQUEST_ACTIVE : SG_REQUEST_COMMITTED;
        if (id && session_queue.entry[id-1].result.state==want) {
            assert(sgpu_session_close(&session_queue,SGPU_SESSION_OWNER)==SG_SESSION_OK);
            close_injected=true;
        }
        lck_mtx_unlock(&sgpu_session_lock);
        if (close_injected) thread_wakeup(&session_queue_event);
    }
}

int main(int argc,char **argv)
{
    assert(argc==2);scenario=(unsigned)atoi(argv[1]);assert(scenario<12);
    fail_start=scenario==1;force_wakes=scenario==2?10:0;
    for(unsigned mode=0;mode<5;mode++)for(unsigned stock=0;stock<3;stock++)
        for(unsigned pixels=0;pixels<3;pixels++)for(unsigned g3=0;g3<3;g3++)for(option=0;option<3;option++) {
            sg.g3=g3;sg.stock_unsecure=stock;sg.stock_pixels=pixels;sg.session=99;
            bool enabled=mode==3 && stock==pixels && pixels==g3 && g3==option && option==1;
            assert(sgpu_session_options(mode)==(!option || enabled));assert(sg.session==(unsigned)enabled);
        }
    struct session_model model={0};init(&model.base,SECURE_GPU);struct sgpu_report report;
    assert(boot_session(&model,&report,1));clobber_stack();model.active=true;
    /* Fail live readiness, WPTR echo, RPTR completion, final faults or a
     * returning cache callback that consumed the request deadline. */
    if(scenario==3) model.injection=1;
    if(scenario==4) model.injection=9;
    if(scenario==5) model.injection=4;
    if(scenario==8) model.injection=3;
    if(scenario==9) model.injection=11;
    owner_thread=pthread_self();queue_lock_address=&sgpu_session_lock;
    session_callback_check=check_worker_and_lock;
    sgpu_session_loop();
    if(fail_start) assert(session_queue.status.state==SG_SESSION_FAULTED && !session_queue.status.admitted);
    else {
        assert(!pthread_join(producer_thread,NULL));
        if(scenario==0 || scenario==2) {
            assert(session_queue.status.state==SG_SESSION_CLOSED && session_queue.status.completed==32);
            assert(session_queue.status.submitted==32 && session_queue.status.wptr==522 && session_queue.status.writes==128);
            assert(registrations>=2 && blocks>=2 && session_idle_count>=2);
        } else if(scenario==6 || scenario==7) {
            unsigned completed=scenario==7;
            assert(close_injected && session_queue.status.state==SG_SESSION_CLOSED);
            assert(session_queue.status.reason==SG_SESSION_CLOSE && !session_queue.status.error);
            assert(session_queue.status.completed==completed && session_queue.status.committed==completed);
            assert(session_queue.status.submitted==completed && model.ibs==2+completed);
        } else {
            unsigned published=scenario==4 || scenario==5 || scenario==8 || scenario==10;
            assert(session_queue.status.state==SG_SESSION_FAULTED && session_queue.status.reason==SG_SESSION_FAILURE);
            assert(session_queue.status.first_failed_id==1 && session_queue.status.failed==1);
            assert(!session_queue.status.completed && session_queue.status.submitted==published);
            assert(model.ibs==2+published);
            assert(session_queue.status.error==(scenario==3 ? SG_BAD_SMMU :
                scenario==5 || scenario==9 ? SG_COMMAND_TIMEOUT :
                scenario>=10 ? SG_BAD_MODE : SG_FAULT));
        }
    }
    assert(!session_queue.status.active && !session_queue.status.outstanding);
    assert(session_queue.status.admitted==session_queue.status.completed+
        session_queue.status.cancelled+session_queue.status.failed);
    struct sgpu_session_queue frozen=session_queue;
    unsigned before=model.accesses;
    assert(sgpu_session_close(&session_queue,SGPU_SESSION_OWNER)==SG_SESSION_OK);
    assert(!sgpu_session_prepare());
    assert(!memcmp(&session_queue,&frozen,sizeof(frozen)) && model.accesses==before && !model.base.frees);
    for(unsigned id=1;id<=session_queue.status.admitted;id++) {
        struct sgpu_session_result r;
        assert(sgpu_session_get(&session_queue,SGPU_SESSION_OWNER,id,&r));
        assert(r.state==SG_REQUEST_COMPLETE || r.state==SG_REQUEST_CANCELLED || r.state==SG_REQUEST_FAILED);
    }
    destroy(&model.base);
    puts("PASS actual session adapter: opt-ins, producer/wakeup, close/fault accounting, immutable terminal retention");
    return 0; /* also valid when reused under a different entrypoint name */
}
