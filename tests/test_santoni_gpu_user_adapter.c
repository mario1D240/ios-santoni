/* Actual scalar devfs adapter methods, with CPU-only XNU API contracts. */
#include "santoni_gpu_core.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdarg.h>
#ifndef __unused
#define __unused __attribute__((unused))
#endif
typedef int wait_result_t;
#define LCK_GRP_DECLARE(name,label) int name __attribute__((unused))
#define LCK_MTX_DECLARE(name,group) pthread_mutex_t name=PTHREAD_MUTEX_INITIALIZER
static _Thread_local unsigned queue_depth;
static void lck_mtx_lock(pthread_mutex_t *lock)
{assert(!queue_depth && !pthread_mutex_lock(lock));queue_depth++;}
static void lck_mtx_unlock(pthread_mutex_t *lock)
{assert(queue_depth==1);queue_depth--;assert(!pthread_mutex_unlock(lock));}
static _Atomic unsigned wakes, terminated;
static _Atomic(void *) last_event;
static void (*wake_hook)(void);
static uint64_t (*time_hook)(void);
static void (*wait_hook)(uint32_t);
static int (*print_hook)(const char *,va_list);
static void thread_wakeup(void *event) {assert(!queue_depth && event);last_event=event;wakes++;if(wake_hook)wake_hook();}
static void thread_terminate_self(void) {assert(!queue_depth);terminated++;}
static uint64_t now_us(void *ctx) {(void)ctx;if(time_hook)return time_hook();assert(false);return 0;}
static void sgpu_kernel_wait_us(void *ctx,uint32_t delay) {(void)ctx;if(wait_hook){wait_hook(delay);return;}assert(false);}
static struct user_sg {uint32_t mode,g3,stock_unsecure,stock_pixels,session,user,user_test;} sg;
static uint32_t option;
static uint32_t test_option;
static bool parse_present=true;
static bool test_parse_present=true;
static bool PE_parse_boot_argn(const char *name,void *out,unsigned bytes)
{
    assert(bytes==4 && !*(uint32_t *)out);
    if(!strcmp(name,"santonigpu_user_test")) {
        if(test_parse_present)memcpy(out,&test_option,4);
        return test_parse_present;
    }
    assert(!strcmp(name,"santonigpu_user"));
    if(parse_present) memcpy(out,&option,4);
    return parse_present;
}
#include "fixtures/santoni_gpu_user_platform.h"
static int adapter_printf(const char *format,...)
{
    va_list args;va_start(args,format);
    int result=print_hook ? print_hook(format,args) : vprintf(format,args);
    va_end(args);return result;
}
#define printf adapter_printf
#include "santoni_gpu_user_adapter_actual.h"
#undef printf

static struct sgpu_user_packet packet(uint32_t id)
{return (struct sgpu_user_packet){.version=SGPU_USER_VERSION,.bytes=SGPU_USER_BYTES,.id=id};}
static int invoke(uint32_t command,struct sgpu_user_packet *packet)
{return sgpu_user_ioctl(makedev(77,0),command,(caddr_t)(void *)packet,0,NULL);}
static void ready(void)
{
    sg=(struct user_sg){.mode=3,.g3=1,.stock_unsecure=1,.stock_pixels=1,.session=1,.user=1};
    assert(sgpu_session_queue_init(&session_queue));
    sgpu_session_producer(NULL,0);
    assert(terminated==1 && sgpu_user_published && sgpu_user_major==77);
    assert(host_namespace_calls==2 && !session_queue.status.admitted && !host_task_refs);
}
static void opened(void)
{
    ready();assert(!sgpu_user_open(makedev(77,0),0,0,NULL));
    assert(host_task_refs==1 && sgpu_user_client.owner==(uint64_t)(uintptr_t)host_task);
}
static void complete(uint32_t id)
{
    struct sgpu_session_request request;
    lck_mtx_lock(&sgpu_session_lock);
    assert(sgpu_session_take(&session_queue,&request) && request.id==id);
    assert(sgpu_session_commit(&session_queue,id));
    struct sgpu_session_result result={.state=SG_REQUEST_COMPLETE,.sequence=id+2,
        .wptr=170+11*id,.writes=4,.publish_attempted=true};
    assert(sgpu_session_finish(&session_queue,id,&result));
    lck_mtx_unlock(&sgpu_session_lock);
}
static _Atomic unsigned successes;
static void *race_open(void *arg)
{
    (void)arg;
    int result=sgpu_user_open(makedev(77,0),0,0,NULL);
    assert(result==0 || result==EBUSY);
    if(!result) successes++;
    return NULL;
}
static void *race_submit(void *arg)
{
    for(unsigned i=0;i<2;i++) {
        struct sgpu_user_packet p=packet(0);p.value[0]=(uint32_t)(uintptr_t)arg+i;
        assert(!invoke(SGPU_USER_SUBMIT,&p) && !p.rc);
        successes++;
    }
    return NULL;
}

int main(int argc,char **argv)
{
    assert(argc==2);unsigned scenario=(unsigned)strtoul(argv[1],NULL,10);
    if(scenario==0) {
        const uint32_t options[]={0,1,2,UINT32_MAX};
        for(unsigned mode=0;mode<5;mode++) for(unsigned mask=0;mask<16;mask++)
            for(unsigned i=0;i<4;i++) {
                sg=(struct user_sg){.session=mask&1,.g3=(mask>>1)&1,
                    .stock_pixels=(mask>>2)&1,.stock_unsecure=(mask>>3)&1,.user=99};
                option=options[i];
                bool allowed=!option || (option==1 && mode==3 && mask==15);
                assert(sgpu_user_options(mode)==allowed);
                assert(sg.user==(unsigned)(option==1 && allowed));
                assert(sg.session==(mask&1) && sg.g3==((mask>>1)&1));
            }
        sg.user=99;parse_present=false;option=1;
        assert(sgpu_user_options(3) && !sg.user && !host_namespace_calls);
    } else if(scenario==1) {
        ready();
        assert(!sgpu_user_publish() && host_namespace_calls==2);
        host_root=false;assert(sgpu_user_open(makedev(77,0),0,0,NULL)==EACCES);
        assert(!host_task_refs && !sgpu_user_client.attempted);
        host_root=true;
        assert(sgpu_user_open(makedev(77,1),0,0,NULL)==ENXIO && !host_task_refs);
        sg.user=0;assert(sgpu_user_open(makedev(77,0),0,0,NULL)==ENXIO);sg.user=1;
        assert(!sgpu_user_open(makedev(77,0),0,0,NULL) && host_task_refs==1);
        assert(sgpu_user_open(makedev(77,0),0,0,NULL)==EBUSY && host_task_refs==1);
    } else if(scenario==2) {
        opened();struct sgpu_user_packet p=packet(0),original=p;
        struct sgpu_session_queue saved=session_queue;
        host_task=(task_t)(uintptr_t)0x2020;
        assert(invoke(SGPU_USER_INFO,&p)==EACCES && !memcmp(&p,&original,sizeof(p)));
        assert(!memcmp(&session_queue,&saved,sizeof(saved)));
        host_task=(task_t)(uintptr_t)0x1010;
        assert(invoke(0xffffffffu,&p)==EINVAL && invoke(SGPU_USER_INFO,NULL)==EINVAL);
        assert(sgpu_user_ioctl(makedev(77,0),((u_long)1<<32)|SGPU_USER_INFO,(caddr_t)(void *)&p,0,NULL)==EINVAL);
        assert(!invoke(SGPU_USER_INFO,&p) && p.state==SG_SESSION_READY && !p.admitted);
        assert(!p.value[0] && !p.reserved && !wakes && host_task_refs==1);
    } else if(scenario==3) {
        opened();
        for(unsigned i=0;i<4;i++) {
            struct sgpu_user_packet p=packet(0);p.value[0]=0xa5070000u+i;
            assert(!invoke(SGPU_USER_SUBMIT,&p) && !p.rc && p.id==i+1);
            memset(&p,0xcc,sizeof(p));assert(session_queue.entry[i].value[0]==0xa5070000u+i);
        }
        struct sgpu_user_packet p=packet(0);
        assert(!invoke(SGPU_USER_SUBMIT,&p) && p.rc==SG_SESSION_FULL && wakes==5);
        assert(last_event==&session_queue_event);
        complete(1);p=packet(1);
        assert(!invoke(SGPU_USER_POLL,&p) && p.result_seq==3 && p.result_writes==4);
    } else if(scenario==4) {
        opened();struct sgpu_user_packet p=packet(0);
        assert(!invoke(SGPU_USER_SUBMIT,&p));
        host_task=(task_t)(uintptr_t)0x2020;
        assert(!sgpu_user_close(makedev(77,0),0,0,NULL));
        assert(sgpu_user_client.closed && host_task_refs==1 && last_event==&session_queue_event);
        struct sgpu_session_request request;assert(!sgpu_session_take(&session_queue,&request));
        assert(session_queue.status.cancelled==1 && session_queue.status.reason==SG_SESSION_CLOSE);
        host_task=(task_t)(uintptr_t)0x1010;p=packet(0);
        assert(!invoke(SGPU_USER_SUBMIT,&p) && p.rc==SG_SESSION_IS_CLOSED);
        assert(sgpu_user_open(makedev(77,0),0,0,NULL)==EBUSY && host_task_refs==1);
    } else if(scenario==5) {
        opened();
        for(unsigned i=1;i<=32;i++) {
            struct sgpu_user_packet p=packet(0);p.value[0]=i;
            assert(!invoke(SGPU_USER_SUBMIT,&p) && !p.rc && p.id==i);
            complete(i);p=packet(i);
            assert(!invoke(SGPU_USER_POLL,&p) && p.result_seq==i+2 && p.result_wptr==170+i*11);
        }
        struct sgpu_user_packet p=packet(0);
        assert(!invoke(SGPU_USER_INFO,&p) && p.state==SG_SESSION_CLOSED && p.reason==SG_SESSION_QUOTA);
        assert(p.completed==32 && p.writes==128 && p.last_seq==34 && p.wptr==522);
        assert(!sgpu_user_close(makedev(77,0),0,0,NULL) && session_queue.status.reason==SG_SESSION_QUOTA);
    } else if(scenario==6 || scenario==7) {
        sg.user=1;assert(sgpu_session_queue_init(&session_queue));
        host_publication_failure=scenario-5;sgpu_session_producer(NULL,0);
        assert(terminated==1 && !sgpu_user_published && !host_task_refs && !session_queue.status.admitted);
        struct sgpu_session_request request;assert(!sgpu_session_take(&session_queue,&request));
        assert(session_queue.status.state==SG_SESSION_CLOSED && session_queue.status.reason==SG_SESSION_CLOSE);
        assert(wakes==1 && last_event==&session_queue_event);
    } else if(scenario==8) {
        ready();pthread_t threads[8];
        for(unsigned i=0;i<8;i++) assert(!pthread_create(&threads[i],NULL,race_open,NULL));
        for(unsigned i=0;i<8;i++) assert(!pthread_join(threads[i],NULL));
        assert(successes==1 && host_task_refs==1 && sgpu_user_client.attempted);
    } else if(scenario==9) {
        opened();pthread_t threads[2];
        for(unsigned i=0;i<2;i++) assert(!pthread_create(&threads[i],NULL,race_submit,(void *)(uintptr_t)(100+i*2)));
        for(unsigned i=0;i<2;i++) assert(!pthread_join(threads[i],NULL));
        assert(successes==4 && session_queue.status.admitted==4 && session_queue.status.outstanding==4);
        for(unsigned i=1;i<=4;i++) complete(i);
        assert(session_queue.status.completed==4 && host_task_refs==1);
    } else assert(false);
    assert(!queue_depth);
    puts("user adapter: scalar devfs ownership/lifecycle/lock contracts passed");
    return 0;
}
