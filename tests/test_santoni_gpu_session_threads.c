#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include "santoni_gpu_core.h"
static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
static struct sgpu_session_queue queue;
static void *produce(void *ctx)
{
    unsigned value=(unsigned)(uintptr_t)ctx;
    for(;;) {
        assert(!pthread_mutex_lock(&mutex));
        uint32_t data[4]={value,value+1,value+2,value+3},id=0;
        unsigned rc=sgpu_session_enqueue(&queue,1,1,data,&id);
        assert(queue.status.outstanding<=4 && queue.status.admitted<=32);
        assert(!pthread_mutex_unlock(&mutex));
        if(rc==SG_SESSION_IS_CLOSED || rc==SG_SESSION_AT_QUOTA)break;
        assert(rc==SG_SESSION_FULL || rc==SG_SESSION_OK);sched_yield();
    }
    return NULL;
}
int main(void)
{
    assert(sgpu_session_queue_init(&queue));pthread_t a,b;
    assert(!pthread_create(&a,NULL,produce,(void *)(uintptr_t)10));
    assert(!pthread_create(&b,NULL,produce,(void *)(uintptr_t)30));
    unsigned complete=0;
    while(complete<32) {
        pthread_mutex_lock(&mutex);struct sgpu_session_request request;
        bool taken=sgpu_session_take(&queue,&request);
        if(taken)assert(sgpu_session_commit(&queue,request.id));
        pthread_mutex_unlock(&mutex);
        if(!taken){sched_yield();continue;}
        assert(request.value[0]==10 || request.value[0]==30);
        for(unsigned i=1;i<4;i++)assert(request.value[i]==request.value[0]+i);
        struct sgpu_session_result r={.sequence=complete+3,.wptr=181+complete*11,
            .writes=4,.publish_attempted=true,.state=SG_REQUEST_COMPLETE};
        sched_yield();pthread_mutex_lock(&mutex);
        assert(sgpu_session_finish(&queue,request.id,&r));complete++;
        pthread_mutex_unlock(&mutex);
    }
    assert(!pthread_join(a,NULL) && !pthread_join(b,NULL));
    assert(queue.status.state==SG_SESSION_CLOSED && queue.status.completed==32 && !queue.status.outstanding);
    puts("PASS queue pthread stress: two producers, one consumer, bounded coherent snapshots; synthetic completions");
}
