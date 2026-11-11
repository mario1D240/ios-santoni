/* Actual CPU-only queue contracts; caller holds the queue lock. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "santoni_gpu_core.h"
static struct sgpu_session_result completed(unsigned sequence,unsigned wptr)
{ return (struct sgpu_session_result){.state=SG_REQUEST_COMPLETE,.sequence=sequence,.wptr=wptr,.writes=4,.publish_attempted=true}; }
int main(void)
{
    for(unsigned close_at=0;close_at<5;close_at++) for(unsigned fail=0;fail<2;fail++) {
        struct sgpu_session_queue q={0};assert(sgpu_session_queue_init(&q));
        assert(!sgpu_session_queue_init(&q));
        uint32_t v[4]={1,2,3,4},id=0;
        for(unsigned i=0;i<4;i++)assert(sgpu_session_enqueue(&q,1,1,v,&id)==SG_SESSION_OK && id==i+1);
        assert(sgpu_session_enqueue(&q,1,1,v,&id)==SG_SESSION_FULL && id==4);
        struct sgpu_session_queue original=q;
        assert(sgpu_session_enqueue(&q,2,1,v,&id)==SG_SESSION_BAD_REQUEST);
        assert(!memcmp(&q,&original,sizeof(q)));
        if(close_at==0) assert(sgpu_session_close(&q,1)==SG_SESSION_OK);
        struct sgpu_session_request request;
        bool taken=sgpu_session_take(&q,&request);
        if(close_at==0) {assert(!taken && q.status.cancelled==4 && q.status.state==SG_SESSION_CLOSED);continue;}
        assert(taken && request.id==1);
        if(close_at==1)sgpu_session_close(&q,1);
        bool commit=sgpu_session_commit(&q,request.id);
        if(close_at==1) {assert(!commit && q.status.cancelled==4 && q.status.state==SG_SESSION_CLOSED);continue;}
        assert(commit);assert(!sgpu_session_commit(&q,request.id));
        if(close_at==2)sgpu_session_close(&q,1);
        struct sgpu_session_result result=completed(3,181);
        if(fail) {result.error=SG_FAULT;result.writes=0;result.phase=SG_SESSION_PUBLISH;}
        assert(sgpu_session_finish(&q,1,&result));
        struct sgpu_session_result stored;assert(sgpu_session_get(&q,1,1,&stored));
        assert(!sgpu_session_finish(&q,1,&result));
        if(fail) {assert(q.status.state==SG_SESSION_FAULTED && q.status.cancelled==3);continue;}
        if(close_at>=3)sgpu_session_close(&q,1);
        assert(!sgpu_session_take(&q,&request));
        assert(q.status.state==SG_SESSION_CLOSED && q.status.completed==1 && q.status.cancelled==3 && !q.status.error);
        sgpu_session_close(&q,1);struct sgpu_session_result after;
        assert(sgpu_session_get(&q,1,1,&after) && !memcmp(&after,&stored,sizeof(after)));
    }
    struct sgpu_session_queue q={0};uint32_t v[4]={0},id=0;
    assert(sgpu_session_enqueue(&q,1,1,v,&id)==SG_SESSION_NOT_READY);
    assert(sgpu_session_queue_init(&q));
    for(unsigned i=0;i<32;i++) {
        assert(sgpu_session_enqueue(&q,1,1,v,&id)==SG_SESSION_OK);
        struct sgpu_session_request r;assert(sgpu_session_take(&q,&r));
        assert(sgpu_session_commit(&q,r.id));
        struct sgpu_session_result result=completed(i+3,181+i*11);
        assert(sgpu_session_finish(&q,r.id,&result));
    }
    assert(q.status.state==SG_SESSION_CLOSED && q.status.reason==SG_SESSION_QUOTA && q.status.completed==32);
    assert(q.status.outstanding==0 && q.status.wptr==522 && q.status.writes==128);
    assert(sgpu_session_enqueue(&q,1,1,v,&id)!=SG_SESSION_OK);
    struct sgpu_session_queue pending={0};assert(sgpu_session_queue_init(&pending));
    for(unsigned i=0;i<32;i++) {
        assert(sgpu_session_enqueue(&pending,1,1,v,&id)==SG_SESSION_OK);
        if(i<29) {
            struct sgpu_session_request r;assert(sgpu_session_take(&pending,&r));
            assert(sgpu_session_commit(&pending,r.id));
            struct sgpu_session_result result=completed(i+3,181+i*11);
            assert(sgpu_session_finish(&pending,r.id,&result));
        }
    }
    assert(pending.status.admitted==32 && pending.status.outstanding==3);
    assert(sgpu_session_enqueue(&pending,1,1,v,&id)==SG_SESSION_AT_QUOTA);
    for(unsigned published=0;published<2;published++) {
        struct sgpu_session_queue rejected={0};assert(sgpu_session_queue_init(&rejected));
        for(unsigned i=0;i<4;i++)assert(sgpu_session_enqueue(&rejected,1,1,v,&id)==SG_SESSION_OK);
        struct sgpu_session_request request;assert(sgpu_session_take(&rejected,&request));
        assert(sgpu_session_commit(&rejected,request.id));
        struct sgpu_session_result first=completed(3,181);
        assert(sgpu_session_finish(&rejected,request.id,&first));
        assert(sgpu_session_take(&rejected,&request) && request.id==2);
        if(published)assert(sgpu_session_commit(&rejected,request.id));
        struct sgpu_session_result invalid={.publish_attempted=published,
            .sequence=published?4:0,.wptr=published?192:0};
        sgpu_session_fault_pending(&rejected,&invalid);
        assert(rejected.status.state==SG_SESSION_FAULTED && rejected.status.reason==SG_SESSION_FAILURE);
        assert(rejected.status.completed==1 && rejected.status.failed==1 && rejected.status.cancelled==2);
        assert(!rejected.status.active && !rejected.status.outstanding);
        assert(rejected.status.submitted==1+published && rejected.status.first_failed_id==2);
        assert(rejected.status.error==SG_BAD_MODE && rejected.status.last_sequence==3 && rejected.status.wptr==181);
        struct sgpu_session_result stored;assert(sgpu_session_get(&rejected,1,1,&stored));
        assert(!memcmp(&first,&stored,sizeof(first)));
        assert(sgpu_session_get(&rejected,1,2,&stored));
        assert(stored.error==SG_BAD_MODE && stored.phase==SG_SESSION_ACCOUNTING && !stored.writes);
        assert(stored.publish_attempted==published && stored.sequence==invalid.sequence && stored.wptr==invalid.wptr);
        struct sgpu_session_queue frozen=rejected;
        sgpu_session_fault_pending(&rejected,NULL);
        assert(!memcmp(&rejected,&frozen,sizeof(frozen)));
    }
    puts("PASS session queue: immutable snapshots, close/commit/fault order, 4/32 limits; no hardware");
}
