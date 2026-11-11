/* Actual portable client/queue contracts; completions are CPU model inputs. */
#include "santoni_gpu_core.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static struct sgpu_user_packet packet(uint32_t id)
{
    return (struct sgpu_user_packet){.version=SGPU_USER_VERSION,.bytes=SGPU_USER_BYTES,.id=id};
}

static void init(struct sgpu_client *c, struct sgpu_session_queue *q)
{
    memset(c,0,sizeof(*c)); memset(q,0,sizeof(*q));
    assert(sgpu_session_queue_init(q));
}

static void complete(struct sgpu_session_queue *q, uint32_t id)
{
    struct sgpu_session_request request;
    assert(sgpu_session_take(q,&request) && request.id==id);
    assert(sgpu_session_commit(q,id));
    struct sgpu_session_result result={.state=SG_REQUEST_COMPLETE,.sequence=id+2,
        .wptr=170+11*id,.writes=4,.publish_attempted=true};
    assert(sgpu_session_finish(q,id,&result));
}

int main(void)
{
    struct sgpu_client c;
    struct sgpu_session_queue q;
    init(&c,&q);
    struct sgpu_session_queue saved=q;
    assert(!sgpu_client_open(&c,&q,1,true,false));
    assert(!sgpu_client_open(&c,&q,1,false,true));
    assert(!sgpu_client_open(&c,&q,0,true,true));
    assert(!sgpu_client_open(NULL,&q,1,true,true));
    assert(!sgpu_client_open(&c,NULL,1,true,true));
    assert(!c.attempted && !c.owner && !memcmp(&q,&saved,sizeof(q)));
    assert(sgpu_client_open(&c,&q,0xabcdef0012345678ull,true,true));
    assert(!sgpu_client_open(&c,&q,0xabcdef0012345678ull,true,true));
    const uint64_t owner=c.owner;
    struct sgpu_user_packet p=packet(0), before=p;
    assert(sgpu_client_call(&c,&q,owner+1,SGPU_USER_INFO,&p,9)==SG_CLIENT_DENIED);
    assert(!memcmp(&p,&before,sizeof(p)) && !memcmp(&q,&saved,sizeof(q)));
    assert(sgpu_client_call(&c,&q,0,SGPU_USER_SUBMIT,&p,9)==SG_CLIENT_DENIED);
    assert(sgpu_client_call(&c,&q,owner,SGPU_USER_INFO,NULL,9)==SG_CLIENT_BAD_PACKET);

    /* Every non-input byte is rejected, not merely the named reserved word. */
    for (unsigned i=0;i<sizeof(p);i++) {
        p=packet(0);
        ((unsigned char *)(void *)&p)[i]^=1;
        assert(sgpu_client_call(&c,&q,owner,SGPU_USER_INFO,&p,9)==SG_CLIENT_BAD_PACKET);
        assert(!memcmp(&q,&saved,sizeof(q)));
    }
    for (uint32_t bad=0;bad<4;bad++) {
        p=packet(0);
        const uint32_t commands[]={0,SGPU_USER_INFO^0x10000u,SGPU_USER_INFO^0x40000000u,0xffffffffu};
        assert(sgpu_client_call(&c,&q,owner,commands[bad],&p,9)==SG_CLIENT_BAD_PACKET);
    }
    p=packet(33);
    assert(sgpu_client_call(&c,&q,owner,SGPU_USER_POLL,&p,9)==SG_CLIENT_BAD_PACKET);
    p=packet(0);
    assert(sgpu_client_call(&c,&q,owner,SGPU_USER_POLL,&p,9)==SG_CLIENT_BAD_PACKET);

    for (unsigned i=0;i<4;i++) {
        p=packet(0);
        for (unsigned j=0;j<4;j++) p.value[j]=0xf0000000u+i*4+j;
        assert(sgpu_client_call(&c,&q,owner,SGPU_USER_SUBMIT,&p,9)==SG_CLIENT_OK);
        assert(!p.rc && p.id==i+1 && p.outstanding==i+1);
        assert(!p.value[0] && !p.value[1] && !p.value[2] && !p.value[3] && !p.reserved);
        memset(&p,0xcc,sizeof(p));
        for (unsigned j=0;j<4;j++) assert(q.entry[i].value[j]==0xf0000000u+i*4+j);
    }
    saved=q; p=packet(0);
    assert(sgpu_client_call(&c,&q,owner,SGPU_USER_SUBMIT,&p,9)==SG_CLIENT_OK);
    assert(p.rc==SG_SESSION_FULL && !memcmp(&q,&saved,sizeof(q)));
    p=packet(1);
    assert(sgpu_client_call(&c,&q,owner,SGPU_USER_POLL,&p,9)==SG_CLIENT_OK);
    assert(p.result_state==SG_REQUEST_QUEUED && !p.result_seq && !p.publish_attempted);
    complete(&q,1);
    /* Populate deliberately private failure values; none has a public field. */
    q.entry[0].result.failure=(struct sgpu_failure){.old=0xfedcba98,.written=0xfedcba98,.got=0xfedcba98};
    p=packet(1);
    assert(sgpu_client_call(&c,&q,owner,SGPU_USER_POLL,&p,13)==SG_CLIENT_OK);
    assert(p.result_state==SG_REQUEST_COMPLETE && p.result_seq==3 && p.result_wptr==181);
    assert(p.result_writes==4 && p.publish_attempted==1 && p.idle==13 && !p.reserved);
    for (unsigned i=0;i<sizeof(p)/4;i++) {
        uint32_t word; memcpy(&word,(const unsigned char *)(const void *)&p+i*4,4);
        assert(word!=0xfedcba98);
    }
    p=packet(0);
    assert(sgpu_client_call(&c,&q,owner,SGPU_USER_CLOSE,&p,13)==SG_CLIENT_OK && c.closed);
    struct sgpu_session_request request;
    assert(!sgpu_session_take(&q,&request));
    assert(q.status.completed==1 && q.status.cancelled==3 && !q.status.outstanding);
    saved=q; sgpu_client_close(&c,&q);
    assert(!memcmp(&q,&saved,sizeof(q)));
    p=packet(0);
    assert(sgpu_client_call(&c,&q,owner,SGPU_USER_SUBMIT,&p,13)==SG_CLIENT_OK);
    assert(p.rc==SG_SESSION_IS_CLOSED && !memcmp(&q,&saved,sizeof(q)));
    assert(!sgpu_client_open(&c,&q,owner,true,true));
    p=packet(1);
    assert(sgpu_client_call(&c,&q,owner,SGPU_USER_POLL,&p,13)==SG_CLIENT_OK && p.result_seq==3);

    /* Close after commitment permits just that operation, then cancels queued. */
    init(&c,&q); assert(sgpu_client_open(&c,&q,owner,true,true));
    for (unsigned i=0;i<4;i++) { p=packet(0); assert(!sgpu_client_call(&c,&q,owner,SGPU_USER_SUBMIT,&p,1)); }
    assert(sgpu_session_take(&q,&request) && sgpu_session_commit(&q,1));
    sgpu_client_close(&c,&q);
    struct sgpu_session_result result={.state=SG_REQUEST_COMPLETE,.sequence=3,.wptr=181,.writes=4,.publish_attempted=true};
    assert(sgpu_session_finish(&q,1,&result));
    assert(q.status.completed==1 && q.status.cancelled==3 && q.status.reason==SG_SESSION_CLOSE);

    init(&c,&q); assert(sgpu_client_open(&c,&q,owner,true,true));
    for (unsigned i=1;i<=32;i++) {
        p=packet(0); p.value[0]=i;
        assert(!sgpu_client_call(&c,&q,owner,SGPU_USER_SUBMIT,&p,2) && !p.rc && p.id==i);
        complete(&q,i);
        p=packet(i);
        assert(!sgpu_client_call(&c,&q,owner,SGPU_USER_POLL,&p,2));
        assert(p.result_seq==i+2 && p.result_wptr==170+11*i && p.result_writes==4);
    }
    saved=q; p=packet(0);
    assert(!sgpu_client_call(&c,&q,owner,SGPU_USER_SUBMIT,&p,2) && p.rc==SG_SESSION_IS_CLOSED);
    assert(!memcmp(&q,&saved,sizeof(q)));
    p=packet(0);
    assert(!sgpu_client_call(&c,&q,owner,SGPU_USER_INFO,&p,32));
    assert(p.state==SG_SESSION_CLOSED && p.reason==SG_SESSION_QUOTA && p.admitted==32);
    assert(p.completed==32 && p.writes==128 && p.last_seq==34 && p.wptr==522 && !p.error);
    puts("user core: ownership, malformed packets, copies, sanitized results, close races and quota passed");
    return 0;
}
