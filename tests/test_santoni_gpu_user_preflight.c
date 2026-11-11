/* Automatic KERNEL caller of actual packet methods; no userspace claim. */
#define main previous_adapter_main
#include "test_santoni_gpu_user_adapter.c"
#undef main

static unsigned test_case, waited, wave_waited, summaries, observed_pass, observed_sent, observed_verified;
static uint64_t clock_value=1000000;
static uint64_t clock_read(void) {assert(!queue_depth);return clock_value;}
static unsigned admission_calls, terminal_calls;

/* Interleave at an actual returning platform call, outside the queue mutex. */
static void interleave(void)
{
    assert(!queue_depth);
    if (test_case==8 && session_queue.status.admitted==15 && ++admission_calls==2)
        session_idle_count=3; /* after INFO, before admission of request16 */
    if ((test_case==10 || test_case==11) && session_queue.status.state==SG_SESSION_CLOSED &&
        ++terminal_calls==(test_case==10 ? 1u : 2u))
        clock_value=101000000; /* expires during final INFO or POLL */
}

static void worker(void)
{
    assert(!queue_depth);
    if(test_case!=1 && test_case!=5 && test_case!=8 && test_case!=10 && test_case!=11) return;
    if(session_queue.status.admitted==16 && wave_waited<3) return;
    if(session_queue.status.admitted>16) {
        assert(session_queue.status.completed>=16 && session_idle_count>1);
        if(test_case==8) assert(wave_waited>=6 && session_idle_count==4);
    }
    lck_mtx_lock(&sgpu_session_lock);
    struct sgpu_session_request request;
    while(sgpu_session_take(&session_queue,&request)) {
        for(unsigned i=0;i<4;i++) assert(request.value[i]==(0xa5070000u^(request.id<<8)^i));
        assert(sgpu_session_commit(&session_queue,request.id));
        struct sgpu_session_result result={.state=SG_REQUEST_COMPLETE,.sequence=request.id+2,
            .wptr=170+11*request.id,.writes=4,.publish_attempted=true};
        assert(sgpu_session_finish(&session_queue,request.id,&result));
        if(test_case==5) session_queue.entry[request.id-1].result.publish_attempted=false;
    }
    lck_mtx_unlock(&sgpu_session_lock);
}

static void delay(uint32_t us)
{
    assert(!queue_depth && us==10000);waited++;
    if(test_case==1 || test_case==5 || test_case==8 || test_case==10 || test_case==11) {
        clock_value+=10000;
        if(session_queue.status.admitted==16) {
            wave_waited++;
            if(wave_waited==6) session_idle_count=test_case==8 ? 4u : 2u;
        }
        worker();
    } else if(test_case==2) clock_value+=10000000;
    else if(test_case==3) clock_value--;
    else if(test_case==9) clock_value=waited==1 ? clock_value+10000 : clock_value-1000;
    else assert(test_case==4);
}

static int capture(const char *format,va_list args)
{
    char line[512];int result=vsnprintf(line,sizeof(line),format,args);
    if(strstr(line,"USER API PREFLIGHT pass=")) {
        assert(sscanf(line,"SANTONI GPU: USER API PREFLIGHT pass=%u sent=%u verified=%u",
                      &observed_pass,&observed_sent,&observed_verified)==3);
        summaries++;
    }
    return result;
}

int main(int argc,char **argv)
{
    assert(argc==2);test_case=(unsigned)strtoul(argv[1],NULL,10);
    sg=(struct user_sg){.stock_unsecure=1,.stock_pixels=1,.g3=1,.session=1,.user=1,.user_test=1};
    assert(sgpu_session_queue_init(&session_queue));
    session_idle_count=1;print_hook=capture;time_hook=clock_read;wait_hook=delay;wake_hook=worker;
    host_task_hook=interleave;
    if(test_case==0) {
        const uint32_t values[]={0,1,2,UINT32_MAX};
        const unsigned modes[]={0,1,2,3,4,UINT32_MAX};
        for(unsigned m=0;m<sizeof(modes)/sizeof(modes[0]);m++) for(unsigned mask=0;mask<32;mask++)
            for(unsigned i=0;i<4;i++) {
                sg.user=mask&1;sg.session=(mask>>1)&1;sg.g3=(mask>>2)&1;
                sg.stock_pixels=(mask>>3)&1;sg.stock_unsecure=(mask>>4)&1;
                sg.user_test=99;test_option=values[i];
                bool valid=!test_option || (modes[m]==3 && mask==31 && test_option==1);
                assert(sgpu_user_test_options(modes[m])==valid);
                assert(sg.user_test==(unsigned)(valid && test_option==1));
            }
        uint32_t *parents[]={&sg.user,&sg.session,&sg.g3,&sg.stock_pixels,&sg.stock_unsecure};
        for(unsigned p=0;p<sizeof(parents)/sizeof(parents[0]);p++)
            for(unsigned bad=2;bad;bad=bad==2 ? UINT32_MAX : 0) {
                *parents[p]=bad;sg.user_test=99;test_option=1;
                assert(!sgpu_user_test_options(3) && !sg.user_test);
                assert(*parents[p]==bad);*parents[p]=1;
            }
        sg.user=1;sg.user_test=99;test_parse_present=false;
        assert(sgpu_user_test_options(3) && !sg.user_test);
        struct sgpu_session_queue saved=session_queue;
        sgpu_user_preflight();
        assert(!host_task_refs && !summaries && !memcmp(&session_queue,&saved,sizeof(saved)));
        sg.user_test=1;assert(sgpu_user_publish());
        assert(sgpu_user_open(makedev(77,0),0,0,NULL)==EBUSY && !host_task_refs);
    } else {
        assert(sgpu_user_publish());
        if(test_case==6) host_task=NULL;
        if(test_case==7) {
            sgpu_user_client=(struct sgpu_client){.owner=0x2020,.attempted=true};
            host_task_refs=1;
        }
        sgpu_user_preflight();
        assert(summaries==1 && !queue_depth);
        if(test_case==1 || test_case==8) {
            assert(observed_pass==1 && observed_sent==32 && observed_verified==32 && wave_waited==6);
            assert(session_queue.status.state==SG_SESSION_CLOSED && session_queue.status.reason==SG_SESSION_QUOTA);
            assert(session_queue.status.completed==32 && session_queue.status.writes==128);
            assert(session_queue.status.last_sequence==34 && session_queue.status.wptr==522);
        } else {
            assert(observed_pass==0 && (test_case==10 || test_case==11 ?
                sgpu_user_client.closed : session_queue.close_requested));
            struct sgpu_session_request request;assert(!sgpu_session_take(&session_queue,&request));
            assert(session_queue.status.state==SG_SESSION_CLOSED &&
                session_queue.status.reason==(test_case==10 || test_case==11 ? SG_SESSION_QUOTA : SG_SESSION_CLOSE));
            assert(!session_queue.status.active && !session_queue.status.outstanding);
            if(test_case==2) assert(waited==10 && observed_sent==4 && observed_verified==0);
            /* Refuse another admission after the first backward-clock wait. */
            if(test_case==3) assert(waited==1 && observed_sent==1 && observed_verified==0);
            if(test_case==4) assert(waited==10000 && observed_sent==4 && observed_verified==0);
            if(test_case==5) assert(observed_sent==1 && observed_verified==0);
            if(test_case==6 || test_case==7) assert(observed_sent==0 && observed_verified==0 && !waited);
            if(test_case==9) assert(waited==2 && observed_sent==2 && observed_verified==0);
            if(test_case==10 || test_case==11) assert(observed_sent==32 && observed_verified==31 &&
                session_queue.status.completed==32 && !session_queue.status.error);
        }
        assert(host_task_refs==(test_case==6 ? 0u : 1u));
    }
    puts("kernel user-API preflight: opt-ins, two waves, scalar result checks, deadlines and close passed");
    return 0;
}
