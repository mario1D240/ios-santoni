/* New scalar producer -> actual session worker/core with pthread scheduling.
 * GPU responses are model inputs; this is not XNU or hardware proof. */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
static unsigned summaries, summary_pass, summary_sent, summary_verified;
static int capture_user_worker(const char *format,...)
{
    char line[1024];va_list args;va_start(args,format);
    int result=vsnprintf(line,sizeof(line),format,args);va_end(args);
    if(strstr(line,"USER API PREFLIGHT pass=")) {
        if(sscanf(line,"SANTONI GPU: USER API PREFLIGHT pass=%u sent=%u verified=%u",
            &summary_pass,&summary_sent,&summary_verified)!=3) return -1;
        summaries++;
    }
    return result;
}
#define printf capture_user_worker
#include "santoni_gpu_session_model.h"
#define main previous_session_main
#include "test_santoni_gpu_session_adapter.c"
#undef main
#undef printf

static void missing_owner(void) {host_task=NULL;}

int main(int argc,char **argv)
{
    assert(argc==2);unsigned test=(unsigned)atoi(argv[1]);assert(test<6);
    scenario=test==5 ? 6u : 0u;
    force_wakes=test==1 ? 10u : 0u;
    host_publication_failure=test==2 ? 1u : 0u;
    host_task_hook=test==3 ? missing_owner : NULL;
    sg.mode=3;sg.g3=sg.stock_unsecure=sg.stock_pixels=sg.session=sg.user=sg.user_test=1;
    struct session_model model={0};init(&model.base,SECURE_GPU);struct sgpu_report report;
    assert(boot_session(&model,&report,1));clobber_stack();model.active=true;
    if(test==4) model.injection=1;
    owner_thread=pthread_self();queue_lock_address=&sgpu_session_lock;
    session_callback_check=check_worker_and_lock;
    sgpu_session_loop();
    assert(!pthread_join(producer_thread,NULL));
    assert(!session_queue.status.active && !session_queue.status.outstanding);
    assert(session_queue.status.admitted==session_queue.status.completed+
        session_queue.status.cancelled+session_queue.status.failed);
    if(test<2) {
        assert(summaries==1 && summary_pass==1 && summary_sent==32 && summary_verified==32);
        assert(session_queue.status.state==SG_SESSION_CLOSED && session_queue.status.reason==SG_SESSION_QUOTA);
        assert(session_queue.status.completed==32 && session_queue.status.writes==128 && model.ibs==34);
        assert(session_queue.status.last_sequence==34 && session_queue.status.wptr==522);
        assert(session_idle_count>=2 && registrations>=2 && blocks>=2);
    } else {
        assert(!summary_pass && !session_queue.status.completed);
        assert(summaries==(test==2 ? 0u : 1u));
        if(test==4) {
            assert(session_queue.status.state==SG_SESSION_FAULTED && session_queue.status.failed==1);
            assert(session_queue.status.error==SG_BAD_SMMU && session_queue.status.first_failed_id==1);
        } else {
            assert(session_queue.status.state==SG_SESSION_CLOSED && session_queue.status.reason==SG_SESSION_CLOSE);
            if(test==5) assert(close_injected && session_queue.status.cancelled);
        }
        assert(model.ibs==2);
    }
    assert(host_task_refs==(test==2 || test==3 ? 0u : 1u));
    assert(!model.base.frees);
    struct sgpu_session_queue saved=session_queue;unsigned accesses=model.accesses;
    assert(!sgpu_session_prepare());
    assert(sgpu_session_close(&session_queue,SGPU_SESSION_OWNER)==SG_SESSION_OK);
    assert(!memcmp(&saved,&session_queue,sizeof(saved)) && model.accesses==accesses && !model.base.frees);
    destroy(&model.base);
    puts("scalar preflight through actual worker/core: scheduling, faults, close and terminal retention passed");
    return 0;
}
