/* Included after actual entry/report/trace functions. The unchanged scalar
 * workload is an injected report, not exercised or certified by these tests. */
#include <assert.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static struct {
    const char *scenario;
    uint32_t pid;
    unsigned runs,forks,execs,trace_opens,trace_closes,writes,first_write_bytes;
    struct sgpu_launch_trace_record records[16]; unsigned records_n;
    char output[1024]; size_t output_bytes;
} pm;
static jmp_buf probe_escape;
static bool scenario(const char *s) { return !strcmp(pm.scenario,s); }
static uint64_t probe_error(int *error, uint32_t value) { *error=1; return value; }
int sgpu_user_probe_run(struct sgpu_probe_report *r)
{
    pm.runs++;
    *r=(struct sgpu_probe_report){.pass=1,.pid=pm.pid,.sent=32,.verified=32,.negative=7};
    if (scenario("gpu-failure")) {
        r->pass=0; r->sent=2; r->verified=1; r->negative=6;
        r->error=P_SYSCALL; r->transport_errno=45;
    }
    return (int)r->pass;
}
uint64_t sgpu_syscall(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2,
    uint64_t a3, uint64_t a4, uint64_t a5, int *error)
{
    assert(!a3 && !a5); *error=0;
    if (nr==S_GETPID) return scenario("getpid-error")?probe_error(error,14):pm.pid;
    if (nr==S_OPEN) {
        assert(!a2 && !a4); const char *path=(void *)(uintptr_t)a0;
        if (!strcmp(path,"/dev/sgpu/sbin/launchd")) {
            assert(a1==0x01000000); pm.trace_opens++;
            return scenario("trace-open-error")?probe_error(error,45):8;
        }
        assert(!strcmp(path,"/dev/console") && a1==2);
        if (scenario("console-error")) return probe_error(error,13);
        if (scenario("console-overflow")) return UINT64_C(0x80000000);
        return 9;
    }
    if (nr==S_IOCTL) {
        assert(a0==8 && a1==SGPU_LAUNCH_TRACE_IOCTL && !a4 && pm.records_n<16);
        const struct sgpu_launch_trace_record *r=(void *)(uintptr_t)a2;
        assert(r->version==1 && r->bytes==64 && r->event>=1 && r->event<=9);
        for (unsigned i=0;i<5;i++) assert(!r->reserved[i]);
        pm.records[pm.records_n++]=*r;
        return scenario("trace-ioctl-error")?probe_error(error,45):0;
    }
    if (nr==S_CLOSE) {
        assert((a0==8 || a0==9) && !a1 && !a2 && !a4);
        if (a0==8) pm.trace_closes++; return 0;
    }
    if (nr==S_WRITE) {
        assert(a0==9 && a2<=512 && !a4); pm.writes++;
        if (pm.writes==1) pm.first_write_bytes=(unsigned)a2;
        if (scenario("write-error")) return probe_error(error,5);
        if (scenario("short-write") && pm.writes==1) return a2-1;
        if (scenario("first-write-error")) return probe_error(error,pm.writes==1?5:14);
        assert(pm.output_bytes+a2<sizeof(pm.output));
        memcpy(pm.output+pm.output_bytes,(void *)(uintptr_t)a1,(size_t)a2);
        pm.output_bytes+=(size_t)a2; return a2;
    }
    if (nr==S_FORK) {
        assert(pm.pid==1 && !a0 && !a1 && !a2 && !a4); pm.forks++;
        if (scenario("pid1-fork-error")) return probe_error(error,11);
        if (scenario("pid1-child")) { pm.pid=2; return 0; }
        return 77;
    }
    if (nr==S_EXECVE) {
        const char *path=(void *)(uintptr_t)a0; const char *const *argv=(void *)(uintptr_t)a1;
        assert(pm.pid==1 && !strcmp(path,"/sbin/launchd") && !strcmp(argv[0],path) &&
            argv[1] && !strcmp(argv[1],"-s") && !argv[2] && !a2 && !a4 && !pm.runs);
        pm.execs++;
        if (scenario("pid1-exec-error")) return probe_error(error,2);
        pm.trace_closes++; longjmp(probe_escape,1); /* simulated CLOEXEC */
    }
    if (nr==S_SELECT) {
        const struct darwin_timeval *tv=(void *)(uintptr_t)a4;
        assert(scenario("pid1-exec-error") && !a0 && !a1 && !a2 && tv->sec==1 && !tv->usec);
        longjmp(probe_escape,2);
    }
    abort();
}
static const struct sgpu_launch_trace_record *event(unsigned kind)
{
    const struct sgpu_launch_trace_record *found=NULL;
    for (unsigned i=0;i<pm.records_n;i++) if (pm.records[i].event==kind) {
        assert(!found); found=&pm.records[i];
    }
    return found;
}
int main(int argc, char **argv)
{
    assert(argc==2); pm.scenario=argv[1]; pm.pid=!strncmp(argv[1],"pid1-",5)?1:2;
    const char *arguments[]={"/dev/sgpu/sbin/launchd","-s",NULL};
    int escaped=setjmp(probe_escape),rc=-1;
    if (!escaped) rc=sgpu_user_probe_entry(2,arguments);
    assert(pm.trace_opens==1 && pm.records_n<=7);
    if (scenario("pid1-parent") || scenario("pid1-fork-error") || scenario("pid1-exec-error")) {
        assert(escaped && !pm.runs && pm.execs==1 && event(SG_LTRACE_INIT_EXEC));
        const struct sgpu_launch_trace_record *fork=event(SG_LTRACE_FORK); assert(fork);
        assert(fork->status==(scenario("pid1-fork-error")?1u:0u));
        assert(fork->value==(scenario("pid1-fork-error")?11u:77u));
        if (scenario("pid1-exec-error")) {
            const struct sgpu_launch_trace_record *failure=event(SG_LTRACE_INIT_RETURN);
            assert(escaped==2 && failure && failure->status==1 && failure->value==2);
            assert(strstr(pm.output,"PID1 retained"));
        } else assert(escaped==1 && pm.trace_closes==1);
    } else if (scenario("console-error") || scenario("console-overflow")) {
        assert(!escaped && rc==1 && !pm.runs && !pm.writes && pm.trace_closes==1);
        const struct sgpu_launch_trace_record *failure=event(SG_LTRACE_RESULT);
        assert(failure && !failure->pass && failure->error==P_SYSCALL &&
            failure->transport_errno==(scenario("console-error")?13u:UINT32_MAX));
        assert(event(SG_LTRACE_CONSOLE) && !event(SG_LTRACE_RUN));
    } else if (scenario("getpid-error")) {
        const struct sgpu_launch_trace_record *entry=event(SG_LTRACE_ENTRY);
        assert(!escaped && rc==1 && !pm.runs && !pm.forks && !pm.writes && pm.trace_closes==1);
        assert(entry && entry->status==1 && entry->value==14 && pm.records_n==1);
    } else {
        assert(!escaped && pm.runs==1 && rc==(scenario("gpu-failure")?1:0));
        if (scenario("trace-open-error")) assert(!pm.records_n && !pm.trace_closes);
        else {
            assert(event(SG_LTRACE_ENTRY) && event(SG_LTRACE_CHILD) && event(SG_LTRACE_RUN));
            assert(pm.trace_closes==1);
            const struct sgpu_launch_trace_record *result=event(SG_LTRACE_RESULT);
            const struct sgpu_launch_trace_record *write=event(SG_LTRACE_WRITE);
            assert(result && write && result->pass==(scenario("gpu-failure")?0u:1u));
            if (scenario("write-error") || scenario("first-write-error"))
                assert(write->status==1 && write->value==5);
            else if (scenario("short-write")) assert(write->status==2 && write->value==pm.first_write_bytes-1);
            else assert(!write->status && !write->value);
        }
        if (scenario("gpu-failure")) assert(strstr(pm.output,"error=1 errno=45"));
        else if (!scenario("write-error") && !scenario("first-write-error") && !scenario("short-write"))
            assert(strstr(pm.output,"RESULT pass=1 pid=2 sent=32 verified=32 negative=7"));
    }
    puts(argv[1]); return 0;
}
