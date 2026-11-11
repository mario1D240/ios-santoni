/* Execute the actual new freestanding C program with syscall contracts.
 * No kernel/hardware claim; the separate child bodies are also exercised.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include "../tools/santoni_gpu_user_probe.c"

static struct {
    int scenario, uid, pid, opened, closed, fd_closed, forks, calls;
    uint32_t admitted, completed, idle, wave_waits, values[32][4];
    unsigned info_calls, waits, submits, closes;
    uint64_t clock;
    int event, exit_status;
    char output[1024]; size_t output_bytes;
} m;
static jmp_buf escape;
enum { NORMAL, BAD_TIME, BACKWARD, STOPPED, DEADLINE, BAD_VERSION_REPLY,
    LEAKED_VALUE, BAD_POLL_SEQ, BAD_POLL_WPTR, NO_PUBLISH, BAD_ID,
    BAD_TERMINAL, LATE_INFO, LATE_POLL, CLOSE_IO_FAIL, CLOSE_FD_FAIL,
    REOPEN_ACCEPTED, ACCEPT_BAD_VERSION, ACCEPT_NULL, ACCEPT_READONLY,
    WAIT_CHILD_TIMEOUT, CHILD_NONROOT, CHILD_NONROOT_ACCEPTED, CHILD_TRANSFER,
    CHILD_TRANSFER_ACCEPTED, PID1_PARENT, PID1_FORK_FAIL, PID1_EXEC_FAIL,
    PID1_CHILD, OPEN_DELAY, MACH_ERROR, ZERO_DEN, ZERO_NUM, BIG_CLOCK,
    MACH_CARRY, CLOCK_RATIO, COUNT };

static uint64_t fail(int *error, uint32_t value) { *error=1; return value; }
static int request_valid(uint32_t cmd, const struct sgpu_user_packet *p)
{
    if (p->version!=1 || p->bytes!=128) return 0;
    if (cmd==SGPU_USER_POLL) { if (!p->id || p->id>32) return 0; }
    else if (p->id) return 0;
    const unsigned char *bytes=(const unsigned char *)p;
    for (unsigned i=12;i<128;i++)
        if (!(cmd==SGPU_USER_SUBMIT && i>=16 && i<32) && bytes[i]) return 0;
    return 1;
}
static void snapshot(struct sgpu_user_packet *p)
{
    p->version=1; p->bytes=128;
    p->state=m.completed==32 ? 4 : m.closed ? 3 : 1;
    p->reason=m.completed==32 ? 1 : 0;
    p->admitted=m.admitted;
    p->outstanding=m.admitted-m.completed;
    p->committed=p->submitted=p->completed=m.completed;
    p->writes=4*m.completed;
    p->last_seq=m.completed+2;
    p->wptr=170+11*m.completed;
    p->idle=m.idle;
}

uint64_t sgpu_syscall(uint64_t nr,uint64_t a0,uint64_t a1,uint64_t a2,
                     uint64_t a3,uint64_t a4,uint64_t a5,int *error)
{
    (void)a3; (void)a5; m.calls++; *error=0;
    if (nr==S_GETPID) return (uint64_t)m.pid;
    if (nr==(uint64_t)M_TIMEBASE) {
        uint32_t *tb=(void *)(uintptr_t)a0;
        tb[0]=m.scenario==CLOCK_RATIO ? 625 : m.scenario==BIG_CLOCK ? UINT32_MAX : 1;
        tb[1]=m.scenario==CLOCK_RATIO ? 12 : 1;
        if (m.scenario==MACH_ERROR) return 5;
        if (m.scenario==ZERO_DEN) tb[1]=0;
        if (m.scenario==ZERO_NUM) tb[0]=0;
        if (m.scenario==MACH_CARRY) *error=1; /* not a BSD errno indication */
        return 0;
    }
    if (nr==S_TIME) {
        if (a0 || a1 || !a2) abort();
        if (m.scenario==BAD_TIME) return fail(error,14);
        *(uint64_t *)(uintptr_t)a2=m.scenario==BIG_CLOCK ? UINT64_MAX :
            m.scenario==CLOCK_RATIO ? m.clock*1000*12/625 : m.clock*1000;
        return 0;
    }
    if (nr==S_FORK) {
        m.forks++;
        if (m.scenario==PID1_FORK_FAIL && m.pid==1) return fail(error,11);
        if (m.scenario==PID1_CHILD && m.pid==1) { m.pid=2; return 0; }
        if (m.scenario==PID1_PARENT || m.scenario==PID1_EXEC_FAIL) return 100;
        if (m.scenario==CHILD_NONROOT || m.scenario==CHILD_NONROOT_ACCEPTED) return 0;
        if ((m.scenario==CHILD_TRANSFER || m.scenario==CHILD_TRANSFER_ACCEPTED) && m.forks==2) return 0;
        return (uint64_t)(100+m.forks);
    }
    if (nr==S_SETUID) { if (a0!=501) abort(); m.uid=501; return 0; }
    if (nr==S_EXIT) { m.event=1; m.exit_status=(int)a0; longjmp(escape,1); }
    if (nr==S_EXECVE) {
        const char *path=(void *)(uintptr_t)a0;
        const char *const *argv=(void *)(uintptr_t)a1;
        if (strcmp(path,"/sbin/launchd") || strcmp(argv[0],path) || a2) abort();
        if (m.opened || m.submits) abort();
        if (m.scenario==PID1_EXEC_FAIL) return fail(error,2);
        m.event=2; longjmp(escape,1);
    }
    if (nr==S_OPEN) {
        const char *path=(void *)(uintptr_t)a0;
        if (a1!=2 || a2) abort();
        if (!strcmp(path,"/dev/console")) return 9;
        if (strcmp(path,"/dev/santonigpu")) abort();
        if (m.uid!=0 && m.scenario!=CHILD_NONROOT_ACCEPTED) return fail(error,13);
        if (m.uid!=0 && m.scenario==CHILD_NONROOT_ACCEPTED) return 4;
        if (m.closed) {
            if (m.scenario==REOPEN_ACCEPTED) return 4;
            return fail(error,16);
        }
        if (m.scenario==OPEN_DELAY && m.waits<3) return fail(error,2);
        if (m.opened) return fail(error,16);
        m.opened=1; return 3;
    }
    if (nr==S_CLOSE) {
        if (a0==3) {
            m.fd_closed=1;
            if (m.scenario==CLOSE_FD_FAIL) return fail(error,4);
        }
        return 0;
    }
    if (nr==S_WRITE) {
        if (a0!=9 || a2>512 || m.output_bytes+a2>=sizeof(m.output)) abort();
        memcpy(m.output+m.output_bytes,(void *)(uintptr_t)a1,(size_t)a2);
        m.output_bytes+=(size_t)a2; return a2;
    }
    if (nr==S_WAIT4) {
        if (a2!=1) abort();
        if (m.scenario==WAIT_CHILD_TIMEOUT) return 0;
        *(int *)(uintptr_t)a1=0; return a0;
    }
    if (nr==S_SELECT) {
        const struct darwin_timeval *tv=(void *)(uintptr_t)a4;
        if (a0 || a1 || a2 || tv->usec<0 || tv->usec>=1000000) abort();
        if (m.scenario==PID1_EXEC_FAIL && tv->sec==1) { m.event=3; longjmp(escape,1); }
        m.waits++;
        if (m.scenario==BACKWARD && m.submits) m.clock--;
        else if (m.scenario==DEADLINE && m.submits) m.clock+=100000000;
        else if (m.scenario!=STOPPED) m.clock+=(uint64_t)tv->sec*1000000+(uint32_t)tv->usec;
        if (m.scenario!=STOPPED && m.scenario!=DEADLINE && m.scenario!=BACKWARD && m.admitted>m.completed) {
            m.completed=m.admitted;
            if (m.admitted!=16) m.idle++;
        }
        if (m.admitted==16 && m.completed==16) {
            m.wave_waits++;
            if (m.wave_waits==3) m.idle++;
        }
        return 0;
    }
    if (nr==S_IOCTL) {
        if (a0!=3) abort();
        uint32_t cmd=(uint32_t)a1;
        if (m.scenario==CHILD_TRANSFER && m.forks==2) return fail(error,13);
        if (m.scenario==CHILD_TRANSFER_ACCEPTED && m.forks==2) return 0;
        struct sgpu_user_packet *p=(void *)(uintptr_t)a2;
        if (!p) return m.scenario==ACCEPT_NULL ? 0 : fail(error,14);
        if (p==&readonly_info) return m.scenario==ACCEPT_READONLY ? 0 : fail(error,14);
        if (!request_valid(cmd,p)) {
            if (m.scenario==ACCEPT_BAD_VERSION && p->version==2) return 0;
            return fail(error,22);
        }
        uint32_t id=p->id,values[4]; memcpy(values,p->value,sizeof(values));
        memset(p,0,sizeof(*p)); p->id=id;
        if (cmd==SGPU_USER_SUBMIT) {
            m.submits++;
            if (m.admitted-m.completed>=4) p->rc=3;
            else {
                if (m.admitted>=16 && m.wave_waits<3) abort();
                for (unsigned i=0;i<4;i++) if (values[i]!=(0xa5080000u^((m.admitted+1)<<8)^i)) abort();
                memcpy(m.values[m.admitted],values,sizeof(values));
                m.admitted++; p->id=m.admitted;
                if (m.admitted==16) m.idle++; /* newer admission snapshot */
                if (m.scenario==BAD_ID) p->id++;
            }
        } else if (cmd==SGPU_USER_POLL) {
            if (id>m.completed) p->rc=1;
            else {
                p->result_state=4; p->result_seq=id+2; p->result_wptr=170+id*11;
                p->result_writes=4; p->publish_attempted=1;
                if (m.scenario==BAD_POLL_SEQ) p->result_seq++;
                if (m.scenario==BAD_POLL_WPTR) p->result_wptr++;
                if (m.scenario==NO_PUBLISH) p->publish_attempted=0;
                if (m.scenario==LATE_POLL && id==32) m.clock=101000000;
            }
        } else if (cmd==SGPU_USER_CLOSE) {
            m.closed=1; m.closes++;
            if (m.scenario==CLOSE_IO_FAIL) return fail(error,14);
        } else if (cmd==SGPU_USER_INFO) {
            m.info_calls++;
            if (m.scenario==LATE_INFO && m.completed==32) m.clock=101000000;
        } else abort();
        snapshot(p);
        if (cmd==SGPU_USER_INFO && m.scenario==BAD_VERSION_REPLY) p->version=2;
        if (cmd==SGPU_USER_INFO && m.scenario==LEAKED_VALUE) p->value[0]=0x98000000;
        if (cmd==SGPU_USER_INFO && m.completed==32 && m.scenario==BAD_TERMINAL) p->writes=127;
        return 0;
    }
    abort();
}

int main(int argc,char **argv)
{
    if (argc!=2) return 2;
    memset(&m,0,sizeof(m)); m.scenario=atoi(argv[1]); m.pid=7; m.idle=1; m.clock=1000000;
    if (m.scenario<0 || m.scenario>=COUNT) return 2;
    if (m.scenario>=PID1_PARENT && m.scenario<=PID1_CHILD) m.pid=1;
    struct sgpu_probe_report r={0};
    if (setjmp(escape)==0) {
        if (m.scenario>=PID1_PARENT && m.scenario<=PID1_CHILD) {
            const char *args[]={"/dev/sgpu/sbin/launchd",NULL};
            int rc=sgpu_user_probe_entry(1,args);
            if (m.scenario!=PID1_CHILD || rc || !strstr(m.output,"pass=1 pid=2")) return 1;
        } else {
            int passed=sgpu_user_probe_run(&r);
            if (m.scenario>=CHILD_NONROOT && m.scenario<=CHILD_TRANSFER_ACCEPTED) return 1;
            int expected=m.scenario==NORMAL || m.scenario==OPEN_DELAY ||
                m.scenario==MACH_CARRY || m.scenario==CLOCK_RATIO;
            if (passed!=expected || (passed && (r.sent!=32 || r.verified!=32 || r.negative!=7))) return 1;
            if (m.opened && (!m.fd_closed || m.closes!=1)) return 1;
            if (m.scenario==STOPPED && m.info_calls!=10000) return 1;
            if (expected && m.wave_waits<3) return 1;
        }
    } else {
        if (m.scenario>=CHILD_NONROOT && m.scenario<=CHILD_TRANSFER_ACCEPTED) {
            int expected=m.scenario==CHILD_NONROOT_ACCEPTED || m.scenario==CHILD_TRANSFER_ACCEPTED;
            if (m.event!=1 || m.exit_status!=expected || m.submits) return 1;
        } else if (m.scenario==PID1_PARENT || m.scenario==PID1_FORK_FAIL) {
            if (m.event!=2 || m.submits || m.opened) return 1;
        } else if (m.scenario==PID1_EXEC_FAIL) {
            if (m.event!=3 || m.submits || m.opened) return 1;
        } else return 1;
    }
    puts("PASS new EL0 probe C contract"); return 0;
}
