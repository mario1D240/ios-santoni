/* Freestanding EL0 scalar probe. Raw syscall numbers are XNU8796.141.3
 * bsd/kern/syscalls.master, not Linux. No libc/Mesa, BO maps, raw IBs or PAs.
 *
 * A PID1 wrapper forks the probe and then execs the original launchd. The
 * wrapper must only be selected by a separately gated temporary boot path.
 * The private vnode trace observes execution independently of /dev/console.
 */
#include <stdint.h>
#include <stddef.h>
#include "santoni_gpu_uapi.h"
#include "santoni_gpu_launch_trace.h"

enum { S_EXIT=1, S_FORK=2, S_WRITE=4, S_OPEN=5, S_CLOSE=6, S_WAIT4=7,
       S_GETPID=20, S_SETUID=23, S_IOCTL=54, S_EXECVE=59, S_SELECT=93, S_TIME=116,
       M_TIMEBASE=-89 };
enum { P_OK, P_SYSCALL, P_CLOCK, P_DEADLINE, P_PACKET, P_ACCOUNTING, P_NEGATIVE };
enum { E_INTR=4, E_NOENT=2, E_NXIO=6, E_ACCESS=13, E_FAULT=14, E_BUSY=16, E_INVAL=22 };
enum { REQUEST_COMPLETE=4, SESSION_CLOSED=4, SESSION_FAULTED=5, QUOTA=1,
       QUEUE_FULL=3, AT_QUOTA=4, LIMIT=32, ATTEMPTS=10000 };

/* Fixed eight-argument internal AAPCS64 wrapper. The .S implementation saves
 * its output pointer across SVC and normalizes Darwin's fork child flag (x1).
 * Carry/error is separate from the scalar service's packet.rc.
 */
extern uint64_t sgpu_syscall(uint64_t, uint64_t, uint64_t, uint64_t,
                             uint64_t, uint64_t, uint64_t, int *);
struct sgpu_probe_report {
    uint32_t pass, pid, sent, verified, negative, error, transport_errno;
};
struct sgpu_console_status { uint32_t status,value; };
struct darwin_timeval { int64_t sec; int32_t usec; uint32_t padding; };
_Static_assert(sizeof(struct darwin_timeval)==16, "Darwin user64 timeval");
_Static_assert(sizeof(struct sgpu_user_packet)==128, "fixed scalar ABI");

void *memset(void *dest, int byte, size_t n)
{
    unsigned char *p=dest;
    for (size_t i=0;i<n;i++) p[i]=(unsigned char)byte;
    return dest;
}
void *memcpy(void *dest, const void *source, size_t n)
{
    unsigned char *d=dest; const unsigned char *s=source;
    for (size_t i=0;i<n;i++) d[i]=s[i];
    return dest;
}

static uint64_t call(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2,
                     uint64_t a3, uint64_t a4, int *error)
{
    *error=0;
    return sgpu_syscall(nr,a0,a1,a2,a3,a4,0,error);
}
static void packet_init(struct sgpu_user_packet *p, uint32_t id)
{
    memset(p,0,sizeof(*p));
    p->version=SGPU_USER_VERSION; p->bytes=sizeof(*p); p->id=id;
}
static uint32_t errno_value(uint64_t value)
{
    return value<=0x7fffffffu ? (uint32_t)value : 0xffffffffu;
}
static void trace_event(int fd, uint32_t event, uint32_t status, uint64_t value,
    const struct sgpu_probe_report *report)
{
    if (fd<0) return;
    struct sgpu_launch_trace_record record={.version=SGPU_LAUNCH_TRACE_VERSION,
        .bytes=sizeof(record),.event=event,.status=status,.value=errno_value(value)};
    if (report) {
        record.pass=report->pass; record.sent=report->sent; record.verified=report->verified;
        record.negative=report->negative; record.error=report->error;
        record.transport_errno=report->transport_errno;
    }
    int ignored;
    (void)call(S_IOCTL,(uint32_t)fd,SGPU_LAUNCH_TRACE_IOCTL,(uintptr_t)&record,0,0,&ignored);
}
static void trace_close(int fd)
{
    if (fd<0) return;
    int ignored; (void)call(S_CLOSE,(uint32_t)fd,0,0,0,0,&ignored);
}
static int now_us(uint64_t *out)
{
    struct { uint32_t numer,denom; } timebase={0}; uint64_t ticks=0; int error;
    /* Mach trap89 returns kern_return_t in x0, not BSD carry/errno. Then BSD
     * gettimeofday's third output supplies absolute time (kern_time.c:158).
     * No wall-clock epoch or hardcoded Santoni timer ratio is used here. */
    uint64_t rc=call((uint64_t)M_TIMEBASE,(uintptr_t)&timebase,0,0,0,0,&error);
    if (rc || !timebase.numer || !timebase.denom) return 0;
    rc=call(S_TIME,0,0,(uintptr_t)&ticks,0,0,&error);
    if (error || rc) return 0;
    uint64_t whole=ticks/timebase.denom, remainder=ticks%timebase.denom;
    if (whole>UINT64_MAX/timebase.numer) return 0;
    uint64_t base=whole*timebase.numer;
    uint64_t fraction=remainder*timebase.numer/timebase.denom;
    if (base>UINT64_MAX-fraction) return 0;
    *out=(base+fraction)/1000;
    return 1;
}
static int deadline(uint64_t start, uint64_t *last)
{
    uint64_t now;
    if (!now_us(&now) || now<*last || now-start>=100000000) return 0;
    *last=now; return 1;
}
static int sleep_us(uint32_t usec)
{
    struct darwin_timeval tv={usec/1000000,(int32_t)(usec%1000000),0}; int error;
    uint64_t rc=call(S_SELECT,0,0,0,0,(uintptr_t)&tv,&error);
    return (!error && rc==0) || (error && rc==E_INTR);
}
static int ioctl_packet(int fd, uint64_t command, struct sgpu_user_packet *p,
                        struct sgpu_probe_report *r)
{
    int error; uint64_t rc=call(S_IOCTL,(uint32_t)fd,command,(uintptr_t)p,0,0,&error);
    if (error || rc) {
        r->error=P_SYSCALL; r->transport_errno=errno_value(rc); return 0;
    }
    if (p->version!=SGPU_USER_VERSION || p->bytes!=sizeof(*p) || p->reserved ||
        p->value[0] || p->value[1] || p->value[2] || p->value[3]) {
        r->error=P_PACKET; return 0;
    }
    return 1;
}
static int denied(int fd, uint64_t command, const void *p, uint32_t expected)
{
    int error;
    uint64_t rc=call(S_IOCTL,(uint32_t)fd,command,(uintptr_t)p,0,0,&error);
    return error && rc==expected;
}
static const struct sgpu_user_packet readonly_info={.version=1,.bytes=128};

static void child_exit(uint32_t status)
{
    int error;
    (void)call(S_EXIT,status,0,0,0,0,&error);
    /* An actual successful exit cannot return. No GPU continuation if it does. */
    for (;;) {
#ifdef __aarch64__
        __asm__ volatile("wfe");
#else
        __asm__ volatile("" ::: "memory");
#endif
    }
}

static int wait_child(uint32_t pid, uint64_t start, uint64_t *last)
{
    /* XNU8796 sys/wait.h WNOHANG=1. Never enter a blocking wait4. */
    for (unsigned attempt=0;attempt<2000;attempt++) {
        int status=-1,error;
        uint64_t got=call(S_WAIT4,pid,(uintptr_t)&status,1,0,0,&error);
        if (error || !deadline(start,last)) return 0;
        if (got==pid) return status==0;
        if (got!=0 || !sleep_us(10000)) return 0;
    }
    return 0;
}
static int child_negative(int fd, int nonroot, uint64_t start, uint64_t *last)
{
    int error; uint64_t pid=call(S_FORK,0,0,0,0,0,&error);
    if (error || pid>0x7fffffffu) return 0;
    if (pid==0) {
        if (nonroot) {
            uint64_t rc=call(S_SETUID,501,0,0,0,0,&error);
            if (error || rc) child_exit(1);
            rc=call(S_OPEN,(uintptr_t)"/dev/santonigpu",2,0,0,0,&error);
            /* Successful nonroot open must fail this test; close its fd. */
            if (!error) { int ignored; (void)call(S_CLOSE,rc,0,0,0,0,&ignored); }
            child_exit(error && rc==E_ACCESS ? 0 : 1);
        } else {
            struct sgpu_user_packet p; packet_init(&p,0);
            child_exit(denied(fd,SGPU_USER_INFO,&p,E_ACCESS) ? 0 : 1);
        }
    }
    return wait_child((uint32_t)pid,start,last);
}

int sgpu_user_probe_run(struct sgpu_probe_report *r)
{
    int fd=-1,error; uint64_t start=0,last=0; uint32_t wave_idle=0;
    memset(r,0,sizeof(*r));
    uint64_t pid=call(S_GETPID,0,0,0,0,0,&error);
    if (error || pid<=1 || pid>0x7fffffffu) { r->error=P_SYSCALL; return 0; }
    r->pid=(uint32_t)pid;
    if (!now_us(&start)) { r->error=P_CLOCK; return 0; }
    last=start;
    /* Missing node/startup is retried within a returning-clock/attempt budget;
     * an already claimed owner, permission failure or other error stops. */
    for (unsigned attempt=0;attempt<1000;attempt++) {
        uint64_t got=call(S_OPEN,(uintptr_t)"/dev/santonigpu",2,0,0,0,&error);
        /* Keep a successful descriptor owned even if the following clock
         * check fails, so done requests session close and closes the fd. */
        if (!error && got<=0x7fffffffu) fd=(int)got;
        if (!deadline(start,&last)) { r->error=P_DEADLINE; goto done; }
        if (fd>=0) break;
        if (!error || (got!=E_NOENT && got!=E_NXIO && got!=E_INTR)) {
            r->error=P_SYSCALL; r->transport_errno=errno_value(got); goto done;
        }
        if (!sleep_us(100000)) { r->error=P_SYSCALL; goto done; }
    }
    if (fd<0) { r->error=P_DEADLINE; goto done; }
    if (!now_us(&start)) { r->error=P_CLOCK; goto done; }
    last=start;
    {
        struct sgpu_user_packet p; packet_init(&p,0); p.version=2;
        if (!denied(fd,SGPU_USER_INFO,&p,E_INVAL)) { r->error=P_NEGATIVE; goto done; }
        r->negative++;
        packet_init(&p,0); p.reserved=1;
        if (!denied(fd,SGPU_USER_INFO,&p,E_INVAL)) { r->error=P_NEGATIVE; goto done; }
        r->negative++;
        if (!denied(fd,SGPU_USER_INFO,NULL,E_FAULT)) { r->error=P_NEGATIVE; goto done; }
        r->negative++;
        if (!denied(fd,SGPU_USER_INFO,&readonly_info,E_FAULT)) { r->error=P_NEGATIVE; goto done; }
        r->negative++;
        if (!child_negative(fd,1,start,&last) || !child_negative(fd,0,start,&last)) {
            r->error=P_NEGATIVE; goto done;
        }
        r->negative+=2;
    }
    for (unsigned attempt=0;attempt<ATTEMPTS;attempt++) {
        struct sgpu_user_packet state,request,completion;
        if (!deadline(start,&last)) { r->error=P_DEADLINE; break; }
        packet_init(&state,0);
        if (!ioctl_packet(fd,SGPU_USER_INFO,&state,r)) break;
        if (!deadline(start,&last)) { r->error=P_DEADLINE; break; }
        if (state.rc || state.error || state.failed || state.cancelled ||
            state.completed>r->sent || state.admitted!=r->sent) {
            r->error=P_ACCOUNTING; break;
        }
        while (r->verified<state.completed && r->verified<LIMIT) {
            packet_init(&completion,r->verified+1);
            if (!ioctl_packet(fd,SGPU_USER_POLL,&completion,r)) goto done;
            if (!deadline(start,&last)) { r->error=P_DEADLINE; goto done; }
            if (completion.rc || completion.result_state!=REQUEST_COMPLETE ||
                completion.result_seq!=r->verified+3 ||
                completion.result_wptr!=170+11*(r->verified+1) ||
                completion.result_writes!=4 || completion.result_error ||
                completion.publish_attempted!=1) { r->error=P_ACCOUNTING; goto done; }
            r->verified++;
        }
        if (state.state==SESSION_CLOSED || state.state==SESSION_FAULTED) {
            r->pass=state.state==SESSION_CLOSED && state.reason==QUOTA &&
                r->sent==LIMIT && r->verified==LIMIT && state.admitted==LIMIT &&
                state.committed==LIMIT && state.submitted==LIMIT && state.completed==LIMIT &&
                !state.active && !state.outstanding && state.writes==128 &&
                state.last_seq==34 && state.wptr==522 && state.idle>=2;
            if (!r->pass) r->error=P_ACCOUNTING;
            break;
        }
        int second_wave=r->sent>=16 && (r->verified<16 || state.idle<=wave_idle);
        if (state.idle && !second_wave && r->sent<LIMIT) {
            packet_init(&request,0);
            for (unsigned i=0;i<4;i++) request.value[i]=0xa5080000u^((r->sent+1)<<8)^i;
            if (!ioctl_packet(fd,SGPU_USER_SUBMIT,&request,r)) break;
            if (!request.rc) {
                if (request.id!=r->sent+1) { r->error=P_ACCOUNTING; break; }
                r->sent++;
                if (r->sent==16) wave_idle=request.idle;
            } else if (request.rc!=QUEUE_FULL && request.rc!=AT_QUOTA) {
                r->error=P_ACCOUNTING; break;
            }
        }
        if (!deadline(start,&last)) { r->error=P_DEADLINE; break; }
        if (!sleep_us(10000)) { r->error=P_SYSCALL; break; }
    }
    if (!r->pass && !r->error) r->error=P_DEADLINE;
done:
    if (fd>=0) {
        struct sgpu_user_packet close; packet_init(&close,0);
        int close_error;
        uint64_t rc=call(S_IOCTL,(uint32_t)fd,SGPU_USER_CLOSE,(uintptr_t)&close,0,0,&close_error);
        if ((close_error || rc) && r->pass) {
            r->pass=0; r->error=P_SYSCALL; r->transport_errno=errno_value(rc);
        }
        rc=call(S_CLOSE,(uint32_t)fd,0,0,0,0,&close_error);
        if ((close_error || rc) && r->pass) {
            r->pass=0; r->error=P_SYSCALL; r->transport_errno=errno_value(rc);
        }
        if (r->pass) {
            rc=call(S_OPEN,(uintptr_t)"/dev/santonigpu",2,0,0,0,&close_error);
            if (!close_error || rc!=E_BUSY) {
                r->pass=0; r->error=P_NEGATIVE;
                if (!close_error) { int ignored; (void)call(S_CLOSE,rc,0,0,0,0,&ignored); }
            } else r->negative++;
        }
    }
    return r->pass!=0;
}

static size_t text_length(const char *s)
{
    size_t n=0; while (s[n]) n++; return n;
}
static void write_bytes(int fd, const void *data, size_t bytes, struct sgpu_console_status *status)
{
    int error;
    uint64_t rc=call(S_WRITE,(uint32_t)fd,(uintptr_t)data,bytes,0,0,&error);
    /* Observe the first failure without retrying or changing the GPU result. */
    if (!status->status && (error || rc!=bytes)) {
        status->status=error?1u:2u;
        status->value=errno_value(rc);
    }
}
static void write_text(int fd, const char *s, struct sgpu_console_status *status)
{
    write_bytes(fd,s,text_length(s),status);
}
static void write_number(int fd, uint32_t value, struct sgpu_console_status *status)
{
    char buffer[10]; unsigned n=0;
    do { buffer[9-n++]=(char)('0'+value%10); value/=10; } while (value && n<10);
    write_bytes(fd,&buffer[10-n],n,status);
}
static void report(int fd, const struct sgpu_probe_report *r, struct sgpu_console_status *status)
{
    write_text(fd,"SANTONI GPU USERSPACE: RESULT pass=",status); write_number(fd,r->pass,status);
    write_text(fd," pid=",status); write_number(fd,r->pid,status);
    write_text(fd," sent=",status); write_number(fd,r->sent,status);
    write_text(fd," verified=",status); write_number(fd,r->verified,status);
    write_text(fd," negative=",status); write_number(fd,r->negative,status);
    write_text(fd," error=",status); write_number(fd,r->error,status);
    write_text(fd," errno=",status); write_number(fd,r->transport_errno,status);
    write_text(fd,"; EL0 BSD open/ioctl; no user DMA maps; NO UI; held until reboot\n",status);
}

static void original_init(uint64_t argc, const char *const *argv, int trace_fd)
{
    /* Original load_init_program_at_path passes argv0 plus optional -s and
     * no environment. Preserve that documented initial argument contract. */
    const char *arguments[3]={"/sbin/launchd",NULL,NULL};
    if (argc==2 && argv && argv[1] && argv[1][0]=='-' && argv[1][1]=='s' && !argv[1][2])
        arguments[1]=argv[1];
    int error;
    trace_event(trace_fd,SG_LTRACE_INIT_EXEC,0,0,NULL);
    uint64_t rc=call(S_EXECVE,(uintptr_t)arguments[0],(uintptr_t)arguments,0,0,0,&error);
    trace_event(trace_fd,SG_LTRACE_INIT_RETURN,(uint32_t)error,rc,NULL);
    /* PID1 may not exit. Failed exec leaves init alive for observation/reboot;
     * it does not retry the GPU or mount/modify persistent files. */
    uint64_t fd=call(S_OPEN,(uintptr_t)"/dev/console",2,0,0,0,&error);
    if (!error && fd<=0x7fffffffu) {
        struct sgpu_console_status ignored={0};
        write_text((int)fd,"SANTONI GPU USERSPACE: original launchd exec failed; PID1 retained; reboot required\n",&ignored);
    }
    for (;;) (void)sleep_us(1000000);
}

int sgpu_user_probe_entry(uint64_t argc, const char *const *argv)
{
    int error;
    uint64_t pid=call(S_GETPID,0,0,0,0,0,&error);
    int trace_fd=-1,open_error;
    /* XNU8796 fcntl.h O_CLOEXEC=0x01000000. Read-only observation descriptor
     * survives fork and closes automatically on successful original exec. */
    uint64_t trace=call(S_OPEN,(uintptr_t)"/dev/sgpu/sbin/launchd",0x01000000,0,0,0,&open_error);
    if (!open_error && trace<=0x7fffffffu) trace_fd=(int)trace;
    trace_event(trace_fd,SG_LTRACE_ENTRY,(uint32_t)error,pid,NULL);
    if (error) { trace_close(trace_fd); return 1; }
    if (pid==1) {
        uint64_t child=call(S_FORK,0,0,0,0,0,&error);
        trace_event(trace_fd,error || child!=0 ? SG_LTRACE_FORK : SG_LTRACE_CHILD,
            (uint32_t)error,child,NULL);
        if (error || child!=0) original_init(argc,argv,trace_fd);
    } else trace_event(trace_fd,SG_LTRACE_CHILD,0,0,NULL);
    uint64_t fd=call(S_OPEN,(uintptr_t)"/dev/console",2,0,0,0,&error);
    trace_event(trace_fd,SG_LTRACE_CONSOLE,(uint32_t)error,fd,NULL);
    if (error || fd>0x7fffffffu) {
        struct sgpu_probe_report failure={.error=P_SYSCALL,.transport_errno=errno_value(fd)};
        trace_event(trace_fd,SG_LTRACE_RESULT,0,0,&failure);
        trace_close(trace_fd);
        return 1;
    }
    trace_event(trace_fd,SG_LTRACE_RUN,0,0,NULL);
    struct sgpu_probe_report r;
    int passed=sgpu_user_probe_run(&r);
    trace_event(trace_fd,SG_LTRACE_RESULT,0,0,&r);
    struct sgpu_console_status output={0};
    report((int)fd,&r,&output);
    trace_event(trace_fd,SG_LTRACE_WRITE,output.status,output.value,NULL);
    int ignored; (void)call(S_CLOSE,fd,0,0,0,0,&ignored);
    trace_close(trace_fd);
    return passed ? 0 : 1;
}
