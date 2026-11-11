/* New contracts for actual reconstructed publication and its late CPU snapshot. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#define DEVFS_CHAR 1
#define UID_ROOT 0
#define makedev(a, b) (((a) << 8) | (b))
static struct { uint32_t mode, user; } sg;
static int sgpu_user_major, sgpu_session_lock;
static bool sgpu_user_published;
static const char sgpu_user_cdevsw;
static bool locked, node_success, ready_value, mounted_value;
static int new_major;
static unsigned switches, nodes, ready_calls, mounted_calls, normal_lines, late_lines, diag_lines;
static unsigned completed;
static uint32_t seen_mode, seen_ready, seen_mounted;

static int cdevsw_add(int slot, const void *sw)
{ assert(slot == -1 && sw == &sgpu_user_cdevsw); switches++; return new_major; }
static void *devfs_make_node(int dev, int kind, int uid, int gid, int mode, const char *path)
{
    assert(dev == makedev(new_major, 0) && kind == DEVFS_CHAR && uid == 0 && gid == 0);
    assert(mode == 0600 && strcmp(path, "santonigpu") == 0);
    nodes++;
    return node_success ? &sg : NULL;
}
static void lck_mtx_lock(int *lock)
{ assert(lock == &sgpu_session_lock && !locked); locked = true; }
static void lck_mtx_unlock(int *lock)
{ assert(lock == &sgpu_session_lock && locked); locked = false; }
static bool santoni_gpu_user_launch_worker_ready(uint32_t mode)
{
    assert(!locked && sgpu_user_published && nodes == 1 && mode == 3);
    ready_calls++;
    return ready_value;
}
static bool santoni_gpu_user_launch_mount_published(void)
{
    assert(!locked && sgpu_user_published && ready_calls == 1);
    mounted_calls++;
    return mounted_value;
}
/* Read-only trace diagnostic snapshot: called once, after both readiness
 * getters and before the diag print, with the mutex released. */
struct sgpu_launch_trace_diag {
    uint32_t open_attempts, open_accepted, open_refused;
    uint32_t ioctl_attempts, ioctl_accepted, ioctl_refused;
    uint32_t open_refuse_stage, ioctl_refuse_stage;
    uint32_t seen_open, seen_ioctl;
};
static unsigned snapshot_calls;
static struct sgpu_launch_trace_diag snapshot_value;
static void santoni_gpu_user_launch_trace_snapshot(struct sgpu_launch_trace_diag *out)
{
    assert(!locked && sgpu_user_published && out && mounted_calls == 1 && late_lines == 1);
    snapshot_calls++;
    *out = snapshot_value;
}
static int host_printf(const char *format, ...)
{
    assert(!locked && sgpu_user_published);
    va_list ap; va_start(ap, format);
    if (strstr(format, "USER LAUNCH LATE")) {
        assert(normal_lines == 1 && ready_calls == 1 && mounted_calls == 1 && !snapshot_calls);
        seen_mode = va_arg(ap, unsigned);
        seen_ready = va_arg(ap, unsigned);
        seen_mounted = va_arg(ap, unsigned);
        assert(strstr(format, "EL0 RESULT still required") && strstr(format, "CPU snapshot"));
        late_lines++;
    } else if (strstr(format, "USER TRACE DIAG")) {
        assert(normal_lines == 1 && late_lines == 1 && snapshot_calls == 1);
        unsigned got[10];
        for (unsigned i = 0; i < 10; i++) got[i] = va_arg(ap, unsigned);
        const uint32_t *w = &snapshot_value.open_attempts;
        for (unsigned i = 0; i < 10; i++) assert(got[i] == w[i]);
        assert(strstr(format, "EL0 RESULT still required"));
        diag_lines++;
    } else {
        assert(strstr(format, "USER ready /dev/santonigpu"));
        normal_lines++;
    }
    va_end(ap);
    return 0;
}
#define printf host_printf
#include "santoni_gpu_late_launch_actual.h"
#undef printf

static void reset(uint32_t mode, uint32_t user)
{
    sg.mode = mode; sg.user = user; sgpu_user_major = -1;
    sgpu_user_published = false; locked = false; node_success = true;
    ready_value = mounted_value = false; new_major = 7;
    switches = nodes = ready_calls = mounted_calls = normal_lines = late_lines = diag_lines = 0;
    snapshot_calls = 0; snapshot_value = (struct sgpu_launch_trace_diag){0};
    seen_mode = seen_ready = seen_mounted = UINT32_MAX;
}
static void pass(const char *label)
{ completed++; printf("PASS %s\n", label); }

int main(void)
{
    char label[80];
    for (uint32_t mode = 0; mode < 4; mode++) {
        for (unsigned ready = 0; ready < 2; ready++) {
            for (unsigned mounted = 0; mounted < 2; mounted++) {
                reset(mode, 1); ready_value = ready; mounted_value = mounted;
                snapshot_value = (struct sgpu_launch_trace_diag){.open_attempts=3,.open_accepted=1,
                    .open_refused=2,.ioctl_attempts=9,.ioctl_accepted=5,.ioctl_refused=4,
                    .open_refuse_stage=3,.ioctl_refuse_stage=4,.seen_open=1,.seen_ioctl=1};
                assert(sgpu_user_publish());
                assert(!locked && sgpu_user_published && sgpu_user_major == 7);
                assert(switches == 1 && nodes == 1 && normal_lines == 1);
                assert(ready_calls == (mode == 3) && mounted_calls == (mode == 3));
                assert(late_lines == (mode == 3) && diag_lines == (mode == 3) && snapshot_calls == (mode == 3));
                if (mode == 3) assert(seen_mode == mode && seen_ready == ready && seen_mounted == mounted);
                else assert(seen_mode == UINT32_MAX);
                snprintf(label, sizeof(label), "mode%u-ready%u-mounted%u", mode, ready, mounted);
                pass(label);
            }
        }
        const uint32_t denied[] = {0, 2, UINT32_MAX};
        for (unsigned i = 0; i < 3; i++) {
            reset(mode, denied[i]);
            assert(!sgpu_user_publish() && !sgpu_user_published && !locked);
            assert(!switches && !nodes && !normal_lines && !late_lines && !ready_calls && !mounted_calls);
            snprintf(label, sizeof(label), "mode%u-user%u-off", mode, denied[i]);
            pass(label);
        }
    }
    for (int major = 0; major < 3; major++) {
        reset(3, 1); sgpu_user_major = major;
        assert(!sgpu_user_publish() && !switches && !nodes && !late_lines && !ready_calls && !mounted_calls);
        snprintf(label, sizeof(label), "already-published-%d", major); pass(label);
    }
    reset(3, 1); new_major = -1;
    assert(!sgpu_user_publish() && switches == 1 && !nodes && !sgpu_user_published);
    assert(!normal_lines && !late_lines && !ready_calls && !mounted_calls && !locked);
    pass("registration-failed");
    reset(3, 1); node_success = false;
    assert(!sgpu_user_publish() && switches == 1 && nodes == 1 && sgpu_user_major == 7);
    assert(!sgpu_user_published && !normal_lines && !late_lines && !ready_calls && !mounted_calls && !locked);
    assert(!sgpu_user_publish() && switches == 1 && nodes == 1);
    pass("node-failed-no-retry");
    assert(completed == 33);
    printf("Completed %u new late-launch contracts\n", completed);
    return 0;
}
