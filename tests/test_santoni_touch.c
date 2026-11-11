/*
 * Host MMIO/kernel model around the ACTUAL reconstructed driver section.
 * Oracles: Linux smem.c, qcom_smd.c, smd-rpm.c, i2c-algo-bit.c, edt-ft5x06.c.
 * A model ACK is not hardware power/touch verification.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <setjmp.h>

typedef uintptr_t vm_offset_t;
typedef int wait_result_t;
typedef uintptr_t thread_t;
typedef struct { bool held; } lck_mtx_t;
#define LCK_GRP_DECLARE(name, label) int name
#define LCK_MTX_DECLARE(name, group) lck_mtx_t name = {false}
#ifndef __unused
#define __unused __attribute__((unused))
#endif
#define KERN_SUCCESS 0
#define NSEC_PER_MSEC 1000000u
#define NSEC_PER_USEC 1000u

static void santoni_mock_barrier(const char *, const char *);
static vm_offset_t ml_io_map(uint64_t, size_t);
static void delay(unsigned);
static void delay_for_interval(unsigned, unsigned);
static __unused void clock_interval_to_deadline(uint32_t, uint32_t, uint64_t *);
static __unused uint64_t mach_absolute_time(void);
static __unused void mock_yield(void);
#define __builtin_arm_yield() mock_yield()
static bool PE_parse_boot_argn(const char *, void *, int);
static int kernel_thread_start(void (*)(void *, wait_result_t), void *, thread_t *);
static void thread_deallocate(thread_t);
static void sweet_hid_touch(int, int, int, int);
static void sweet_hid_key(int, int);
static __unused bool sweet_hid_buttons_ready(void);
static __unused void lck_mtx_lock(lck_mtx_t *);
static __unused void lck_mtx_unlock(lck_mtx_t *);
static int driver_printf(const char *, ...) __attribute__((format(printf, 1, 2)));

/* Unused private entry points/old crc_bad are harmless in the baseline. All
 * other diagnostics, including real driver format/type errors, stay fatal. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"
#define printf driver_printf
#include "santoni_touch_driver.h"
#undef printf
#pragma GCC diagnostic pop

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #c); \
    fputs(driver_log, stdout); exit(1); \
} } while (0)

static _Alignas(8) uint8_t gpio[0x60000], smem[0x100000], msgram[0x10000];
static _Alignas(8) uint8_t ipc[0x1000], gic[0x1000], core[0x1000];
static _Alignas(8) uint8_t observer[0x800000];
static bool scl_stuck, sda_stuck;
static unsigned elapsed_us, intervals, stop_after;
static unsigned short_scheduler_delays;
static unsigned hid_ready_at, mutex_locks, mutex_unlocks;
static bool spmi_mutex_held;
static void (*started_threads[4])(void *, wait_result_t);
static unsigned nstarted_threads;
static int rpm_enabled;
static jmp_buf thread_exit;
static char driver_log[32768];
static size_t log_used;

enum bus_phase { BUS_IDLE, BUS_RX, BUS_ACK, BUS_TX, BUS_MASTER_ACK };
static struct {
    bool enabled, started, slave_low, prev_scl, prev_sda, prev_master_scl;
    bool address, send_after_ack, more, clock_blocked;
    enum bus_phase phase;
    uint8_t value, reg;
    unsigned bits, pos, nack_stage, rises, fail_rise;
    unsigned stretch_rise, stretch_us, stretch_until, int_low_until;
    uint8_t data[256][64], frames[4][33], frames_reg;
    unsigned nframes, frame, reads[256], bytes[256];
} bus;
static struct { int id, down, x, y; unsigned tick; } events[64];
static unsigned nevents;
static struct { int id, down; unsigned tick; } key_events[64];
static unsigned nkey_events, observer_maps;
static struct {
    bool enabled, stalled;
    uint8_t samples[64]; /* bit 0: volume up; bit 1: RESIN; bit 2: power */
    bool failed[64];
} buttons;
static bool auto_rpm, unrelated_reply;
static unsigned rpm_votes[16], rpm_fail_remaining[16];
static uint8_t last_request[52];
static void mock_rpm(void);

static uint32_t get32(const void *p)
{
    uint32_t value;
    memcpy(&value, p, sizeof(value));
    return value;
}

static void put32(void *p, uint32_t value) { memcpy(p, &value, 4); }
static void put16(void *p, uint16_t value) { memcpy(p, &value, 2); }

static int driver_printf(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = vsnprintf(driver_log + log_used, sizeof(driver_log) - log_used,
                      format, ap);
    va_end(ap);
    if (n > 0) {
        size_t left = sizeof(driver_log) - log_used;
        log_used += (size_t)n < left ? (size_t)n : left - 1;
    }
    return n;
}

static uint8_t slave_byte(void)
{
    if (bus.pos >= 64) return 0xff;
    if (bus.nframes && bus.reg == bus.frames_reg && bus.pos < 33)
        return bus.frames[bus.frame][bus.pos];
    return bus.data[bus.reg][bus.pos];
}

static void slave_received(void)
{
    bool ack = true;
    bus.send_after_ack = false;
    if (bus.address) {
        bus.address = false;
        unsigned stage = bus.value == 0x70 ? 1 : 3;
        ack = (bus.value == 0x70 || bus.value == 0x71) && bus.nack_stage != stage;
        if (ack && bus.value == 0x71) {
            bus.send_after_ack = true;
            bus.pos = 0;
            bus.frame = bus.reads[bus.reg];
            if (bus.nframes && bus.frame >= bus.nframes) bus.frame = bus.nframes - 1;
            bus.reads[bus.reg]++;
        }
    } else {
        bus.reg = bus.value;
        ack = bus.nack_stage != 2;
    }
    bus.slave_low = ack;
    bus.phase = BUS_ACK;
    bus.bits = bus.value = 0;
}

static void slave_sync(bool master_scl, bool master_sda)
{
    if (!bus.prev_master_scl && master_scl) {
        bus.rises++;
        if (bus.rises == bus.fail_rise) bus.clock_blocked = true;
        if (bus.rises == bus.stretch_rise)
            bus.stretch_until = elapsed_us + bus.stretch_us;
    }
    bool scl = master_scl && !scl_stuck && !bus.clock_blocked &&
               elapsed_us >= bus.stretch_until;
    if (bus.prev_scl && scl && bus.prev_sda != master_sda) {
        if (!master_sda) {
            bus.started = bus.address = true;
            bus.phase = BUS_RX;
            bus.bits = bus.value = 0;
            bus.slave_low = false;
        } else {
            bus.started = bus.slave_low = false;
            bus.phase = BUS_IDLE;
        }
    } else if (!bus.prev_scl && scl && bus.started) {
        if (bus.phase == BUS_RX) {
            bus.value = (uint8_t)((bus.value << 1) | master_sda);
            bus.bits++;
        } else if (bus.phase == BUS_TX) {
            if (++bus.bits == 8) bus.bytes[bus.reg]++;
        } else if (bus.phase == BUS_MASTER_ACK) {
            bus.more = !master_sda;
        }
    } else if (bus.prev_scl && !scl && bus.started) {
        if (bus.phase == BUS_RX && bus.bits == 8) {
            slave_received();
        } else if (bus.phase == BUS_ACK) {
            bus.slave_low = false;
            bus.phase = bus.send_after_ack ? BUS_TX : BUS_RX;
            if (bus.phase == BUS_TX) bus.slave_low = !(slave_byte() & 0x80);
        } else if (bus.phase == BUS_TX) {
            if (bus.bits == 8) {
                bus.phase = BUS_MASTER_ACK;
                bus.bits = 0;
                bus.slave_low = false;
            } else {
                bus.slave_low = !(slave_byte() & (0x80u >> bus.bits));
            }
        } else if (bus.phase == BUS_MASTER_ACK) {
            bus.bits = 0;
            bus.pos++;
            bus.phase = bus.more ? BUS_TX : BUS_IDLE;
            bus.slave_low = bus.more && !(slave_byte() & 0x80);
        }
    }
    bus.prev_scl = scl;
    bus.prev_sda = master_sda;
    bus.prev_master_scl = master_scl;
    uint32_t io = get32(gpio + PIN_SCL * 0x1000u + 4);
    put32(gpio + PIN_SCL * 0x1000u + 4, (io & ~1u) | scl);
    bool sda = master_sda && !sda_stuck && !bus.slave_low;
    io = get32(gpio + PIN_SDA * 0x1000u + 4);
    put32(gpio + PIN_SDA * 0x1000u + 4, (io & ~1u) | sda);
}

static void sync_gpio(void)
{
    bool scl = true, sda = true;
    for (unsigned pin = 0; pin < 96; pin++) {
        uint32_t cfg = get32(gpio + 0x1000u * pin);
        uint32_t io = get32(gpio + 0x1000u * pin + 4);
        bool high = (cfg & TLMM_OE) ? (io & 2u) != 0 : true;
        if (pin == PIN_SCL) scl = high;
        if (pin == PIN_SDA) sda = high;
        if ((pin == PIN_SCL && scl_stuck) ||
            (pin == PIN_SDA && sda_stuck)) high = false;
        if (bus.enabled && pin == PIN_TOUCH_INT)
            high = bus.reads[0] + bus.reads[0xf9] >= bus.int_low_until;
        if (buttons.enabled && pin == PIN_VOL_UP)
            high = !(buttons.samples[intervals < 64 ? intervals : 63] & 1);
        put32(gpio + 0x1000u * pin + 4, (io & ~1u) | (high ? 1u : 0u));
    }
    if (bus.enabled) slave_sync(scl, sda);
}

static void santoni_mock_barrier(const char *fn, __unused const char *kind)
{
    sync_gpio();
    if (auto_rpm && !strcmp(fn, "santoni_smd_kick")) mock_rpm();
    if (!strcmp(fn, "santoni_spmi_read_locked")) CHECK(spmi_mutex_held);
    if (buttons.enabled && (!strcmp(fn, "santoni_spmi_read") ||
                            !strcmp(fn, "santoni_spmi_read_locked"))) {
        unsigned tick = intervals < 64 ? intervals : 63;
        put32(observer + 5 * 0x8000 + 0x08,
              buttons.stalled ? 0 : buttons.failed[tick] ? 3 : 1);
        put32(observer + 5 * 0x8000 + 0x18,
              (buttons.samples[tick] & 2) | ((buttons.samples[tick] >> 2) & 1));
        put32(observer + 6 * 0x8000 + 0x08, 1);
        put32(observer + 6 * 0x8000 + 0x18, 0x80);
    }
}
static void delay(unsigned us)
{
    /* XNU can block here with the port's zero cpu_idle_latency. Count calls
     * even when this deterministic MMIO model advances without scheduler lag. */
    if (us <= 20) short_scheduler_delays++;
    elapsed_us += us; sync_gpio();
}
static void clock_interval_to_deadline(uint32_t interval, uint32_t scale, uint64_t *deadline)
{
    *deadline = elapsed_us + (uint64_t)interval * scale / NSEC_PER_USEC;
}
static uint64_t mach_absolute_time(void) { return elapsed_us; }
static void mock_yield(void) { elapsed_us++; sync_gpio(); }
static void delay_for_interval(unsigned n, unsigned scale)
{
    delay(n * (scale / 1000u));
    if (stop_after && ++intervals >= stop_after) longjmp(thread_exit, 1);
}

static vm_offset_t ml_io_map(uint64_t pa, size_t size)
{
    if (pa == TLMM_BASE_PHYS && size <= sizeof(gpio)) return (vm_offset_t)gpio;
    if (pa == TLMM_BASE_PHYS + PIN_VOL_UP * 0x1000u && size <= 0x1000)
        return (vm_offset_t)(gpio + PIN_VOL_UP * 0x1000u);
    if (pa == SMEM_PHYS && size <= sizeof(smem)) return (vm_offset_t)smem;
    if (pa == RPM_MSGRAM_PHYS && size <= sizeof(msgram)) return (vm_offset_t)msgram;
    if (pa == APCS1_PHYS && size <= sizeof(ipc)) return (vm_offset_t)ipc;
    if (pa == 0x0b000000UL && size <= sizeof(gic)) return (vm_offset_t)gic;
    if (pa == SPMI_CORE_PHYS && size <= sizeof(core)) return (vm_offset_t)core;
    if (pa >= SPMI_OBS_PHYS && pa - SPMI_OBS_PHYS <= sizeof(observer) &&
        size <= sizeof(observer) - (pa - SPMI_OBS_PHYS)) {
        observer_maps++;
        return (vm_offset_t)(observer + (pa - SPMI_OBS_PHYS));
    }
    return 0;
}

static bool PE_parse_boot_argn(const char *name, void *p, int size)
{
    if (strcmp(name, "santonirpm") || size != sizeof(int)) return false;
    memcpy(p, &rpm_enabled, sizeof(rpm_enabled));
    return true;
}
static int kernel_thread_start(void (*fn)(void *, wait_result_t),
                               __unused void *p, thread_t *t)
{
    CHECK(nstarted_threads < 4);
    started_threads[nstarted_threads++] = fn;
    *t = 1;
    return 0;
}
static void thread_deallocate(__unused thread_t t) {}
static void sweet_hid_touch(int id, int down, int x, int y)
{
    CHECK(nevents < sizeof(events) / sizeof(events[0]));
    events[nevents].id = id; events[nevents].down = down;
    events[nevents].x = x; events[nevents].y = y;
    events[nevents++].tick = intervals;
}
static void sweet_hid_key(int id, int down)
{
    CHECK(nkey_events < sizeof(key_events) / sizeof(key_events[0]));
    key_events[nkey_events].id = id;
    key_events[nkey_events].down = down;
    key_events[nkey_events++].tick = intervals;
}
static bool sweet_hid_buttons_ready(void) { return intervals >= hid_ready_at; }
static void lck_mtx_lock(lck_mtx_t *lock)
{
    CHECK(!lock->held && !spmi_mutex_held);
    lock->held = spmi_mutex_held = true;
    mutex_locks++;
}
static void lck_mtx_unlock(lck_mtx_t *lock)
{
    CHECK(lock->held && spmi_mutex_held);
    lock->held = spmi_mutex_held = false;
    mutex_unlocks++;
}

static void init_model(void)
{
    santoni_smd.smem = (vm_offset_t)smem;
    santoni_smd.msgram = (vm_offset_t)msgram;
    santoni_smd.ipc = (vm_offset_t)ipc;
    sync_gpio();
}

static void legacy(unsigned item, uint32_t off, uint32_t size, uint32_t aux)
{
    uint8_t *e = smem + SMEM_TOC_OFFSET + 16u * item;
    put32(e, 1); put32(e + 4, off); put32(e + 8, size); put32(e + 12, aux);
}

static void fifo_model(bool word, uint32_t size)
{
    santoni_smd.word = word;
    santoni_smd.fifo_size = size;
    santoni_smd.txinfo = (vm_offset_t)(smem + 0x3000);
    santoni_smd.rxinfo = santoni_smd.txinfo + INFO_HALF;
    santoni_smd.txfifo = (vm_offset_t)(smem + 0x4000);
    santoni_smd.rxfifo = santoni_smd.txfifo + size;
    santoni_smd.mapped = santoni_smd.open = true;
    smd_write32(santoni_smd.txinfo, INFO_STATE, SMD_OPENED);
    smd_write32(santoni_smd.rxinfo, INFO_STATE, SMD_OPENED);
}

static void reply(uint32_t id)
{
    uint32_t words[] = { RPM_MSG_REQ, 12, RPM_MSG_MSG_ID, 4, id };
    memcpy(santoni_smd.resp, words, sizeof(words));
    santoni_smd.resp_len = sizeof(words);
}

static void queue_reply(uint32_t id)
{
    uint32_t words[] = {20, 0, 0, 0, 0, 0x00716572, 12, 0x2367736d, 4, id};
    uint32_t head = get32((void *)(santoni_smd.rxinfo + INFO_HEAD));
    const uint8_t *p = (const uint8_t *)words;
    for (unsigned i = 0; i < sizeof(words); i++)
        ((uint8_t *)santoni_smd.rxfifo)[(head + i) & (santoni_smd.fifo_size - 1)] = p[i];
    put32((void *)(santoni_smd.rxinfo + INFO_HEAD),
          (head + sizeof(words)) & (santoni_smd.fifo_size - 1));
}

static void mock_rpm(void)
{
    if (!santoni_smd.open || !santoni_smd.txinfo) return;
    uint32_t head = get32((void *)(santoni_smd.txinfo + INFO_HEAD));
    uint32_t tail = get32((void *)(santoni_smd.txinfo + INFO_TAIL));
    if (head == tail) return;
    uint32_t mask = santoni_smd.fifo_size - 1;
    for (unsigned i = 0; i < sizeof(last_request); i++)
        last_request[i] = ((uint8_t *)santoni_smd.txfifo)[(tail + 20 + i) & mask];
    put32((void *)(santoni_smd.txinfo + INFO_TAIL), head);
    unsigned ldo = get32(last_request + 20);
    CHECK(ldo < 16);
    rpm_votes[ldo]++;
    if (rpm_fail_remaining[ldo]) { rpm_fail_remaining[ldo]--; return; }
    uint32_t id = get32(last_request + 8);
    if (unrelated_reply) queue_reply(id + 1);
    queue_reply(id);
}

static void empty_generic(uint8_t *p)
{
    memset(p, 0, 33);
    for (unsigned i = 0; i < 5; i++) { p[3 + 6*i] = 0xc0; p[5 + 6*i] = 0xf0; }
}

static void generic_slot(uint8_t *p, unsigned slot, unsigned ev, unsigned id,
                         unsigned x, unsigned y)
{
    p += 3 + 6*slot;
    p[0] = (uint8_t)((ev << 6) | (x >> 8)); p[1] = (uint8_t)x;
    p[2] = (uint8_t)((id << 4) | (y >> 8)); p[3] = (uint8_t)y;
}

static void init_i2c(void)
{
    bus.enabled = true;
    bus.prev_scl = bus.prev_sda = bus.prev_master_scl = true;
    empty_generic(bus.data[0]);
    bus.data[0xa6][0] = 0xa5;
    sync_gpio();
}

static void run_thread(unsigned ticks)
{
    stop_after = ticks;
    if (!setjmp(thread_exit)) santoni_keys_thread(NULL, 0);
}

static void run_buttons(unsigned ticks)
{
#ifdef SANTONI_HOST_HAS_BUTTON_THREAD
    stop_after = ticks;
    if (!setjmp(thread_exit)) santoni_buttons_thread(NULL, 0);
#else
    run_thread(ticks);
#endif
}

static void i2c_normal(void)
{
    init_i2c();
    uint8_t byte = 0;
    CHECK(santoni_ft5435_read((vm_offset_t)gpio, 0xa6, &byte, 1));
    CHECK(byte == 0xa5 && bus.bytes[0xa6] == 1);
    CHECK(!bus.started && bus.prev_scl && bus.prev_sda);
}

static void i2c_edges_do_not_schedule(void)
{
    init_i2c();
    uint8_t byte;
    CHECK(santoni_ft5435_read((vm_offset_t)gpio, 0xa6, &byte, 1));
    CHECK(byte == 0xa5);
    CHECK(short_scheduler_delays == 0);
    CHECK(elapsed_us > 500 && elapsed_us < 2000);
}

static void stretch(unsigned us, bool succeeds)
{
    init_i2c();
    bus.stretch_rise = 29; bus.stretch_us = us; /* first read-data clock */
    uint8_t byte = 0x5a;
    CHECK(santoni_ft5435_read((vm_offset_t)gpio, 0xa6, &byte, 1) == succeeds);
    CHECK(byte == (succeeds ? 0xa5 : 0x5a));
    CHECK(!(get32(gpio + PIN_SCL * 0x1000u) & TLMM_OE));
    CHECK(!(get32(gpio + PIN_SDA * 0x1000u) & TLMM_OE));
}
static void i2c_stretch_39(void) { stretch(39, true); }
static void i2c_stretch_40(void) { stretch(40, true); }
static void i2c_stretch_41(void) { stretch(41, false); }

static void clock_failure(unsigned rise)
{
    init_i2c(); bus.fail_rise = rise;
    uint8_t byte = 0x5a;
    CHECK(!santoni_ft5435_read((vm_offset_t)gpio, 0xa6, &byte, 1));
    CHECK(!(get32(gpio + PIN_SCL * 0x1000u) & TLMM_OE));
    CHECK(!(get32(gpio + PIN_SDA * 0x1000u) & TLMM_OE));
    if (rise <= 37) CHECK(byte == 0x5a);
}
static void i2c_write_clock(void) { clock_failure(1); }
static void i2c_write_ack_clock(void) { clock_failure(9); }
static void i2c_command_clock(void) { clock_failure(10); }
static void i2c_restart_clock(void) { clock_failure(19); }
static void i2c_read_address_clock(void) { clock_failure(20); }
static void i2c_data_clock(void) { clock_failure(29); }
static void i2c_read_ack_clock(void) { clock_failure(37); }
static void i2c_stop_clock(void) { clock_failure(38); }

static void nack_diagnostic(unsigned stage, const char *text)
{
    init_i2c(); bus.nack_stage = stage;
    run_thread(1);
    CHECK(strstr(driver_log, "I2C NACK stage="));
    CHECK(strstr(driver_log, text));
}
static void i2c_write_nack_diag(void) { nack_diagnostic(1, "stage=write-address"); }
static void i2c_command_nack_diag(void) { nack_diagnostic(2, "stage=command"); }
static void i2c_read_nack_diag(void) { nack_diagnostic(3, "stage=read-address"); }

static void touch_all_slots(void)
{
    init_i2c(); uint8_t *p = bus.data[0]; p[2] = 1;
    generic_slot(p, 0, 1, 0, 100, 200);
    generic_slot(p, 4, 2, 4, 719, 1279);
    struct santoni_touch_point pts[5];
    CHECK(santoni_ft5435_read_points((vm_offset_t)gpio, pts, 5) == 2);
    CHECK(pts[0].id == 0 && !pts[0].down);
    CHECK(pts[1].id == 4 && pts[1].down && pts[1].x == 719 && pts[1].y == 1279);
    CHECK(bus.bytes[0] == 33);
}

static void touch_zero_count_up(void)
{
    init_i2c(); generic_slot(bus.data[0], 4, 1, 4, 123, 456);
    struct santoni_touch_point pts[5];
    CHECK(santoni_ft5435_read_points((vm_offset_t)gpio, pts, 5) == 1);
    CHECK(pts[0].id == 4 && !pts[0].down);
}

static void touch_five_points(void)
{
    init_i2c(); bus.data[0][2] = 5;
    for (unsigned i = 0; i < 5; i++) generic_slot(bus.data[0], i, 2, i, i, 1279-i);
    struct santoni_touch_point pts[5];
    CHECK(santoni_ft5435_read_points((vm_offset_t)gpio, pts, 5) == 5);
    for (int i = 0; i < 5; i++) CHECK(pts[i].id == i && pts[i].x == i && pts[i].y == 1279-i);
    CHECK(bus.bytes[0] == 33);
}

static void touch_bad_count(void)
{
    init_i2c(); bus.data[0][2] = 6;
    struct santoni_touch_point pts[5];
    CHECK(santoni_ft5435_read_points((vm_offset_t)gpio, pts, 5) == -2);
}

static void touch_id_bound(void)
{
    init_i2c(); bus.data[0][2] = 2;
    generic_slot(bus.data[0], 0, 2, 4, 0, 0);
    generic_slot(bus.data[0], 1, 2, 5, 4095, 4095);
    struct santoni_touch_point pts[5];
    CHECK(santoni_ft5435_read_points((vm_offset_t)gpio, pts, 5) == 1);
    CHECK(pts[0].id == 4 && pts[0].x == 0 && pts[0].y == 0);
}

static void touch_evervision(void)
{
    init_i2c(); bus.data[0xa8][0] = 0x59; bus.data[0][2] = 1;
    generic_slot(bus.data[0], 0, 2, 0, 123, 456);
    struct santoni_touch_point pts[5];
    CHECK(santoni_ft5435_read_points((vm_offset_t)gpio, pts, 5) == 1);
    CHECK(pts[0].x == 456 && pts[0].y == 123 && bus.reads[0x53] == 1);
}

static void m06_frame(uint8_t *p, unsigned ev)
{
    memset(p, 0, 33); p[0] = p[1] = 0xaa; p[2] = 26;
    for (unsigned i = 0; i < 5; i++) p[5 + 4*i] = 0xc0;
    p[5] = (uint8_t)(ev << 6); p[6] = 123; p[7] = 1; p[8] = 200;
    for (unsigned i = 0; i < 25; i++) p[25] ^= p[i];
}

static void touch_m06(void)
{
    init_i2c(); memcpy(bus.data[0xbb] + 1, "eP0", 3); m06_frame(bus.data[0xf9], 2);
    struct santoni_touch_point pts[5];
    CHECK(santoni_ft5435_read_points((vm_offset_t)gpio, pts, 5) == 1);
    CHECK(pts[0].x == 123 && pts[0].y == 456 && pts[0].down);
    CHECK(bus.reads[0] == 0 && bus.bytes[0xf9] == 26 && bus.bytes[0xbb] == 22);
}

static void touch_m06_bad_crc(void)
{
    init_i2c(); memcpy(bus.data[0xbb] + 1, "EP0", 3); m06_frame(bus.data[0xf9], 2);
    bus.data[0xf9][25] ^= 1;
    struct santoni_touch_point pts[5];
    CHECK(santoni_ft5435_read_points((vm_offset_t)gpio, pts, 5) == -2);
}

static void touch_m12(void)
{
    init_i2c(); memcpy(bus.data[0xbb], "ep0", 3); bus.data[0][2] = 1;
    generic_slot(bus.data[0], 4, 2, 4, 123, 456);
    struct santoni_touch_point pts[5];
    CHECK(santoni_ft5435_read_points((vm_offset_t)gpio, pts, 5) == 1);
    CHECK(pts[0].id == 4 && bus.reads[0xbb] == 1 && bus.reads[0xa6] == 0);
}

static void touch_release(bool pulse, bool bad)
{
    init_i2c(); bus.nframes = bad ? 4 : 3; bus.int_low_until = pulse ? 2 : 0;
    for (unsigned i = 0; i < bus.nframes; i++) empty_generic(bus.frames[i]);
    bus.frames[1][2] = 1; generic_slot(bus.frames[1], 4, 2, 4, 719, 1279);
    if (bad) bus.frames[2][2] = 6;
    generic_slot(bus.frames[bus.nframes - 1], 4, 1, 4, 0, 0);
    run_thread(20);
    CHECK(nevents == 2 && events[0].down && !events[1].down);
    CHECK(events[0].id == 4 && events[1].id == 4);
    CHECK(events[1].x == 719 && events[1].y == 1279);
    CHECK(events[1].tick <= events[0].tick + (bad ? 2u : 1u));
}
static void touch_release_after_int(void) { touch_release(true, false); }
static void touch_missed_int_pulse(void) { touch_release(false, false); }
static void touch_bad_report_keeps_contact(void) { touch_release(true, true); }

static void rpm_fifo_ack(void)
{
    fifo_model(false, 512); auto_rpm = true;
    CHECK(santoni_rpm_ldo(10, 2850000));
    CHECK(get32(last_request) == 0x00716572 && get32(last_request + 4) == 44);
    CHECK(get32(last_request + 16) == 0x616f646c && get32(last_request + 20) == 10);
    CHECK(get32(last_request + 28) == 0x6e657773 && get32(last_request + 36) == 1);
    CHECK(get32(last_request + 40) == 0x00007675 && get32(last_request + 48) == 2850000);
    CHECK(rpm_votes[10] == 1 && strstr(driver_log, "ack fifo"));
}

static void touch_m06_down_keeps_contact(void)
{
    init_i2c(); memcpy(bus.data[0xbb] + 1, "EP0", 3);
    bus.nframes = 4; bus.frames_reg = 0xf9; bus.int_low_until = 2;
    m06_frame(bus.frames[0], 3); m06_frame(bus.frames[1], 2);
    m06_frame(bus.frames[2], 0); m06_frame(bus.frames[3], 1);
    run_thread(10);
    CHECK(nevents == 2 && events[0].down && !events[1].down);
    CHECK(events[1].tick == events[0].tick + 2);
    CHECK(events[1].x == 123 && events[1].y == 456);
}

static void rpm_stale_snapshot(void)
{
    fifo_model(false, 512);
    uint32_t words[] = {0x00716572, 12, 0x2367736d, 4, 1};
    memcpy(msgram, words, sizeof(words));
    CHECK(!santoni_rpm_ldo(10, 2850000));
    CHECK(!memcmp(msgram, words, sizeof(words)));
}

static void rpm_unrelated_then_ack(void)
{
    fifo_model(true, 512); auto_rpm = unrelated_reply = true;
    CHECK(santoni_rpm_ldo(5, 1800000));
    CHECK(rpm_votes[5] == 1);
}

static void touch_both_rail_retry(void)
{
    fifo_model(false, 512); auto_rpm = true; rpm_enabled = 1;
    rpm_fail_remaining[5] = 1; init_i2c();
    run_thread(1010);
    CHECK(rpm_votes[10] == 2 && rpm_votes[5] == 2);
    CHECK(santoni_diag.l10 == 1 && santoni_diag.l5 == 1);
    CHECK(strstr(driver_log, "both votes ACK on retry"));
}

static void i2c_stuck_clock(void)
{
    uint8_t byte = 0xa5;
    scl_stuck = sda_stuck = true;
    sync_gpio();
    CHECK(!santoni_ft5435_read((vm_offset_t)gpio, 0, &byte, 1));
    CHECK(byte == 0xa5);
    CHECK(elapsed_us < 1000);
    CHECK(!(get32(gpio + PIN_SCL * 0x1000u) & TLMM_OE));
    CHECK(!(get32(gpio + PIN_SDA * 0x1000u) & TLMM_OE));
}

static void rpm_valid_reply(void)
{
    reply(7);
    CHECK(santoni_rpm_parse_reply(10, 7));
    CHECK(!santoni_rpm_parse_reply(10, 8));
}

static void rpm_wrong_service(void)
{
    reply(7); put32(santoni_smd.resp, 0x12345678);
    CHECK(!santoni_rpm_parse_reply(10, 7));
}

static void rpm_truncated_header(void)
{
    reply(7); put32(santoni_smd.resp + 4, 16);
    CHECK(!santoni_rpm_parse_reply(10, 7));
}

static void rpm_malformed_tail(void)
{
    reply(7); put32(santoni_smd.resp + 4, 20);
    put32(santoni_smd.resp + 20, RPM_MSG_ERR);
    put32(santoni_smd.resp + 24, 1);
    santoni_smd.resp_len = 28;
    CHECK(!santoni_rpm_parse_reply(10, 7));
}

static void rpm_oversized_id(void)
{
    reply(7); put32(santoni_smd.resp + 4, 16);
    put32(santoni_smd.resp + 12, 8); put32(santoni_smd.resp + 20, 0);
    santoni_smd.resp_len = 24;
    CHECK(!santoni_rpm_parse_reply(10, 7));
}

static void rpm_long_error(void)
{
    reply(7);
    put32(santoni_smd.resp + 20, RPM_MSG_ERR);
    put32(santoni_smd.resp + 24, 64);
    memset(santoni_smd.resp + 28, 'x', 64);
    put32(santoni_smd.resp + 4, 84); santoni_smd.resp_len = 92;
    CHECK(!santoni_rpm_parse_reply(10, 7));
}

static void partition(unsigned index, uint32_t part_off, uint32_t size)
{
    uint8_t *table = smem + SMEM_PTABLE_OFFSET;
    put32(table, SMEM_PTABLE_MAGIC); put32(table + 4, 1);
    put32(table + 8, index + 1);
    uint8_t *e = table + 32 + 48 * index; /* Linux sizeof(smem_ptable_entry) */
    put32(e, part_off); put32(e + 4, size);
    put16(e + 12, SMEM_GLOBAL_HOST); put16(e + 14, SMEM_GLOBAL_HOST);
    put32(e + 16, 32);
    uint8_t *part = smem + part_off;
    put32(part, SMEM_PART_MAGIC); put16(part + 4, SMEM_GLOBAL_HOST);
    put16(part + 6, SMEM_GLOBAL_HOST); put32(part + 8, size);
    put32(part + 12, 56); put32(part + 16, size);
    put16(part + 32, SMEM_PRIV_CANARY); put16(part + 34, 13);
    put32(part + 36, 8);
}

static void smem_partition_stride(void)
{
    partition(1, 0x8000, 0x1000);
    size_t size = 0;
    CHECK(santoni_smem_item_partition(13, &size) == (vm_offset_t)(smem + 0x8030));
    CHECK(size == 8);
}

static void smem_uncached_bound(void)
{
    partition(0, 0x8000, 0x1000);
    put32(smem + 0x8000 + 12, 48); /* header published, data not allocated */
    size_t size = 0;
    CHECK(!santoni_smem_item_partition(13, &size));
}

static void smem_cached_item(void)
{
    partition(0, 0x8000, 0x1000);
    uint8_t *part = smem + 0x8000;
    put32(part + 12, 32); put32(part + 16, 0xfa0);
    uint8_t *entry = part + 0xfe0; /* ALIGN(header, cacheline=32) */
    put16(entry, SMEM_PRIV_CANARY); put16(entry + 2, 13);
    put32(entry + 4, 32); put16(entry + 8, 3); put16(entry + 10, 16);
    size_t size = 0;
    CHECK(santoni_smem_item_partition(13, &size) == (vm_offset_t)(part + 0xfc0));
    CHECK(size == 29);
}

static void alloc_entry(uint8_t *e, unsigned cid)
{
    memcpy(e, "rpm_requests", 13); put32(e + 20, cid);
    put32(e + 24, SMD_FLAG_PACKET | SMD_EDGE_RPM); put32(e + 28, 1);
}

static void smd_allocation_bound(void)
{
    legacy(13, 0x3000, 32, 0);
    alloc_entry(smem + 0x3020, 4); /* just OUTSIDE the allocation */
    legacy(18, 0x4000, 40, 0); legacy(342, 0x5000, 256, 0);
    CHECK(!santoni_smd_map_channel());
    CHECK(!santoni_smd.txinfo && !santoni_smd.txfifo);
}

static void smd_odd_fifo(void)
{
    legacy(13, 0x3000, 32, 0); alloc_entry(smem + 0x3000, 4);
    legacy(18, 0x4000, 40, 0); legacy(342, 0x5000, 257, 0);
    CHECK(!santoni_smd_map_channel());
    CHECK(!santoni_smd.txinfo && !santoni_smd.txfifo);
}

static void smd_partial_packet(void)
{
    fifo_model(false, 64);
    put32((void *)santoni_smd.rxfifo, 48);
    smd_write32(santoni_smd.rxinfo, INFO_HEAD, 20);
    CHECK(!santoni_smd_rx_drain());
    CHECK(smd_read32(santoni_smd.rxinfo, INFO_TAIL) == 20);
    CHECK(!santoni_smd.resp_ready);
    /* Once header space is freed, remote can publish its complete payload. */
    for (unsigned i = 0; i < 48; i++)
        ((uint8_t *)santoni_smd.rxfifo)[(20 + i) & 63] = (uint8_t)i;
    smd_write32(santoni_smd.rxinfo, INFO_HEAD, 4);
    CHECK(santoni_smd_rx_drain());
    CHECK(santoni_smd.resp_len == 48 && santoni_smd.resp_ready);
    for (unsigned i = 0; i < 48; i++) CHECK(santoni_smd.resp[i] == i);
    CHECK(smd_read32(santoni_smd.rxinfo, INFO_TAIL) == 4);
}

static void smd_word_send_alignment(void)
{
    fifo_model(true, 128);
    uint8_t data[4] = {1, 2, 3, 4};
    CHECK(!santoni_smd_send(data, 3));
    CHECK(smd_read32(santoni_smd.txinfo, INFO_HEAD) == 0);
    CHECK(santoni_smd_send(data, 4));
    CHECK(smd_read32(santoni_smd.txinfo, INFO_HEAD) == 24);
    CHECK(get32((void *)santoni_smd.txfifo) == 4);
}

static void rpm_duplicate_id(void)
{
    reply(7); put32(santoni_smd.resp + 4, 24);
    put32(santoni_smd.resp + 20, RPM_MSG_MSG_ID);
    put32(santoni_smd.resp + 24, 4); put32(santoni_smd.resp + 28, 7);
    santoni_smd.resp_len = 32;
    CHECK(!santoni_rpm_parse_reply(10, 7));
}

static void smem_global_precedence(void)
{
    partition(1, 0x8000, 0x1000); legacy(13, 0x5000, 32, 0);
    size_t size = 0;
    CHECK(santoni_smem_item(13, &size) == (vm_offset_t)(smem + 0x8030));
    CHECK(size == 8);
}

static void smem_partition_last_entry(void)
{
    partition(83, 0x8000, 0x1000);
    size_t size = 0;
    CHECK(santoni_smem_item_partition(13, &size) == (vm_offset_t)(smem + 0x8030));
}

static void smem_allocation_neighbors(void)
{
    const unsigned limits[] = {32, 47, 48, 55, 56, 57, 64, 4097};
    for (unsigned i = 0; i < sizeof(limits)/sizeof(limits[0]); i++) {
        memset(smem, 0, sizeof(smem)); partition(0, 0x8000, 0x1000);
        put32(smem + 0x800c, limits[i]); size_t size = 0;
        vm_offset_t p = santoni_smem_item_partition(13, &size);
        CHECK((p != 0) == (limits[i] == 56 || limits[i] == 64));
        if (p) CHECK(p == (vm_offset_t)(smem + 0x8030) && size == 8);
    }
}

static void smem_cached_bad_size(void)
{
    partition(0, 0x8000, 0x1000);
    uint8_t *part = smem + 0x8000;
    put32(part + 12, 32); put32(part + 16, 0xfa0);
    uint8_t *entry = part + 0xfe0;
    put16(entry, SMEM_PRIV_CANARY); put16(entry + 2, 13);
    put32(entry + 4, 0x200); size_t size = 0;
    CHECK(!santoni_smem_item_partition(13, &size));
}

static void smd_short_header(void)
{
    fifo_model(false, 64); smd_write32(santoni_smd.rxinfo, INFO_HEAD, 19);
    CHECK(!santoni_smd_rx_drain());
    CHECK(smd_read32(santoni_smd.rxinfo, INFO_TAIL) == 0);
}

static void smd_payload_split(void)
{
    fifo_model(false, 128); put32((void *)santoni_smd.rxfifo, 20);
    for (unsigned i = 0; i < 20; i++) ((uint8_t *)santoni_smd.rxfifo)[20+i] = (uint8_t)i;
    smd_write32(santoni_smd.rxinfo, INFO_HEAD, 25);
    CHECK(!santoni_smd_rx_drain());
    CHECK(smd_read32(santoni_smd.rxinfo, INFO_TAIL) == 25);
    smd_write32(santoni_smd.rxinfo, INFO_HEAD, 40);
    CHECK(santoni_smd_rx_drain() && santoni_smd.resp_len == 20);
    for (unsigned i = 0; i < 20; i++) CHECK(santoni_smd.resp[i] == i);
}

static void smd_reply_size(unsigned size, bool accepted)
{
    fifo_model(false, 512); put32((void *)santoni_smd.rxfifo, size);
    for (unsigned i = 0; i < size; i++) ((uint8_t *)santoni_smd.rxfifo)[20+i] = (uint8_t)i;
    smd_write32(santoni_smd.rxinfo, INFO_HEAD, 20 + size);
    CHECK(santoni_smd_rx_drain() == accepted);
    CHECK(santoni_smd.resp_ready == accepted);
    CHECK(smd_read32(santoni_smd.rxinfo, INFO_TAIL) == 20 + size);
    if (accepted) CHECK(santoni_smd.resp_len == size);
}
static void smd_max_reply(void) { smd_reply_size(128, true); }
static void smd_oversize_reply(void) { smd_reply_size(129, false); }

static void smd_word_receive_alignment(void)
{
    fifo_model(true, 128); put32((void *)santoni_smd.rxfifo, 3);
    smd_write32(santoni_smd.rxinfo, INFO_HEAD, 24);
    CHECK(!santoni_smd_rx_drain() && !santoni_smd.resp_ready);
}

static void smem_legacy_aux_bounds(void)
{
    size_t size = 0;
    const unsigned bases[] = {0x60000, 0x68000};
    for (unsigned i = 0; i < 2; i++) {
        legacy(13, 0x7ff8, 8, bases[i]);
        CHECK(santoni_smem_item_legacy(13, &size) ==
              (vm_offset_t)(msgram + i*0x8000 + 0x7ff8));
        CHECK(size == 8);
        legacy(13, 0x7ff8, 9, bases[i]);
        CHECK(!santoni_smem_item_legacy(13, &size));
    }
    legacy(13, 0, 8, 0x60004);
    CHECK(!santoni_smem_item_legacy(13, &size));
    legacy(13, 0xffff8, 8, 0);
    CHECK(santoni_smem_item_legacy(13, &size) == (vm_offset_t)(smem + 0xffff8));
    legacy(13, 0xffff8, 9, 0);
    CHECK(!santoni_smem_item_legacy(13, &size));
    CHECK(!santoni_smem_item_legacy(512, &size));
}

static void init_buttons(void)
{
    buttons.enabled = true;
    put32(core + 0x800 + 4 * 5, 0x0800); /* SID 0, PON peripheral 0x08 */
    init_i2c();
}

static void buttons_idle(void)
{
    init_buttons(); run_buttons(16);
    CHECK(nkey_events == 0);
}

static void volume_press_release(unsigned sample, unsigned code)
{
    init_buttons();
    for (unsigned i = 5; i < 11; i++) buttons.samples[i] = (uint8_t)sample;
    run_buttons(16);
    CHECK(nkey_events == 2);
    CHECK(key_events[0].id == (int)code && key_events[0].down);
    CHECK(key_events[1].id == (int)code && !key_events[1].down);
    CHECK(key_events[0].tick >= 7 && key_events[1].tick >= 13);
}
static void volume_up_no_home(void) { volume_press_release(1, 1); }
static void volume_down_resin(void) { volume_press_release(2, 2); }
static void power_pon(void) { volume_press_release(4, 0); }

static void all_buttons_independent(void)
{
    init_buttons();
    for (unsigned i = 0; i < 6; i++) buttons.samples[i] = 7;
    run_buttons(12);
    CHECK(nkey_events == 6);
    bool held[3] = {false};
    unsigned count[3] = {0};
    for (unsigned i = 0; i < nkey_events; i++) {
        int id = key_events[i].id;
        CHECK(id >= 0 && id <= 2 && key_events[i].down != held[id]);
        held[id] = key_events[i].down;
        count[id]++;
    }
    for (unsigned i = 0; i < 3; i++) CHECK(count[i] == 2 && !held[i]);
}

static void power_read_failure(void)
{
    init_buttons();
    for (unsigned i = 0; i < 8; i++) buttons.samples[i] = 4;
    for (unsigned i = 8; i < 12; i++) buttons.failed[i] = true;
    buttons.samples[12] = buttons.samples[14] = 4;
    run_buttons(22);
    CHECK(nkey_events == 2);
    CHECK(key_events[0].id == 0 && key_events[0].down);
    CHECK(key_events[1].id == 0 && !key_events[1].down && key_events[1].tick >= 17);
}

static void volume_both_held_at_start(void)
{
    init_buttons();
    for (unsigned i = 0; i < 6; i++) buttons.samples[i] = 3;
    run_buttons(12);
    CHECK(nkey_events == 4);
    bool held[3] = {false};
    unsigned count[3] = {0};
    for (unsigned i = 0; i < 4; i++) {
        int id = key_events[i].id;
        CHECK(id == 1 || id == 2);
        CHECK(key_events[i].down != held[id]);
        held[id] = key_events[i].down;
        count[id]++;
    }
    CHECK(count[1] == 2 && count[2] == 2 && !held[1] && !held[2]);
}

static void volume_up_bounce(void)
{
    init_buttons();
    buttons.samples[3] = buttons.samples[5] = buttons.samples[14] = 1;
    for (unsigned i = 7; i < 13; i++) buttons.samples[i] = 1;
    run_buttons(22);
    CHECK(nkey_events == 2);
    CHECK(key_events[0].id == 1 && key_events[0].down && key_events[0].tick >= 9);
    CHECK(key_events[1].id == 1 && !key_events[1].down && key_events[1].tick >= 17);
}

static void volume_down_read_failure(void)
{
    init_buttons();
    for (unsigned i = 0; i < 8; i++) buttons.samples[i] = 2;
    for (unsigned i = 8; i < 12; i++) buttons.failed[i] = true;
    buttons.samples[12] = buttons.samples[14] = 2;
    run_buttons(22);
    CHECK(nkey_events == 2);
    CHECK(key_events[0].id == 2 && key_events[0].down);
    CHECK(key_events[1].id == 2 && !key_events[1].down && key_events[1].tick >= 17);
}

static void volume_up_without_pon(void)
{
    init_buttons(); put32(core + 0x800 + 4 * 5, 0);
    for (unsigned i = 5; i < 11; i++) buttons.samples[i] = 3;
    run_buttons(16);
    CHECK(nkey_events == 2 && key_events[0].id == 1 && key_events[1].id == 1);
}

static void spmi_observer_cache(void)
{
    init_buttons(); put32(core + 0x800 + 4 * 6, 0x4400);
    for (unsigned i = 0; i < 30; i++) {
        uint8_t value = 0xff;
        CHECK(santoni_spmi_read(0x0810, &value) && value == 0);
        CHECK(santoni_spmi_read(0x4446, &value) && value == 0x80);
    }
    CHECK(observer_maps == 2);
}

static void spmi_timeout_is_short(void)
{
    init_buttons(); buttons.stalled = true;
    uint8_t value = 0xa5;
    unsigned start = elapsed_us;
    CHECK(!santoni_spmi_read(0x0810, &value));
    CHECK(value == 0xa5 && elapsed_us - start == 1000);
    CHECK(short_scheduler_delays == 0);
}

static void buttons_without_touch(void)
{
    init_buttons();
    for (unsigned i = 4; i < 10; i++) buttons.samples[i] = 7;
    run_buttons(15);
    CHECK(nkey_events == 6);
    CHECK(bus.reads[0] == 0 && bus.reads[0xf9] == 0 && bus.reads[0xbb] == 0);
    CHECK(get32(gpio + PIN_TOUCH_RST * 0x1000u) == 0);
}

static void touch_without_button_reads(void)
{
    init_buttons();
    run_thread(15);
    CHECK(nkey_events == 0);
    CHECK(observer_maps == 0); /* PON has an APID; rails do not in this model. */
    CHECK(bus.reads[0] > 0);
}

static void buttons_wait_for_hid(void)
{
    init_buttons(); hid_ready_at = 6;
    for (unsigned i = 0; i < 11; i++) buttons.samples[i] = 7;
    run_buttons(17);
    CHECK(nkey_events == 6);
    for (unsigned i = 0; i < nkey_events; i++) CHECK(key_events[i].tick >= 6);
}

static void input_threads_both_start(void)
{
    santoni_keys_start();
    CHECK(nstarted_threads == 2);
#ifdef SANTONI_HOST_HAS_BUTTON_THREAD
    CHECK(started_threads[0] == santoni_buttons_thread);
#endif
    CHECK(started_threads[1] == santoni_keys_thread);
}

static void spmi_mutex_releases_on_error(void)
{
    init_buttons(); buttons.stalled = true;
    uint8_t value = 0xa5;
    CHECK(!santoni_spmi_read(0x0810, &value));
    CHECK(!spmi_mutex_held && mutex_locks == 1 && mutex_unlocks == 1);
    buttons.stalled = false;
    CHECK(santoni_spmi_read(0x0810, &value) && value == 0);
    CHECK(!spmi_mutex_held && mutex_locks == 2 && mutex_unlocks == 2);
}

static const struct { const char *name; void (*run)(void); } tests[] = {
    {"i2c_stuck_clock", i2c_stuck_clock},
    {"i2c_normal", i2c_normal},
    {"i2c_edges_do_not_schedule", i2c_edges_do_not_schedule},
    {"i2c_stretch_39", i2c_stretch_39},
    {"i2c_stretch_40", i2c_stretch_40},
    {"i2c_stretch_41", i2c_stretch_41},
    {"i2c_write_clock", i2c_write_clock},
    {"i2c_write_ack_clock", i2c_write_ack_clock},
    {"i2c_command_clock", i2c_command_clock},
    {"i2c_restart_clock", i2c_restart_clock},
    {"i2c_read_address_clock", i2c_read_address_clock},
    {"i2c_data_clock", i2c_data_clock},
    {"i2c_read_ack_clock", i2c_read_ack_clock},
    {"i2c_stop_clock", i2c_stop_clock},
    {"i2c_write_nack_diag", i2c_write_nack_diag},
    {"i2c_command_nack_diag", i2c_command_nack_diag},
    {"i2c_read_nack_diag", i2c_read_nack_diag},
    {"touch_all_slots", touch_all_slots},
    {"touch_zero_count_up", touch_zero_count_up},
    {"touch_five_points", touch_five_points},
    {"touch_bad_count", touch_bad_count},
    {"touch_id_bound", touch_id_bound},
    {"touch_evervision", touch_evervision},
    {"touch_m06", touch_m06},
    {"touch_m06_bad_crc", touch_m06_bad_crc},
    {"touch_m06_down_keeps_contact", touch_m06_down_keeps_contact},
    {"touch_m12", touch_m12},
    {"touch_release_after_int", touch_release_after_int},
    {"touch_missed_int_pulse", touch_missed_int_pulse},
    {"touch_bad_report_keeps_contact", touch_bad_report_keeps_contact},
    {"touch_both_rail_retry", touch_both_rail_retry},
    {"rpm_fifo_ack", rpm_fifo_ack},
    {"rpm_stale_snapshot", rpm_stale_snapshot},
    {"rpm_unrelated_then_ack", rpm_unrelated_then_ack},
    {"rpm_valid_reply", rpm_valid_reply},
    {"rpm_wrong_service", rpm_wrong_service},
    {"rpm_truncated_header", rpm_truncated_header},
    {"rpm_malformed_tail", rpm_malformed_tail},
    {"rpm_oversized_id", rpm_oversized_id},
    {"rpm_long_error", rpm_long_error},
    {"rpm_duplicate_id", rpm_duplicate_id},
    {"smem_partition_stride", smem_partition_stride},
    {"smem_uncached_bound", smem_uncached_bound},
    {"smem_cached_item", smem_cached_item},
    {"smem_global_precedence", smem_global_precedence},
    {"smem_partition_last_entry", smem_partition_last_entry},
    {"smem_allocation_neighbors", smem_allocation_neighbors},
    {"smem_cached_bad_size", smem_cached_bad_size},
    {"smem_legacy_aux_bounds", smem_legacy_aux_bounds},
    {"smd_allocation_bound", smd_allocation_bound},
    {"smd_odd_fifo", smd_odd_fifo},
    {"smd_partial_packet", smd_partial_packet},
    {"smd_word_send_alignment", smd_word_send_alignment},
    {"smd_short_header", smd_short_header},
    {"smd_payload_split", smd_payload_split},
    {"smd_max_reply", smd_max_reply},
    {"smd_oversize_reply", smd_oversize_reply},
    {"smd_word_receive_alignment", smd_word_receive_alignment},
    {"buttons_idle", buttons_idle},
    {"volume_up_no_home", volume_up_no_home},
    {"volume_down_resin", volume_down_resin},
    {"power_pon", power_pon},
    {"all_buttons_independent", all_buttons_independent},
    {"power_read_failure", power_read_failure},
    {"volume_both_held_at_start", volume_both_held_at_start},
    {"volume_up_bounce", volume_up_bounce},
    {"volume_down_read_failure", volume_down_read_failure},
    {"volume_up_without_pon", volume_up_without_pon},
    {"spmi_observer_cache", spmi_observer_cache},
    {"spmi_timeout_is_short", spmi_timeout_is_short},
    {"buttons_without_touch", buttons_without_touch},
    {"touch_without_button_reads", touch_without_button_reads},
    {"buttons_wait_for_hid", buttons_wait_for_hid},
    {"input_threads_both_start", input_threads_both_start},
    {"spmi_mutex_releases_on_error", spmi_mutex_releases_on_error},
};

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "--list")) {
        for (unsigned i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
            puts(tests[i].name);
        return 0;
    }
    init_model();
    for (unsigned i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        if (!strcmp(argv[1], tests[i].name)) {
            tests[i].run();
            fputs(driver_log, stdout);
            return 0;
        }
    }
    return 2;
}
