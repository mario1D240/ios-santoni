/* Host-only MMIO/kernel fixture. Production logic is included from reconstructed
 * pe_fiq.c, SweetCPU::signalCPU and sleh_irq, not reimplemented here.
 * This models banked registers and SGI source tokens; it is NOT a cache/CPU or
 * weak-memory emulator. Barrier tests check call ordering, not hardware latency.
 */
#include <algorithm>
#include <array>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#define SANTONI 1
#define SWEET 1
#define HAS_GIC_V3 0
#define MACH_ASSERT 0
#define SWEET_SMP_MAX_CPUS 8
#define SWEET_VTIMER_INTID 20
#define SWEET_IPI_SGI 1
#define SECURITY_READ_ONLY_LATE(type) type
#ifndef __unused
#define __unused __attribute__((unused))
#endif
#define TRUE true
#define DSB_SY 0xf
#define DSB_ISHST 0xa
#define DMB_ISHLD 0x9
#define DMB_ISH 0xb
#define ISB_SY 0xf
using vm_offset_t = uintptr_t;
using DTEntry = void *;
constexpr int kSuccess = 0;
constexpr uintptr_t DIST = 0x10000, CPU_IF = 0x20000;
/* GICv2 SGI enables are RAO/WI; only PPIs are software-maskable. */
constexpr uint32_t PRIVATE = (1U << 20) | 0xffffU;
constexpr unsigned IRQ_COUNT = 256;

struct Event { std::string kind; uintptr_t addr; uint32_t value; unsigned cpu; };
static std::vector<Event> events;
static unsigned current_cpu, cpu_count = 8, dt_calls, map_calls;
static uint32_t dt_timer = 20;
static bool invalid_cpu, group_raz_wi;
static unsigned iface[8] = {4, 5, 6, 7, 0, 1, 2, 3};
static uint32_t target_words[8][8];
static uint32_t global_regs[0x1000 / 4];
static uint32_t private_regs[8][0x1000 / 4];
static uint32_t cpu_regs[8][0x2000 / 4];
static uint16_t pending[8][8], active[8][8];
static unsigned ipis[8], timer_calls, other_calls;
static bool inject_iar, repend;
static uint32_t injected_iar, last_eoi, other_intid;

static void require(bool value, const char *why) {
    if (!value) throw std::runtime_error(why);
}
[[noreturn]] static void panic(const char *fmt, ...) {
    char buf[256]; va_list args;
    va_start(args, fmt); vsnprintf(buf, sizeof(buf), fmt, args); va_end(args);
    throw std::runtime_error(std::string("PANIC: ") + buf);
}
static void kprintf(const char *, ...) {}
static uint64_t mock_rsr(const char *reg) {
    require(std::strcmp(reg, "MPIDR_EL1") == 0, "unexpected sysreg read");
    return current_cpu < 4 ? 0x100 + current_cpu : current_cpu - 4;
}
static int ml_get_cpu_number(uint32_t mpidr) {
    if (invalid_cpu) return -1;
    return (mpidr & 0x100) ? (mpidr & 3) : 4 + (mpidr & 3);
}
static int cpu_number() { return current_cpu; }
static void mock_barrier(const char *kind, uint32_t scope) {
    events.push_back({kind, 0, scope, current_cpu});
}
#define __builtin_arm_rsr64(reg) mock_rsr(reg)
#define __builtin_arm_dsb(scope) mock_barrier("dsb", scope)
#define __builtin_arm_dmb(scope) mock_barrier("dmb", scope)
#define __builtin_arm_isb(scope) mock_barrier("isb", scope)

static uint32_t &dist_register(unsigned off) {
    bool banked = off == 0x80 || off == 0x100 || off == 0x200 || off == 0x300 ||
        (off >= 0x400 && off < 0x420) || off == 0xc00 || off == 0xc04;
    return banked ? private_regs[current_cpu][off / 4] : global_regs[off / 4];
}
static uint32_t acknowledge() {
    if (inject_iar) return injected_iar;
    if (!(global_regs[0] & 1) || !(cpu_regs[current_cpu][0] & 1)) return 1023;
    for (unsigned src = 0; src < 8; src++) {
        for (unsigned sgi = 0; sgi < 16; sgi++) {
            unsigned priority = (dist_register(0x400 + (sgi / 4) * 4) >>
                                 ((sgi % 4) * 8)) & 0xff;
            if ((pending[current_cpu][src] & (1U << sgi)) &&
                !(active[current_cpu][src] & (1U << sgi)) &&
                (dist_register(0x100) & (1U << sgi)) &&
                priority < cpu_regs[current_cpu][1]) {
                pending[current_cpu][src] &= ~(1U << sgi);
                active[current_cpu][src] |= 1U << sgi;
                return (src << 10) | sgi;
            }
        }
    }
    return 1023;
}
static uint32_t read_mmio(uintptr_t addr) {
    uint32_t value;
    if (addr >= DIST && addr < DIST + 0x1000) {
        unsigned off = addr - DIST;
        value = off >= 0x800 && off < 0x820 ?
            target_words[current_cpu][(off - 0x800) / 4] :
            group_raz_wi && off == 0x80 ? 0 : dist_register(off);
    } else {
        require(addr >= CPU_IF && addr < CPU_IF + 0x2000, "MMIO outside GIC");
        value = addr == CPU_IF + 0xc ? acknowledge() :
            cpu_regs[current_cpu][(addr - CPU_IF) / 4];
    }
    events.push_back({"read", addr, value, current_cpu});
    return value;
}
static void write_mmio(uintptr_t addr, uint32_t value) {
    events.push_back({"write", addr, value, current_cpu});
    if (addr >= DIST && addr < DIST + 0x1000) {
        unsigned off = addr - DIST;
        if (off == 0xf00) {
            unsigned filter = (value >> 24) & 3;
            unsigned mask = filter == 2 ? 1U << iface[current_cpu] :
                filter == 1 ? 0xffU & ~(1U << iface[current_cpu]) : (value >> 16) & 0xff;
            for (unsigned dst = 0; dst < cpu_count; dst++)
                if (mask & (1U << iface[dst]))
                    pending[dst][iface[current_cpu]] |= 1U << (value & 15);
            return;
        }
        if (off >= 0x800 && off < 0x820) return; // banked targets are read-only
        if (off == 0x80 && group_raz_wi) return;
        if (off == 0x100) { dist_register(off) |= value & 0xffff0000U; return; }
        if (off == 0x180) { dist_register(0x100) &= ~(value & 0xffff0000U); return; }
        for (unsigned base : {0x100U, 0x200U, 0x300U}) {
            if (off >= base && off < base + 0x80) {
                dist_register(off) |= value; return;
            }
            if (off >= base + 0x80 && off < base + 0x100) {
                dist_register(off - 0x80) &= ~value; return;
            }
        }
        dist_register(off) = value;
    } else {
        require(addr >= CPU_IF && addr < CPU_IF + 0x2000, "MMIO outside GIC");
        cpu_regs[current_cpu][(addr - CPU_IF) / 4] = value;
        if (addr == CPU_IF + 0x10) {
            last_eoi = value;
            if ((value & 0x3ff) < 16)
                active[current_cpu][(value >> 10) & 7] &= ~(1U << (value & 15));
        }
    }
}
struct MMIO32 {
    uintptr_t addr;
    operator uint32_t() const { return read_mmio(addr); }
    void operator=(uint32_t value) const { write_mmio(addr, value); }
};
static MMIO32 mock_mmio32(uintptr_t addr) { return {addr}; }

static vm_offset_t pe_arm_get_soc_base_phys() { return 0; }
static vm_offset_t ml_io_map(vm_offset_t addr, uint64_t) { map_calls++; return addr; }
static int SecureDTLookupEntry(void *, const char *, DTEntry *entry) {
    dt_calls++; *entry = nullptr; return kSuccess;
}
static int SecureDTGetProperty(DTEntry, const char *name, void const **prop, unsigned *size) {
    static uint64_t reg[] = {DIST, 0x1000, CPU_IF, 0x2000};
    dt_calls++;
    if (std::strcmp(name, "reg") == 0) { *prop = reg; *size = sizeof(reg); }
    else { *prop = &dt_timer; *size = sizeof(dt_timer); }
    return kSuccess;
}
extern "C" {
#include "santoni_fiq_actual.h"
}

struct ml_topology_cpu_t { uint32_t phys_id; };
struct ml_topology_info_t { unsigned num_cpus; ml_topology_cpu_t cpus[8]; };
static ml_topology_info_t topology;
static const ml_topology_info_t *ml_get_topology_info() { return &topology; }
struct IOCPU {
    unsigned number;
    unsigned getCPUNumber() const { return number; }
};
struct SweetCPU : IOCPU { void signalCPU(IOCPU *); };
#include "santoni_signal_actual.h"

struct arm_saved_state_t {};
struct cpu_data_t {
    int cpu_decrementer;
    void (*interrupt_handler)(void *, void *, void *, uint32_t);
    void *interrupt_target, *interrupt_refCon, *interrupt_nub;
};
static cpu_data_t cpu_data;
static cpu_data_t *getCpuDatap() { return &cpu_data; }
enum { DBG_INTR_TYPE_TIMER, DBG_INTR_TYPE_IPI, DBG_INTR_TYPE_OTHER };
static void sleh_interrupt_handler_prologue(arm_saved_state_t *, int) {}
static void sleh_interrupt_handler_epilogue() { events.push_back({"epilogue", 0, 0, current_cpu}); }
static void entropy_collect() {}
#define INTERRUPT_MASKED_DEBUG_START(func, kind) ((void)0)
#define INTERRUPT_MASKED_DEBUG_END() ((void)0)
static void rtclock_intr(bool) { timer_calls++; events.push_back({"timer", 0, 0, current_cpu}); }
static void cpu_signal_handler() {
    ipis[current_cpu]++;
    events.push_back({"handler", 0, 0, current_cpu});
    if (repend) { pending[current_cpu][7] |= 1U << 1; repend = false; }
}
#include "santoni_irq_actual.h"

static void fixture(unsigned count, unsigned layout = 0) {
    cpu_count = count;
    static const unsigned maps[][8] = {{4,5,6,7,0,1,2,3}, {7,0,5,2,6,1,4,3}, {0,1,2,3,4,5,6,7}};
    std::copy(maps[layout], maps[layout] + 8, iface);
    topology.num_cpus = count;
    global_regs[1] = IRQ_COUNT / 32 - 1;
    for (unsigned cpu = 0; cpu < 8; cpu++) {
        topology.cpus[cpu].phys_id = cpu < 4 ? 0x100 + cpu : cpu - 4;
        target_words[cpu][0] = (1U << iface[cpu]) * 0x01010101U;
        private_regs[cpu][0x100 / 4] = (1U << 27) | 0xffffU; // PPI + always-enabled SGIs
        private_regs[cpu][0x300 / 4] = 0xffffffffU; // inherited active state
        for (unsigned i = 0; i < 8; i++) private_regs[cpu][0x400 / 4 + i] = 0xffffffffU;
    }
}
static void init_all() {
    for (current_cpu = 0; current_cpu < cpu_count; current_cpu++) pe_init_fiq();
    current_cpu = 0;
}
static size_t find_event(const char *kind, uintptr_t addr = 0, size_t after = 0) {
    for (size_t i = after; i < events.size(); i++)
        if (events[i].kind == kind && events[i].addr == addr) return i;
    return events.size();
}
template <typename F> static void expect_panic(F fn) {
    try { fn(); } catch (const std::runtime_error &e) {
        require(std::string(e.what()).find("PANIC:") == 0, "fixture failed, not a kernel panic"); return;
    }
    throw std::runtime_error("invalid configuration accepted instead of panicking");
}
static void receive(uint32_t iar) {
    gicc_base = CPU_IF; inject_iar = true; injected_iar = iar;
    arm_saved_state_t state;
    sleh_irq(&state);
}

int main(int argc, char **argv) {
    try {
        require(argc >= 2, "missing case");
        std::string which = argv[1];
        unsigned a = argc > 2 ? std::strtoul(argv[2], nullptr, 0) : 0;
        unsigned b = argc > 3 ? std::strtoul(argv[3], nullptr, 0) : 0;
        unsigned c = argc > 4 ? std::strtoul(argv[4], nullptr, 0) : 0;
        if (which == "unknown") {
            require(sweet_gic_cpu_iface(a) == 0xffffffffU, "unprobed CPU has invented interface");
        } else if (which == "probe") {
            fixture(1); iface[0] = a;
            std::memset(target_words[0], 0, sizeof(target_words[0]));
            target_words[0][c] = (1U << a) << (b * 8);
            pe_init_fiq();
            require(sweet_gic_cpu_iface(0) == a, "banked mask byte/word/high-bit probe failed");
        } else if (which == "badmask" || which == "badtimer" || which == "invalidcpu") {
            fixture(1);
            if (which == "badmask") target_words[0][0] = a;
            if (which == "badtimer") dt_timer = a;
            if (which == "invalidcpu") invalid_cpu = true;
            expect_panic(pe_init_fiq);
        } else if (which == "timerbound") {
            fixture(1); dt_timer = a; pe_init_fiq();
            require(private_regs[0][0x100 / 4] == ((1U << a) | 0xffffU), "PPI boundary enable wrong");
        } else if (which == "duplicate") {
            fixture(2); pe_init_fiq(); current_cpu = 1;
            target_words[1][0] = target_words[0][0];
            expect_panic(pe_init_fiq);
        } else if (which == "unprobed-target") {
            fixture(2); pe_init_fiq(); SweetCPU sender; sender.number = 0; IOCPU target{1};
            expect_panic([&]() { sender.signalCPU(&target); });
            require(find_event("write", DIST + 0xf00) == events.size(), "unknown target still signalled");
        } else if (which == "bank-isolation") {
            fixture(2); pe_init_fiq();
            private_regs[0][0x100 / 4] |= 1U << 23;
            private_regs[0][0x300 / 4] = 1U << 30;
            private_regs[0][0x400 / 4] = 0x44332211;
            auto before = std::array<uint32_t, 0x1000 / 4>{};
            std::copy(private_regs[0], private_regs[0] + before.size(), before.begin());
            current_cpu = 1; pe_init_fiq();
            require(std::equal(before.begin(), before.end(), private_regs[0]), "secondary damaged another private bank");
            require(dt_calls == 3 && map_calls == 2, "secondary remapped distributor");
        } else if (which == "ns-groups") {
            fixture(8); group_raz_wi = true; init_all();
            for (unsigned cpu = 0; cpu < cpu_count; cpu++) {
                bool attempted = false;
                for (const auto &event : events)
                    attempted |= event.kind == "write" && event.addr == DIST + 0x80 && event.cpu == cpu;
                require(attempted, "banked group setup not attempted");
                require(sweet_gic_cpu_iface(cpu) == iface[cpu], "RAZ/WI group readback broke discovery");
            }
        } else if (which == "spi" || which == "private" || which == "ipi" || which == "sendbarrier") {
            fixture(a ? a : 1, b); init_all();
            if (which == "spi") {
                for (unsigned i = 32; i < IRQ_COUNT; i += 4)
                    require(global_regs[(0x800 + i) / 4] == (1U << iface[0]) * 0x01010101U,
                            "shared IRQ does not target discovered boot interface");
                require(dt_calls == 3 && map_calls == 2, "secondary remapped global/readonly GIC state");
            } else if (which == "private") {
                for (unsigned cpu = 0; cpu < cpu_count; cpu++) {
                    require(private_regs[cpu][0x100 / 4] == PRIVATE, "unrelated private interrupt left enabled");
                    require(private_regs[cpu][0x300 / 4] == 0, "private active state not reset");
                    require(private_regs[cpu][0x80 / 4] == 0xffffffffU, "private group setup omitted on secondary");
                    for (unsigned i = 0; i < 8; i++)
                        require(private_regs[cpu][0x400 / 4 + i] == 0xa0a0a0a0U, "private priority inherited");
                    require(cpu_regs[cpu][0] == 1 && cpu_regs[cpu][1] == 0xff && cpu_regs[cpu][2] == 0,
                            "local CPU interface configuration incomplete");
                }
            } else if (which == "sendbarrier") {
                events.clear(); SweetCPU sender; sender.number = 0; sender.signalCPU(&sender);
                size_t barrier = find_event("dsb");
                require(barrier < find_event("write", DIST + 0xf00) && events[barrier].value == DSB_ISHST,
                        "shared data not ordered before SGIR");
            } else {
                for (unsigned src = 0; src < cpu_count; src++) {
                    for (unsigned dst = 0; dst < cpu_count; dst++) {
                        current_cpu = src; SweetCPU sender; sender.number = src; IOCPU target{dst};
                        sender.signalCPU(&target);
                        unsigned previous = ipis[dst]; current_cpu = dst;
                        arm_saved_state_t state; sleh_irq(&state);
                        require(ipis[dst] == previous + 1, "cross-CPU SGI reached wrong/no CPU");
                        require(last_eoi == ((iface[src] << 10) | 1U), "SGI EOI lost source bits");
                        require(active[dst][iface[src]] == 0, "SGI source left active");
                    }
                }
            }
        } else if (which == "recv" || which == "receive-order" || which == "eoi-complete") {
            uint32_t token = which == "eoi-complete" ? (a == 1 ? 20 : a == 2 ? 200 : 0x1c01) : (a << 10) | 1;
            receive(token);
            require(last_eoi == token, "EOI did not preserve complete IAR token");
            if (which == "recv") require(ipis[0] == 1, "SGI not dispatched");
            if (which == "receive-order") {
                size_t read = find_event("read", CPU_IF + 0xc), barrier = find_event("dmb");
                require(read < barrier && barrier < find_event("handler") &&
                        (events[barrier].value == DMB_ISHLD || events[barrier].value == DMB_ISH),
                        "IAR load not ordered before shared signal consumption");
            }
            if (which == "eoi-complete")
                require(find_event("write", CPU_IF + 0x10) < find_event("dsb") &&
                        find_event("dsb") < find_event("epilogue"), "EOI MMIO not completed before return");
        } else if (which == "spurious") {
            receive(a);
            require(find_event("write", CPU_IF + 0x10) == events.size() && ipis[0] == 0,
                    "spurious/reserved IAR was EOIed or dispatched");
        } else if (which == "timer") {
            receive(20); require(timer_calls == 1 && ipis[0] == 0 && cpu_data.cpu_decrementer == -1,
                                 "timer dispatch regressed");
        } else if (which == "other") {
            cpu_data.interrupt_handler = [](void *, void *, void *, uint32_t irq) { other_calls++; other_intid = irq; };
            receive(200); require(other_calls == 1 && other_intid == 200 && ipis[0] == 0,
                                  "shared interrupt dispatch regressed");
        } else if (which == "repend") {
            fixture(1); init_all(); inject_iar = false;
            pending[0][7] = 2; repend = true;
            arm_saved_state_t state; sleh_irq(&state); sleh_irq(&state);
            require(ipis[0] == 2 && active[0][7] == 0, "same-source SGI raised during handler lost");
        } else throw std::runtime_error("unknown case");
        return 0;
    } catch (const std::exception &e) {
        std::fprintf(stderr, "%s: %s\n", argv[1], e.what()); return 1;
    }
}
