/* Execute the real startCPU guard, handoff reset and PSCI arguments on a host. */
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>

using vm_offset_t = uintptr_t;
using kern_return_t = int;
#define SANTONI 1
#define SWEET_SMP_MAX_CPUS 8
#define KERN_SUCCESS 0
#define DSB_SY 15
extern "C" unsigned clean_calls;
static unsigned psci_calls, clean_at_psci;
static unsigned last_context;
static uint64_t last_target, last_entry;
static int32_t psci_result;
static void __attribute__((unused)) kprintf(const char *, ...) {}
static void __attribute__((unused)) IOLog(const char *, ...) {}
[[noreturn]] static void panic(const char *, ...) { throw std::runtime_error("startup guard"); }
extern "C" void sweet_secondary_entry(void) {}
struct ml_topology_cpu_t { uint32_t phys_id; };
struct ml_topology_info_t { ml_topology_cpu_t cpus[8]; const ml_topology_cpu_t *boot_cpu; };
static ml_topology_info_t topology;
static const ml_topology_info_t *ml_get_topology_info() { return &topology; }
static vm_offset_t ml_static_vtop(vm_offset_t) { return 0x99001000; }
#define __builtin_arm_dsb(scope) ((void)(scope))
static int32_t sweet_psci_cpu_on(uint64_t target, uint64_t entry, uint64_t context)
{
    last_target = target; last_entry = entry; last_context = (unsigned)context;
    clean_at_psci = clean_calls;
    psci_calls++;
    return psci_result;
}
struct SweetCPU {
    unsigned number;
    uint32_t initialized = 0;
    unsigned getCPUNumber() const { return number; }
    kern_return_t startCPU(vm_offset_t, vm_offset_t);
};
#include "santoni_start_cpu_actual.h"
#ifdef SANTONI_HOST_HAS_RESET_TRACE
extern "C" { sweet_cpu_reset_trace sweet_secondary_trace[8]; }
#endif

#define CHECK(value) do { if (!(value)) { \
    std::fprintf(stderr, "startCPU:%d: %s\n", __LINE__, #value); return 1; \
} } while (0)

int main()
{
    static const uint32_t ids[] = {0x100, 0x101, 0x102, 0x103, 0, 1, 2, 3};
    for (unsigned i = 0; i < 8; i++) topology.cpus[i].phys_id = ids[i];
    topology.boot_cpu = &topology.cpus[0];
    unsigned checks = 0;
    for (unsigned i = 1; i < 8; i++) {
#ifdef SANTONI_HOST_HAS_RESET_TRACE
        for (auto &trace : sweet_secondary_trace) {
            trace.stage = 0xdead;
            trace.mpidr = 0xdead;
        }
#endif
        SweetCPU cpu; cpu.number = i;
        unsigned old_clean = clean_calls;
        CHECK(cpu.startCPU(0, 0) == KERN_SUCCESS);
        CHECK(last_target == ids[i] && last_context == i && last_entry == 0x99001000);
        CHECK(cpu.initialized == 0); /* asynchronous: never fabricate completion */
#ifdef SANTONI_HOST_HAS_RESET_TRACE
        CHECK(clean_calls == old_clean + 1);
        CHECK(clean_at_psci == old_clean + 1);
        CHECK(sweet_secondary_trace[i].stage == 0 && sweet_secondary_trace[i].mpidr == 0);
        for (unsigned other = 0; other < 8; other++)
            if (other != i) CHECK(sweet_secondary_trace[other].stage == 0xdead);
#else
        (void)old_clean;
        CHECK(false);
#endif
        checks++;
    }
    for (unsigned kind = 0; kind < 4; kind++) {
        SweetCPU cpu; cpu.number = kind == 0 ? 0 : 4;
        if (kind == 1) cpu.initialized = 1;
        unsigned old = psci_calls;
        bool rejected = false;
        try { cpu.startCPU(kind == 2 ? 1 : 0, kind == 3 ? 1 : 0); }
        catch (const std::runtime_error &) { rejected = true; }
        CHECK(rejected && psci_calls == old);
        checks++;
    }
    SweetCPU cpu; cpu.number = 4; psci_result = -1;
    bool rejected = false;
    try { cpu.startCPU(0, 0); }
    catch (const std::runtime_error &) { rejected = true; }
    CHECK(rejected && last_target == 0);
    checks++;
    std::printf("Actual startCPU checks: %u/%u passed\n", checks, checks);
    return 0;
}
