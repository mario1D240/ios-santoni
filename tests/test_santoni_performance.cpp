/* Execute the actual optional probe with synthetic read-only clock pages. */
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <string>

using vm_offset_t = uintptr_t;
using vm_size_t = size_t;
using thread_t = void *;
using wait_result_t = int;
struct processor { unsigned cpu; } processors[8];
using processor_t = processor *;
#define SANTONI 1
#ifndef __unused
#define __unused __attribute__((unused))
#endif
#define THREAD_CONTINUE_NULL nullptr
#define DMB_ISH 11
struct ml_topology_info_t { unsigned num_cpus, num_clusters; };
static ml_topology_info_t topology = {8, 1};
static ml_topology_info_t *ml_get_topology_info() { return &topology; }
static unsigned current_cpu, binds, frees, terminations;
static bool allocation_fails, clocks_fail;
static int failed_cpu = -1;
static processor_t requested;
static uint64_t clock_tick;
static std::string log_text;
static uint32_t apcs[3][1024], pll[2][16];
static int capture_printf(const char *format, ...)
{
    char buffer[2048]; va_list args;
    va_start(args, format); vsnprintf(buffer, sizeof(buffer), format, args); va_end(args);
    log_text += buffer;
    return 0;
}
static vm_offset_t ml_io_map(vm_offset_t pa, vm_size_t)
{
    if (clocks_fail) return 0;
    const uintptr_t bases[] = {0x0b011000, 0x0b111000, 0x0b1d1000};
    for (unsigned i = 0; i < 3; i++) if (pa == bases[i]) return (uintptr_t)apcs[i];
    if (pa == 0x0b016000) return (uintptr_t)pll[0];
    if (pa == 0x0b116000) return (uintptr_t)pll[1];
    return 0;
}
static void *IOMallocZeroData(size_t size) { return allocation_fails ? nullptr : std::calloc(1, size); }
static void IOFreeData(void *memory, size_t) { frees++; std::free(memory); }
static int thread_block(void *)
{
    if (requested && (int)requested->cpu != failed_cpu) current_cpu = requested->cpu;
    return 0;
}
static int cpu_number(void) { return (int)current_cpu; }
static thread_t current_thread(void) { return nullptr; }
static void thread_terminate(thread_t) { terminations++; }
static uint64_t mach_absolute_time(void) { return clock_tick += 1000; }
static void absolutetime_to_nanoseconds(uint64_t value, uint64_t *out) { *out = value; }
static uint64_t read_register(const char *name)
{
    if (!std::strcmp(name, "SCTLR_EL1")) return 0x1005;
    if (!std::strcmp(name, "MAIR_EL1")) return 0xff;
    if (!std::strcmp(name, "MPIDR_EL1")) return current_cpu < 4 ? 0x100 + current_cpu : current_cpu - 4;
    std::abort();
}
#define __builtin_arm_rsr64(name) read_register(name)
#define __builtin_arm_dmb(kind) ((void)(kind))
struct SweetCPU {
    processor_t machProcessor;
    static void probePerformance(void *, wait_result_t);
} cpus[8];
static SweetCPU *sweet_cpus[8];
#define printf capture_printf
#include "santoni_performance_actual.h"
#undef printf

/* Definition comes after the actual function: without its source declaration
 * the probe must fail to compile, as it did in the exported IOKit headers. */
processor_t thread_bind(processor_t cpu)
{
    processor_t old = requested; requested = cpu;
    if (cpu) binds++;
    return old;
}

int main(int argc, char **argv)
{
    if (argc > 1) {
        allocation_fails = !std::strcmp(argv[1], "allocation-fails");
        clocks_fail = !std::strcmp(argv[1], "clock-map-fails");
        if (!std::strcmp(argv[1], "bind-fails")) failed_cpu = 4;
    }
    for (unsigned i = 0; i < 8; i++) {
        processors[i].cpu = i; cpus[i].machProcessor = &processors[i]; sweet_cpus[i] = &cpus[i];
    }
    apcs[0][0x54 / 4] = apcs[1][0x54 / 4] = (5u << 8) | 1;
    apcs[2][0x54 / 4] = (4u << 8) | 2;
    pll[0][1] = 73; pll[1][1] = 57;
    uint32_t saved_apcs[3][1024], saved_pll[2][16];
    std::memcpy(saved_apcs, apcs, sizeof(apcs)); std::memcpy(saved_pll, pll, sizeof(pll));
    SweetCPU::probePerformance(nullptr, 0);
    if (allocation_fails) {
        if (binds || frees || terminations != 1) return 1;
        std::puts("ok   optional probe handles allocation failure without binding a CPU");
        return 0;
    }
    if (binds != 8 || frees != 1 || terminations != 1 ||
        std::memcmp(saved_apcs, apcs, sizeof(apcs)) || std::memcmp(saved_pll, pll, sizeof(pll))) return 1;
    for (unsigned i = 0; i < 8; i++) {
        if ((int)i == failed_cpu) continue;
        std::string text = "cpu=" + std::to_string(i) + " ";
        size_t at = log_text.find(text);
        if (at == std::string::npos) return 1;
        size_t end = log_text.find('\n', at);
        std::string row = log_text.substr(at, end - at);
        if (row.find("D=1 I=1") == std::string::npos || row.find("stale_lines=0") == std::string::npos) return 1;
    }
    if (failed_cpu >= 0 && log_text.find("skipped") == std::string::npos) return 1;
    if (clocks_fail && log_text.find("clock map failed") == std::string::npos) return 1;
    std::puts("Actual performance probe: 8 CPU reports; clock registers unchanged; buffer freed; no stale model lines");
    return 0;
}
