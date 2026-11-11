/* Execute the real cpu_start() with separate cache/PoC views. This models
 * publication omissions, not firmware, runtime coherency, or a real boot. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SWEET 1
#ifndef GENERIC_CONTROL
#define SANTONI 1
#endif
#define MAX_CPUS 8
#define XNU_MONITOR 0
#define FALSE 0
#define KERN_SUCCESS 0
#define THREAD_NULL NULL
#define DSB_SY 15
typedef uintptr_t vm_offset_t;
typedef uintptr_t vm_address_t;
typedef int kern_return_t;
typedef struct cpu_data cpu_data_t;
typedef struct thread *thread_t;
struct thread {
    struct { cpu_data_t *CpuDatap; uintptr_t pcpu_data_base; } machine;
    vm_offset_t kernel_stack;
    uint64_t thread_id;
};
struct processor { thread_t startup_thread, idle_thread; };
typedef struct processor *processor_t;
struct cpu_data {
    unsigned cpu_phys_id, cpu_number;
    vm_offset_t cpu_reset_handler;
    struct { void *cpu_nested_pmap; } cpu_pmap_cpu_data;
    thread_t cpu_active_thread;
    void *cpu_id;
    struct processor processor;
};
typedef struct { cpu_data_t *cpu_data_vaddr; uintptr_t cpu_data_paddr; } cpu_data_entry_t;
static cpu_data_entry_t CpuDataEntries[8], ram_entries[8];
static cpu_data_t live_cpus[8], ram_cpus[8];
static struct thread startup_thread, idle_thread, ram_first_thread;
static uint64_t first_stack[32], ram_first_stack[32];
static bool data_cleaned[8], entries_cleaned, thread_cleaned, stack_cleaned, barrier;
static unsigned firmware_calls, self_init, current_cpu, target_cpu = 4;
size_t kernel_stack_size = sizeof(first_stack);
static vm_offset_t start_cpu_paddr = 0x9943b0e8;
static struct { uintptr_t cpu_data_entries; } ResetHandlerData;
typedef struct { uintptr_t virt_base; } boot_args_t;
static boot_args_t boot_args;
static boot_args_t *BootArgs = &boot_args;
static uint64_t sysreg_restore[8], cpu_ttep;
#define BOOTSTRAP_TABLE_SIZE 64
uint8_t bootstrap_pagetables[BOOTSTRAP_TABLE_SIZE];
#define PERCPU_GET_RELATIVE(field, type, p) (&(p)->processor)
#define __PERCPU_ADDR(type) 0x1000u
static bool processor_should_kprintf(processor_t p, bool boot) { (void)p; (void)boot; return false; }
static int cpu_number(void) { return (int)current_cpu; }
static void cpu_machine_init(void) { self_init++; }
static void configure_coresight_registers(cpu_data_t *p) { (void)p; }
static void flush_dcache(vm_offset_t va, size_t size, int physical) { (void)va; (void)size; (void)physical; }
#define kprintf(...) ((void)0)

static void CleanPoC_DcacheRegion_Force(vm_offset_t va, size_t size)
{
    if (va == (uintptr_t)CpuDataEntries && size == sizeof(CpuDataEntries)) {
        memcpy(ram_entries, CpuDataEntries, size); entries_cleaned = true;
    }
    for (unsigned i = 0; i < MAX_CPUS; i++) {
        if (va == (uintptr_t)&live_cpus[i] && size == sizeof(live_cpus[i])) {
            ram_cpus[i] = live_cpus[i]; data_cleaned[i] = true;
        }
    }
    if ((va == (uintptr_t)&startup_thread || va == (uintptr_t)&idle_thread) && size == sizeof(startup_thread)) {
        ram_first_thread = *(thread_t)va; thread_cleaned = true;
    }
    if (va == (uintptr_t)first_stack && size == sizeof(first_stack)) {
        memcpy(ram_first_stack, first_stack, size); stack_cleaned = true;
    }
    barrier = false;
}
void model_dsb(int kind)
{
    if (kind != DSB_SY) abort();
    barrier = true;
}
#define __builtin_arm_dsb(kind) model_dsb(kind)
static int PE_cpu_start(void *cpu, vm_offset_t start, vm_offset_t arg)
{
    if (!barrier || !entries_cleaned || start || arg || cpu != live_cpus[target_cpu].cpu_id) {
        fputs("FAIL: entry table/publication barrier missing before PE_cpu_start\n", stderr);
        abort();
    }
    firmware_calls++;
    return KERN_SUCCESS;
}
#include "startup_publication_actual.h"

int main(int argc, char **argv)
{
    const unsigned ids[] = {0x100, 0x101, 0x102, 0x103, 0, 1, 2, 3};
    bool holes = argc > 1 && !strcmp(argv[1], "holes");
    bool idle = argc > 1 && !strcmp(argv[1], "idle");
    bool self = argc > 1 && !strcmp(argv[1], "self");
    bool visible = argc > 1 && !strcmp(argv[1], "records-visible");
    if (argc > 1 && strlen(argv[1]) == 4 && !strncmp(argv[1], "cpu", 3)) {
        target_cpu = (unsigned)(argv[1][3] - '0');
        if (target_cpu == 0 || target_cpu >= MAX_CPUS) return 1;
    }
    for (unsigned i = 0; i < MAX_CPUS; i++) {
        live_cpus[i].cpu_number = i;
        live_cpus[i].cpu_phys_id = ids[i];
        live_cpus[i].cpu_id = (void *)(uintptr_t)(i + 1);
        CpuDataEntries[i].cpu_data_vaddr = &live_cpus[i];
        CpuDataEntries[i].cpu_data_paddr = (uintptr_t)&ram_cpus[i];
    }
    if (visible) memcpy(ram_cpus, live_cpus, sizeof(ram_cpus));
    if (holes) {
        for (unsigned i = 6; i < 8; i++) {
            CpuDataEntries[i].cpu_data_vaddr = NULL;
            CpuDataEntries[i].cpu_data_paddr = 0;
        }
    }
    /* The inspected arm64 binary loads FP/LR at +0x50 and SP at +0x60. */
    first_stack[11] = 0xfffffff0072ec5f0ULL;
    first_stack[12] = (uint64_t)(uintptr_t)first_stack;
    startup_thread.kernel_stack = idle_thread.kernel_stack = (uintptr_t)first_stack;
    startup_thread.thread_id = 33; idle_thread.thread_id = 34;
    live_cpus[target_cpu].processor.startup_thread = idle ? NULL : &startup_thread;
    live_cpus[target_cpu].processor.idle_thread = &idle_thread;
    if (self) {
        current_cpu = target_cpu;
        if (cpu_start((int)target_cpu) != KERN_SUCCESS || self_init != 1 || firmware_calls) return 1;
        puts("ok   self-CPU init does not issue PSCI or publish a new context");
        return 0;
    }
    if (cpu_start((int)target_cpu) != KERN_SUCCESS || firmware_calls != 1) return 1;
#ifdef GENERIC_CONTROL
    if (!data_cleaned[target_cpu] || data_cleaned[0] || thread_cleaned || stack_cleaned) return 1;
    puts("ok   non-Santoni SWEET publication behavior unchanged");
    return 0;
#else
    printf("POC: {\"target\":%u,\"mpidr\":%u,\"records\":[", target_cpu, ids[target_cpu]);
    for (unsigned i = 0; i < MAX_CPUS; i++) {
        printf("%s{\"present\":%s,\"phys\":%u,\"logical\":%u,\"handler\":%s}",
            i ? "," : "", ram_entries[i].cpu_data_paddr ? "true" : "false",
            ram_cpus[i].cpu_phys_id, ram_cpus[i].cpu_number,
            ram_cpus[i].cpu_reset_handler ? "true" : "false");
    }
    puts("]}");
    if (!thread_cleaned || !stack_cleaned || ram_first_stack[11] != first_stack[11] ||
        ram_first_stack[12] != first_stack[12] ||
        ram_first_thread.machine.CpuDatap != &live_cpus[target_cpu] ||
        ram_first_thread.machine.pcpu_data_base != (uintptr_t)&live_cpus[target_cpu] - 0x1000u ||
        ram_cpus[target_cpu].cpu_active_thread != (idle ? &idle_thread : &startup_thread)) {
        fputs("FAIL: first thread/LR/SP handoff was not fully published\n", stderr);
        return 1;
    }
    for (unsigned i = 0; i < MAX_CPUS; i++) {
        if (CpuDataEntries[i].cpu_data_vaddr && !data_cleaned[i]) {
            fprintf(stderr, "FAIL: scanned CPU%u record was not published\n", i);
            return 1;
        }
    }
    puts("ok   all scanned records and first thread/stack published before PE_cpu_start");
    return 0;
#endif
}
