/* Host-only cache publication for privately mapped, inspected EL0 helpers.
 * This is not compiled into XNU and performs no MMIO or device operation. */
void sgpu_cpu_cache_publish(void *begin, void *end)
{
    __builtin___clear_cache(begin, end);
}

void sgpu_cpu_bzero(void *address, unsigned long bytes)
{
    __builtin_memset(address, 0, bytes);
}
