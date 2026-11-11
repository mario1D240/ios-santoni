/* Real C ABI for the host link regression; no kernel headers or ARM code. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

unsigned clean_calls;

void CleanPoC_DcacheRegion_Force(uintptr_t address, size_t length)
{
    if (!address || length != 64) abort();
    clean_calls++;
}
