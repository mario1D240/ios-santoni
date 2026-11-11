/* Extracted actual adapter bounds/permission/options; only ARM stores mocked. */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include "santoni_gpu_core.h"
typedef uintptr_t vm_offset_t;
static struct {
    vm_offset_t maps[SG_BLOCKS];
    uint32_t sizes[SG_BLOCKS], mode, stock_unsecure;
} sg;
static unsigned stores, width_seen;
static uintptr_t address_seen;
static uint64_t value_seen;
static void host_store(unsigned width, uintptr_t address, uint64_t value)
{ stores++; width_seen=width; address_seen=address; value_seen=value; }
#include "santoni_gpu_stock_adapter_actual.h"

int main(void)
{
    sg.maps[SG_GPU]=0x100000; sg.sizes[SG_GPU]=0x40000;
    sg.maps[SG_CC]=0x200000; sg.sizes[SG_CC]=0x1000;
    const unsigned offsets[]={0x3bffc,0x3c000,0x3cffc,0x3d000,0x3d004,0x3d001,0x3fffc,0x40000};
    const unsigned values[]={0,1,2,0x80000000u,~0u};
    unsigned cases=0;
    for(unsigned mode=0;mode<=4;mode++) for(unsigned opt=0;opt<=2;opt++)
        for(unsigned i=0;i<sizeof(offsets)/sizeof(offsets[0]);i++)
            for(unsigned j=0;j<sizeof(values)/sizeof(values[0]);j++) {
                sg.mode=mode; sg.stock_unsecure=opt; stores=0;
                unsigned off=offsets[i], value=values[j];
                bool allowed=off<0x40000 && !(off&3) &&
                    (off<0x3c000 || (mode==3 && opt==1 && off==0x3d000 && value==0));
                sgpu_io_write32(NULL, SG_GPU, off, value);
                assert(stores==(unsigned)allowed);
                if(allowed) assert(width_seen==4 && address_seen==0x100000+off && value_seen==value);
                stores=0; sgpu_io_write64(NULL, SG_GPU, off, value);
                assert(stores==(unsigned)(off<0x3c000 && !(off&7)));
                cases++;
            }
    sg.mode=3; sg.stock_unsecure=1;
    for(unsigned block=0;block<=SG_BLOCKS;block++) {
        bool expected=block==SG_GPU;
        assert(sgpu_stock_write_allowed(3,1,(enum sgpu_block)block,0x3d000,0)==expected);
        stores=0; sgpu_io_write32(NULL,(enum sgpu_block)block,0x40000,0);
        assert(!stores);
    }
    sg.maps[SG_GPU]=0; stores=0;
    sgpu_io_write32(NULL,SG_GPU,0x3d000,0); assert(!stores);
    printf("PASS stock adapter: %u combinations; exact 32-bit exception, 64-bit guard intact\n", cases);
    return 0;
}
