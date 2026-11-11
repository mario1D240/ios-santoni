/* Actual patched Mesa BO-table loop and actual pinned fd_bo/MSM declarations.
 * The enclosing submit object is a model; no GPU or transport runs here. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "drm/freedreno_drmif.h"
#include "msm_drm.h"
#include "mesa_submit_bos.h"
int main(int argc,char **argv)
{
    assert(argc==2);unsigned test=(unsigned)strtoul(argv[1],NULL,10);assert(test<8);
    const uint32_t input[]={3,3,7,5,2,2,7,1};
    const uint32_t readonly[]={0,1,1,1,0,1,0,1};
    struct fd_bo first={.handle=73,.reloc_flags=input[test],.alloc_flags=readonly[test]?FD_BO_GPUREADONLY:0};
    struct fd_bo second={.handle=91,.reloc_flags=MSM_SUBMIT_BO_READ|MSM_SUBMIT_BO_WRITE};
    struct fd_bo *bos[]={&first,&second};
    struct drm_msm_gem_submit_bo output[2];
    memset(output,0xa5,sizeof(output));actual_submit_bos(bos,2,output);
    uint32_t expected=input[test];
#ifdef SANTONI_GFX_MESA
    if(readonly[test])expected&=~MSM_SUBMIT_BO_WRITE;
#endif
    assert(output[0].flags==expected && output[0].handle==73 && !output[0].presumed);
    assert(output[1].flags==3 && output[1].handle==91 && !output[1].presumed);
    assert(first.reloc_flags==input[test] && first.alloc_flags==(readonly[test]?FD_BO_GPUREADONLY:0));
    puts("PASS actual Mesa BO-table loop; no admission or hardware execution");return 0;
}
