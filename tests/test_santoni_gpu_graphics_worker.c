/* Actual parser/getter/worker; allocation, bootstrap and log sinks modeled. */
#include "santoni_gpu_graphics_hw.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned test,allocations,starts,begins,releases,publications,logs;
static uint32_t sgpu_render_enabled=1;
static bool sgpu_ui_enabled,sgpu_render_allocation_retained;
static struct {uint32_t mode;} sg={3};
static struct sgpu_render_memory sgpu_render_owned;
static bool PE_parse_boot_argn(const char *name,void *out,unsigned bytes)
{
    assert(!strcmp(name,"santonigpu_graphics") && bytes==4);
    *(int *)out=test==1 || test==7?0:test==6?2:1;return true;
}
static bool sgpu_render_allocate(void)
{assert(!santoni_gpu_graphics_worker_ready());allocations++;return test!=2;}
static void sgpu_render_release(void)
{assert(!santoni_gpu_graphics_worker_ready());releases++;}
bool sgpu_render_live_start(const struct sgpu_ops *ops,uint32_t mode,uint32_t enabled,
    const uint8_t *fw,size_t bytes,const struct sgpu_render_memory *memory,
    struct sgpu_report *boot,struct sgpu_render_live_result *result)
{
    assert(!santoni_gpu_graphics_worker_ready() && ops && mode==3 && enabled==1 && fw && bytes==64 && memory==&sgpu_render_owned);
    starts++;boot->memory_retained=true;result->exposed=test!=3;result->passed=test!=3;
    result->phase=SG_LIVE_DONE;result->wptr=316;return test!=3;
}
bool sgpu_graphics_hw_begin(uint32_t mode,uint32_t enabled)
{assert(!santoni_gpu_graphics_worker_ready() && mode==3 && enabled==1);begins++;return test!=4;}
void sgpu_graphics_hw_snapshot(struct sgpu_graphics_hw_result *out)
{assert(!santoni_gpu_graphics_worker_ready());memset(out,0,sizeof(*out));out->ready=test!=4;}
static void sgpu_failure_summary(const char *name,const struct sgpu_failure *failure)
{assert(!santoni_gpu_graphics_worker_ready() && name && failure);logs++;}
static int worker_printf(const char *format,...)
{assert(!santoni_gpu_graphics_worker_ready() && format);logs++;return 0;}
static void sgpu_ui_publish(bool passed)
{assert(!santoni_gpu_graphics_worker_ready());(void)passed;publications++;}
#define printf worker_printf
#include "santoni_gpu_graphics_worker_actual.h"
#undef printf
int main(int argc,char **argv)
{
    assert(argc==2);test=(unsigned)strtoul(argv[1],NULL,10);assert(test<8);
    if(test==5)sg.mode=1;
    __atomic_store_n(&sgpu_graphics_published,1,__ATOMIC_RELEASE);
    bool options=sgpu_graphics_options(sg.mode);
    assert(!santoni_gpu_graphics_worker_ready());
    if(test==5 || test==6) {assert(!options && !sgpu_graphics_enabled);goto done;}
    assert(options);
    if(test==7)goto done;
    uint8_t firmware[64]={0};struct sgpu_ops ops={0};struct sgpu_report boot={0};
    sgpu_render_worker(&ops,firmware,sizeof(firmware),&boot);
    assert(santoni_gpu_graphics_worker_ready()==(test==0));
    assert(allocations==1 && starts==(unsigned)(test!=2));
    assert(begins==(unsigned)(test==0 || test==4));
    assert(publications==(unsigned)(test!=2) && releases==(unsigned)(test==3));
done:
    printf("PASS graphics worker case=%u; actual release handoff, hardware/log sinks modeled\n",test);return 0;
}
