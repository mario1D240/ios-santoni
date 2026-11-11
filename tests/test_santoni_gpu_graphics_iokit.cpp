#include "santoni_gpu_graphics_iokit_stubs.h"
#include "SantoniGraphics_actual.cpp"
extern "C" uint32_t sgpu_graphics_hw_vm_profile(){return SGPU_GRAPHICS_VM_LEGACY;}
static bool hw_ready=true,hw_publish_fail=false;
static bool worker_ready=true;
extern "C" bool santoni_gpu_graphics_worker_ready(){return worker_ready;}
static uint64_t hw_ptes[SGPU_RENDER_MAX_PAGES];
static uint32_t hw_fence_value;
extern "C" bool sgpu_graphics_hw_ready(){return hw_ready;}
extern "C" bool sgpu_graphics_hw_reserved(uint64_t pa){return pa==0x98000000;}
extern "C" uint64_t sgpu_graphics_hw_fence_pa(){return 0x98000000;}
extern "C" uint64_t sgpu_graphics_hw_pte(uint32_t va){assert(va>=SGPU_RENDER_VA);return hw_ptes[(va-SGPU_RENDER_VA)/SGPU_PAGE];}
extern "C" bool sgpu_graphics_hw_map(uint32_t va,const uint64_t *pa,uint32_t pages,uint64_t attrs,uint32_t guard)
{
    assert(guard==va+pages*SGPU_PAGE);test_hw_maps++;
    for(unsigned i=0;i<pages;i++)hw_ptes[(va-SGPU_RENDER_VA)/SGPU_PAGE+i]=pa[i]|attrs;return true;
}
extern "C" bool sgpu_graphics_hw_unmap(uint32_t va,uint32_t pages,uint32_t guard)
{assert(guard==va+pages*SGPU_PAGE);for(unsigned i=0;i<pages;i++)hw_ptes[(va-SGPU_RENDER_VA)/SGPU_PAGE+i]=0;return true;}
extern "C" void sgpu_graphics_hw_clean(const void *,uint32_t){}
extern "C" void sgpu_graphics_hw_invalidate(const void *,uint32_t){}
extern "C" void sgpu_graphics_hw_invalidate_fence(){}
extern "C" uint32_t sgpu_graphics_hw_fence(){return hw_fence_value;}
extern "C" bool sgpu_graphics_hw_faulted(){return false;}
extern "C" bool sgpu_graphics_hw_idle(){return true;}
static uint32_t packet7(uint32_t op,uint32_t n)
{uint32_t p=1,q=1;for(uint32_t v=n;v;v>>=1)p^=v&1;for(uint32_t v=op;v;v>>=1)q^=v&1;return 0x70000000|n|(p<<15)|(op<<16)|(q<<23);}
extern "C" bool sgpu_graphics_hw_publish(const sgpu_graphics_command *cmd,uint32_t count,uint32_t seq)
{
    assert(count==1 && cmd[0].bytes==4);test_hw_pubs++;
    if(hw_publish_fail)return false;
    hw_fence_value=seq;return true;
}
static IOReturn invoke(SantoniGraphicsClient &client,uint32_t selector,const uint64_t *in,unsigned ni,uint64_t *out,unsigned no,
    const void *structure=nullptr,uint32_t bytes=0)
{
    IOExternalMethodArguments a;a.scalarInput=in;a.scalarInputCount=ni;a.scalarOutput=out;a.scalarOutputCount=no;
    a.structureInput=structure;a.structureInputSize=bytes;return client.externalMethod(selector,&a,nullptr,nullptr,nullptr);
}
int main(int argc,char **argv)
{
    assert(argc==2);unsigned test=(unsigned)strtoul(argv[1],nullptr,10);assert(test<30);
    hw_ptes[0]=0x98000000|0x0060000000000e47ull;
    SantoniGraphics service;
    if(test>=19 && test<=25) {
        test_boot_raster=1;
        if(test==19)test_boot_raster=2;if(test==20)test_boot_raster=-1;
        if(test==21)test_boot_mode=1;if(test==22)test_boot_mode=2;
        if(test==23)test_boot_render=0;if(test==24)test_boot_ui=1;if(test==25)test_boot_graphics=0;
        assert(!service.start(nullptr) && !test_service_registers && test_buffers.empty() && !gfx.raster_enabled);return 0;
    }
    if(test==26 || test==28)test_boot_raster=1;
    if(test==27)test_raster_present=false;
    if(test<=3 && test) {
        if(test==1)test_boot_graphics=0;if(test==2)test_boot_mode=1;if(test==3)test_boot_ui=1;
        assert(!service.start(nullptr) && !test_service_registers && test_buffers.empty());return 0;
    }
    assert(service.start(nullptr));assert(gfx.raster_enabled==(test==26 || test==28));SantoniGraphicsClient client;
    if(test==17) {
        worker_ready=false;assert(!client.initWithTask(test_task,test_task,0));
        assert(!gfx.claimed && !test_task_refs && test_buffers.empty());
        worker_ready=true;assert(client.initWithTask(test_task,test_task,0));
        assert(client.clientClose()==0);return 0;
    }
    if(test==4)test_admin=false;
    if(test==5)hw_ready=false;
    if(test==6)test_missing_page=GFX_PUBLIC_PAGES-1;
    if(test>=4 && test<=6){assert(!client.initWithTask(test_task,test_task,0));client.free();return 0;}
    assert(client.initWithTask(test_task,test_task,0) && test_task_refs==1 && test_buffers.size()==2);
    uint64_t advertised[10]={};assert(invoke(client,SG_GFX_INFO,nullptr,0,advertised,10)==0);
    assert(advertised[9]==0 && advertised[4]==SGPU_RENDER_VA &&
        advertised[5]==SGPU_RENDER_MAX_PAGES*SGPU_PAGE &&
        advertised[6]==SGPU_RENDER_BO_BYTES);
    uint64_t input[2]={4096,SGPU_GRAPHICS_RO},output[10]={};
    if(test==7){test_task=(void *)0x9999;assert(invoke(client,SG_GFX_NEW,input,2,output,4)==kIOReturnNotPermitted);return 0;}
    if(test==8){assert(invoke(client,SG_GFX_NEW,input,1,output,4)==kIOReturnBadArgument && !test_hw_maps);return 0;}
    assert(invoke(client,SG_GFX_NEW,input,2,output,4)==0);uint32_t handle=(uint32_t)output[0];assert(handle && output[3]==handle);
    IOOptionBits options=0;IOMemoryDescriptor *map=nullptr;
    assert(client.clientMemoryForType(handle,&options,&map)==0 && map && map->parent==gfx.user.memory);
    assert(!(gfx.commands.memory->options&kIOMemoryKernelUserShared));
    ((uint32_t *)map->getBytesNoCopy())[0]=packet7(0x10,0);
    sgpu_graphics_wire_submit request={};request.version=1;request.ibs=1;request.handles=1;request.ib[0]={handle,0,4};request.handle[0]=handle;
    if(test==28 || test==29) {
        uint32_t *words=(uint32_t *)map->getBytesNoCopy();words[0]=packet7(0x38,3);
        words[1]=4|(2u<<6);words[2]=1;words[3]=3;request.ib[0].bytes=16;
        assert(invoke(client,SG_GFX_SUBMIT,nullptr,0,output,1,&request,sizeof(request))!=0 && !test_hw_pubs);
        assert(!gfx.raster_enabled || gfx.raster.error);return 0;
    }
    if(test==9)request.reserved=1;
    if(test==10)request.ib[7].handle=123;
    if(test==11)request.handle[55]=123;
    if(test==12)request.ib[0].handle=999;
    if(test==13)hw_publish_fail=true;
    IOReturn result=invoke(client,SG_GFX_SUBMIT,nullptr,0,output,1,&request,sizeof(request));
    if(test>=9 && test<=13) {
        assert(result!=0 && test_hw_pubs==(unsigned)(test==13));
        if(test==13)assert(gfx.core.quarantined && gfx.core.retained_pages==2);
        return 0;
    }
    assert(result==0 && output[0]==1);uint64_t seq=output[0];
    assert(invoke(client,SG_GFX_WAIT,&seq,1,nullptr,0)==0);
    if(test==14) {
        assert(client.clientMemoryForType(handle+1,&options,&map)!=0); /* private handle is never a user memory type */
    }
    if(test==15) {
        uint64_t h=handle;assert(invoke(client,SG_GFX_FREE,&h,1,nullptr,0)==0);
        assert(client.clientMemoryForType(handle,&options,&map)!=0);
    }
    assert(client.clientClose()==0);assert(test_buffers.size()==2); /* retained until reboot */
    if(test==16)assert(invoke(client,SG_GFX_NEW,input,2,output,4)==kIOReturnNotPermitted);
    SantoniGraphicsClient other;assert(!other.initWithTask(test_task,test_task,0));
    printf("PASS actual IOKit client case=%u maps=%u pubs=%u; hardware/VM modeled\n",test,test_hw_maps,test_hw_pubs);
    return 0;
}
