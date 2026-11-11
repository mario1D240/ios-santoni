#include "santoni_gpu_graphics_iokit_stubs.h"
#include "SantoniGraphics_actual.cpp"
static uint32_t test_profile=SGPU_GRAPHICS_VM_WIDE;
extern "C" uint32_t sgpu_graphics_hw_vm_profile(){return test_profile;}
static bool hw_ready=true,hw_publish_fail=false;
static bool worker_ready=true;
extern "C" bool santoni_gpu_graphics_worker_ready(){return worker_ready;}
static uint64_t hw_ptes[SGPU_GRAPHICS_WIDE_PAGES];
static uint32_t hw_fence_value;
extern "C" bool sgpu_graphics_hw_ready(){return hw_ready;}
extern "C" bool sgpu_graphics_hw_reserved(uint64_t pa){return pa==0x98000000;}
extern "C" uint64_t sgpu_graphics_hw_fence_pa(){return 0x98000000;}
extern "C" uint64_t sgpu_graphics_hw_pte(uint32_t va){assert(va>=SGPU_GRAPHICS_WIDE_VA);return hw_ptes[(va-SGPU_GRAPHICS_WIDE_VA)/SGPU_PAGE];}
extern "C" bool sgpu_graphics_hw_map(uint32_t va,const uint64_t *pa,uint32_t pages,uint64_t attrs,uint32_t guard)
{
    assert(guard==va+pages*SGPU_PAGE);test_hw_maps++;
    for(unsigned i=0;i<pages;i++)hw_ptes[(va-SGPU_GRAPHICS_WIDE_VA)/SGPU_PAGE+i]=pa[i]|attrs;return true;
}
extern "C" bool sgpu_graphics_hw_unmap(uint32_t va,uint32_t pages,uint32_t guard)
{assert(guard==va+pages*SGPU_PAGE);for(unsigned i=0;i<pages;i++)hw_ptes[(va-SGPU_GRAPHICS_WIDE_VA)/SGPU_PAGE+i]=0;return true;}
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
    assert(argc==2);unsigned test=(unsigned)strtoul(argv[1],nullptr,10);assert(test<86);
    hw_ptes[0]=0x98000000|0x0060000000000e47ull;
    SantoniGraphics service;
    if(test>=30) {
        test_boot_raster=1;test_boot_gles=1;test_boot_renderer=1;
        if(test>=31 && test<=39) {
            if(test==31)test_boot_raster=0;if(test==32)test_boot_gles=2;if(test==33)test_boot_gles=-1;
            if(test==34)test_boot_gles=0;if(test==35)test_boot_renderer=2;if(test==36)test_boot_renderer=-1;
            if(test==37)test_boot_mode=1;if(test==38)test_boot_mode=2;if(test==39)test_boot_ui=1;
            assert(!service.start(nullptr) && !test_service_registers && test_buffers.empty());return 0;
        }
        if(test==30 || test==77)test_boot_renderer=0;
        if(test==66){test_boot_renderer=0;test_boot_gles=0;}
        assert(service.start(nullptr));
        SantoniGraphicsClient observer,client;
        if(test>=78) {
            test_admin=false;
            if(test==84) {
                lookup_error=2;
                assert(!client.initWithTask(test_task,test_task,SGPU_GRAPHICS_CLIENT_RENDERER));
                assert(!genuine.held && !other.held && !gfx.claimed && test_buffers.empty());
                lookup_error=0;
            }
            assert(client.initWithTask(test_task,test_task,SGPU_GRAPHICS_CLIENT_RENDERER));
            assert(!genuine.held && !other.held);
            unsigned previous_lookups=lookup_calls;
            // Admission must revalidate current namespace/attributes. A cached
            // first success would incorrectly allow all of these transitions.
            if(test==78)path_vnode=&other;
            if(test==79)genuine.uid=501;
            if(test==80)genuine.mode=0775;
            if(test==81)genuine.mode=0757;
            if(test==82)mode_supported=false;
            if(test==83)attribute_error=5;
            if(test==85)current_context=nullptr;
            test_attribute_hook=[] {assert(!gfx.lock->held);};
            uint64_t info[10]={};
            IOReturn expected=test==84?kIOReturnSuccess:kIOReturnNotPermitted;
            assert(invoke(client,SG_GFX_INFO,nullptr,0,info,10)==expected);
            assert(lookup_calls==previous_lookups+(test==85?0u:1u));
            if(test!=84)for(uint64_t value:info)assert(value==0);
            assert(!genuine.held && !other.held && !test_hw_pubs);
            assert(client.clientClose()==0 && gfx.core.closed);return 0;
        }
        if(test==77) {
            test_admin=false;
            assert(!observer.initWithTask(test_task,test_task,SGPU_GRAPHICS_CLIENT_OBSERVER) && !gfx.claimed && !test_task_refs && test_buffers.empty());
            return 0;
        }
        if(test==75 || test==76) {
            if(test==75) {
                test_admin=false;assert(client.initWithTask(test_task,test_task,SGPU_GRAPHICS_CLIENT_RENDERER));
                assert(client.clientClose()==0 && gfx.core.closed);
            }else test_profile=0;
            assert(observer.initWithTask(test_task,test_task,SGPU_GRAPHICS_CLIENT_OBSERVER));
            uint64_t status[5]={};assert(invoke(observer,SG_GFX_RENDERER_STATUS,nullptr,0,status,5)==0);
            assert(status[2]==(test==75?1u:0u) && status[3]==(test==75?1u:0u) && status[4]==(test==75?1u:0u));
            assert(!test_hw_maps && !test_hw_pubs);observer.clientClose();return 0;
        }
        if(test>=70) {
            if(test==72 || test==73) {
                test_admin=false;assert(client.initWithTask(test_task,test_task,SGPU_GRAPHICS_CLIENT_RENDERER));
                uint64_t in[2]={4096,SGPU_GRAPHICS_RO},bo[4]={};
                assert(invoke(client,SG_GFX_NEW,in,2,bo,4)==0);
                static SantoniGraphicsClient *closing;closing=&client;
                test_attribute_hook=[] {assert(!gfx.lock->held);closing->clientClose();};
                if(test==72) {
                    uint64_t second[4]={};
                    assert(invoke(client,SG_GFX_NEW,in,2,second,4)==kIOReturnNotPermitted && !second[0]);
                }else {
                    IOOptionBits options=0;IOMemoryDescriptor *memory=nullptr;
                    assert(client.clientMemoryForType((UInt32)bo[0],&options,&memory)==kIOReturnNotPermitted && !memory);
                }
                assert(gfx.core.closed && !test_hw_pubs && !genuine.held && !other.held);return 0;
            }
            assert(observer.initWithTask(test_task,test_task,SGPU_GRAPHICS_CLIENT_OBSERVER) && test_task_refs==1);
            if(test==70) {
                std::atomic<bool> start{false};std::vector<std::thread> threads;
                for(unsigned i=0;i<8;i++)threads.emplace_back([&,i] {
                    while(!start.load(std::memory_order_acquire)) {}
                    for(unsigned j=0;j<500;j++) {
                        uint64_t status[5]={};IOReturn result=invoke(observer,SG_GFX_RENDERER_STATUS,nullptr,0,status,5);
                        assert(result==0 || result==kIOReturnNotPermitted);
                        if(result==0)assert(status[0]==1 && status[1]==1 && status[2]==1 && !status[3] && !status[4]);
                        if(j==i)assert(observer.clientClose()==0);
                    }
                });
                start.store(true,std::memory_order_release);for(auto &thread:threads)thread.join();
                assert(!test_task_refs && !gfx.claimed && test_buffers.empty());
            }else if(test==71) {
                observer.free();assert(!test_task_refs);observer.free();assert(!test_task_refs);
            }else {
                IOExternalMethodArguments a;a.scalarOutputCount=5;
                assert(observer.externalMethod(SG_GFX_RENDERER_STATUS,&a,nullptr,nullptr,nullptr)==kIOReturnBadArgument);
            }
            uint64_t status[5]={};observer.clientClose();
            assert(invoke(observer,SG_GFX_RENDERER_STATUS,nullptr,0,status,5)==kIOReturnNotPermitted && !test_task_refs);
            return 0;
        }
        if(test==30) {
            assert(client.initWithTask(test_task,test_task,0));uint64_t info[10]={};
            assert(invoke(client,SG_GFX_INFO,nullptr,0,info,10)==0 && info[9]==1);return 0;
        }
        if(test==66){assert(!observer.initWithTask(test_task,test_task,2) && !gfx.claimed && test_buffers.empty());return 0;}
        if(test==40){test_admin=false;worker_ready=false;hw_ready=false;}
        if(test==41){assert(!observer.initWithTask((void *)0x9999,test_task,2));return 0;}
        if(test==42){assert(!observer.initWithTask(test_task,(void *)0x9999,2));return 0;}
        if(test==50){worker_ready=false;assert(!client.initWithTask(test_task,test_task,1) && !gfx.claimed && !test_task_refs && test_buffers.empty());return 0;}
        if(test>=51 && test<=56) {
            if(test==51)process.exe=&other;if(test==52)process.uid=0;if(test==53)genuine.uid=501;
            if(test==54)genuine.mode=0775;if(test==55)uid_supported=false;if(test==56)lookup_error=2;
            test_admin=false;
            assert(!client.initWithTask(test_task,test_task,1) && !gfx.claimed && !test_task_refs && test_buffers.empty());
            assert(!genuine.held && !other.held);return 0;
        }
        if(test==65){assert(!client.initWithTask(test_task,test_task,3));return 0;}
        if(test==49 || test==57 || test==59 || test==60 || test==61 || test==63 || test==64) {
            test_admin=test==64;
            assert(client.initWithTask(test_task,test_task,test==64?0:1));
            assert(gfx.claimed && test_task_refs==1 && test_buffers.size()==2);
            uint64_t info[10]={};assert(invoke(client,SG_GFX_INFO,nullptr,0,info,10)==0 && info[9]==1);
            if(test==63){SantoniGraphicsClient duplicate;assert(!duplicate.initWithTask(test_task,test_task,1));return 0;}
            if(test==59 || test==60 || test==61) {
                process.exe=&other;
                if(test==59){IOOptionBits flags=0;IOMemoryDescriptor *memory=nullptr;assert(client.clientMemoryForType(1,&flags,&memory)==kIOReturnNotPermitted && !memory);}
                if(test==60)assert(invoke(client,SG_GFX_INFO,nullptr,0,info,10)==kIOReturnNotPermitted);
                if(test==61)assert(client.clientClose()==0 && gfx.core.closed);
                assert(!genuine.held && !other.held);return 0;
            }
            if(test==57 || test==64){assert(client.clientClose()==0 && gfx.core.closed);return 0;}
        }
        if(test==58)worker_ready=false;
        assert(observer.initWithTask(test_task,test_task,2));
        assert(test_task_refs==(test==49?2u:1u) && test_buffers.size()==(test==49?2u:0u));
        uint64_t status[5]={};
        if(test==43){assert(invoke(observer,SG_GFX_RENDERER_STATUS,nullptr,0,status,4)==kIOReturnBadArgument);return 0;}
        if(test==44){uint64_t in=0;assert(invoke(observer,SG_GFX_RENDERER_STATUS,&in,1,status,5)==kIOReturnBadArgument);return 0;}
        if(test==45){unsigned char data=0;assert(invoke(observer,SG_GFX_RENDERER_STATUS,nullptr,0,status,5,&data,1)==kIOReturnBadArgument);return 0;}
        if(test==46){assert(invoke(observer,SG_GFX_NEW,nullptr,0,status,5)==kIOReturnBadArgument && !test_hw_maps && !test_hw_pubs);return 0;}
        if(test==47){IOOptionBits flags=0;IOMemoryDescriptor *memory=nullptr;assert(observer.clientMemoryForType(1,&flags,&memory)==kIOReturnNotPermitted && !memory);return 0;}
        if(test==62){test_task=(void *)0x9999;assert(invoke(observer,SG_GFX_RENDERER_STATUS,nullptr,0,status,5)==kIOReturnNotPermitted);return 0;}
        if(test>=67) {
            IOExternalMethodArguments a;a.scalarOutput=status;a.scalarOutputCount=5;
            if(test==67)a.structureOutputSize=1;if(test==68)a.structureInputDescriptor=(IOMemoryDescriptor *)(uintptr_t)1;
            if(test==69)a.structureOutputDescriptor=(IOMemoryDescriptor *)(uintptr_t)1;
            assert(observer.externalMethod(SG_GFX_RENDERER_STATUS,&a,nullptr,nullptr,nullptr)==kIOReturnBadArgument);return 0;
        }
        assert(invoke(observer,SG_GFX_RENDERER_STATUS,nullptr,0,status,5)==0);
        assert(status[0]==1 && status[1]==1 && status[2]==(test==40 || test==58?0u:1u));
        assert(status[3]==(test==49?1u:0u) && !status[4] && !test_hw_maps && !test_hw_pubs);
        assert(observer.clientClose()==0 && test_task_refs==(test==49?1u:0u));
        assert(observer.clientClose()==0 && invoke(observer,SG_GFX_RENDERER_STATUS,nullptr,0,status,5)==kIOReturnNotPermitted);
        if(test==49)assert(!gfx.core.closed);
        if(test==58){worker_ready=true;test_admin=false;assert(client.initWithTask(test_task,test_task,1) && gfx.claimed && test_task_refs==1);}
        return 0;
    }
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
    assert(advertised[9]==0 && advertised[4]==SGPU_GRAPHICS_WIDE_VA &&
        advertised[5]==SGPU_GRAPHICS_WIDE_BYTES &&
        advertised[6]==SGPU_GRAPHICS_WIDE_BO_BYTES);
    if(test==18) {
        uint64_t request[2]={SGPU_RENDER_BO_BYTES,SGPU_GRAPHICS_RW},a[4],b[4];
        assert(invoke(client,SG_GFX_NEW,request,2,a,4)==0 && invoke(client,SG_GFX_NEW,request,2,b,4)==0);
        assert(b[1]>=a[1]+SGPU_RENDER_BO_BYTES+SGPU_PAGE);
        assert(gfx.core.retained_pages==2048 && gfx.user.pages==SGPU_GRAPHICS_WIDE_PUBLIC_PAGES);
        assert(client.clientClose()==0 && test_buffers.size()==2);return 0;
    }
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
