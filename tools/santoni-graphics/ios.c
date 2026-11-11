/* Actual Darwin transport shared by the staged Mesa frontend. */
#include "santoni_drm.h"
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
static io_connect_t connection;
static bool mach_call(void *ctx,uint32_t selector,const uint64_t *input,uint32_t ni,uint64_t *output,
    uint32_t no,const void *wire,size_t bytes)
{
    uint32_t count=no;
    kern_return_t kr=IOConnectCallMethod(*(io_connect_t *)ctx,selector,input,ni,wire,bytes,output,&count,NULL,NULL);
    if(kr!=KERN_SUCCESS || count!=no) {
        fprintf(stderr,"MESA TRANSPORT selector=%u status=0x%x scalars=%u/%u\n",selector,kr,count,no);return false;
    }
    return true;
}
static bool mach_map(void *ctx,uint32_t type,uint8_t **out,uint64_t *length)
{
    mach_vm_address_t address=0;mach_vm_size_t size=0;
    if(IOConnectMapMemory64(*(io_connect_t *)ctx,type,mach_task_self(),&address,&size,kIOMapAnywhere)!=KERN_SUCCESS)return false;
    *out=(uint8_t *)(uintptr_t)address;*length=size;return true;
}
static void mach_unmap(void *ctx,uint32_t type,uint8_t *address)
{IOConnectUnmapMemory64(*(io_connect_t *)ctx,type,mach_task_self(),(mach_vm_address_t)(uintptr_t)address);}
static void mach_close(void *ctx)
{if(*(io_connect_t *)ctx)IOServiceClose(*(io_connect_t *)ctx);*(io_connect_t *)ctx=0;}
static bool connect_role(struct sgfx_transport *out,uint32_t role)
{
    if(!out || connection || (role!=SGPU_GRAPHICS_CLIENT_ADMIN && role!=SGPU_GRAPHICS_CLIENT_RENDERER))return false;
    io_service_t service=IOServiceGetMatchingService(kIOMainPortDefault,IOServiceMatching("SantoniGraphics"));
    if(!service)return false;
    kern_return_t kr=IOServiceOpen(service,mach_task_self(),role,&connection);IOObjectRelease(service);
    if(kr!=KERN_SUCCESS || !connection) {
        if(connection)IOServiceClose(connection);
        connection=0;return false;
    }
    *out=(struct sgfx_transport){&connection,mach_call,mach_map,mach_unmap,mach_close};return true;
}
bool sgfx_ios_connect(struct sgfx_transport *out)
{return connect_role(out,SGPU_GRAPHICS_CLIENT_ADMIN);}
bool sgfx_ios_connect_renderer(struct sgfx_transport *out)
{return connect_role(out,SGPU_GRAPHICS_CLIENT_RENDERER);}
int sgfx_ios_renderer_status(uint64_t out[SGPU_GRAPHICS_RENDERER_STATUS_WORDS])
{
    if(!out)return -EINVAL;
    io_service_t service=IOServiceGetMatchingService(kIOMainPortDefault,IOServiceMatching("SantoniGraphics"));
    if(!service)return -ENODEV;
    io_connect_t observer=0;
    kern_return_t kr=IOServiceOpen(service,mach_task_self(),SGPU_GRAPHICS_CLIENT_OBSERVER,&observer);
    IOObjectRelease(service);
    if(kr!=KERN_SUCCESS || !observer) {
        if(observer)IOServiceClose(observer);
        return -EACCES;
    }
    uint64_t status[SGPU_GRAPHICS_RENDERER_STATUS_WORDS]={0};uint32_t count=SGPU_GRAPHICS_RENDERER_STATUS_WORDS;
    kr=IOConnectCallMethod(observer,SG_GFX_RENDERER_STATUS,NULL,0,NULL,0,status,&count,NULL,NULL);
    kern_return_t closed=IOServiceClose(observer);
    if(kr!=KERN_SUCCESS || closed!=KERN_SUCCESS || count!=SGPU_GRAPHICS_RENDERER_STATUS_WORDS)return -EIO;
    if(status[0]!=SGPU_GRAPHICS_UAPI_VERSION || status[1]>1 || status[2]>1 || status[3]>1 || status[4]>1 ||
        (status[4] && !status[3]))return -EPROTO;
    memcpy(out,status,sizeof(status));return 0;
}
