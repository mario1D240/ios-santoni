/* Isolated BO/IB proof. This executable does not claim GLES/UI rendering. */
#include "client.h"
#include <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>
static bool mach_call(void *ctx,uint32_t selector,const uint64_t *input,uint32_t ni,uint64_t *output,
    uint32_t no,const void *wire,size_t bytes)
{
    uint32_t count=no;
    kern_return_t kr=IOConnectCallMethod(*(io_connect_t *)ctx,selector,input,ni,wire,bytes,output,&count,NULL,NULL);
    if(kr!=KERN_SUCCESS || count!=no) {
        fprintf(stderr,"GRAPHICS CLIENT: selector=%u status=0x%x scalars=%u/%u\n",selector,kr,count,no);return false;
    }
    return true;
}
static bool mach_map(void *ctx,uint32_t type,uint8_t **out,uint64_t *length)
{
    mach_vm_address_t address=0;mach_vm_size_t size=0;
    kern_return_t kr=IOConnectMapMemory64(*(io_connect_t *)ctx,type,mach_task_self(),&address,&size,kIOMapAnywhere);
    if(kr!=KERN_SUCCESS)return false;
    *out=(uint8_t *)(uintptr_t)address;*length=size;return true;
}
static void mach_unmap(void *ctx,uint32_t type,uint8_t *address)
{IOConnectUnmapMemory64(*(io_connect_t *)ctx,type,mach_task_self(),(mach_vm_address_t)(uintptr_t)address);}
static void mach_close(void *ctx){IOServiceClose(*(io_connect_t *)ctx);}
int main(int argc,char **argv)
{
    if(argc!=2 || strcmp(argv[1],"--bo-ib-proof")) {
        fprintf(stderr,"usage: %s --bo-ib-proof (opt-in graphics boot, root; no framework injection)\n",argv[0]);return 2;
    }
    io_service_t service=IOServiceGetMatchingService(kIOMainPortDefault,IOServiceMatching("SantoniGraphics"));
    if(!service) {fprintf(stderr,"GRAPHICS CLIENT: service absent\n");return 1;}
    io_connect_t connection=0;kern_return_t kr=IOServiceOpen(service,mach_task_self(),0,&connection);IOObjectRelease(service);
    if(kr!=KERN_SUCCESS) {fprintf(stderr,"GRAPHICS CLIENT: open status=0x%x; VM/root/task gate required\n",kr);return 1;}
    struct sgfx_client client={0};struct sgfx_transport transport={&connection,mach_call,mach_map,mach_unmap,mach_close};
    bool pass=sgfx_init(&client,&transport);
    struct sgfx_bo *commands=pass?sgfx_new(&client,16,SGFX_READ):NULL;
    struct sgfx_bo *data=commands?sgfx_new(&client,32*4,SGFX_WRITE):NULL;
    if(!data)pass=false;
    for(unsigned i=0;pass && i<32;i++) {
        uint32_t words[4]={0x703d8003,data->gpu_va+i*4,0,0xa5050000u+i}; /* vendor CP_MEM_WRITE(3), type7 parity */
        memcpy(commands->cpu,words,sizeof(words));
        struct sgpu_graphics_wire_ib ib={commands->handle,0,16};uint32_t handles[2]={commands->handle,data->handle};
        uint32_t sequence=sgfx_submit(&client,&ib,1,handles,2);
        pass=sequence==i+1 && sgfx_wait(&client,sequence) && sgfx_cpu_prep(&client,data->handle);
        for(unsigned j=0;pass && j<=i;j++) {
            uint32_t pixel;memcpy(&pixel,data->cpu+j*4,4);if(pixel!=0xa5050000u+j)pass=false;
        }
    }
    if(pass)pass=sgfx_free(&client,commands->handle) && sgfx_free(&client,data->handle);
    printf("GRAPHICS CLIENT RESULT pass=%u submitted=%u completed=%u chip=%08x page=%llu gles=%llu; BO/IB READBACK ONLY\n",
        pass?1u:0u,client.submitted,client.completed,(uint32_t)client.info[2],
        (unsigned long long)client.info[1],(unsigned long long)client.info[9]);
    sgfx_close(&client);return pass?0:1;
}
