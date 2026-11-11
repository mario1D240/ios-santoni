/* Executes the actual framebuffer methods; IOKit and core result are models. */
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#define SANTONI 1
#define SWEET_FB_LAYERS 4
#define SWEET_FB_FORMAT_BGRA 0x42475241
struct IOMemoryDescriptor { virtual ~IOMemoryDescriptor()=default; virtual uint64_t getLength()const=0; };
struct IOBufferMemoryDescriptor: IOMemoryDescriptor {
    uint64_t bytes=3932160;
    uint64_t getLength()const override {return bytes;}
};
struct SweetSurface {
    uint32_t id=1,width=720,height=1280,offset=0,pixelFormat=SWEET_FB_FORMAT_BGRA;
    uint32_t planeCount=0,bytesPerRow=3072;
    uint16_t bytesPerElement=4;
    uint8_t elementWidth=1,elementHeight=1;
    bool wrapped=false;
    IOMemoryDescriptor *memory=nullptr;
    uintptr_t pixels=0;
    int refs=1,holds=0;
    void release(){assert(refs>1);refs--;}
    uintptr_t kernelAddress(){return pixels;}
};
#define OSDynamicCast(type,obj) dynamic_cast<type *>(obj)
#define OSSafeReleaseNULL(s) do{if(s){s->release();s=nullptr;}}while(0)
static SweetSurface *surfaces[4];
static SweetSurface *sweet_surface_copy(uint32_t id) {
    if(id>=4 || !surfaces[id])return nullptr;
    surfaces[id]->refs++;return surfaces[id];
}
static void sweet_hold(SweetSurface *s,bool on){s->holds+=on?1:-1;assert(s->holds>=0);}
static int sweet_console_muted;
static unsigned barriers,calls,queries,display_logs;
static int core_rc=1;
static bool quiet=true;
static std::vector<uint8_t> gpu(3932160);
static void IOLog(const char *,...){display_logs++;}
static void IOLockLock(void *){}
static void IOLockUnlock(void *){}
static bool PE_parse_boot_argn(const char *name,void *out,unsigned bytes) {
    assert(bytes==sizeof(int));
    if(!strcmp(name,"sweetfb_console")){*(int *)out=0;return true;}
    assert(!strcmp(name,"sweetfb_noconsole"));*(int *)out=quiet;return true;
}
extern "C" int santoni_gpu_ui_copy(const void *source,uint32_t bytes,uint32_t width,
    uint32_t height,uint32_t stride,const void **out,uint32_t *out_stride) {
    assert(source && bytes==3932160 && width==720 && height==1280 && stride==3072);
    calls++;
    if(core_rc==1){memcpy(gpu.data(),source,bytes);*out=gpu.data();*out_stride=stride;}
    else {*out=nullptr;*out_stride=0;if(core_rc<0)memset(gpu.data(),0xcc,gpu.size());}
    return core_rc;
}
extern "C" bool santoni_gpu_ui_frame(const void **out,uint32_t *stride) {
    queries++;assert(core_rc>=0);*out=gpu.data();*stride=3072;return true;
}
struct AppleCLCD {
    uint32_t fBpp=3,fWidth=720,fHeight=1280,fPanelStride=2160,fRowBytes=2880;
    int32_t fOffX=0,fOffY=0;
    uintptr_t fPanelVA=0,fPixels=0;
    SweetSurface *fSurface=nullptr;
    void *fFlip[2]={nullptr,nullptr};
    bool fConsolePaused=false;
    bool fConsShown=false;
    const uint8_t *fLastVA=nullptr;
    void *fLock=nullptr;
    volatile uint32_t *fVig0=nullptr;
    uint64_t fScanPhys=0;
    uint32_t fBootSrc=0,fBootStride=0;
    bool gpuPresent(const uint8_t *);
    void gpuRestoreShadow();
    bool directPresent(const uint8_t *){return false;}
    void scanFrom(uint64_t,uint32_t){}
    uint8_t *backBuffer(){return (uint8_t *)fPixels;}
    void flipBack(){}
    void blitPanel();
    void present(const uint8_t *);
};
static uint32_t sweet_fb_swaps_logged;
#include "santoni_gpu_ui_framebuffer_actual.h"

static void put32(uint8_t *record,unsigned off,uint32_t value){memcpy(record+off,&value,4);}
int main(int argc,char **argv) {
    assert(argc==2);unsigned test=(unsigned)strtoul(argv[1],nullptr,10);
    std::vector<uint8_t> source(3932160),source2(3932160),shadow(3686400,0xa5),panel(2764800,0x5a);
    for(unsigned i=0;i<source.size();i++){source[i]=(uint8_t)(i*19+3);source2[i]=(uint8_t)(i*23+7);}
    IOBufferMemoryDescriptor memory,memory2;
    SweetSurface s,s2;s.memory=&memory;s.pixels=(uintptr_t)source.data();
    s2.id=2;s2.memory=&memory2;s2.pixels=(uintptr_t)source2.data();
    surfaces[1]=&s;surfaces[2]=&s2;
    AppleCLCD fb;fb.fPixels=(uintptr_t)shadow.data();fb.fPanelVA=(uintptr_t)panel.data();
    uint8_t rec[0x46c]={};put32(rec,0x104,1);put32(rec,0x54,1);
    put32(rec,0xc4+8,720);put32(rec,0xc4+12,1280);
    if(test==1)s.pixelFormat=0x52474241;
    if(test==2)s.wrapped=true;
    if(test==3)s.offset=64;
    if(test==4)s.bytesPerRow=2880;
    if(test==5)put32(rec,0x104,3);
    if(test==6)put32(rec,0xc4,1);
    if(test==7)memory.bytes--;
    if(test==8)s.bytesPerElement=2;
    if(test==9)s.elementWidth=2;
    if(test==10)s.planeCount=2;
    if(test==11)core_rc=0;
    if(test==12)fb.fOffX=1;
    if(test==13)fb.fBpp=4;
    if(test==14)put32(rec,0xc4+8,719);
    if(test==15)fb.fSurface=&s;
    if(test==18 || test==19) {
        fb.present(rec);
        assert(calls==1 && barriers==1 && santoni_ui_shown);
        put32(rec,0x54,2);
        if(test==18)core_rc=-1;
        else {put32(rec,0x104,3);put32(rec,0x54+4,2);}
        fb.present(rec);
        assert(queries==(test==18?0u:1u));
        assert(!santoni_ui_shown);
        const uint8_t *expected=test==18?source2.data():source2.data();
        for(unsigned y=0;y<1280;y++)for(unsigned x=0;x<720;x++)for(unsigned c=0;c<3;c++)
            assert(panel[y*2160+x*3+c]==expected[y*3072+x*4+c]);
        if(test==18)assert(s.holds==1 && s2.holds==1 && santoni_ui_failed);
    } else if(test>=1 && test<=15) {
        assert(!fb.gpuPresent(rec));
        assert(!s.holds && s.refs==1 && !barriers && !santoni_ui_shown);
        assert(calls==(test==11?1u:0u));
    } else {
        assert(fb.gpuPresent(rec));
        assert(s.holds==1 && s.refs==2 && barriers==1 && calls==1 && sweet_console_muted==1);
        for(unsigned y=0;y<1280;y++)for(unsigned x=0;x<720;x++)for(unsigned c=0;c<3;c++)
            assert(panel[y*2160+x*3+c]==source[y*3072+x*4+c]);
        for(uint8_t b:shadow)assert(b==0xa5); /* fast path skipped CPU shadow copy */
        if(test==16) {
            fb.gpuRestoreShadow();
            assert(queries==1 && !santoni_ui_shown);
            for(unsigned y=0;y<1280;y++)assert(!memcmp(shadow.data()+y*2880,source.data()+y*3072,2880));
        } else {
            put32(rec,0x54,2);
            if(test==17)core_rc=-1;
            bool second=fb.gpuPresent(rec);
            if(test==17) {
                assert(!second && santoni_ui_failed && santoni_ui_quarantine==&s2);
                assert(s.holds==1 && s2.holds==1 && s.refs==2 && s2.refs==2);
                fb.gpuRestoreShadow();assert(!queries); /* never read possibly live output */
                unsigned before=calls;assert(!fb.gpuPresent(rec));assert(calls==before);
            } else {
                assert(second && s.holds==0 && s.refs==1 && s2.holds==1 && s2.refs==2);
                assert(santoni_ui_import==&s2 && barriers==2);
            }
        }
    }
    printf("PASS UI framebuffer case=%u copies=%u barriers=%u; IOKit/core models only\n",test,calls,barriers);
    return 0;
}
