#include "ui_surface.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct peer {unsigned test,status,uploads,reads,finishes;uint32_t seq,done;bool flip;struct sgfx_ui_surface *surface;};
static bool status(void *context,uint32_t *seq,uint32_t *done)
{
    struct peer *p=context;p->status++;
    if(p->test==6)return false;
    *seq=p->seq;*done=p->done;
    if(p->test==12 && p->status==3)*done=*seq-1;
    if(p->test==13 && p->status==3)*seq=*done=7;
    if(p->test==14 && p->status==3)*seq=*done=0;
    if(p->test==18 && p->status==2)p->surface->width=99;
    return true;
}
static bool upload(void *context,uint32_t width,uint32_t height,const uint8_t *pixels)
{
    struct peer *p=context;p->uploads++;assert(width==3 && height==2);
    const uint8_t normal[]={3,2,1,4,7,6,5,8,11,10,9,12,15,14,13,16,19,18,17,20,23,22,21,24};
    assert(!memcmp(pixels,normal+(p->flip?12:0),12));assert(!memcmp(pixels+12,normal+(p->flip?0:12),12));
    return p->test!=7;
}
static bool finish(void *context)
{
    struct peer *p=context;p->finishes++;
    if(p->test==9)return false;
    p->seq=8;p->done=p->test==10?7:8;return true;
}
static bool readback(void *context,uint32_t width,uint32_t height,uint8_t *pixels)
{
    struct peer *p=context;p->reads++;assert(width==3 && height==2);
    for(unsigned i=0;i<6;i++) {pixels[i*4]=i<3?255:0;pixels[i*4+1]=0;pixels[i*4+2]=i<3?0:255;pixels[i*4+3]=255;}
    return p->test!=11;
}
int main(int argc,char **argv)
{
    assert(argc==2);unsigned test=(unsigned)strtoul(argv[1],NULL,10);assert(test<21);
    uint8_t bytes[48],original[48];memset(bytes,0xa7,sizeof(bytes));
    for(unsigned i=0;i<12;i++){bytes[4+i]=(uint8_t)(i+1);bytes[20+i]=(uint8_t)(i+13);}
    memcpy(original,bytes,sizeof(bytes));
    struct sgfx_ui_surface s={bytes,sizeof(bytes),4,3,2,16,SGFX_UI_BGRA,test==1};
    struct peer p={.test=test,.seq=7,.done=7,.flip=s.flip_y,.surface=&s};
    struct sgfx_ui_transfer_ops ops={&p,upload,finish,readback,status};
    if(test==2)s.stride=8;
    if(test==3)s.allocation_bytes=35;
    if(test==4)s.offset=49;
    if(test==5)s.format=0;
    if(test==8)p.done=6;
    if(test==15)s.base=(void *)(UINTPTR_MAX-15);
    if(test==16)ops.fence_status=NULL;
    if(test==17)p.done=8;
    if(test==19) {
        size_t packed;struct sgfx_ui_surface boundary={bytes,SGFX_UI_MAX_BYTES,0,2048,2048,8192,SGFX_UI_BGRA,false};
        assert(sgfx_ui_surface_valid(&boundary,&packed) && packed==SGFX_UI_MAX_BYTES);
        boundary.height++;assert(!sgfx_ui_surface_valid(&boundary,&packed));return 0;
    }
    bool upload_ok=sgfx_ui_upload(&ops,&s);
    bool valid=test==0 || test==1 || (test>=9 && test<=14) || test==18 || test==20;
    assert(upload_ok==valid);assert(!memcmp(bytes,original,sizeof(bytes)));
    if(test==18)s.width=3;
    p.status=0;uint32_t seq=99;
    bool committed=sgfx_ui_commit(&ops,&s,&seq);
    bool expected=test==0 || test==1 || test==7 || test==8 || test==18 || test==20;
    if(test==20) {
        /* Invalid callback sets are checked before reading caller memory. */
        ops.read_rgba=NULL;assert(!sgfx_ui_commit(&ops,&s,&seq));
    }
    assert(committed==expected);
    if(expected) {
        assert(seq==8);
        for(unsigned i=0;i<48;i++) {
            bool pixel=(i>=4 && i<16) || (i>=20 && i<32);
            if(!pixel)assert(bytes[i]==original[i]);
        }
        const uint8_t red[]={0,0,255,255},blue[]={255,0,0,255};
        for(unsigned x=0;x<3;x++) {assert(!memcmp(bytes+4+x*4,p.flip?blue:red,4));assert(!memcmp(bytes+20+x*4,p.flip?red:blue,4));}
    } else {assert(seq==99);assert(!memcmp(bytes,original,sizeof(bytes)));}
    printf("PASS UI surface case=%u; transfer/layout real, GLES/IOKit callbacks modeled\n",test);return 0;
}
