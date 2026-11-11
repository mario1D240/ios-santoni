/* Actual context + transfer code. Mesa and IOSurface callbacks are models. */
#include "ui_context.h"
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct surface {uint8_t bytes[48];uint32_t seed;unsigned holds,locks,unlocks;bool locked;};
struct backend {unsigned uploads,reads,finishes,selects,restores,destroys,binds;
    uint32_t selected,sequence;uint8_t copied[24];};
static unsigned test;
static struct backend one,two;
static struct surface first,second;
static void retain(void *opaque) {struct surface *s=opaque;s->holds++;}
static void release(void *opaque) {struct surface *s=opaque;assert(s->holds);s->holds--;}
static bool lock_surface(void *opaque,bool write,struct sgfx_ui_surface *out,uint32_t *seed)
{
    (void)write;struct surface *s=opaque;s->locks++;assert(!s->locked);
    if(test==4)return false;
    s->locked=true;*seed=s->seed;
    *out=(struct sgfx_ui_surface){s->bytes,48,4,3,2,test==5?32:16,SGFX_UI_BGRA,false};return true;
}
static bool unlock_surface(void *opaque,bool write,uint32_t *seed)
{
    struct surface *s=opaque;assert(s->locked);s->locked=false;s->unlocks++;
    if(write)s->seed++;*seed=s->seed;return test!=11;
}
static bool bind(void *opaque,bool enable)
{struct backend *b=opaque;b->binds++;return !(enable && test==2 && b==&two);}
static void destroy(void *opaque) {struct backend *b=opaque;b->destroys++;}
static bool select_texture(void *opaque,uint32_t name,bool read,uint32_t *saved)
{
    (void)read;struct backend *b=opaque;b->selects++;*saved=b->selected;
    if(test==6)return false;b->selected=name;return true;
}
static bool restore_texture(void *opaque,uint32_t saved,bool read)
{(void)read;struct backend *b=opaque;b->restores++;b->selected=saved;return test!=10;}
static bool upload(void *opaque,uint32_t width,uint32_t height,const uint8_t *bytes)
{struct backend *b=opaque;assert(width==3 && height==2);b->uploads++;memcpy(b->copied,bytes,24);return test!=7;}
static bool finish(void *opaque) {struct backend *b=opaque;b->finishes++;return test!=8;}
static bool read_pixels(void *opaque,uint32_t width,uint32_t height,uint8_t *bytes)
{
    struct backend *b=opaque;assert(width==3 && height==2);b->reads++;
    for(unsigned i=0;i<6;i++) {bytes[i*4]=255;bytes[i*4+1]=2;bytes[i*4+2]=0;bytes[i*4+3]=255;}
    b->sequence++;return test!=9;
}
static bool fence(void *opaque,uint32_t *submitted,uint32_t *completed)
{
    struct backend *b=opaque;*submitted=b->sequence;*completed=b->sequence;
    if(test==12 && b->reads)*completed=b->sequence-1;return true;
}
static void noop(void) {}
static struct sgfx_ui_context *create(void *object,struct backend *b)
{
    void *dispatch[SGFX_UI_SLOTS];for(unsigned i=0;i<SGFX_UI_SLOTS;i++)dispatch[i]=(void *)noop;
    struct sgfx_ui_surface_ops ops={retain,release,lock_surface,unlock_surface};
    struct sgfx_ui_transfer_ops transfer={b,upload,finish,read_pixels,fence};
    struct sgfx_ui_backend backend={b,bind,destroy,select_texture,restore_texture,transfer};
    return sgfx_ui_context_create(object,3,&backend,&ops,dispatch);
}
static void *foreign(void *opaque)
{
    struct sgfx_ui_context *c=opaque;
    assert(!sgfx_ui_context_bind(c));assert(!sgfx_ui_context_destroy(c));
    assert(!sgfx_ui_context_attach(c,1,&second,false));return NULL;
}
static void init_surface(struct surface *s)
{
    memset(s->bytes,0xa7,48);s->seed=1;
    for(unsigned i=0;i<12;i++) {s->bytes[4+i]=(uint8_t)(i+1);s->bytes[20+i]=(uint8_t)(i+13);}
}
int main(int argc,char **argv)
{
    assert(argc==2);test=(unsigned)strtoul(argv[1],NULL,10);assert(test<19);
    one.sequence=two.sequence=7;one.selected=two.selected=99;init_surface(&first);init_surface(&second);
    struct sgfx_ui_context *c=create(&one,&one);assert(c);
    assert(sgfx_ui_context_lookup(&one)==c && sgfx_ui_context_api(c)==3);
    struct sgfx_ui_macro *macro=sgfx_ui_context_macro(c);assert(macro && macro->context==c && macro->dispatch[1035]);
    assert(!create(&one,&two));assert(sgfx_ui_context_bind(c));
    if(test==1) {
        pthread_t thread;assert(!pthread_create(&thread,NULL,foreign,c));assert(!pthread_join(thread,NULL));
        assert(sgfx_ui_context_current()==&one && !second.holds && sgfx_ui_context_destroy(c));return 0;
    }
    if(test==2) {
        struct sgfx_ui_context *other=create(&two,&two);assert(other && !sgfx_ui_context_bind(other));
        assert(sgfx_ui_context_current()==&one && sgfx_ui_context_destroy(c));return 0;
    }
    if(test==3) {
        assert(!sgfx_ui_context_bind((struct sgfx_ui_context *)(uintptr_t)1));
        assert(!sgfx_ui_context_attach(c,0,&first,false));assert(!sgfx_ui_context_attach(c,1,NULL,false));
        assert(sgfx_ui_context_destroy(c));return 0;
    }
    uint8_t original[48];memcpy(original,first.bytes,48);
    bool attached=sgfx_ui_context_attach(c,17,&first,test==13);
    bool attach_ok=test<4 || test>11 || test==8 || test==9;
    if(test==8)attach_ok=false;
    assert(attached==attach_ok);
    assert(!first.locked && one.selected==99 && !memcmp(first.bytes,original,48));
    if(!attached) {
        assert(!first.holds && !sgfx_ui_context_refresh(c,17));
        struct sgfx_ui_report report;assert(sgfx_ui_context_report(c,&report) && report.first_failure);
        unsigned why=report.first_failure;sgfx_ui_context_fail(c,SGFX_UI_UNSUPPORTED,1024);
        assert(sgfx_ui_context_report(c,&report) && report.first_failure==why);
        assert(report.restore_failed==(test==10) && report.unlock_failed==(test==11));
        assert(!sgfx_ui_context_destroy(c) && !one.destroys);return 0;
    }
    assert(first.holds==1 && one.uploads==1);
    const uint8_t rgba[]={3,2,1,4,7,6,5,8,11,10,9,12,15,14,13,16,19,18,17,20,23,22,21,24};
    assert(!memcmp(one.copied,rgba+(test==13?12:0),12));
    assert(sgfx_ui_context_refresh(c,17) && one.uploads==1);
    first.seed++;first.bytes[4]=42;assert(sgfx_ui_context_refresh(c,17) && one.uploads==2);
    if(test==14) {
        assert(sgfx_ui_context_attach(c,17,&second,false));assert(!first.holds && second.holds==1);
        assert(sgfx_ui_context_forget(c,17) && !second.holds && sgfx_ui_context_destroy(c));return 0;
    }
    if(test==15) {
        for(uint32_t i=18;i<18+SGFX_UI_TEXTURES-1;i++)assert(sgfx_ui_context_attach(c,i,&first,false));
        assert(first.holds==SGFX_UI_TEXTURES && !sgfx_ui_context_attach(c,999,&second,false));
        assert(!second.holds && !sgfx_ui_context_destroy(c));return 0;
    }
    if(test==16) {
        assert(sgfx_ui_context_destroy(c) && !first.holds && one.destroys==1 && !sgfx_ui_context_macro(c));
        assert(!sgfx_ui_context_bind(c));struct sgfx_ui_context *other=create(&two,&two);assert(other && other!=c);
        assert(!sgfx_ui_context_bind(c) && sgfx_ui_context_destroy(other));return 0;
    }
    assert(sgfx_ui_context_dirty(c,17));memcpy(original,first.bytes,48);
    bool committed;
    if(test==17) {
        struct sgfx_ui_context *other=create(&two,&two);assert(other);
        committed=sgfx_ui_context_bind(other);assert(committed && sgfx_ui_context_current()==&two);
        assert(sgfx_ui_context_destroy(c) && sgfx_ui_context_destroy(other));
    } else if(test==18)committed=sgfx_ui_context_forget(c,17);
    else committed=sgfx_ui_context_flush(c);
    assert(committed==(test!=9 && test!=12));
    assert(!first.locked && one.selected==99);
    if(committed) {
        struct sgfx_ui_report report;assert(sgfx_ui_context_report(c,&report) && report.frames==1 && report.sequence==8);
        if(test==0) {unsigned reads=one.reads;assert(sgfx_ui_context_flush(c) && one.reads==reads);}
        for(unsigned i=0;i<48;i++) {
            bool pixel=(i>=4 && i<16) || (i>=20 && i<32);
            if(!pixel)assert(first.bytes[i]==original[i]);
        }
        const uint8_t bgra[]={0,2,255,255};assert(!memcmp(first.bytes+4,bgra,4));
        if(test!=17)assert(sgfx_ui_context_destroy(c));
        assert(!first.holds && one.destroys==1);
    } else {
        assert(!memcmp(first.bytes,original,48) && first.holds==1);
        unsigned reads=one.reads;assert(!sgfx_ui_context_flush(c) && one.reads==reads);
        assert(!sgfx_ui_context_destroy(c) && !one.destroys);
    }
    printf("PASS UI context case=%u; GLES/IOSurface models\n",test);return 0;
}
