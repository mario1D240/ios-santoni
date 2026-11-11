/* Original modeled callbacks; group/context/transfer implementation is actual. */
#include "context_models.h"
static struct sgfx_ui_surface_ops surface_ops(void)
{return (struct sgfx_ui_surface_ops){retain,release,lock_surface,unlock_surface};}
static struct sgfx_ui_context *in_group(void *object,struct backend *b,struct sgfx_ui_group *g)
{
    void *dispatch[SGFX_UI_SLOTS];for(unsigned i=0;i<SGFX_UI_SLOTS;i++)dispatch[i]=(void *)noop;
    struct sgfx_ui_transfer_ops t={b,upload,finish,read_pixels,fence};
    struct sgfx_ui_backend backend={b,bind,destroy,select_texture,restore_texture,t};
    return sgfx_ui_context_create_in_group(object,3,&backend,g,dispatch);
}
struct peer_call {struct sgfx_ui_context *context;bool dirty,refresh,refresh_first;};
static void *unsynchronized_peer(void *opaque)
{
    struct peer_call *call=opaque;assert(sgfx_ui_context_bind(call->context));
    if(call->refresh_first) {
        call->refresh=sgfx_ui_context_refresh(call->context,17);
        call->dirty=sgfx_ui_context_dirty(call->context,17);
    }else{
        call->dirty=sgfx_ui_context_dirty(call->context,17);
        call->refresh=sgfx_ui_context_refresh(call->context,17);
    }
    return NULL;
}
int main(int argc,char **argv)
{
    assert(argc==2);unsigned scenario=(unsigned)strtoul(argv[1],NULL,10);assert(scenario<9);
    one.sequence=two.sequence=7;one.selected=two.selected=99;init_surface(&first);init_surface(&second);
    struct sgfx_ui_surface_ops ops=surface_ops();struct sgfx_ui_group *g=sgfx_ui_group_create(&ops);assert(g);
    struct sgfx_ui_context *a=in_group(&one,&one,g),*b=scenario==6?create(&two,&two):in_group(&two,&two,g);
    assert(a && b && sgfx_ui_context_bind(a));
    if(scenario==5){
        assert(!in_group(&second,&two,(void *)(uintptr_t)1));
        assert(!sgfx_ui_group_retain((void *)(uintptr_t)1) && !sgfx_ui_group_release((void *)(uintptr_t)1));
        assert(!sgfx_ui_group_release(NULL));
        pthread_t thread;assert(!pthread_create(&thread,NULL,foreign,a));assert(!pthread_join(thread,NULL));
        assert(sgfx_ui_context_destroy(a) && sgfx_ui_context_destroy(b) && sgfx_ui_group_release(g));
        assert(!sgfx_ui_group_release(g) && !sgfx_ui_group_retain(g));return 0;
    }
    assert(sgfx_ui_context_attach(a,17,&first,false) && first.holds==1);
    if(scenario==3 || scenario==4 || scenario==8){
        uint8_t before[48];memcpy(before,first.bytes,48);assert(sgfx_ui_context_dirty(a,17));
        if(scenario==3){test=12;assert(!sgfx_ui_context_flush(a));assert(!sgfx_ui_context_bind(b));}
        else{
            struct peer_call call={.context=b,.refresh_first=scenario==8};pthread_t thread;
            assert(!pthread_create(&thread,NULL,unsynchronized_peer,&call));assert(!pthread_join(thread,NULL));
            assert(!call.dirty && !call.refresh && !one.reads && !two.reads);
        }
        assert(!memcmp(before,first.bytes,48) && !first.locked && first.holds==1);
        struct sgfx_ui_report report;assert(sgfx_ui_context_report(b,&report));
        assert(report.group_failure==(scenario==3?SGFX_UI_TRANSFER:SGFX_UI_BIND));
        assert(!sgfx_ui_context_destroy(a) && !sgfx_ui_context_destroy(b) && !sgfx_ui_group_release(g));
        assert(!one.destroys && !two.destroys);return 0;
    }
    if(scenario==7){
        for(uint32_t i=18;i<18+SGFX_UI_TEXTURES-1;i++)assert(sgfx_ui_context_attach(a,i,&first,false));
        assert(first.holds==SGFX_UI_TEXTURES && sgfx_ui_context_bind(b));
        assert(!sgfx_ui_context_attach(b,999,&second,false) && !second.holds);
        assert(!sgfx_ui_context_destroy(a) && !sgfx_ui_context_destroy(b) && !sgfx_ui_group_release(g));return 0;
    }
    if(scenario==1){
        assert(sgfx_ui_context_dirty(a,17) && sgfx_ui_context_bind(b));
        assert(one.reads==1 && !two.reads && first.bytes[4]==0 && first.bytes[6]==255);
        assert(sgfx_ui_context_refresh(b,17) && !two.uploads);
        assert(sgfx_ui_context_dirty(b,17) && sgfx_ui_context_flush(b) && two.reads==1);
    }else{
        assert(sgfx_ui_context_bind(b));
        if(scenario==6){
            assert(sgfx_ui_context_attach(b,17,&second,false));unsigned uploads=two.uploads;
            first.seed++;assert(sgfx_ui_context_refresh(b,17) && two.uploads==uploads);
            assert(sgfx_ui_context_destroy(a) && first.holds==1 && second.holds==1);
        }else{
            assert(sgfx_ui_context_refresh(b,17) && !two.uploads);
            first.seed++;assert(sgfx_ui_context_refresh(b,17) && two.uploads==1);
        }
    }
    if(scenario!=6)assert(sgfx_ui_context_destroy(a) && first.holds==1);
    if(scenario==2)assert(sgfx_ui_context_forget(b,17) && !first.holds);
    assert(sgfx_ui_group_release(g));
    if(scenario==6)assert(!first.holds && second.holds==1);
    if(scenario!=2 && scenario!=6)assert(first.holds==1);
    assert(sgfx_ui_context_destroy(b) && !first.holds && !second.holds && one.destroys==1 && two.destroys==1);
    assert(!sgfx_ui_group_release(g));
    printf("PASS shared surface group scenario=%u; GL/IOSurface modeled\n",scenario);return 0;
}
