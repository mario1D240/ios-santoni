/* Actual admission/publication/pmap adapter; kernel and core boundaries modeled. */
#include "santoni_gpu_ui_adapter_model.h"
#include "santoni_gpu_live_adapter_actual.h"
static unsigned ui_starts,ui_copies,ui_snapshots;
static uint8_t ui_output;
bool sgpu_ui_start(uint32_t on){assert(ui_lock_depth==1 && on==1);ui_starts++;return true;}
int sgpu_ui_copy(const struct sgpu_ui_image *s,const uint8_t **out,uint32_t *stride) {
    assert(ui_lock_depth==1 && s->va==(const uint8_t *)ui_fixture_source);
    assert(s->pages==960 && s->bytes==3932160 && s->width==720 && s->height==1280 && s->stride==3072);
    ui_copies++;
    for(unsigned i=0;i<s->pages;i++) {
        if(testcase==8 && i==s->pages-1){assert(!s->pa[i]);*out=NULL;*stride=0;return 0;}
        assert(s->pa[i]==0xa3000000ull+i*2*SGPU_PAGE);
    }
    if(testcase==14){*out=NULL;*stride=0;return -1;}
    *out=&ui_output;*stride=3072;return 1;
}
bool sgpu_ui_frame(const uint8_t **out,uint32_t *stride) {
    assert(ui_lock_depth==1);*out=&ui_output;*stride=3072;return true;
}
void sgpu_ui_snapshot(struct sgpu_ui_result *out) {
    assert(ui_lock_depth==1);ui_snapshots++;memset(out,0,sizeof(*out));
    out->frames=1;out->sequence=3;out->wptr=389;out->phase=SG_LIVE_DONE;
    if(testcase==14){out->failed=true;out->error=SG_COMMAND_TIMEOUT;}
}
int main(int argc,char **argv) {
    assert(argc==2);testcase=(unsigned)strtoul(argv[1],NULL,10);
    if(testcase==999){sgpu_kernel_thread(NULL,0);return 0;} /* referenced legacy extraction */
    sg.mode=testcase==3?1:testcase==4?2:testcase==24?0:testcase>=21?testcase-21:3;
    sg.stock_unsecure=sg.stock_pixels=sg.g3=sg.session=1;
    sgpu_render_enabled=1;
    if(testcase==5)sg.stock_unsecure=0;
    if(testcase==6)sgpu_render_enabled=0;
    if(testcase==7)sg.user=1;
    bool ok=sgpu_ui_options(sg.mode);
    if((testcase>=2 && testcase<=7) || testcase==24) {
        assert(!ok && !sgpu_ui_enabled && !ui_starts && !ui_copies && !translations);
    } else {
        bool enabled=testcase!=1 && testcase<21;
        assert(ok && sgpu_ui_enabled==enabled);
        sgpu_ui_publish(testcase!=20);
        assert(sgpu_ui_published==(enabled && testcase!=20));
        assert(ui_starts==(enabled && testcase!=20));
        void *source=NULL;assert(!posix_memalign(&source,SGPU_PAGE,SGPU_RENDER_BYTES));
        ui_fixture_source=(uintptr_t)source;
        if(testcase==9)source=(uint8_t *)source+1;
        if(testcase==19)source=(void *)(UINTPTR_MAX&~(uintptr_t)(SGPU_PAGE-1));
        if(testcase==16)sgpu_ui_published=false;
        if(testcase==17)page_shift=14;
        if(testcase==18)page_size=16384;
        uint32_t bytes=testcase==10?SGPU_RENDER_BYTES-1:SGPU_RENDER_BYTES;
        uint32_t width=testcase==11?719:720,height=testcase==12?1279:1280,stride=testcase==13?2880:3072;
        const void *out=NULL;uint32_t out_stride=0;
        int rc=santoni_gpu_ui_copy(source,bytes,width,height,stride,&out,&out_stride);
        if(testcase==0 || testcase==15) {
            assert(rc==1 && out==&ui_output && out_stride==3072 && translations==960 && ui_copies==1);
            if(testcase==15)assert(santoni_gpu_ui_frame(&out,&out_stride));
        } else if(testcase==14) {
            assert(rc==-1 && !out && !out_stride && !sgpu_ui_published && ui_snapshots==1);
            unsigned before=translations;
            assert(!santoni_gpu_ui_copy(source,bytes,width,height,stride,&out,&out_stride));
            assert(translations==before && !santoni_gpu_ui_frame(&out,&out_stride));
        } else {
            assert(!rc && !out && !out_stride);
            assert(translations==(testcase==8?960u:0u));
            assert(ui_copies==(testcase==8?1u:0u));
        }
        assert(!ui_lock_depth && !allocs && !frees);
        free((void *)ui_fixture_source);
    }
    printf("PASS UI adapter case=%u pmap=%u core_copies=%u; kernel/core boundaries modeled\n",testcase,translations,ui_copies);
    return 0;
}
