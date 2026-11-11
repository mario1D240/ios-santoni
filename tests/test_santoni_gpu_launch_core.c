/* Actual new CPU-launch contracts with explicit owned-memory/VFS models.
 * No native kernel code, dispatcher, pager or device access executes here. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "santoni_gpu_launch_core.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"launch contract line %d\n",__LINE__); return 1; } } while (0)
enum { NORMAL, ROLE_MATRIX, NULL_IMAGE, SHORT_IMAGE, BAD_CPU, BAD_COMMAND,
    WRITABLE_TEXT, BAD_ENTRY, BAD_SIGN, BAD_THREAD, ALLOC_FAIL, ALLOC_AMBIG,
    BAD_KVA, MISSING_FIRST, MISSING_LAST, NONCONTIG, COPY_FAIL, PUBLISH_FAIL,
    CLEANUP_FAIL, MISSING_CALLBACK, REUSE_SUCCESS, REUSE_FAILURE, COUNT };
static struct {
    unsigned scenario, allocated, page_calls, copied, published, released;
    uint64_t kva;
    uint32_t span;
    unsigned char *input, memory[32768];
} m;

static bool allocate(void *ctx,uint32_t span,uint64_t *out)
{
    if (ctx!=&m || span!=20480 || m.allocated) abort();
    m.allocated++;m.span=span;m.kva=UINT64_C(0x70000000);
    *out=m.scenario==ALLOC_FAIL?0:m.scenario==BAD_KVA?m.kva+1:m.kva;
    return m.scenario!=ALLOC_FAIL && m.scenario!=ALLOC_AMBIG;
}
static uint64_t page_pa(void *ctx,uint64_t kva)
{
    if (ctx!=&m || kva<m.kva || kva>=m.kva+m.span || kva%4096) abort();
    unsigned off=(unsigned)(kva-m.kva);m.page_calls++;
    if ((m.scenario==MISSING_FIRST && off==0) ||
        ((m.scenario==MISSING_LAST || m.scenario==CLEANUP_FAIL || m.scenario==REUSE_FAILURE) && off==m.span-4096)) return 0;
    return UINT64_C(0x91000000)+off+(m.scenario==NONCONTIG && off==4096?4096:0);
}
static bool copy(void *ctx,uint64_t kva,const void *data,uint32_t bytes,uint32_t span)
{
    if (ctx!=&m || kva!=m.kva || data!=m.input || bytes!=16635 || span!=20480 || m.page_calls!=5) abort();
    m.copied++;
    memset(m.memory,0,span);memcpy(m.memory,data,bytes);
    return m.scenario!=COPY_FAIL;
}
static bool publish(void *ctx,uint64_t kva,uint32_t bytes,uint32_t span)
{
    if (ctx!=&m || kva!=m.kva || bytes!=16635 || span!=20480 || m.page_calls!=5 || m.copied!=1 || m.released) abort();
    if (memcmp(m.memory,m.input,bytes)) abort();
    for (unsigned i=bytes;i<span;i++) if (m.memory[i]) abort();
    m.published++;
    return m.scenario!=PUBLISH_FAIL;
}
static bool release(void *ctx,uint64_t kva,uint32_t span)
{
    if (ctx!=&m || kva!=m.kva || span!=20480 || m.released) abort();
    m.released++;
    return m.scenario!=CLEANUP_FAIL;
}
static void put32(unsigned char *p,uint32_t v)
{
    for (unsigned i=0;i<4;i++) p[i]=(unsigned char)(v>>(8*i));
}
static void put64(unsigned char *p,uint64_t v)
{
    put32(p,(uint32_t)v);put32(p+4,(uint32_t)(v>>32));
}
static int role_matrix(void)
{
    struct sgpu_launch_options good={.mode=3,.enabled=1,.stock=1,.pixels=1,
        .submit=1,.session=1,.user=1};
    CHECK(sgpu_launch_role(NULL)==SG_LAUNCH_INVALID);
    CHECK(sgpu_launch_role(&good)==SG_LAUNCH_ON);
    uint32_t values[]={0,1,2,3,4,UINT32_MAX};
    const uint32_t approved[11]={3,1,1,1,1,1,1,0,0,0,0};
    for (unsigned field=0;field<11;field++) for (unsigned v=0;v<6;v++) {
        struct sgpu_launch_options o=good;
        memcpy((unsigned char *)&o+field*4,&values[v],4);
        enum sgpu_launch_role expected=field==1 && values[v]==0?SG_LAUNCH_OFF:
            values[v]==approved[field]?SG_LAUNCH_ON:SG_LAUNCH_INVALID;
        CHECK(sgpu_launch_role(&o)==expected);
    }
    struct sgpu_launch_options off={.enabled=0,.mode=1,.zap=1,.scm=1,.cache=2};
    CHECK(sgpu_launch_role(&off)==SG_LAUNCH_OFF);
    return 0;
}

int main(int argc,char **argv)
{
    if (argc!=3) return 2;
    m.scenario=(unsigned)atoi(argv[2]);
    CHECK(m.scenario<COUNT);
    if (m.scenario==ROLE_MATRIX) return role_matrix();
    FILE *f=fopen(argv[1],"rb");CHECK(f!=NULL);
    m.input=malloc(16635);CHECK(m.input!=NULL);
    CHECK(fread(m.input,1,16635,f)==16635);CHECK(fgetc(f)==EOF);fclose(f);
    if (m.scenario==BAD_CPU) put32(m.input+4,0x01000007);
    if (m.scenario==BAD_COMMAND) put32(m.input+32+4,UINT32_MAX);
    if (m.scenario==WRITABLE_TEXT) { put32(m.input+104+56,7);put32(m.input+104+60,7); }
    if (m.scenario==BAD_ENTRY) put64(m.input+328+16+32*8,UINT64_C(0x100004000));
    if (m.scenario==BAD_SIGN) m.input[16384]^=1;
    if (m.scenario==BAD_THREAD) put64(m.input+328+16,1);
    struct sgpu_launch_ops ops={.ctx=&m,.allocate=allocate,.page_pa=page_pa,
        .copy=copy,.publish=publish,.release=release};
    if (m.scenario==MISSING_CALLBACK) ops.publish=NULL;
    struct sgpu_launch_report r={0};
    const void *input=m.scenario==NULL_IMAGE?NULL:m.input;
    uint32_t bytes=m.scenario==SHORT_IMAGE?31:16635;
    bool ok=sgpu_launch_prepare(&ops,input,bytes,&r);
    unsigned expected=m.scenario==NORMAL || m.scenario==REUSE_SUCCESS;
    CHECK(ok==expected);
    if (expected) {
        CHECK(r.ready && r.exposed && r.retained && !r.error && !r.cleanup_error && r.kva==m.kva);
        CHECK(m.allocated==1 && m.page_calls==5 && m.copied==1 && m.published==1 && !m.released);
    } else if (m.scenario>=NULL_IMAGE && m.scenario<=BAD_THREAD) {
        CHECK(r.error==SG_LAUNCH_IMAGE && !m.allocated && !r.exposed && !r.retained);
    } else if (m.scenario==MISSING_CALLBACK) {
        CHECK(r.error==SG_LAUNCH_ARGUMENT && !m.allocated);
    } else if (m.scenario==ALLOC_FAIL || m.scenario==ALLOC_AMBIG) {
        CHECK(r.error==SG_LAUNCH_ALLOC && !m.released && !r.exposed);
        CHECK(r.retained==(m.scenario==ALLOC_AMBIG));
    } else if (m.scenario==BAD_KVA) {
        CHECK(r.error==SG_LAUNCH_ADDRESS && r.retained && !m.released && !m.page_calls);
    } else if (m.scenario==PUBLISH_FAIL) {
        CHECK(r.error==SG_LAUNCH_PUBLISH && r.exposed && r.retained && r.kva==m.kva && !m.released);
    } else {
        CHECK(r.error==(m.scenario==COPY_FAIL?SG_LAUNCH_COPY:SG_LAUNCH_MAPPING));
        CHECK(!r.exposed && m.released==1 && !m.published);
        if (m.scenario==CLEANUP_FAIL) CHECK(r.cleanup_error==SG_LAUNCH_CLEANUP && r.retained && r.kva==m.kva);
        else CHECK(!r.kva && !r.retained && !r.cleanup_error);
    }
    if (m.scenario==MISSING_LAST || m.scenario==CLEANUP_FAIL || m.scenario==REUSE_FAILURE) CHECK(m.page_calls==5);
    if (m.scenario==REUSE_SUCCESS || m.scenario==REUSE_FAILURE) {
        struct sgpu_launch_report saved=r;
        CHECK(!sgpu_launch_prepare(&ops,input,bytes,&r));
        CHECK(saved.kva==r.kva && saved.first_pa==r.first_pa && saved.entry==r.entry &&
            saved.file_bytes==r.file_bytes && saved.span_bytes==r.span_bytes &&
            saved.error==r.error && saved.cleanup_error==r.cleanup_error &&
            saved.exposed==r.exposed && saved.retained==r.retained && saved.ready==r.ready && m.allocated==1);
    }
    free(m.input);
    puts("PASS new launcher CPU contract");
    return 0;
}
