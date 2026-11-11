/* The changed getter compiled for an ordinary SWEET board keeps its old policy. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#define CS_SIGNED 0x20000000u
#define CS_PLATFORM_BINARY 0x04000000u
struct cs_blob { int csb_platform_binary; };
struct vnode { struct cs_blob *blob; };
struct proc { struct vnode *p_textvp; int64_t p_textoff; uint32_t flags; };
uint32_t santoni_remoted_platform = 1;
static uint32_t proc_getcsflags(struct proc *p) { return p->flags; }
static struct cs_blob *ubc_cs_blob_get(struct vnode *vp, int a, int b, int64_t off)
{ assert(a == -1 && b == -1 && off == 0); return vp->blob; }
#include "santoni_remoted_platform_other_actual.h"
int main(void)
{
    struct cs_blob blob = { 0 };
    struct vnode vp = { &blob };
    struct proc p = { &vp, 0, CS_SIGNED | CS_PLATFORM_BINARY };
    assert(csproc_get_platform_binary(&p) == 0);
    puts("PASS other/process_flag_does_not_change_policy");
    blob.csb_platform_binary = 1;
    assert(csproc_get_platform_binary(&p) == 1);
    puts("PASS other/original_platform_blob");
    p.flags = CS_PLATFORM_BINARY;
    assert(csproc_get_platform_binary(&p) == 0);
    puts("PASS other/unsigned_process_refused");
    p.flags = CS_SIGNED;
    vp.blob = NULL;
    assert(csproc_get_platform_binary(&p) == 0);
    puts("PASS other/missing_blob_refused");
    p.p_textvp = NULL;
    assert(csproc_get_platform_binary(&p) == 0);
    puts("PASS other/missing_text_refused");
    assert(csproc_get_platform_binary(NULL) == 0);
    puts("PASS other/null_process_refused");
    return 0;
}
