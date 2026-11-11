/* Test-only source-fragment oracle from ios-sailfish 6f27e41ff249f2680540ebe8ee5ab982c5e641c9.
 * Actual emit_blit and PM4 header bodies, with only the two highest-bank-bit
 * values retargeted AFTER generation. No GPU or kernel primitives are called.
 */
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include "santoni_gpu_core.h"
#define R_UCHE_CACHE_INVALIDATE_MIN 0x0e91
#define R_RB_RENDER_CNTL 0xe141
#define R_RB_2D_BLIT_CNTL 0x2100
#define R_GRAS_2D_BLIT_CNTL 0x2180
#define R_UNKNOWN_2184 0x2184
#define R_RB_CNTL 0xe140
#define R_RB_MODE_CNTL 0xcc6
#define R_SP_MODE_CNTL 0xec2
#define R_TPL1_MODE_CNTL 0xf02
#define R_HLSQ_MODE_CNTL 0xe06
#define R_GRAS_CL_CNTL 0xe000
#define R_RB_2D_SRC_INFO 0x2107
#define R_RB_2D_DST_INFO 0x2110
#define R_GRAS_2D_SRC_INFO 0x2181
#define R_GRAS_2D_DST_INFO 0x2182
#define CP_WAIT_FOR_IDLE 0x26
#define CP_SET_RENDER_MODE 0x6c
#define CP_BLIT 0x2c
#define CP_EVENT_WRITE 0x46
#define BLIT_OP_SCALE 3
#define BLIT2D 5
#define BLIT2DSCALE 7
#define END2D 8
#define PC_CCU_FLUSH_COLOR_TS 0x1d
#define CACHE_FLUSH_TS 4
static uint32_t reference[128], rb_n;

static uint32_t parity(uint32_t v)
{
    return (0x9669u >> (0xfu & (v ^ (v >> 4) ^ (v >> 8) ^ (v >> 12) ^ (v >> 16) ^
           (v >> 20) ^ (v >> 24) ^ (v >> 28)))) & 1u;
}
static uint32_t pkt7(uint32_t op, uint32_t cnt)
{
    return (7u << 28) | cnt | (parity(cnt) << 15) | ((op & 0x7fu) << 16) | (parity(op) << 23);
}
static uint32_t pkt4(uint32_t reg, uint32_t cnt)
{
    return (4u << 28) | cnt | (parity(cnt) << 7) | ((reg & 0x3ffffu) << 8) | (parity(reg) << 27);
}
static void emit(uint32_t v)
{
    assert(rb_n < 128);
    reference[rb_n++] = v;
}

static void
emit_blit(uint32_t op, uint32_t sfmt, uint64_t src, uint32_t spitch, uint32_t sw, uint32_t sh,
    uint32_t dfmt, uint64_t dst, uint32_t dpitch, uint32_t dw, uint32_t dh, uint64_t fence, uint32_t seq)
{
	emit(pkt4(R_UCHE_CACHE_INVALIDATE_MIN, 5));
	emit(0); emit(0); emit(0); emit(0);
	emit(0x12);
	emit(pkt7(CP_WAIT_FOR_IDLE, 0));
	emit(pkt4(R_RB_RENDER_CNTL, 1)); emit(0x8);
	emit(pkt4(R_RB_2D_BLIT_CNTL, 1)); emit(0x86000000);
	emit(pkt4(R_GRAS_2D_BLIT_CNTL, 1)); emit(0x86000000);
	emit(pkt4(R_UNKNOWN_2184, 1)); emit(0x9);
	emit(pkt4(R_RB_CNTL, 1)); emit(1u << 17);
	emit(pkt4(R_RB_MODE_CNTL, 1)); emit(0x4);
	emit(pkt4(R_SP_MODE_CNTL, 1)); emit(0xc);
	emit(pkt4(R_TPL1_MODE_CNTL, 1)); emit(0x344);
	emit(pkt4(R_HLSQ_MODE_CNTL, 1)); emit(0x2);
	emit(pkt4(R_GRAS_CL_CNTL, 1)); emit(0x181);
	emit(pkt7(CP_SET_RENDER_MODE, 1)); emit(op == BLIT_OP_SCALE ? BLIT2DSCALE : BLIT2D);
	emit(pkt4(R_RB_2D_SRC_INFO, 9));
	emit(sfmt);
	emit((uint32_t)src); emit((uint32_t)(src >> 32));
	emit((spitch >> 6) | (((spitch * sh) >> 6) << 16));
	emit(0); emit(0); emit(0); emit(0); emit(0);
	emit(pkt4(R_GRAS_2D_SRC_INFO, 1)); emit(sfmt);
	emit(pkt4(R_RB_2D_DST_INFO, 9));
	emit(dfmt);
	emit((uint32_t)dst); emit((uint32_t)(dst >> 32));
	emit((dpitch >> 6) | (((dpitch * dh) >> 6) << 16));
	emit(0); emit(0); emit(0); emit(0); emit(0);
	emit(pkt4(R_GRAS_2D_DST_INFO, 1)); emit(dfmt);
	emit(pkt7(CP_BLIT, 5));
	emit(op);
	emit(0);
	emit((sw - 1) | ((sh - 1) << 16));
	emit(0);
	emit((dw - 1) | ((dh - 1) << 16));
	emit(pkt7(CP_SET_RENDER_MODE, 1)); emit(END2D);
	emit(pkt7(CP_WAIT_FOR_IDLE, 0));
	emit(pkt7(CP_EVENT_WRITE, 4)); emit(PC_CCU_FLUSH_COLOR_TS);
	emit((uint32_t)fence); emit((uint32_t)(fence >> 32)); emit(0);
	emit(pkt7(CP_EVENT_WRITE, 4)); emit(CACHE_FLUSH_TS);
	emit((uint32_t)fence); emit((uint32_t)(fence >> 32)); emit(seq);
	emit(pkt7(CP_WAIT_FOR_IDLE, 0));
}

int main(void)
{
    uint32_t actual[128];
    emit_blit(1,0x30,SGPU_SOURCE_VA,64,16,16,0x30,SGPU_DEST_VA,64,16,16,
        SGPU_MARKER_VA+768,0xa5052d01);
    for(unsigned i=0;i<rb_n;) {
        uint32_t h=reference[i++];
        unsigned count=(h>>28)==4 ? h&127 : h&0x3fff;
        if((h>>28)==4) {
            unsigned reg=(h>>8)&0x3ffff;
            if(reg==R_RB_MODE_CNTL) reference[i]=2;
            if(reg==R_TPL1_MODE_CNTL) reference[i]=0x2c4;
        }
        i+=count;
    }
    unsigned count=sgpu_blit_commands(actual,128,SGPU_MARKER_VA+768);
    assert(count==rb_n);
    for(unsigned i=0;i<count;i++) {
        if(actual[i]!=reference[i]) {
            fprintf(stderr,"word %u: actual %08x reference %08x\n",i,actual[i],reference[i]);
            return 1;
        }
    }
    printf("PASS %u A5xx offscreen-blit words match the independent source-fragment oracle\n",count);
    return 0;
}
