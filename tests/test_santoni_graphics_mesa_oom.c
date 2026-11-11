/* Actual save_Attr64bit body; allocation/GL-dispatch primitives are modeled. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned GLenum;
typedef double GLdouble;
union uint64_pair {uint64_t uint64;uint32_t uint32[2];};
typedef union {uint32_t ui;} Node;
enum {GL_DOUBLE=1,OPCODE_ATTR_1D=100,OPCODE_ATTR_1UI64=200,VERT_ATTRIB_GENERIC0=16};
struct gl_context {
    struct {unsigned ActiveAttribSize[32];uint32_t CurrentAttrib[32][8];} ListState;
    void *Dispatch_Exec;
    bool ExecuteFlag;
};
static struct gl_context context;
static Node nodes[16];
static unsigned allocation_count,flush_count,dispatch_count,error_count,wanted_size,wanted_type,wanted_index;
static bool fail_allocation;
static uint64_t input[4]={UINT64_C(0x7ff8000012345678),UINT64_C(0x8000000000000000),
    UINT64_C(0xfff0123476543210),UINT64_C(0x0000000000000042)};
#define SAVE_FLUSH_VERTICES(ctx) do {assert((ctx)==&context);flush_count++;} while(0)
#include "assign-nodes.h"
static Node *alloc_instruction(struct gl_context *ctx,unsigned opcode,unsigned length)
{
    allocation_count++;assert(ctx==&context);
    assert(opcode==(wanted_type==GL_DOUBLE?OPCODE_ATTR_1D:OPCODE_ATTR_1UI64)+wanted_size-1);
    assert(length==1+wanted_size*2);
    if(fail_allocation){error_count++;return NULL;}
    return nodes;
}
static double as_double(uint64_t bits){union {uint64_t u;double d;} v={.u=bits};return v.d;}
#define UINT64_AS_DOUBLE(value) as_double(value)
static void dispatched(unsigned size,unsigned attr,const void *values)
{dispatch_count++;assert(size==wanted_size && attr==wanted_index-VERT_ATTRIB_GENERIC0);assert(!memcmp(values,input,size*sizeof(uint64_t)));}
#define CALL_VertexAttribL4dv(ctx,args) dispatched4 args
#define CALL_VertexAttribL3dv(ctx,args) dispatched3 args
#define CALL_VertexAttribL2dv(ctx,args) dispatched2 args
#define CALL_VertexAttribL1d(ctx,args) dispatched1 args
#define CALL_VertexAttribL1ui64ARB(ctx,args) dispatched_u64 args
static void dispatched4(unsigned attr,const double *v){dispatched(4,attr,v);}
static void dispatched3(unsigned attr,const double *v){dispatched(3,attr,v);}
static void dispatched2(unsigned attr,const double *v){dispatched(2,attr,v);}
static void dispatched1(unsigned attr,double value){dispatched(1,attr,&value);}
static void dispatched_u64(unsigned attr,uint64_t value){dispatched(1,attr,&value);}
#define ALWAYS_INLINE __attribute__((always_inline)) inline
#include "function.h"
int main(int argc,char **argv)
{
    assert(argc==2);unsigned test=(unsigned)strtoul(argv[1],NULL,10);assert(test<40);
    unsigned kind=test/8;wanted_size=kind==4?1:kind+1;wanted_type=kind==4?2:GL_DOUBLE;
    fail_allocation=(test&1)!=0;context.ExecuteFlag=(test&2)!=0;wanted_index=(test&4)?31:18;
    memset(nodes,0xa7,sizeof(nodes));memset(&context.ListState,0x5b,sizeof(context.ListState));
    struct gl_context before=context;
    save_Attr64bit(&context,wanted_index,wanted_size,wanted_type,input[0],input[1],input[2],input[3]);
    assert(flush_count==1 && allocation_count==1 && error_count==(unsigned)fail_allocation);
    assert(dispatch_count==(unsigned)context.ExecuteFlag);
    assert(context.ListState.ActiveAttribSize[wanted_index]==wanted_size);
    assert(!memcmp(context.ListState.CurrentAttrib[wanted_index],input,wanted_size*sizeof(uint64_t)));
    memcpy(before.ListState.CurrentAttrib[wanted_index],input,wanted_size*sizeof(uint64_t));
    before.ListState.ActiveAttribSize[wanted_index]=wanted_size;
    assert(!memcmp(&before.ListState,&context.ListState,sizeof(before.ListState)));
    if(!fail_allocation){assert(nodes[1].ui==wanted_index-VERT_ATTRIB_GENERIC0);assert(!memcmp(&nodes[2],input,wanted_size*sizeof(uint64_t)));}
    printf("PASS actual attr64 case=%u size=%u alloc_failed=%u; GL/allocation modeled\n",test,wanted_size,fail_allocation);
    return 0;
}
