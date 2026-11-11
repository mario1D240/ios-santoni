/* HOST-ONLY recorder of actual Mesa-produced BO/command bytes. GPU never runs.
 * It replaces the production command packager ONLY in the capture executable. */
#include "commands.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint32_t captures;
static uint64_t total_bytes;
unsigned sgfx_capture_count(void) {return captures;}
static struct sgfx_bo *find(struct sgfx_client *client,uint32_t handle)
{for(unsigned i=0;i<SGPU_GRAPHICS_UAPI_HANDLES;i++)if(client->bo[i].handle==handle && handle)return &client->bo[i];return NULL;}
uint32_t sgfx_submit_commands(struct sgfx_client *client,const struct sgpu_graphics_wire_ib *roots,uint32_t nr,
    const uint32_t *handles,uint32_t nh,struct sgfx_command_result *result)
{
    if(!result)return 0;memset(result,0,sizeof(*result));result->error=SGFX_CMD_INPUT;
    const char *directory=getenv("SANTONI_CAPTURE_DIR");
    if(!directory || !client || !client->initialized || client->failed || client->closed ||
        !roots || !handles || !nr || nr>SGPU_GRAPHICS_UAPI_IBS || !nh || nh>SGPU_GRAPHICS_UAPI_HANDLES ||
        captures==512 || client->submitted==UINT32_MAX)return 0;
    uint64_t bytes=0;
    for(unsigned i=0;i<nh;i++) {
        struct sgfx_bo *b=find(client,handles[i]);if(!b || !b->cpu)return 0;
        for(unsigned j=0;j<i;j++)if(handles[i]==handles[j])return 0;
        bytes+=b->bytes;
    }
    if(bytes>128u*1024u*1024u || total_bytes+bytes>256u*1024u*1024u)return 0;
    for(unsigned i=0;i<nr;i++) {
        struct sgfx_bo *b=find(client,roots[i].handle);bool listed=false;
        for(unsigned j=0;j<nh;j++)if(roots[i].handle==handles[j])listed=true;
        if(!b || !listed || !roots[i].bytes || ((roots[i].offset|roots[i].bytes)&3) ||
            roots[i].offset>b->bytes || roots[i].bytes>b->bytes-roots[i].offset)return 0;
    }
    char filename[4096];int n=snprintf(filename,sizeof(filename),"%s/submit-%04u.bin",directory,captures);
    if(n<0 || (size_t)n>=sizeof(filename))return 0;
    FILE *file=fopen(filename,"wx");if(!file)return 0;
    /* All supported hosts are little endian. Magic SGCP/version1 explicitly
     * marks synthetic VA/admission/fence responses; no physical PA is stored. */
    uint32_t header[8]={0x50434753u,1,nh,nr,client->submitted+1,0,505,0};
    bool ok=fwrite(header,sizeof(header),1,file)==1 && fwrite(roots,sizeof(*roots),nr,file)==nr;
    for(unsigned i=0;i<nh && ok;i++) {
        struct sgfx_bo *b=find(client,handles[i]);uint32_t metadata[4]={b->handle,b->gpu_va,b->bytes,b->flags};
        ok=fwrite(metadata,sizeof(metadata),1,file)==1 && fwrite(b->cpu,1,b->bytes,file)==b->bytes;
    }
    if(fclose(file))ok=false;
    if(!ok) {client->failed=true;result->error=SGFX_CMD_IO;return 0;}
    total_bytes+=bytes;captures++;client->submitted++;client->completed=client->submitted;
    result->error=0;result->command_buffers=nh;result->roots=nr;result->sequence=client->submitted;
    result->submitted=result->completed=true; /* Capturer's modeled state ONLY. */
    return client->submitted;
}
