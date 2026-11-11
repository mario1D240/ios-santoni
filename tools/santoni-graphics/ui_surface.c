#include "ui_surface.h"
#include <stdlib.h>
#include <string.h>
bool sgfx_ui_surface_valid(const struct sgfx_ui_surface *s,size_t *packed_bytes)
{
    if(!s || !packed_bytes || !s->base || !s->width || !s->height ||
        s->format!=SGFX_UI_BGRA || s->width>4096 || s->height>4096 ||
        s->stride<s->width*4 || (s->stride&3) || s->offset>s->allocation_bytes ||
        s->height>SGFX_UI_MAX_BYTES/s->stride)return false;
    size_t span=(size_t)s->stride*s->height;
    if(span>s->allocation_bytes-s->offset ||
        (uintptr_t)s->base>UINTPTR_MAX-s->allocation_bytes)return false;
    *packed_bytes=(size_t)s->width*s->height*4;return true;
}
static bool transfer_ops(const struct sgfx_ui_transfer_ops *ops,bool read)
{
    return ops && ops->fence_status && (read?ops->finish && ops->read_rgba:ops->upload_rgba!=NULL);
}
static bool completed_fence(const struct sgfx_ui_transfer_ops *ops,uint32_t *sequence)
{
    uint32_t submitted=0,completed=0;
    if(!ops->fence_status(ops->context,&submitted,&completed) || submitted!=completed)return false;
    *sequence=submitted;return true;
}
bool sgfx_ui_upload(const struct sgfx_ui_transfer_ops *ops,const struct sgfx_ui_surface *surface)
{
    size_t size=0;
    if(!transfer_ops(ops,false) || !sgfx_ui_surface_valid(surface,&size))return false;
    struct sgfx_ui_surface s=*surface;uint32_t sequence;
    if(!completed_fence(ops,&sequence))return false;
    uint8_t *pixels=malloc(size);if(!pixels)return false;
    for(unsigned y=0;y<s.height;y++) {
        unsigned row=s.flip_y?s.height-1-y:y;
        const uint8_t *source=s.base+s.offset+(size_t)row*s.stride;
        uint8_t *dest=pixels+(size_t)y*s.width*4;
        for(unsigned x=0;x<s.width;x++,source+=4,dest+=4) {
            dest[0]=source[2];dest[1]=source[1];dest[2]=source[0];dest[3]=source[3];
        }
    }
    bool ok=ops->upload_rgba(ops->context,s.width,s.height,pixels);
    free(pixels);return ok;
}
bool sgfx_ui_commit(const struct sgfx_ui_transfer_ops *ops,const struct sgfx_ui_surface *surface,uint32_t *sequence)
{
    size_t size=0;
    if(!sequence || !transfer_ops(ops,true) || !sgfx_ui_surface_valid(surface,&size))return false;
    struct sgfx_ui_surface s=*surface;uint32_t before=0,prior_completed=0,finished=0,after=0;
    if(!ops->fence_status(ops->context,&before,&prior_completed) || prior_completed>before ||
        !ops->finish(ops->context) ||
        !completed_fence(ops,&finished) || finished<before)return false;
    uint8_t *pixels=malloc(size);if(!pixels)return false;
    bool ok=ops->read_rgba(ops->context,s.width,s.height,pixels) &&
        completed_fence(ops,&after) && after>=finished && after!=0;
    if(ok) {
        for(unsigned y=0;y<s.height;y++) {
            unsigned row=s.flip_y?s.height-1-y:y;
            const uint8_t *source=pixels+(size_t)y*s.width*4;
            uint8_t *dest=s.base+s.offset+(size_t)row*s.stride;
            for(unsigned x=0;x<s.width;x++,source+=4,dest+=4) {
                dest[0]=source[2];dest[1]=source[1];dest[2]=source[0];dest[3]=source[3];
            }
        }
        *sequence=after;
    }
    free(pixels);return ok;
}
