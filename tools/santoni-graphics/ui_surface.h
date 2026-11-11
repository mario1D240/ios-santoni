/* CPU IOSurface transfer around real Mesa rendering. No external surface is
 * mapped for GPU DMA: the GLES backend owns its separate texture/target BOs. */
#ifndef SANTONI_GRAPHICS_UI_SURFACE_H
#define SANTONI_GRAPHICS_UI_SURFACE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define SGFX_UI_BGRA 0x42475241u
#define SGFX_UI_MAX_BYTES (16u*1024u*1024u)
struct sgfx_ui_surface {
    uint8_t *base;
    size_t allocation_bytes,offset;
    uint32_t width,height,stride,format;
    bool flip_y;
};
struct sgfx_ui_transfer_ops {
    void *context;
    /* upload must copy client bytes before returning (GLES client-memory
     * semantics, unpack PBO disabled). Client memory is never GPU-mapped. */
    bool (*upload_rgba)(void *,uint32_t,uint32_t,const uint8_t *);
    bool (*finish)(void *);
    /* readback is synchronous client memory, with pack PBO/row state reset. */
    bool (*read_rgba)(void *,uint32_t,uint32_t,uint8_t *);
    bool (*fence_status)(void *,uint32_t *,uint32_t *);
};
bool sgfx_ui_surface_valid(const struct sgfx_ui_surface *,size_t *);
bool sgfx_ui_upload(const struct sgfx_ui_transfer_ops *,const struct sgfx_ui_surface *);
/* Destination bytes change only after finish, readback and the post-readback
 * fence agree. Successful completion is a transfer result, not hardware proof. */
bool sgfx_ui_commit(const struct sgfx_ui_transfer_ops *,const struct sgfx_ui_surface *,uint32_t *);
#endif
