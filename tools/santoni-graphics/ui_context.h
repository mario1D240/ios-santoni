/* Owned, thread-bound EAGL macro contexts and synchronous IOSurface transfers.
 * All surface bytes stay CPU memory; Mesa owns separate texture/render BOs. */
#ifndef SANTONI_GRAPHICS_UI_CONTEXT_H
#define SANTONI_GRAPHICS_UI_CONTEXT_H
#include "ui_surface.h"
#define SGFX_UI_SLOTS 1036u
#define SGFX_UI_CONTEXTS 32u
#define SGFX_UI_TEXTURES 64u
struct sgfx_ui_context;
struct sgfx_ui_group;
struct sgfx_ui_macro {void *context;void *dispatch[SGFX_UI_SLOTS];};
struct sgfx_ui_surface_ops {
    void (*retain)(void *);
    void (*release)(void *);
    bool (*lock)(void *,bool,struct sgfx_ui_surface *,uint32_t *);
    bool (*unlock)(void *,bool,uint32_t *);
};
struct sgfx_ui_backend {
    void *context;
    bool (*current)(void *,bool);
    void (*destroy)(void *);
    /* Select an owned texture for upload/readback, restoring the caller's
     * texture/read-framebuffer state even on a failed transfer. */
    bool (*select)(void *,uint32_t,bool,uint32_t *);
    bool (*restore)(void *,uint32_t,bool);
    struct sgfx_ui_transfer_ops transfer;
};
enum sgfx_ui_failure { SGFX_UI_OK,SGFX_UI_BIND,SGFX_UI_SURFACE,SGFX_UI_CAPACITY,
    SGFX_UI_TRANSFER,SGFX_UI_UNSUPPORTED };
struct sgfx_ui_report {unsigned first_failure;uint32_t first_slot,frames,sequence;
    bool live,restore_failed,unlock_failed;uint32_t group_failure,group_slot;};
struct sgfx_ui_context *sgfx_ui_context_create(void *,unsigned,const struct sgfx_ui_backend *,
    const struct sgfx_ui_surface_ops *,void *const *);
struct sgfx_ui_group *sgfx_ui_group_create(const struct sgfx_ui_surface_ops *);
bool sgfx_ui_group_retain(struct sgfx_ui_group *);
bool sgfx_ui_group_release(struct sgfx_ui_group *);
struct sgfx_ui_context *sgfx_ui_context_create_in_group(void *,unsigned,
    const struct sgfx_ui_backend *,struct sgfx_ui_group *,void *const *);
struct sgfx_ui_context *sgfx_ui_context_lookup(void *);
struct sgfx_ui_macro *sgfx_ui_context_macro(struct sgfx_ui_context *);
unsigned sgfx_ui_context_api(struct sgfx_ui_context *);
bool sgfx_ui_context_bind(struct sgfx_ui_context *);
bool sgfx_ui_context_destroy(struct sgfx_ui_context *);
void *sgfx_ui_context_current(void);
void *sgfx_ui_context_backend(struct sgfx_ui_context *);
bool sgfx_ui_context_report(struct sgfx_ui_context *,struct sgfx_ui_report *);
bool sgfx_ui_context_fail(struct sgfx_ui_context *,unsigned,uint32_t);
bool sgfx_ui_context_attach(struct sgfx_ui_context *,uint32_t,void *,bool);
bool sgfx_ui_context_refresh(struct sgfx_ui_context *,uint32_t);
bool sgfx_ui_context_dirty(struct sgfx_ui_context *,uint32_t);
bool sgfx_ui_context_flush(struct sgfx_ui_context *);
bool sgfx_ui_context_forget(struct sgfx_ui_context *,uint32_t);
#endif
