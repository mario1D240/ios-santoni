#ifndef SANTONI_GRAPHICS_UI_GL_H
#define SANTONI_GRAPHICS_UI_GL_H
#include "gles.h"
#include "ui_surface.h"
struct sgfx_ui_gl {
    struct sgfx_gles_context *gles;
    uint32_t first_error;
    uint32_t first_framebuffer_status;
    bool failed;
};
/* The caller binds its target FBO or source texture before transfer. */
bool sgfx_ui_gl_ops(struct sgfx_ui_gl *,struct sgfx_ui_transfer_ops *);
#endif
