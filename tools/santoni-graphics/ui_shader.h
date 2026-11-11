#ifndef SANTONI_GRAPHICS_UI_SHADER_H
#define SANTONI_GRAPHICS_UI_SHADER_H
#include <stdint.h>
#define SGFX_UI_SHADER_BYTES (1024u*1024u)
#define SGFX_UI_SHADER_NAME 64u
/* Copy exact GL source extents. A single rectangle sampler is normalized by
 * the draw adapter, including vec3/vec4 projected coordinates. Unsupported
 * rectangle arrays/multiple names are refused.
 * No framebuffer-fetch or blur approximation is manufactured. Caller frees. */
char *sgfx_ui_shader_source(int32_t,const char *const *,const int32_t *,char [SGFX_UI_SHADER_NAME]);
#endif
