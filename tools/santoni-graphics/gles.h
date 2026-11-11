/* Surfaceless Mesa GLES frontend. No EAGL/IOSurface hook is installed. */
#ifndef SANTONI_GRAPHICS_GLES_H
#define SANTONI_GRAPHICS_GLES_H
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct sgfx_gles_context;
struct sgfx_gles_context *sgfx_gles_create(void);
struct sgfx_gles_context *sgfx_gles_create_api(unsigned);
/* Caller holds a live reference to shared during creation. Both ES2/ES3 use
 * Mesa's API_OPENGLES2 profile; children retain the same screen until close. */
struct sgfx_gles_context *sgfx_gles_create_shared_api(unsigned,struct sgfx_gles_context *);
bool sgfx_gles_retain(struct sgfx_gles_context *);
unsigned sgfx_gles_api(const struct sgfx_gles_context *);
bool sgfx_gles_status(const struct sgfx_gles_context *,uint32_t *,uint32_t *);
bool sgfx_gles_current(struct sgfx_gles_context *);
void sgfx_gles_destroy(struct sgfx_gles_context *);
bool sgfx_gles_readback_proof(void);
/* ES2/ES3 startup proof under an already retained renderer lease. Success
 * includes checked cleanup and the same transport still completed/live. */
bool sgfx_gles_ui_readback_proof(int,unsigned);
#ifdef __cplusplus
}
#endif
#endif
