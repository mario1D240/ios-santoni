/* Serialized Mesa/libdrm facade. Tokens are NOT operating-system descriptors. */
#ifndef SANTONI_GRAPHICS_DRM_H
#define SANTONI_GRAPHICS_DRM_H
#include "msm.h"
#ifdef __cplusplus
extern "C" {
#endif
int sgfx_drm_open(void);
/* Select renderer role before the first permanent open. Later default opens
 * share that lease; an already selected administrator lease cannot change. */
int sgfx_drm_open_renderer(void);
int sgfx_drm_open_transport(const struct sgfx_transport *);
int sgfx_drm_dup(int);
int sgfx_drm_close(int);
void *sgfx_drm_bo_map(int,uint64_t,size_t);
void sgfx_drm_bo_unmap(void *,size_t);
bool sgfx_drm_status(int,uint32_t *,uint32_t *);
bool sgfx_ios_connect(struct sgfx_transport *);
bool sgfx_ios_connect_renderer(struct sgfx_transport *);
/* Ephemeral observer: no BO mappings, renderer lease or permanent DRM attempt.
 * Returns 0, -ENODEV (service not registered), or a terminal transport error. */
int sgfx_ios_renderer_status(uint64_t [SGPU_GRAPHICS_RENDERER_STATUS_WORDS]);
/* Bounded CPU-only readiness polling, before any permanent renderer open. */
bool sgfx_ios_renderer_wait(void);
#ifdef __cplusplus
}
#endif
#endif
