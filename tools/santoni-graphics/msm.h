/* Mesa25.0.7 msm UAPI translation. The caller serializes access to the client. */
#ifndef SANTONI_GRAPHICS_MSM_H
#define SANTONI_GRAPHICS_MSM_H
#include "commands.h"
bool sgfx_msm_render_ready(const struct sgfx_client *);
int sgfx_msm_command(struct sgfx_client *,unsigned long,void *,size_t);
int sgfx_msm_gem_close(struct sgfx_client *,uint32_t);
void *sgfx_msm_map(struct sgfx_client *,uint64_t);
#endif
