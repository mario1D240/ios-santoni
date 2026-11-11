#ifndef SANTONI_GRAPHICS_UI_BACKEND_H
#define SANTONI_GRAPHICS_UI_BACKEND_H
#include "ui_context.h"
#include "ui_gl.h"
#include "ui_shader.h"
#include <pthread.h>
/* A bounded userspace texture-unit shadow, never a hardware register count. */
#define SGFX_UI_UNITS 64u
struct sgfx_ui_shader_record {uint32_t name;char sampler[SGFX_UI_SHADER_NAME];};
struct sgfx_ui_program_record {uint32_t name;int32_t scale,sampler;};
struct sgfx_ui_mesa_group {
    pthread_mutex_t lock;
    uint32_t references;
    struct sgfx_gles_context *anchor;
    struct sgfx_ui_shader_record shaders[64];
    struct sgfx_ui_program_record programs[64];
};
struct sgfx_ui_mesa {struct sgfx_ui_gl gl;uint32_t read_fbo;
    uint32_t texture_2d[SGFX_UI_UNITS],texture_rect[SGFX_UI_UNITS];
    struct sgfx_ui_shader_record shaders[64];
    struct sgfx_ui_program_record programs[64];
    struct sgfx_ui_mesa_group *group;};
bool sgfx_ui_mesa_create(unsigned,struct sgfx_ui_backend *);
struct sgfx_ui_mesa_group *sgfx_ui_mesa_group_create(unsigned);
bool sgfx_ui_mesa_group_retain(struct sgfx_ui_mesa_group *);
bool sgfx_ui_mesa_group_release(struct sgfx_ui_mesa_group *);
bool sgfx_ui_mesa_create_in_group(unsigned,struct sgfx_ui_mesa_group *,struct sgfx_ui_backend *);
static inline void sgfx_ui_mesa_meta_lock(struct sgfx_ui_mesa *m)
{if(m->group)pthread_mutex_lock(&m->group->lock);}
static inline void sgfx_ui_mesa_meta_unlock(struct sgfx_ui_mesa *m)
{if(m->group)pthread_mutex_unlock(&m->group->lock);}
static inline struct sgfx_ui_shader_record *sgfx_ui_mesa_shaders(struct sgfx_ui_mesa *m)
{return m->group?m->group->shaders:m->shaders;}
static inline struct sgfx_ui_program_record *sgfx_ui_mesa_programs(struct sgfx_ui_mesa *m)
{return m->group?m->group->programs:m->programs;}
#endif
