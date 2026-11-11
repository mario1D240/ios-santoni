/* Reusable userspace BO/IB transport for SantoniGraphics UAPI v1. */
#ifndef SANTONI_GRAPHICS_CLIENT_H
#define SANTONI_GRAPHICS_CLIENT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "santoni_gpu_graphics_uapi.h"
#define SGFX_READ 1u
#define SGFX_WRITE 2u
struct sgfx_transport {
    void *context;
    bool (*call)(void *,uint32_t,const uint64_t *,uint32_t,uint64_t *,uint32_t,const void *,size_t);
    bool (*map)(void *,uint32_t,uint8_t **,uint64_t *);
    void (*unmap)(void *,uint32_t,uint8_t *);
    void (*close)(void *);
};
struct sgfx_bo {uint32_t handle,gpu_va,bytes,flags;uint8_t *cpu;};
struct sgfx_client {
    struct sgfx_transport transport;
    uint64_t info[10];
    struct sgfx_bo bo[SGPU_GRAPHICS_UAPI_HANDLES];
    uint32_t submitted,completed;
    bool initialized,failed,closed;
};
bool sgfx_init(struct sgfx_client *,const struct sgfx_transport *);
struct sgfx_bo *sgfx_new(struct sgfx_client *,uint32_t,uint32_t);
bool sgfx_free(struct sgfx_client *,uint32_t);
uint32_t sgfx_submit(struct sgfx_client *,const struct sgpu_graphics_wire_ib *,uint32_t,const uint32_t *,uint32_t);
bool sgfx_wait(struct sgfx_client *,uint32_t);
bool sgfx_cpu_prep(struct sgfx_client *,uint32_t);
void sgfx_close(struct sgfx_client *);
#endif
