/* Package Mesa's separate nested command BOs for the v1 private-IB transport. */
#ifndef SANTONI_GRAPHICS_COMMANDS_H
#define SANTONI_GRAPHICS_COMMANDS_H
#include "client.h"
enum sgfx_command_error { SGFX_CMD_OK,SGFX_CMD_INPUT,SGFX_CMD_LIMIT,SGFX_CMD_PACKET,
    SGFX_CMD_ADDRESS,SGFX_CMD_CYCLE,SGFX_CMD_MEMORY,SGFX_CMD_IO };
struct sgfx_command_result {
    uint32_t sequence,error,command_buffers,roots;
    bool submitted,completed;
};
/* Synchronous, bounded by the existing kernel wait. Whole command and VS/FS
 * shader/constant BOs are copied once; indirect/draw-state/LOAD_STATE4 and
 * shader-object pointers are relocated. Extra BOs use a disjoint NOP root
 * (appended when fully occupied), preserving code and data. Kernel validation
 * remains authoritative; shader/texture/raster admission is still required. */
uint32_t sgfx_submit_commands(struct sgfx_client *,const struct sgpu_graphics_wire_ib *,uint32_t,
    const uint32_t *,uint32_t,struct sgfx_command_result *);
#endif
