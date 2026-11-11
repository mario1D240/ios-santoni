/* SPDX-License-Identifier: GPL-2.0-only
 * PM4/ME source-fragment oracle from MSM4.9 adreno_pm4types.h/adreno_a5xx.c.
 * Copyright (c) 2014-2016, 2018-2019, The Linux Foundation.
 * Host stubs only; this program never accesses a GPU.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
typedef unsigned int uint;
#define BIT(x) (1u << (x))
#define CP_TYPE7_PKT 0x70000000u
#define ADRENO_REV_A504 504
#define ADRENO_REV_A505 505
#define ADRENO_REV_A506 506
#define ADRENO_REV_A510 510
#define ADRENO_REV_A530 530
#define ADRENO_REV_A540 540
struct adreno_device { int gpurev; };
#define ADRENO_GPUREV(d) ((d)->gpurev)
static bool adreno_is_a530v1(struct adreno_device *d) { (void)d; return false; }
static bool adreno_is_a540v1(struct adreno_device *d) { (void)d; return false; }

static inline uint pm4_calc_odd_parity_bit(uint val)
{
	return (0x9669 >> (0xf & ((val) ^
	((val) >> 4) ^ ((val) >> 8) ^ ((val) >> 12) ^
	((val) >> 16) ^ ((val) >> 20) ^ ((val) >> 24) ^
	((val) >> 28)))) & 1;
}

static inline uint cp_type7_packet(uint opcode, uint cnt)
{
	return CP_TYPE7_PKT | ((cnt) << 0) |
	(pm4_calc_odd_parity_bit(cnt) << 15) |
	(((opcode) & 0x7F) << 16) |
	((pm4_calc_odd_parity_bit(opcode) << 23));
}

static int _me_init_ucode_workarounds(struct adreno_device *adreno_dev)
{
	switch (ADRENO_GPUREV(adreno_dev)) {
	case ADRENO_REV_A510:
		return 0x00000001;
	case ADRENO_REV_A504:
	case ADRENO_REV_A505:
	case ADRENO_REV_A506:
	case ADRENO_REV_A530:
		return 0x0000000B;
	case ADRENO_REV_A540:
		if (adreno_is_a540v1(adreno_dev))
			return 0x0000000A;
	default:
		return 0x00000000;
	}
}

#define CP_INIT_MAX_CONTEXT BIT(0)
#define CP_INIT_ERROR_DETECTION_CONTROL BIT(1)
#define CP_INIT_HEADER_DUMP BIT(2)
#define CP_INIT_DEFAULT_RESET_STATE BIT(3)
#define CP_INIT_DRAWCALL_FILTER_RANGE BIT(4)
#define CP_INIT_UCODE_WORKAROUND_MASK BIT(5)
#define CP_INIT_MASK (CP_INIT_MAX_CONTEXT | \
	CP_INIT_ERROR_DETECTION_CONTROL | \
	CP_INIT_HEADER_DUMP | \
	CP_INIT_DEFAULT_RESET_STATE | \
	CP_INIT_UCODE_WORKAROUND_MASK)

static void _set_ordinals(struct adreno_device *adreno_dev,
		unsigned int *cmds, unsigned int count)
{
	unsigned int *start = cmds;
	*cmds++ = CP_INIT_MASK;
	if (CP_INIT_MASK & CP_INIT_MAX_CONTEXT) {
		if (adreno_is_a530v1(adreno_dev))
			*cmds++ = 0x00000000;
		else
			*cmds++ = 0x00000003;
	}
	if (CP_INIT_MASK & CP_INIT_ERROR_DETECTION_CONTROL)
		*cmds++ = 0x20000000;
	if (CP_INIT_MASK & CP_INIT_HEADER_DUMP) {
		*cmds++ = 0x00000000;
		*cmds++ = 0x00000000;
	}
	if (CP_INIT_MASK & CP_INIT_DRAWCALL_FILTER_RANGE) {
		*cmds++ = 0x00000000;
		*cmds++ = 0x00000000;
	}
	if (CP_INIT_MASK & CP_INIT_UCODE_WORKAROUND_MASK)
		*cmds++ = _me_init_ucode_workarounds(adreno_dev);
	while ((unsigned int)(cmds - start) < count)
		*cmds++ = 0x0;
}

int main(void)
{
	struct adreno_device device = {505}; unsigned cmds[9];
	cmds[0] = cp_type7_packet(0x48, 8); _set_ordinals(&device, cmds + 1, 8);
	for (unsigned i = 0; i < 9; i++) printf("%u\n", cmds[i]);
	return 0;
}
