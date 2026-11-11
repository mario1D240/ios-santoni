#!/bin/bash
# Host tests + patch validation for the Santoni bring-up.
#
# Called by shim/build.sh and the xnu workflow: storage/log host tests,
# executable tests of the reconstructed SMP/input/display drivers, and patch checks.
# Everything here is host-only: no device or external XNU checkout required.
#
#   tests/run_tests.sh            # normal run, binaries in out/
#   OUT_DIR=/tmp/t tests/run_tests.sh
#
# Exit status is non-zero if a test fails, a patch has a malformed hunk, or a
# requirement asserted below is missing from the code that the patch ships.
set -euo pipefail

cd "$(dirname "$0")/.."

python3 tools/verify_santoni_gpu_graphics_evidence.py graphics tests/santoni_gpu_graphics_host_evidence.json
python3 tools/verify_santoni_gpu_graphics_evidence.py pm4 tests/santoni_gpu_pm4_host_evidence.json
python3 tools/verify_santoni_gpu_graphics_evidence.py bridge tests/santoni_gpu_graphics_bridge_host_evidence.json
python3 tools/verify_santoni_gpu_graphics_evidence.py publish tests/santoni_gpu_graphics_publish_host_evidence.json
python3 tools/verify_santoni_gpu_graphics_evidence.py publish-mutants tests/santoni_gpu_graphics_publish_mutants_host_evidence.json
python3 tools/verify_santoni_gpu_raster_evidence.py ir3 tests/santoni_gpu_ir3_host_evidence.json
python3 tools/verify_santoni_gpu_raster_evidence.py raster tests/santoni_gpu_raster_host_evidence.json
python3 tools/verify_santoni_gpu_live_evidence.py tests/santoni_gpu_live_host_evidence.json
python3 tools/verify_santoni_gpu_render_evidence.py tests/santoni_gpu_render_host_evidence.json
python3 -m unittest tests.test_native_santoni_gpu_core tests.test_santoni_gpu_raster_evidence tests.test_santoni_gpu_native_vm_evidence
python3 -m unittest tests.test_santoni_gpu_graphics_gates
python3 -m unittest tests.test_santoni_graphics_build_policy
python3 -m unittest tests.test_santoni_graphics_loader_build tests.test_santoni_ui_loader_binding tests.test_santoni_graphics_startup
python3 -m unittest tests.test_santoni_gpu_dyld tests.test_santoni_gpu_dyld_audit tests.test_santoni_gpu_ui_launch
python3 -m unittest tests.test_santoni_gpu_dyld_startup
python3 -m unittest tests.test_santoni_graphics_library tests.test_santoni_graphics_terminal
python3 -m unittest tests.test_santoni_graphics_mesa_oom
python3 -m unittest tests.test_santoni_graphics_mesa_terminal
python3 -m unittest tests.test_santoni_graphics_gles tests.test_santoni_graphics_gles_sharing
python3 -m unittest tests.test_santoni_graphics_ui_context tests.test_santoni_graphics_ui_groups
python3 -m unittest tests.test_santoni_graphics_ui_backend tests.test_santoni_graphics_ui_backend_groups
python3 -m unittest tests.test_santoni_graphics_dispatch tests.test_santoni_graphics_ui_dispatch tests.test_santoni_graphics_ui_dispatch_shared tests.test_santoni_graphics_ui_shader
python3 -m unittest tests.test_santoni_graphics_eagl tests.test_santoni_graphics_eagl_groups
python3 -m unittest tests.test_santoni_graphics_capture tests.test_santoni_graphics_capture_inspect tests.test_santoni_graphics_capture_ui

python3 tools/verify_santoni_gpu_ui_evidence.py tests/santoni_gpu_ui_host_evidence.json
python3 -m unittest tests.test_santoni_gpu_ui_gates
python3 -m unittest tests.test_santoni_gpu_ui_binary
python3 -m unittest tests.test_santoni_gpu_render_audit
python3 -m unittest tests.test_santoni_gpu_session_composition tests.test_santoni_gpu_exclusion_scopes tests.test_santoni_gpu_session_entry_replay

python3 -m unittest tests.test_santoni_gpu_live
python3 -m unittest tests.test_santoni_gpu_render

python3 -m unittest tests.test_santoni_gpu_readiness
python3 tools/verify_santoni_gpu_readiness_evidence.py tests/santoni_gpu_readiness_host_evidence.json

echo "== rootfs: extension setup and preserved migration state =="
python3 -m unittest tests.test_sweet_root_tweaks

echo "== SANTONI: exact recorded PID1 user-fault observation contracts =="
python3 -m unittest tests.test_santoni_gpu_user_fault_evidence
python3 -m unittest tests.test_santoni_gpu_user_fault_binary
python3 tools/verify_santoni_gpu_user_fault_evidence.py tests/santoni_gpu_user_fault_host_evidence.json

CC="${HOST_CC:-${CC:-clang}}"
OUT="${OUT_DIR:-out}"
mkdir -p "$OUT"

P142="xnu/patches/0142-santoni-sdhci-emmc-driver.patch"
P143="xnu/patches/0143-santoni-persistent-console-log.patch"
P144="xnu/patches/0144-santoni-4k-unsigned-dyld-cache.patch"
P149="xnu/patches/0149-santoni-varfix.patch"

echo "== host unit tests (-Wall -Wextra) =="
for t in test_sdhci_mock test_gpt_parser test_log_ring; do
	"$CC" -O2 -Wall -Wextra -I. "tests/$t.c" -o "$OUT/$t"
	case "$OUT" in
		/*) "$OUT/$t" ;;
		*)  "./$OUT/$t" ;;
	esac
done

echo "== SANTONI: executable touch/buttons/RPM contracts from the actual patch chain =="
python3 tests/test_santoni_touch.py --cc "$CC" --out-dir "$OUT/santoni-touch"

echo "== SANTONI: actual HID timer and panel conversion =="
python3 tests/test_santoni_ui.py --out-dir "$OUT/santoni-ui"

echo "== SANTONI: actual GICv2 routing, private IRQ banks and IPI ordering =="
python3 tests/test_santoni_smp.py

echo "== SANTONI: actual EL1/EL2 secondary entry and CPU_ON handoff =="
python3 tests/test_santoni_secondary.py

echo "== SANTONI: actual startup/reset publication with separate cache/PoC views =="
python3 tests/test_santoni_startup_publication.py

echo "== SANTONI: iOS resolver config and read-only per-CPU performance probe =="
python3 tests/test_santoni_performance.py

echo "== SANTONI: vendor A505 target, command packets and firmware preparation =="
python3 tests/test_santoni_gpu_prepare.py

echo "== SANTONI: actual guarded A505 kernel core, cache/DMA and offscreen tests =="
python3 tests/test_santoni_gpu_driver.py
python3 -m unittest tests.test_santoni_gpu_stock
python3 -m unittest tests.test_santoni_gpu_pixels
python3 -m unittest tests.test_santoni_gpu_g3
python3 -m unittest tests.test_santoni_gpu_session
python3 -m unittest tests.test_santoni_gpu_user
python3 tests/test_santoni_gpu_pas_cache.py

echo "== SANTONI: GPU hardware-delivery and actual-binary audit rejection gates =="
python3 tests/test_santoni_gpu_boot_gates.py
python3 tests/test_santoni_gpu_kernel_audit.py
python3 -m unittest tests.test_santoni_gpu_stock_audit
python3 -m unittest tests.test_santoni_gpu_pixel_audit
python3 -m unittest tests.test_santoni_gpu_g3_audit
python3 -m unittest tests.test_santoni_gpu_session_gates
python3 -m unittest tests.test_santoni_gpu_user_gates
python3 -m unittest tests.test_santoni_gpu_session_audit
python3 -m unittest tests.test_santoni_gpu_control_audit
python3 -m unittest tests.test_santoni_gpu_binary_model
python3 -m unittest tests.test_santoni_gpu_session_replay

echo "== SANTONI: coherent WFI idle cache policy =="
python3 tests/test_santoni_idle.py

echo "== persistent log extraction (fake ADB only) =="
python3 tests/test_sweet_log_pull.py

echo "== CI artifact fallback (fake curl only) =="
python3 -m unittest tests.test_gofile_upload

echo "== unified diff structure (all xnu/patches) =="
python3 tools/check_patch.py xnu/patches/*.patch > "$OUT/check_patch.log"
tail -3 "$OUT/check_patch.log"

echo "== STOR-03: GPT CRC32 + SYSTEM parse + fenced log writes (0142) =="
python3 tools/check_patch.py "$P142" -q \
	--added-contains 'bsd/dev/santoni_sdhci.c:0xEDB88320u' \
	--added-contains 'bsd/dev/santoni_sdhci.c:santoni_crc32(hdr_raw, hdr.header_size)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:santoni_crc32(b, entry_bytes)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:uint64_t sys_first_block, sys_nblocks;' \
	--added-contains 'bsd/dev/santoni_sdhci.c:strcmp(name, "system")' \
	--added-contains 'bsd/dev/santoni_sdhci.c:SANTONI_LOG_SYSTEM_BLOCKS 8193u' \
	--added-contains 'bsd/dev/santoni_sdhci.c:int santoni_sdhci_write_log_blocks(' \
	--added-contains 'bsd/dev/santoni_sdhci.c:lba < se.sys_first_block' \
	--added-contains 'bsd/dev/santoni_sdhci.c:error = sdhci_write_pio((uint32_t)lba, count, buf);' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:su.dma'
echo "ok   0142 ships CRC32, system partition and the 8193-sector log fence"

echo "== STOR-04: log flusher on SYSTEM, no Sweet userdata ring (0143) =="
python3 tools/check_patch.py "$P143" -q \
	--added-contains 'bsd/dev/santoni_sdhci.c:santoni_log_start();' \
	--added-contains 'bsd/dev/santoni_sdhci.c:error = santoni_sdhci_write_log_blocks(base + 1 + blk,' \
	--added-contains 'bsd/dev/santoni_sdhci.c:error = santoni_sdhci_write_log_blocks(base, 1, bounce);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:PE_parse_boot_argn("sweetlog", &on, sizeof(on));' \
	--added-contains 'osfmk/console/serial_console.c:santoni_log_append(c, size);' \
	--added-contains 'osfmk/console/serial_console.c:#if !defined(ARM64_BOARD_CONFIG_SANTONI)' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:base = sys.first_block;' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:se.dma' \
	--added-lacks 'osfmk/console/serial_console.c:sweet_log_append(c, size);'
echo "ok   0143 routes Santoni to SYSTEM and not to sweet_log_append"

echo "== STOR-05: 4 KiB pages with a 16 KiB-signed dyld cache (0144) =="
python3 tools/check_patch.py "$P144" -q \
	--added-contains 'bsd/kern/ubc_subr.c:cd->pageSize != 14' \
	--added-contains 'bsd/kern/ubc_subr.c:cd->pageSize > PAGE_SHIFT' \
	--added-contains 'osfmk/vm/vm_shared_region.c:vm_map_cs_enforcement_set(vm_shared_region_vm_map(shared_region), false);'
echo "ok   0144 allows pageSize 14, skips 16 KiB hashing, disables CS enforcement"

echo "== STOR-06: SDHCI consensus fixes (CMD12-after-BLK_CNT_EN, DATA_INHIBIT, ==="
echo "==          recover, R2 CRC strip, SEC_COUNT fence, idempotent probe,     =="
echo "==          HC-mode takeover from LK's legacy MCI mode)                  =="
python3 tools/check_patch.py "$P142" -q \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_poll_state(SDHCI_CMD_INHIBIT | SDHCI_DATA_INHIBIT,' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_recover(void)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:hc_rd(SDHCI_RESPONSE + 4 * (3 - i))' \
	--added-contains 'bsd/dev/santoni_sdhci.c:se.sec_count = sec_count;' \
	--added-contains 'bsd/dev/santoni_sdhci.c:lba + (uint64_t)count > se.sec_count' \
	--added-contains 'bsd/dev/santoni_sdhci.c:static bool attempted;' \
	--added-contains 'bsd/dev/santoni_sdhci.c:int init_error;' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_core_check(void)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:#define SDHCI_CTRL_8BITBUS' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_enter_hc_mode(void)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:core_wr(CORE_HC_MODE, (hc_mode & ~CORE_HC_MODE_EN) | CORE_HC_MODE_EN);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:core_wr(CORE_HC_MODE, hc_mode | CORE_HC_MODE_EN | CORE_FF_CLK_SW_RST_DIS);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:HC_MODE_EN reads back 0' \
	--added-contains 'bsd/dev/santoni_sdhci.c:FF_CLK_SW_RST_DIS did not stick' \
	--added-contains 'bsd/dev/santoni_sdhci.c:card clock gate was closed' \
	--added-contains 'bsd/dev/santoni_sdhci.c:hc_wr(SDHCI_INT_ENABLE, 0xffffffffu);' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:core not in HC mode' \
	--added-contains 'iokit/bsddev/IOKitBSDInit.cpp:santoni_sdhci_probe();' \
	--added-contains 'iokit/bsddev/IOKitBSDInit.cpp:IOLog("SANTONI: eMMC probe failed' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:return sdhci_stop_transmission();'
echo "ok   0142 fixes DATA_INHIBIT, CMD12/recover, R2 order, SEC_COUNT and probe"
python3 tools/check_patch.py "$P143" -q \
	--added-contains 'bsd/dev/santoni_sdhci.c:uint32_t on = 0;' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:uint32_t on = 1;'
echo "ok   0143 defaults the console log OFF (sweetlog=1 enables it)"

echo "== STOR-07: addressed commands carry LK's RCA, R2 is CRC-stripped, and  =="
echo "==          the RCA ladder diagnoses itself (VENDOR_SPEC, CMD5, CMD0)   =="
python3 tools/check_patch.py "$P142" -q \
	--added-contains 'bsd/dev/santoni_sdhci.c:#define SANTONI_CARD_RCA' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_send_status(uint32_t rca, uint32_t *r1)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_cmd(13, rca << 16, 0,' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_read_response128(9, se.rca << 16, csd)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:out[i] = (lo << 8) | (hi >> 24);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:hc_wr(CORE_VENDOR_SPEC, CORE_VENDOR_SPEC_BOARD_VAL);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_sleep_awake(uint32_t rca, uint32_t *r1)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_restore_state(uint32_t *r1)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_restore_controller(void)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:hc_wr16(SDHCI_HOST_CONTROL2, handoff_hc2);' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:hc_wr(CORE_VENDOR_SPEC, CORE_VENDOR_SPEC_POR_VAL);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:CMD0 did not complete either: no SDCLK' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:core_wr(CORE_VENDOR_SPEC' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:sdhci_cmd(13, 0, 0,' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:sdhci_read_response128(10,' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:card is not in transfer state'
echo "ok   0142 addresses CMD13/CMD9 with RCA and removes illegal TRAN-state CMD10"

echo "== STOR-08: HC datapath clock - vendor MCLK select, DLL CK_OUT_EN,    =="
echo "==          and status-enable all ones for the polled loop (0142)      =="
python3 tools/check_patch.py "$P142" -q \
	--added-contains 'bsd/dev/santoni_sdhci.c:#define CORE_DLL_CONFIG         0x100' \
	--added-contains 'bsd/dev/santoni_sdhci.c:#define CORE_CK_OUT_EN          0x00040000u' \
	--added-contains 'bsd/dev/santoni_sdhci.c:#define CORE_DLL_OFF            (CORE_DLL_RST | CORE_DLL_PDN)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:hc_wr(CORE_VENDOR_SPEC, CORE_VENDOR_SPEC_BOARD_VAL);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_select_hc_clock(void)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:vs |= CORE_HC_MCLK_SEL_DFLT;' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_clock_output(void)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:bool dll_live = (dll & CORE_DLL_EN) && !(dll & CORE_DLL_OFF) &&' \
	--added-contains 'bsd/dev/santoni_sdhci.c:CORE_DLL_CONFIG 0x%08x CORE_DLL_STATUS 0x%08x' \
	--added-contains 'bsd/dev/santoni_sdhci.c:hc_wr(SDHCI_SIGNAL_ENABLE, 0);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:card clock gate did not' \
	--added-contains 'bsd/dev/santoni_sdhci.c:hc_wr16(SDHCI_CLOCK_CONTROL, SDHCI_CLOCK_INT_EN);' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:SDHCI_CLOCK_DIV' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:core_wr(CORE_VENDOR_SPEC' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:hc_wr(SDHCI_INT_ENABLE, 0);' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:core_wr(CORE_HC_MODE, hc_mode | want);'
echo "ok   0142 clocks the HC datapath, follows the DLL and enables status"

echo "== STOR-09: card clock comes from GCC sdcc1_apps_clk_src, not the    =="
echo "==          ignored SDHCI divider (mapped RCG page, M/N/D, UPDATE)     =="
python3 tools/check_patch.py "$P142" -q \
	--added-contains 'bsd/dev/santoni_sdhci.c:#define GCC_SDCC1_APPS_PHYS      0x01842000u' \
	--added-contains 'bsd/dev/santoni_sdhci.c:#define GCC_SDCC1_APPS_CMD_RCGR  0x004u' \
	--added-contains 'bsd/dev/santoni_sdhci.c:se.gcc = ml_io_map(GCC_SDCC1_APPS_PHYS, GCC_SDCC1_APPS_SIZE);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_gcc_set_apps(const struct santoni_gcc_rate *r)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:gcc_wr(GCC_SDCC1_APPS_M, r->m);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:gcc_wr(GCC_SDCC1_APPS_N, r->n);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:gcc_wr(GCC_SDCC1_APPS_D, r->d);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:cfg &= ~(GCC_CFG_DIV_MASK | GCC_CFG_SEL_MASK | GCC_CFG_MODE_MASK);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:gcc_wr(GCC_SDCC1_APPS_CMD_RCGR, cmd | GCC_CMD_UPDATE);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:{ "400 kHz", 0x01u, 0xfcu, 0xfbu, 0x2017u },' \
	--added-contains 'bsd/dev/santoni_sdhci.c:{ "25 MHz",  0x01u, 0xfeu, 0xfdu, 0x211fu },' \
	--added-contains 'bsd/dev/santoni_sdhci.c:absolutetime_to_nanoseconds(mach_absolute_time() - start, &ns);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:CMD0 -> error %d, %llu ns' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:gcc_wr(GCC_SDCC1_APPS_CBCR' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:SDHCI_DIVIDER_400KHZ'
echo "ok   0142 programs the GCC RCG and keeps the branch/AHB gates untouched"

echo "== STOR-10: 400 kHz uses UHS=0 feedback clock, 1-bit bus, DLL off;   =="
echo "==          CMD13/CMD5 precede CMD0 and CMD1 polls only while busy    =="
python3 tools/check_patch.py "$P142" -q \
	--added-contains 'bsd/dev/santoni_sdhci.c:#define SDHCI_CTRL_UHS_MASK' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_snapshot_untouched(void)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_snapshot_standard(const char *tag)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_set_legacy_host(const char *why)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:new_hc2 = (uint16_t)(hc2 & ~SDHCI_CTRL_UHS_MASK);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:SDHCI_CTRL_DMA_MASK |' \
	--added-contains 'bsd/dev/santoni_sdhci.c:(dll | CORE_DLL_RST | CORE_DLL_PDN) &' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_cmd1_poll(uint32_t *ocr)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:if (*ocr & 0x80000000u)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:command timeout is not "busy"' \
	--added-contains 'bsd/dev/santoni_sdhci.c:probe step 2: CMD5 awake RCA 2' \
	--added-contains 'bsd/dev/santoni_sdhci.c:GO_PRE_IDLE retry' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_set_legacy_host("rung 3 controller restore");' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:hc_wr(CORE_VENDOR_SPEC, CORE_VENDOR_SPEC_HS400_DIV2_VAL);'
echo "ok   0142 uses the low-speed feedback path and a bounded CMD1 poll"

echo "== STOR-11: CMD2/CMD3/CMD9/CMD7/CMD8 enumeration and 25 MHz 8-bit HS =="
echo "==          switch; R2 has no index check and CMD6 waits for DAT0        =="
python3 tools/check_patch.py "$P142" -q \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_read_response128(uint8_t index, uint32_t arg, uint32_t out[4])' \
	--added-contains 'bsd/dev/santoni_sdhci.c:SDHCI_CMD_RESP_LONG | SDHCI_CMD_CRC, NULL);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_enumerate_card(void)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_read_response128(2, 0, cid)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_cmd(3, SANTONI_CARD_RCA << 16, 0,' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_read_response128(9, se.rca << 16, csd)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_select_card(se.rca)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_read_pio(8, 0, 1, (void *)(se.dma + DMA_BOUNCE))' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_gcc_set_apps(&santoni_gcc_rates[SANTONI_GCC_RATE_25M])' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_switch_ext_csd(EXT_CSD_BUS_WIDTH,' \
	--added-contains 'bsd/dev/santoni_sdhci.c:EXT_CSD_BUS_WIDTH_8, SDHCI_CTRL_8BITBUS, SDHCI_CTRL_BUS_MASK,' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_switch_ext_csd(EXT_CSD_HS_TIMING,' \
	--added-contains 'bsd/dev/santoni_sdhci.c:EXT_CSD_TIMING_HS, SDHCI_CTRL_HISPD, 0, "HS_TIMING=1")' \
	--added-contains 'bsd/dev/santoni_sdhci.c:SDHCI_DATA_0_LVL_MASK' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_wait_card_ready(uint32_t rca, const char *what)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:#define SDHCI_R1_SWITCH_ERROR' \
	--added-contains 'bsd/dev/santoni_sdhci.c:if (r1 & SDHCI_R1_SWITCH_ERROR) {' \
	--added-contains 'bsd/dev/santoni_sdhci.c:se.enumerated = true;' \
	--added-contains 'bsd/dev/santoni_sdhci.c:error = sdhci_enumerate_card();' \
	--added-contains 'bsd/dev/santoni_sdhci.c:if (se.enumerated) {' \
	--added-contains 'bsd/dev/santoni_sdhci.c:not downgrading the card bus' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:SDHCI_CMD_RESP_LONG | SDHCI_CMD_CRC | SDHCI_CMD_INDEX'
echo "ok   0142 enumerates READY->TRAN, reads EXT_CSD 1-bit, then switches 25 MHz/8-bit/HS"

echo "== STOR-12: CMD17 single-block, CMD18/25 AUTO_CMD12, and 8-bit bus verification (0142) =="
python3 tools/check_patch.py "$P142" -q \
	--added-contains 'bsd/dev/santoni_sdhci.c:#define SDHCI_TRNS_AUTO_CMD12   0x0004' \
	--added-contains 'bsd/dev/santoni_sdhci.c:SDHCI_TRNS_AUTO_CMD12' \
	--added-contains 'bsd/dev/santoni_sdhci.c:sdhci_verify_highspeed_bus(uint32_t expected_sec_count)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:error = sdhci_verify_highspeed_bus(se.sec_count);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:return sdhci_read_pio(count == 1 ? 17 : 18, (uint32_t)lba, count, buf);' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:sdhci_card_check(void)'
echo "ok   0142 uses CMD17 for 1 block, AUTO_CMD12 for multi-block, and verifies 8-bit bus"

echo "== STOR-13: cdev I/O uses uiomove, not physio/user-VA memcpy; B_PHYS ==="
echo "==          strategy buffers use copyin/copyout (0142)                  =="
python3 tools/check_patch.py "$P142" -q \
	--added-contains 'bsd/dev/santoni_sdhci.c:santoni_sdhci_uio(struct uio *uio, bool rd)' \
	--added-contains 'bsd/dev/santoni_sdhci.c:return santoni_sdhci_uio(uio, true);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:kmem_alloc(kernel_map, &bounce, bsize, KMA_DATA,' \
	--added-contains 'bsd/dev/santoni_sdhci.c:error = uiomove(buf + skip, (int)want, uio);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:!santoni_kernel_address(vaddr);' \
	--added-contains 'bsd/dev/santoni_sdhci.c:error = copyout(bounce + skip,' \
	--added-contains 'bsd/dev/santoni_sdhci.c:error = copyin((user_addr_t)(vaddr + done),' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:return physio('
echo "ok   0142 never hands a user VA to memcpy and keeps the cdev lock off uiomove"

echo "== STOR-14: kernel buffers copied under the lock, psize in 512-byte  =="
echo "==          units, sync/solid-state/feature ioctls, pread LBA 2      =="
python3 tools/check_patch.py "$P142" -q \
	--added-contains 'bsd/dev/santoni_sdhci.c:case DKIOCSYNCHRONIZE:' \
	--added-contains 'bsd/dev/santoni_sdhci.c:case DKIOCSYNCHRONIZECACHE:' \
	--added-contains 'bsd/dev/santoni_sdhci.c:case DKIOCISSOLIDSTATE:' \
	--added-contains 'bsd/dev/santoni_sdhci.c:case DKIOCGETFEATURES:' \
	--added-contains 'bsd/dev/santoni_sdhci.c:*f = DK_FEATURE_BARRIER;' \
	--added-contains 'bsd/dev/santoni_sdhci.c:(int)MIN(se.nblocks, (uint64_t)INT_MAX)' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:(int)MIN(se.nblocks * SDHCI_BLOCK'
grep -q '^#define SYS_pread	153$' tools/santoni-init.S
grep -q 'mov	x3, #1024' tools/santoni-init.S
grep -q 'read eMMC LBA 2 (off 1024)' tools/santoni-init.S
echo "ok   0142 locks kernel memcpy, reports sectors, and accepts sync ioctls"

echo "== SANTONI-01: /private/var mkdir rescue and EACCES paths (0149) =="
python3 tools/check_patch.py "$P149" -q \
	--added-contains 'bsd/vfs/vfs_syscalls.c:santoni_varfix_enabled(void)' \
	--added-contains 'bsd/vfs/vfs_syscalls.c:santoni_var_path(kbuf)' \
	--added-contains 'bsd/vfs/vfs_syscalls.c:santoni_chown_created(rctx' \
	--added-contains 'bsd/vfs/vfs_syscalls.c:mkdir1at(rctx, (user_addr_t)(uintptr_t)kbuf' \
	--added-contains 'bsd/vfs/vfs_syscalls.c:SANTONI VFS: mkdir' \
	--added-contains 'bsd/vfs/vfs_syscalls.c:SANTONI VFS: open' \
	--added-lacks 'bsd/vfs/vfs_syscalls.c:santoni_var_path("/'
grep -Eq 'sweetfb_noconsole=[01]' shim/build.sh
grep -q 'santoni_varfix=1' shim/build.sh
# sweetlog=1 is optional; omitting it disables console line filtering
echo "ok   0149 rescues data-volume mkdir and logs EACCES paths"

# Optional deep check: if a patched XNU source tree is provided, the three
# storage patches plus 0149 must also apply to it as-is (git apply --check).
if [ -n "${XNU_SRC:-}" ]; then
	echo "== git apply --check against XNU_SRC=$XNU_SRC =="
	(cd "$XNU_SRC" && git apply --check \
	    "$OLDPWD/$P142" "$OLDPWD/$P143" "$OLDPWD/$P144" "$OLDPWD/$P149")
	echo "ok   all four patches apply to $XNU_SRC"
fi

echo "== SANTONI-02: SPMI v2 map, 0164 FIFO/poll/CRC, GIC SPI 168->200 and I2C half-period (0164) =="
python3 tools/check_patch.py xnu/patches/0164-santoni-touch-fixes.patch -q \
	--added-contains 'bsd/dev/santoni_sdhci.c:pmic_arb_apid_map_offset_v2() = 0x800 + 4*APID' \
	--added-contains 'bsd/dev/santoni_sdhci.c:uint8_t tmp[128];' \
	--added-contains 'bsd/dev/santoni_sdhci.c:uint8_t crc = 0;' \
	--added-contains 'bsd/dev/santoni_sdhci.c:GIC_SPI 168 -> hwirq 200' \
	--added-contains 'bsd/dev/santoni_sdhci.c:static bool' \
	--added-lacks 'bsd/dev/santoni_sdhci.c:core + 0x2000'
echo "ok   0164 carries SPMI/GIC/FT-CRC/FIFO/reply-parse fixes"

echo "== SANTONI-03: CI must not silently drop numbered Santoni patches (xnu.yml) =="
if grep -Fq "if grep -E 'Skipping patch .*[0-9]{4}-santoni' build.log; then" .github/workflows/xnu.yml; then
	echo "ok   workflow fails on skipped Santoni patches, including 016x and 0201"
else
	echo "workflow skip guard does not cover every four-digit Santoni patch" >&2
	exit 1
fi


echo "run_tests: all hosts tests, patch checks and shipped-code assertions passed"
