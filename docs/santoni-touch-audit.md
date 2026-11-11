---

Historical input/CPU audit. For the current hardware and GPU qualification,
see [current status](santoni-gpu-status.md).

status: candidate_code_reviewed_hardware_pending
date: 2026-10-25
review_type: manual_self_audit
base: b120d161b0d7415f21bce0194336a7aa59c23dde
candidate: c692ebd
independent_review: unavailable_provider_error
---

# Santoni touch recovery audit

## Outcome

The touch recovery **candidate** passes its source/host checks. It has not been
booted, so restored physical touch and improved eight-core boot time are **not
established**. The last hardware result remains dead touch with kernel `4a2480b`
and a 5–7 minute eight-core penalty. Three independent-review attempts failed at
the provider before producing a review. This report is the author's self-audit,
not an independent approval or a guarantee of no bugs.

Button implementation was deferred during this audit. GPU implementation is
out of scope and remains gated on working physical inputs.

## Scope and authoritative inputs

- Review against the user-proven touch kernel `b120d16` / patches through 0165.
- Inspect 0166–0169 and 0171 together: key polling's effect on touch, HID entry
  points/test timer, GIC lifecycle/ordering, panel copying, short waits and idle.
- Reconstruct source in lexical patch order with `git apply --check` before each
  section, not from the stale `scratch/bt/xnu` tree. Public upstream SMP/idle
  inputs are pinned to SHA256 for `xnu-8796.141.3`.
- Hardware reference: `msm8937.dtsi`, `msm8940-xiaomi-santoni.dts`, `pm8937.dtsi`,
  Linux `spmi-pmic-arb.c`, `edt-ft5x06.c`, `irq-gic.c`, `irq-gic-common.c`.
- Sailfish reference: 0089 keys and 0180 coherent idle. Pixel GPIO addresses,
  Synaptics protocol, GICv3 and its intentional Volume-Down-to-Home mapping are
  **not** suitable Santoni substitutions.

## Verified findings and dispositions

| Finding | Evidence | Disposition |
|---|---|---|
| Short hardware waits can schedule | XNU `clock.c:1575–1614` calls `thread_block` unless `ml_delay_should_spin` or context requires a spin. `machine_routines.c:2360–2372` selects blocking for zero idle latency; SweetCPU's processor info supplies no powergate latency. | 0169 routes exactly the existing thirty 1–20 µs waits to a counter/YIELD helper. All millisecond reset/rail waits remain unchanged. |
| The ordinary ARM spin helper is not a strict polling delay | `rtclock.c:519–528` uses WFE before checking time; it depends on an event. | The new helper uses YIELD, not WFE, and no scheduler/wait primitive. `clock_interval_to_deadline` performs the kernel's calibrated conversion and overflow handling. |
| Whole-cache idle work is unnecessary for this port's plain WFI | `cpu.c` calls `platform_cache_idle_enter` on non-Apple boards; `caches.c:337–352` invokes clean/invalidate; `caches_asm.s` uses set/way operations. Santoni declares coherent caches and performs plain WFI, not PSCI suspend. | 0171 keeps the DSB and WFI but skips that hook only for Santoni. Explicit startup and DMA maintenance are unchanged. The three-mode host test verifies generic ARM and Apple behavior is preserved. |
| SYSTEM log extraction lost partition identity | Resolving `/by-name/system` to `mmcblk0pN` made the old string test choose USERDATA-tail offsets. | Preserve the allowlisted by-name path. Test both path prefixes and both layouts with fake ADB; no physical device is contacted. |
| Log size checks were GNU-stat-specific and USERDATA short reads were unchecked | `stat -c` is not portable to the macOS CI host; a short tail read could reach the decoder. | Use Python file sizes and reject short reads for both layouts. Ten fake-ADB cases cover success, missing paths and truncated data. |

The short-wait and idle defects are source-confirmed. Their contribution to the
actual regression is **not** proven without a boot result or runtime evidence.

## Cross-file checks

### Physical protocol and HID

- The reconstructed `santoni_ft5435_identify` and `santoni_ft5435_read_points`
  functions are byte-identical to the user-proven post-0165 source.
- I2C START/STOP/write/read/combined-read bodies match that source exactly after
  substituting the short-wait function name. Clock timeout/error propagation,
  GPIO wiring, open-drain operation, report format, CRC and all-slot/releases
  have not been changed by this recovery candidate.
- `SweetHIDTouch::touch` remains byte-identical to the working baseline,
  including normalization and edge-tip flags. Wrapper bounds checks do not
  reject any valid Santoni ID (0–4).
- Optional synthetic input emits no Home keys. It ends after four swipes or
  physical input; this is a **known diagnostic limitation**, not proof of lock
  screen readiness. Four swipes can be consumed before a late lock screen.
- The staged failing image was checked: `sweethidtest=1` is present in both
  Android and SWEETXNU command lines. It is not a misspelled-option diagnosis.

### SPMI and interference

- DT `spmi@200f000` declares core `0x0200f000/0x1000`, observer
  `0x02c00000/0x800000` and EE 0. APID scan addresses end inside the core map;
  each cached observer is a single page inside the observer resource.
- SID 0 PON PPID `0x008`, EXT_READL byte count/opcode/offset and read-data/status
  offsets agree with the local Linux v2 reference. No PMIC register programming
  or acknowledgements are added.
- The candidate's PON polling still precedes touch polling in the same thread.
  Its no-DONE case now performs 1000 short waits rather than 1000 potentially
  scheduled sleeps. A targeted actual-function test checks unchanged output,
  the bounded polling count and zero short scheduler calls.
- Separate button polling will be assessed in the button stage: it must not
  introduce concurrent access to the reader's lazy maps/observer commands
  without synchronization. The current audited reader has one caller thread.

### GIC, display and builds

- 0167 routes SGIs using banked one-hot targets and SPIs to the discovered boot
  target; it does not change PSCI, CPU affinity IDs or timer INTID 20. Private
  configuration is performed from per-CPU platform initialization, before the
  self-SGI startup acknowledgement. No runtime resume path is implemented.
- Self-SGI startup still does **not** establish all-pairs hardware IPI health.
  The model exhausts legal target layouts/private state, but firmware and
  actual cache latency remain untested.
- 0168's packed BGR24 stores preserve guard bytes, row padding and odd widths
  in host checks. Inspection of the actual `4a2480b` CI kernel's `blitPanel`
  disassembly shows scalar W-register operations/stores and a final DSB, not
  NEON/FP instructions. No local kernel compilation was performed.
- Native panel-copy output checks and HID tests also pass ASan/UBSan. They
  cannot prove FPS, panel timing or UI responsiveness.
- The workflow rejects skipped Santoni patches and runs the actual-source
  regressions. The compact kernel artifact must be checksum-verified before
  packaging. User's local `sweethidtest=1` recipe is preserved.

## Validation

Run: `HOST_CC=clang HOST_CXX=clang++ OUT_DIR=out/santoni-touch-self-audit bash tests/run_tests.sh`.

- Input/RPM: **67/67**, including no-scheduler edges and bounded SPMI timeout.
- HID/display: **8/8**.
- GIC/SMP: **128/128**.
- Idle cache policy: **3/3**.
- Fake-ADB log extraction: **10/10**.
- Storage/log unit suites, patch structure and shipped-code gates: passed.
- Input/RPM **67/67** and HID/display **8/8** also passed ASan/UBSan.
- Previously demonstrated baseline failures are retained; no tests were
  deleted or relaxed to turn a failure green.

## Hardware gate / unresolved evidence

The source audit is complete enough to proceed to the separate button stage,
but **physical touch remains unverified**. Before declaring recovery:

1. Boot the CI-built candidate temporarily and verify actual taps, drags,
   releases and unlock without synthetic input.
2. If it still fails, use the same-kernel four-core comparison and the corrected
   SYSTEM log reader to determine whether touch polling, I2C, HID delivery or
   the UI is the failing layer. Do not add more unrelated register guesses.
3. Keep `/sdcard/boot-working-touch.img` intact as the exact working fallback.
4. Do not begin GPU implementation until physical touch and all three buttons
   have been confirmed on hardware.

## Post-audit build verification

Combined audited kernel `cc215ac` passed CI **40170676997**. The downloaded
checksum and both packaged command lines were verified. Built-code inspection
confirms the short-wait YIELD, PMIC mutex, HID acquire publication and absence
of the generic cache-idle call. **No new hardware boot has occurred.** See the
controlled image manifests for exact image paths/hashes and the control image.
