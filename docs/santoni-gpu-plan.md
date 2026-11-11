# Santoni GPU implementation plan

Updated: 2026-11-11. Current audited development checkpoint:
`a688893`.
[Evidence status](santoni-gpu-status.md) distinguishes hardware results from
source, native-test, CI and binary-model coverage.

## Target architecture

```text
CoreAnimation OpenGL ES calls
  -> Santoni EAGL / GL dispatch adapter
  -> Mesa Gallium freedreno + IR3 compiler
  -> msm/libdrm translation
  -> Santoni IOKit client: owned buffers, mapping, submit, fences
  -> portable GPU core + Santoni platform callbacks
  -> A505-rendered IOSurfaces
  -> CPU BGR24 panel presentation
```

The initial presentation path retains CPU conversion and physical input while
GPU rendering is qualified. Hardware scanout optimization follows measured
correctness of rendered surfaces. Metal is outside this GLES path.

## Target-derived contracts

Santoni uses Adreno 505, a 4 KiB GPU page contract and 136 KiB GMEM. The address
window, translation attributes, packet grammar, clock sequence and chip profile
come from the Santoni driver as programmed and its vendor references. Sailfish
provides architectural patterns; its A530 addresses and compute assumptions are
not the target contract.

Every BO is owner-bound and has an unmapped guard page. Physical mappings are
validated per page. Secure staging requires separately proven contiguous owned
spans. Firmware parsing validates structure, magic, CRC and ELF layouts; it does
not establish authenticity or TrustZone acceptance.

MMIO writes use readback checks and barriers. Polls have hard budgets. Forward
failure and rollback failure remain distinct, and potentially exposed buffers
are quarantined after uncertain completion. A software timeout cannot prove that
one hardware instruction returns.

## Milestones and remaining proof

| Stage | Existing evidence | Remaining acceptance |
| --- | --- | --- |
| CPU display/input | Identified hardware boots and input tests | Regression checks for every new kernel |
| Power, clocks, CP and SMMU | Hardware power tests and controlled command markers | Complete identified power/input result for the latest checkpoint |
| Buffer ownership, mappings and submission | Native contracts and exact-kernel instruction replay | Device lifetime, fault and repeatability behavior |
| Full-size GPU copies | Earlier identified copy/readback and presentation results | New-checkpoint regression and failure-path observations |
| Mesa, IR3, EAGL and IOKit | Compiled libraries, ISA checks, ABI and client contracts | Runtime loader entry, EAGL installation and shader-driven frames |
| UI performance | Configured four-core / 30 Hz baseline | Sustained frame rate, lock/wake, memory and thermal behavior |
| Wallpaper | Built static-overlay draft with limited controller tests | Production policy, rootfs integration and device appearance |

## Current integration boundary

Patch `0229-santoni-gpu-dyld-caller-context.patch` preserves fresh executable-vnode
and permission validation on every renderer admission. Lookup and attributes use
the calling VFS context outside the graphics mutex. Selector-90 diagnostics record
policy/copy outcomes, and the UI loader flushes progress markers before its load
and install operations. The prior runtime failure's root cause and the effect of
this change remain unproven. Patch 0230 adds bounded, paired boundary traces
around identity/VFS calls and a loader constructor marker before mutex entry.
Missing return markers identify the last observed boundary, with logging and
device timing still unproven.

The current rootfs artifact contains audited EAGL/loader libraries and both
backboardd launch descriptions. Its installed files, modes, extent bounds and
complete sparse-image decode were checked. A full original-to-rebuilt catalog
and cache comparison was unavailable. Resolved cache payload hashes identify
the new artifact; they are not an original-image comparison.

The latest a688893 UI image was delivered with an explicit user-requested
power-test skip. Its software contracts passed; the rebuilt loader overlay is
still offline. The current console/no-logo report needs an identified boot and
fresh log before selecting a startup change. The skipped qualification does not
establish a hardware power/input pass or shader-rendered UI.

## Qualification sequence

1. Complete the audited checkpoint's identified power/input hardware result.
2. Exercise a separately enabled renderer image with the matching loader/rootfs.
3. Observe dyld policy, loader stages, EAGL installation, submissions and fences.
4. Establish shader-produced pixels and sustained UI frames with the CPU fallback.
5. Measure longer memory/input/power behavior and bounded fault handling.
6. Integrate the separate wallpaper policy and validate visible appearance.
7. Evaluate panel conversion or scanout optimization using measured frame results.

PAS load/auth/reset, direct scanout, Metal, video decoding and unrelated device
support retain separate scope and acceptance criteria.
