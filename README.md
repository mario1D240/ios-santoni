# ios-santoni

Experimental iOS 16 / XNU 8796 bring-up for the Xiaomi Redmi 4X (`santoni`),
Qualcomm MSM8937 and Adreno 505.

The device boots the iOS interface with CPU display rendering, touch and
physical buttons. Development now includes an A505 submission path, owned GPU
buffers, Mesa freedreno/IR3, an EAGL adapter and an explicitly enabled UI loader.
Shader-driven iOS UI acceleration remains unproven on hardware.

## Current status — 2026-11-11

| Area | Verified status |
| --- | --- |
| Boot and CPU display | iOS UI works on identified hardware builds |
| Input | Touch, Power lock/wake and both volume buttons work on identified builds |
| Delivery baseline | Four Cortex-A53 cores and a configured 30 Hz CPU display path |
| GPU power and command processor | Power/clock checks and controlled command markers have hardware evidence |
| GPU copies | Two full-screen offscreen BGRA copy/readback jobs have hardware evidence |
| Panel presentation | GPU copies followed by CPU BGR24 presentation have hardware evidence |
| Mesa / EAGL / UI loader | Built and screened for Cortex-A53; kernel and adapter contracts tested |
| Shader UI and sustained 30 Hz | No accepted hardware proof yet |
| Wallpaper | Separate static-overlay draft; absent from the current delivered rootfs |
| PAS / TrustZone | Structural firmware checks and allocation are separate from authentication; PAS authentication remains unproven |

The latest audited development checkpoint is
`a688893`.
Its kernel and GLES/loader CI builds passed. The complete scalar, launcher,
renderer-client, live-copy and UI binary contracts also passed. Patch 0230 adds
bounded startup traces around renderer admission and VFS operations. A four-core,
30 Hz GLES/Mesa UI trial was delivered with an explicitly requested power-test
skip. The latest user report describes a console with no Apple logo or visible
error; its exact boot filename and current log are pending. Hardware qualification
and shader UI remain unproven. Earlier results apply to their identified kernels.

[Detailed status and evidence](docs/santoni-gpu-status.md) ·
[GPU implementation plan](docs/santoni-gpu-plan.md)

## Graphics architecture

The intended UI path is CoreAnimation/OpenGL ES through the EAGL adapter,
Mesa Gallium freedreno and IR3, the Santoni IOKit client, and the A505 backend.
CPU panel conversion and physical input remain the fallback. Metal and hardware
video decoding are separate capabilities.

GPU roles are explicitly selected by the controlled boot packager:

| Role | Behavior |
| --- | --- |
| Mode 0 | GPU diagnostic disabled |
| Mode 1 | Power/clock/readback and restoration diagnostic; UI acceleration disabled |
| Mode 2 | Command-processor/SMMU diagnostic |
| Mode 3 | Separately enabled execution, copy or renderer trials |
| Allocation preflight | Owned staging only; no SMC |
| Scalar SCM probe | Convention, availability and PAS-ID13 queries; no firmware upload or PAS load/auth/reset |

The userspace renderer uses `santonigpu_renderer=1` with the graphics/raster/GLES
roles and `santonigpu_ui=0`. The latter selects the userspace route rather than
the separate kernel UI-copy bridge. An enabled route is not a hardware result.
The packager binds each image to its commit, CI run, kernel hash and binary
certificates. Higher modes require the same kernel's identified power/input pass
by default. The renderer's explicit `--skip-mode1` option records omitted hardware
validation and keeps all software gates; it does not establish UI acceleration.

## Source and validation

| Path | Purpose |
| --- | --- |
| `xnu/patches/` | Numbered production changes applied to XNU in order |
| `tools/` | Firmware intake, actual-binary audits, controlled packaging and graphics adapters |
| `tests/` | Native C/C++ and Python contracts against reconstructed production sources |
| `shim/` | Boot shim and command-line recipe |
| `resources/` | Vendor and reference implementations |

The repository contains source and validation tools. Apple runtime files,
device firmware and device captures are supplied separately. Reconstructed
sources and build artifacts are not substitutes for numbered production patches.
Inherited Sweet/Topaz patch and shim names remain because Santoni depends on
that ordered source chain. Removing them would change the tested build.

Stored host-test receipts use `${PROJECT_ROOT}`, `${HOST_TMP}` and `${HOST_HOME}`
for machine paths. Each edited receipt identifies its original hash; recorded
results, source/input hashes, test cases and compiler flags are retained.

Local validation uses Python, clang/LLVM, git and bash:

```sh
git diff --check
bash tests/run_tests.sh
python3 -m unittest tests.test_santoni_gpu_driver
python3 -m unittest tests.test_santoni_gpu_prepare tests.test_santoni_gpu_boot_gates tests.test_santoni_gpu_kernel_audit
```

Native contracts use O0, O2 and UBSan. Kernel CI uses macOS 15, Xcode 16.0 and
`iig --deployment-target 13.5` for the XNU 8796 target. Downloaded binaries are
screened for Cortex-A53 instruction compatibility, real-register MMIO stores,
barriers, ownership and bounded failure paths.

## Project limits

This is research software with relaxed security and substantial unsupported
hardware. Experimental kernels use temporary RAM boot. The iOS HFS+ root resides
in `userdata`; writing a root image replaces that partition's contents. Boot
partitions, the partition table and the CPU display/input fallback are preserved
by the controlled bring-up process.

Source tests, binary models and CI validate software contracts. Hardware claims
require identified device results; allocation, command markers and successful
library linking do not establish shader pixels, UI performance or PAS acceptance.
