# Santoni graphics status

Updated: 2026-11-11. This page describes the audited development checkpoint and
identified hardware evidence. It does not equate a build or model result with
accelerated UI on the device.

## Audited development checkpoint

| Identity | Value |
| --- | --- |
| Source commit | `adc6e1e0f51bdfd81f49aeddb5b64c5d1e199691` |
| CI commit, identical source tree | `a688893a022b3b1c42e6b457ccd38ce0c491cc99` |
| Kernel CI run | `42833150315` — passed, attempt 2 |
| GLES / loader CI run | `42833173777` — passed |
| Kernel SHA-256 | `78c81156a060e67353139f45fcb02d592f56219a5dabfd2325a977a33e6f9d1a` |
| Production change | Patch 0230: bounded renderer startup diagnostics |
| Packaging follow-up | `e29756b`: explicit renderer power-test skip |
| Hardware qualification | Complete identified power/input acceptance pending |

The full CI host gate and skipped-patch guard passed. The downloaded kernel and
GLES/loader artifacts were checksum-bound to their real CI metadata. Actual code
was screened for Cortex-A53 compatibility and the loader's readonly declarations
were bound to the exact EAGL library.

Patch 0230 preserves fresh executable-vnode and permission checks while adding
paired entry/return markers around identity and VFS operations. Separate bounded
trace budgets preserve mobile samples after root samples are exhausted. The
rebuilt loader adds a constructor-entry marker before its mutex. These are
diagnostics; no startup fix or GPU register change is claimed.

## Software contract coverage

- Native reconstructed source contracts cover input/display, ownership,
  malformed inputs, mappings, lifetime and opt-in negatives at O0/O2/UBSan.
- Exact-kernel power control, readiness, late-launch, fault reporting and the
  scoped remoted workaround passed their binary contracts.
- All 37 live-copy and 65 UI cases passed, including full-size modeled frames,
  ring behavior, cache/fence ordering, fault paths and CPU fallback.
- Ten fresh renderer-client components cover admission, complete pool-overlap
  checks, observer restrictions, all selectors, descriptors, submit arguments,
  close retention and dyld policy/copy/registration operands.
- Complete scalar, session, preflight, launcher, trace and worker components
  passed and were assembled into the same kernel's delivery certificate.

These checks execute reconstructed native code or bound instruction models with
explicit platform/GPU responses. They do not prove device scheduling, TrustZone
acceptance, shader output or UI frame rate.

## Hardware evidence and limits

Earlier identified kernels have power/input and controlled CP/SMMU evidence.
Kernel `debe2d4c14fe41682873677eadcb7aacff928e6a`, CI run 42565330210, has a complete
power/input result and reports two full-screen offscreen BGRA copy/readback jobs:

```text
pass=1 phase=12 error=0 submitted=2 completed=2
pixels=1843200 width=720 height=1280 stride=3072
```

GPU-copy presentation followed by CPU BGR24 panel conversion also has reported
hardware results. These are copy/presentation results; no accepted shader-driven
EAGL/GLES UI frame or sustained 30 Hz result has been recorded. Hardware results
remain tied to their identified kernels and images.

Mode 1 keeps UI acceleration disabled. The separate mode-3 userspace renderer
requires explicit graphics/raster/GLES/renderer options and its own binary
contracts. By default it also requires the same kernel's complete power/input
hardware result. The explicit `--skip-mode1` route records skipped qualification
and unverified hardware/UI fields while retaining the software gates.

## Latest trial and startup report

The user explicitly requested delivery without the power test. The controlled
packager produced `ui-accn-a688893-20261110T153810Z/boot.img`, with four cores,
30 Hz requested, visible console and the GLES/Mesa UI renderer enabled. Its
SHA-256 is `7a63dec1ee0599a0e983a09f6a0deb413e5f505865614f1852a327bb604116f7`.
The saved shim, DTB/init recipe, embedded kernel bytes and boot options were
verified. No accepted power result was created for this kernel.

The latest user report is a console with no Apple logo and no visible error.
The exact boot filename has not been reconfirmed and the current-boot log is
pending. A quiet console alone does not locate the startup failure. Preserve a
screen photo, then extract the persistent SYSTEM log from the known Santoni
recovery with `tools/sweet-log-pull.sh`, keeping both decoded text and raw bytes
before another iOS trial. Startup cause, shader UI and sustained 30 Hz remain
unproven.

## Rootfs and wallpaper

The 405af27 rebuilt rootfs includes audited EAGL/UI loader libraries and both
backboardd launch plists; its installation is user-confirmed. Native file
ownership/modes, regular executable permissions, fork/catalog extent bounds,
launch semantics and complete RAW/FILL decode/hash agreement were checked
offline. Installed-root hashes and runtime dyld/EAGL execution remain unproven.
The newer a688893 loader overlay is audited and staged offline; its installation
and constructor-entry marker on the device have not been verified. Graphics UAPI
compatibility between the two builds was checked.

An older cache receipt hashed zero-length HFS hardlink placeholder forks. Its
empty hashes are not cache-integrity evidence. Current verification resolves the
real inode payloads and records 44 nonempty cache hashes. Full before/after cache
and catalog comparison with the original image remains unproven.

The static wallpaper overlay is a separate tested draft. It is absent from the
current delivered rootfs and has not established a visible wallpaper fix on the
device. Its remaining work includes production policy, rootfs integration and
hardware validation.
