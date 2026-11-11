# CPU 4 secondary-entry audit

Historical input/CPU audit. For the current hardware and GPU qualification,
see [current status](santoni-gpu-status.md).


**Date:** 2026-10-25. **Type:** manual self-audit. **Hardware success:** pending.

## Evidence, not inference

The user confirmed the named `cc215ac` eight-core image. The correctly oriented
photo shows cores 0–3 reaching GIC/initCPU on `0x100..0x103`, then CPU4's
`cpu_start()` and a five-second startup timeout. There is no CPU4 GIC/init line.
An earlier reading of CPU3's line as CPU4 was corrected. CPU4 is the registered
physical `0x000` core; its actual reset-entry EL is not yet observed.

The previous host GIC tests began at per-core GIC setup and did not cover this
pre-GIC entry path. They were not evidence that CPU4 reset worked on hardware.

## Source-confirmed corrections in 0173

1. Guard `ICC_SRE_EL2` accesses with `HAS_GIC_V3`. Santoni's GICv2 entry must not
   require GICv3 system-register support. The existing EL1 path is unchanged.
2. Before EL2→EL1, copy physical `MPIDR_EL1`/`MIDR_EL1` into
   `VMPIDR_EL2`/`VPIDR_EL2`. EL1's identity must describe this CPU, not inherited
   virtual-ID state. Reference: Linux `asm/el2_setup.h:258–263`.
3. Preserve PSCI target/context, handler validation, full-affinity CPU lookup,
   interrupt routing and the five-second timeout. Physical ID zero remains
   valid; the source had no physical-zero boot-CPU shortcut to "fix".

These are real entry-path defects. **The photo does not prove CPU4 entered EL2,
so the causal explanation for its timeout remains a candidate.**

## Diagnostic audit

- Assembly and C++ share 64-byte-aligned, 64-byte slots: stage, MPIDR, six
  padding words. One slot per selected logical CPU avoids cache-line sharing.
- Initial entry validates the PSCI context before computing a slot. CPU-data
  lookup validates the registered logical ID separately. Neither can write
  outside the eight-slot array.
- Only scratch registers x2/x16/x17 are used for markers; required x0 context,
  x19 reset data and x20/x21 boot/CPU data are preserved. EL2 return state is
  programmed before `eret`; identity setup does not alter targets.
- The controller clears stage/MPIDR and cleans the complete slot to RAM **before
  CPU_ON**. Cache-off entry stores end with DSB. On timeout, the controller
  flushes/invalidates its clean slot before inspecting it. No allocation,
  scheduler wait or PMIC operation occurs in the reset stub.
- Marker storage is kernel-owned `__DATA`; relative addressing follows the
  same original-text physical entry used by PSCI. Santoni does not implement
  a copied-vector resume/power-collapse path; this adds no such support.
- CPU_ON and its return now use visible `kprintf`. Timeout prints initialized,
  SGI and reset/MPIDR values instead of hiding the failure or marking it online.

Markers: `0x104/0x108` entry at EL1/EL2; `0x208` prepared EL2 return;
`0x304` reached EL1; `0x404` matched the registered CPU-data slot. Zero means
no marker was observed, not categorical proof that firmware never branched.

## Tests and limitations

- **53/53** checks preprocess and interpret the actual assembly fragment:
  EL1/EL2, GICv2/GICv3 controls, identity state, per-CPU trace bounds, invalid
  contexts/EL and all eight physical lookups including zero.
- **12/12** execute the actual C++ `startCPU` function with mocked firmware:
  valid targets/context, cache-clean ordering, slot isolation, rejected
  restarts/arguments and propagated PSCI failure. It never fabricates init.
- Pre-0173: **17/53** assembly checks pass, including healthy EL1 and physical
  lookup controls; missing/unsupported entry/trace behavior fails. The new C++
  trace handoff check also fails as expected.
- The fixture is not a real CPU/MMU/cache/GIC/firmware emulator. It does not
  prove the target powers on or that reset-table loads succeed on Santoni.
- No local ARM assembly/kernel build was run. CI must validate real assembly,
  generated offsets, linking and the actual symbol layout before packaging.
- Touch, power/volume, storage and GPU implementation paths are unchanged.
- Final integrated run passes **290/290** existing/new contracts plus storage,
  logging and patch gates; Python syntax and whitespace checks pass.

Next: build only in GitHub Actions, verify the compiled guard/identity/trace
layout, then temporary eight-core boot. If CPU4 still stops, record CPU_ON rc
and the new startup-detail line. The existing four-core input-control image
remains available; GPU implementation is still gated on working inputs.

## CI linkage finding and correction

CI **40175653165** passed host/patch validation and assembly but failed linking:
the bare cache header declared `CleanPoC_DcacheRegion_Force` with C++ linkage,
while its definition is an assembly C symbol. The earlier C++ fixture defined
the same mangled helper and therefore masked this integration error.

0174 removes that include and supplies explicit C declarations for the cache
clean/flush helpers. The revised test extracts the actual declaration and links
the C++ startup routine to a **separate native C translation unit**. Pre-0174
reproduces the exact undefined mangled symbol; 0174 links and all logic tests
pass. No startup or cache-maintenance behavior was removed to make it green.
No failed kernel was packaged.

## Successful retry binary gate

CI **40177112851** succeeded for `3222f2b`. Before packaging, the actual kernel
was inspected by system-register encodings: no ICC_SRE_EL2 in the GICv2 entry,
VMPIDR/VPIDR writes present. The trace symbol is 64-byte aligned and its 512-byte
array is initialized within the kernel's data segment. The verified kernel and
boot hashes/paths are retained with the controlled image manifests.
**CPU4's real reset/entry behavior and physical inputs remain to be tested.**
