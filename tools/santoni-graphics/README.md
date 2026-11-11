# Santoni graphics userspace transport

`client.c` implements the production v1 BO allocation, managed CPU mappings,
pointer-free IB submission, fences and cache-preparation interface. It validates
the reported 4 KiB page size, GPU window, allocation limits and returned leases.
Failed calls disable further work; closing CPU aliases leaves GPU backing under
the kernel's independent wait/quarantine contract. Mesa's msm backend can use
this interface once the A505 raster packet policy is implemented and audited.

`probe.c` checks 32 repeated CP memory writes and CPU readbacks through owned
BOs and private command snapshots. Run it separately as root on a graphics
candidate with `--bo-ib-proof`. It requires `SantoniGraphics` and the completed
worker handoff. It does not inject into graphics processes or render GLES.

The `xnu` workflow's `userspace_only=true` dispatch builds the probe for iOS16
arm64 with Xcode16.0 and Cortex-A53 flags, using the UAPI reconstructed from the
same checked production patches. This dispatch builds no kernel and installs
nothing. The artifact includes a source/UAPI/build/hash manifest. Native protocol
checks pass on modeled IOKit responses; Darwin linking and device execution need
their own CI/hardware results.

The current kernel advertises GLES capability zero. The existing 30 Hz
presentation and four-core CPU display/input fallback remain the UI path while
the render backend is completed. A new CI kernel needs its own hardware gate;
an old image's result cannot validate this transport.

`commands.c` packages Mesa's separate nested command BOs for the v1 interface.
It copies each whole command BO once and relocates indirect/draw-state pointers.
The A505 VS/FS `CP_LOAD_STATE4` shader and constant uploads and both shader-object
entry-point pointers now also refer to copied BOs. Referenced data intervals
cannot become command intervals or synthetic NOP storage. A fully occupied
child/data BO receives a bounded appended NOP word in its new mirror; command
roots remain unchanged. This gives the kernel snapshots without executing
data or a child's state again. Cycles, missing/late/out-of-bounds addresses,
unsupported state formats and capacity overflow fail before submission.
Temporary mirrors survive uncertain waits. Shader/texture/UBO/SSBO and raster
validation in the kernel remains necessary; packaging does not authorize GLES.

`msm.c` translates the pinned Mesa25.0.7 msm allocation, mapping, queue,
submission, cache and fence requests over that transport. It requires the GLES
capability before rendering submissions and rejects physical relocations,
sudo packets, external sync objects and unsupported context restoration.
It supplies no invented clock or fault measurements. Full libdrm/Gallium linking
has passed CI; kernel raster policy and EAGL integration remain unfinished.

The combined command/kernel-PM4 tests pass60 host executions, and the msm
translator passes51, across O0/O2/UBSan. Their peer/GPU execution is modeled.
For the msm tests, provide the exact `mesa-reference.json` dependency using
`SANTONI_MESA_SOURCE`; the consumed UAPI header hashes are checked.

The additional state-packaging contracts pass78 host executions and reject18
compiling mutants across O0/O2/UBSan. They inspect the actual translated
shader/constant pointers and protected bytes, then verify that the unchanged
kernel PM4 parser still refuses the submission. This is no GPU execution or
shader-admission evidence. A nonzero hardware capability has not been added.

`drm.c` now supplies the serialized libdrm entry points over that adapter.
Its tokens are tracked independently from OS descriptors; the Mesa port hooks
device duplicate/close and managed BO mapping explicitly. The softpin dialect
disables native fences, shared memory and unsupported reset reporting. PRIME
and sync objects return errors. Final close is terminal for the boot-long
owner lease, and failed waits retain BO backing. The facade passes 36 host
cases across O0/O2/UBSan, including concurrent duplicate/close and actual PM4
validation; IOKit and GPU execution remain modeled.

`gles.c` supplies a surfaceless Mesa state-tracker frontend. Its explicit
`--gles-readback-proof` executable creates an ES2 context, verifies all 4096
pixels of a blue clear, then checks 4032 pixels around a red shader triangle
and requires new completed transport fences for both stages. It has no load
constructor, EAGL injection or system OpenGLES dependency. The pinned Mesa
port is a mechanically generated `mesa-ios.patch`; original references remain
read-only. `build_santoni_graphics_gles.py` and the `userspace_only=gles` workflow
build the full Gallium/IR3/GL stack for iOS16/Cortex-A53. A successful link is
build evidence; raster-policy admission, device pixel proof, IOSurface/EAGL
and CoreAnimation integration are still required for accelerated UI.

`ui_surface.c` now provides bounded BGRA IOSurface transfers around Mesa's
separate GPU textures: packed RGBA upload, synchronous readback, per-row channel
conversion, optional row inversion and preservation of offset/padding bytes.
The destination changes only after completed post-readback fences. `ui_gl.c`
supplies actual Mesa calls with PBOs disabled and pack/unpack row state restored;
first GL/framebuffer failures remain visible. The clear/triangle executable now
uses this same BGRA transfer path. ES2 remains its default, while the frontend
also accepts ES3 for the forthcoming EAGL bridge. These functions have host
layout/fence and GL-state tests; device rendering and EAGL hooks remain pending.

The complete iOS build passed CI `42237726149` at
`35f085de97194ca26ed77e509ab6c942549c2df1`. Its 16,436,336-byte executable is
plain arm64/iOS16.0; source, pinned Mesa, UAPI, executable and archive hashes
were checked after download. Mesa GL entry points, A505 state emission, IR3
compilation and the MSM adapter are defined in its actual text; system OpenGLES
is absent from its dependencies. This verifies compilation/linking. Runtime
libraries on our20H392 userland, CPU ISA screening and device rendering remain
unverified. Kernel GLES capability is still zero; no app or EAGL hook was installed.

For command-policy development, `userspace_only=capture` runs the real pinned
Mesa state tracker and IR3 compiler on a native macOS memory-only transport.
The capture submitter replaces `commands.c` only in that host executable. Its
admission, GPU addresses and completion responses are models; no GPU is opened
and no pixels or hardware pass can be derived from this run. Failed primary
captures and bounded LLDB diagnostic runs have separate packet directories.

`parse_santoni_graphics_capture.py` checks immutable SGCP framing/BO ownership.
`inspect_santoni_graphics_capture.py CAPTURE --mesa MESA` inventories bounded
IB/draw-state references and register writes using the pinned A5xx XML names.
Draw-state payloads are potential commands, not proof of actual execution.
The inspector does not validate shader operands, descriptor values or register
safety and must never be used as a kernel admission certificate.

The userspace packager now recognizes only direct VS/FS texture state with four
sampler or twelve descriptor words per unit, at most16 units starting at zero.
Descriptor addresses must name a listed same-owner BO; their pixel contents
stay in that public resource, not a small copied command BO. Sampler/format/
tiling/pitch/layer/complete-address safety still belongs to the kernel policy.
Framing acceptance is not content approval: the current kernel still refuses
every such texture submit and advertises GLES capability zero.
