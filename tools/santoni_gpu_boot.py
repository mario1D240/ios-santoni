#!/usr/bin/env python3
"""Package CI-built A505 diagnostics with private, locally supplied firmware.

Modes: 0 GPU-off control; 1 powered register probe; 2 CP memory proof;
3 CP proof + guarded offscreen 2D copy (no secure-mode control writes by default).
--stock-unsecure is a separate transition-only opt-in: one checked TRUST zero
write after owned CP proof, no pixels/PAS, state held until reboot after attempt.
--stock-pixels separately opts into the fixed 256-pixel offscreen test afterward.
--user-client enables scalar root-open requests; --user-preflight separately
exercises that interface from a kernel caller, without a userspace-boundary claim.
--user-exec separately embeds a recorded EL0 probe for the default-off0208
launcher, preserving HFS/Apple launchd and requiring new exact-kernel gates.
Never compile a kernel, install userland files, flash a partition or replace boot.img.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess

import adt
import mkpayload
import santoni_gpu_launcher_gate as launcher_gate
import santoni_remoted_platform_gate as remoted_gate
import santoni_gpu_renderer_gate as renderer_gate
import santoni_gpu_late_launch_gate as late_launch_gate
import santoni_gpu_user_fault_gate as user_fault_gate
import santoni_gpu_readiness_gate as readiness_gate
import santoni_gpu_ui_gate as ui_gate
from santoni_gpu_prepare import read_limited, ucode, zap_segments

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'out/proven-boot-948ea52'
SHARED = Path('/storage/emulated/0')
PROVEN_COMPONENT_SHA256 = {
    'boot.img': '948ea52e7cf7d3dc8f720647cf1832227930988044821269be541a800d694181',
    'Image': 'ca043f116a04601b5fe40d6c5cb2caa421a2dc1b9226935e485318c7dca35460',
    'santoni.adt': 'bde0238194efbfe053f19029b5ec80a1e972c795ad669df339eccef51cf87b8a',
    'init.macho': '79d03d591953d509d88d4b5c2d0fc59827b7a01cd95ada9e6e00868a006879d3',
}
FW_MAX = 32768
PROPERTY = 'santoni-gpu-firmware'
NAMES = ('a530_pm4.fw', 'a530_pfp.fw')
ZAP_PROPERTIES = ('santoni-gpu-zap-mdt', 'santoni-gpu-zap-b02')
ZAP_BINARY_GATE = 'PAS_allocation_preflight_wiring_checked'
SCM_BINARY_GATE = 'SCM_capability_probe_wiring_checked'
CACHE_BINARY_GATE = 'PAS_cache_preflight_wiring_checked'
STOCK_BINARY_GATE = 'stock_A505_transition_wiring_checked'
PIXEL_BINARY_GATE = 'stock_A505_pixel_wiring_checked'
G3_BINARY_GATE = 'G3_kernel_IB_wiring_checked'
SESSION_BINARY_GATE = 'G3_persistent_session_wiring_checked'
CONTROL_BINARY_GATE = 'mode1_control_session_unreachable_checked'
USER_BINARY_GATE = 'G3_scalar_user_client_wiring_checked'
USER_PREFLIGHT_BINARY_GATE = 'G3_scalar_user_preflight_wiring_checked'
USER_CONTROL_BINARY_GATE = 'mode1_control_scalar_user_unreachable_checked'


def validate_zap_option(mode, enabled):
    if type(enabled) is not bool or (enabled and mode != 3):
        raise ValueError('zap allocation preflight requires explicit boolean opt-in and mode 3')


def validate_probe_options(mode, zap_preflight, zap_scm_probe, zap_cache_preflight=False,
                           stock_unsecure=False, stock_pixels=False, g3=False, session=False,
                           user=False, user_preflight=False, user_exec=False, render_test=False):
    validate_zap_option(mode, zap_preflight)
    if type(zap_scm_probe) is not bool or (zap_scm_probe and mode != 3):
        raise ValueError('SCM capability probe requires explicit boolean opt-in and mode 3')
    if type(zap_cache_preflight) is not bool or (zap_cache_preflight and mode != 3):
        raise ValueError('PAS cache preflight requires explicit boolean opt-in and mode 3')
    if type(stock_unsecure) is not bool or (stock_unsecure and mode != 3):
        raise ValueError('stock TRUST transition requires explicit boolean opt-in and mode 3')
    if type(stock_pixels) is not bool or (stock_pixels and mode != 3):
        raise ValueError('stock pixel test requires explicit boolean opt-in and mode 3')
    if type(g3) is not bool or (g3 and mode != 3):
        raise ValueError('G3 kernel IB proof requires explicit boolean opt-in and mode 3')
    if type(session) is not bool or (session and mode != 3):
        raise ValueError('persistent session requires explicit boolean opt-in and mode 3')
    for name, enabled in (('scalar user client', user), ('kernel user preflight', user_preflight),
                          ('EL0 launcher', user_exec)):
        if type(enabled) is not bool or (enabled and mode != 3):
            raise ValueError(name + ' requires explicit boolean opt-in and mode 3')
    if type(render_test) is not bool or render_test and mode != 3:
        raise ValueError('full-buffer render test requires explicit mode3')
    if sum((zap_preflight, zap_scm_probe, zap_cache_preflight, stock_unsecure, stock_pixels,
            g3, session, user, user_preflight, user_exec, render_test)) > 1:
        raise ValueError('allocation, SCM, cache, stock transition-only and stock pixels are separate diagnostics')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def firmware_blob(bundle):
    """Use attested intake copies, not a filename-only guess or committed blobs."""
    import zlib
    target = json.loads((bundle / 'target.json').read_text())
    if (target.get('chipid'), target.get('gmem_bytes'), target.get('kernel_page_bytes')) != (
            0x05000500, 139264, 4096):
        raise ValueError('firmware preparation is not the Santoni A505/4K target')
    intake = json.loads((bundle / 'firmware-intake.json').read_text())
    entries = {item['file']: item for item in intake.get('ucode', [])}
    files, reports = [], []
    for name in NAMES:
        original = read_limited(bundle / 'firmware' / name, FW_MAX)
        if len(original) < 16 or int.from_bytes(original[:4], 'little') != 0:
            raise ValueError(f'{name}: unsupported/truncated firmware header')
        info, payload = ucode(original, name)
        if not info['version'] or info['version'] == 0xffffffff:
            raise ValueError(f'{name}: invalid firmware version')
        previous = entries.get(name)
        if not previous or any(previous.get(key) != info[key] for key in (
                'file_sha256', 'payload_sha256', 'version', 'payload_bytes', 'payload_dwords')):
            raise ValueError(f'{name}: firmware differs from the validated intake')
        saved_payload = read_limited(bundle / 'firmware' / (name + '.payload'), FW_MAX)
        if saved_payload != payload:
            raise ValueError(f'{name}: saved payload is not the original minus one dword')
        files.append(original)
        reports.append(info)
    a, b = files
    header = struct.pack('<8s6I', b'SGPUA505', 1, 0x05000500, len(a), len(b),
                         zlib.crc32(a), zlib.crc32(b))
    return header + a + b, reports


def add_firmware(tree, blob):
    root, end = adt.parse(tree)
    if end != len(tree):
        raise ValueError('baseline ADT has unparsed trailing data')
    chosen = [node for node in root.children if node.name == 'chosen']
    if len(chosen) != 1 or chosen[0].prop(PROPERTY) is not None:
        raise ValueError('ambiguous chosen node or existing GPU firmware property')
    chosen[0].props.append((PROPERTY, 0, blob))
    if len(chosen[0].props) > 256:
        raise ValueError('GPU ADT exceeds the saved shim property limit')
    return adt.serialize(root)


def zap_preflight_inputs(bundle):
    """Bound the reviewed single-b02 format and recheck the private intake hashes.

    These are read-only input properties, NOT an ADT-backed PAS workspace.
    Keep in step with 0199's actual adapter parser; authentication is unproven.
    """
    target = json.loads((bundle / 'target.json').read_text())
    if (target.get('chipid'), target.get('kernel_page_bytes'), target.get('vendor_zap_subsystem')) != (
            0x05000500, 4096, 'a506_zap'):
        raise ValueError('zap intake is not the Santoni a506_zap target')
    intake = json.loads((bundle / 'firmware-intake.json').read_text())
    report, copies = zap_segments(bundle / 'firmware', 'a506_zap')
    if intake.get('zap') != report:
        raise ValueError('zap files differ from the structurally validated intake')
    files = dict(copies)
    metadata = files['a506_zap.mdt']
    if (len(metadata) > 16384 or metadata[:7] != b'\x7fELF\x01\x01\x01' or
            struct.unpack_from('<HHI', metadata, 16) != (2, 164, 1) or
            struct.unpack_from('<HH', metadata, 40) != (52, 32)):
        raise ValueError('zap preflight requires bounded ELF32 QDSP6 metadata')
    phoff = struct.unpack_from('<I', metadata, 28)[0]
    count = struct.unpack_from('<H', metadata, 44)[0]
    loads = []
    for index in range(count):
        ptype, _, _, paddr, size, memsz, flags, alignment = struct.unpack_from(
            '<8I', metadata, phoff + index * 32)
        if ptype == 1 and (flags & 0x07000000) != 0x02000000 and memsz:
            loads.append((index, paddr, size, memsz, flags, alignment))
    if len(loads) != 1:
        raise ValueError('zap preflight supports exactly one relocatable b02 load')
    index, paddr, size, memsz, flags, alignment = loads[0]
    if (index != 2 or not flags & 0x08000000 or paddr % 4096 or
            not 0 < size <= memsz <= 65536 or alignment > 0x100000 or
            (alignment and alignment & (alignment - 1))):
        raise ValueError('zap b02 relocation/span/alignment exceeds the reviewed preflight')
    segment = files['a506_zap.b02']
    if len(segment) != size:
        raise ValueError('zap b02 payload size differs from metadata')
    inputs = dict(zip(ZAP_PROPERTIES, (metadata, segment)))
    evidence = {'metadata_sha256': sha(metadata), 'metadata_bytes': len(metadata),
                'segment_sha256': sha(segment), 'segment_bytes': size,
                'image_span_bytes': (memsz + 4095) & ~4095,
                'physical_alignment_bytes': max(alignment, 4096),
                'allocation_only': True, 'signature_or_TZ_acceptance_verified': False}
    return inputs, evidence


def add_zap_inputs(tree, inputs):
    if set(inputs) != set(ZAP_PROPERTIES) or any(not isinstance(value, bytes) or not value
                                               for value in inputs.values()):
        raise ValueError('exact nonempty zap input properties required')
    root, end = adt.parse(tree)
    chosen = [node for node in root.children if node.name == 'chosen']
    if end != len(tree) or len(chosen) != 1 or any(chosen[0].prop(name) is not None for name in ZAP_PROPERTIES):
        raise ValueError('ambiguous ADT or existing zap properties')
    chosen[0].props.extend((name, 0, inputs[name]) for name in ZAP_PROPERTIES)
    if len(chosen[0].props) > 256:
        raise ValueError('GPU ADT exceeds the saved shim property limit')
    return adt.serialize(root)


def add_probe_input(tree, probe):
    if not isinstance(probe, bytes) or len(probe) != 16635:
        raise ValueError('exact bounded EL0 probe input required')
    root, end = adt.parse(tree)
    chosen = [node for node in root.children if node.name == 'chosen']
    if end != len(tree) or len(chosen) != 1 or chosen[0].prop(launcher_gate.PROPERTY) is not None:
        raise ValueError('ambiguous ADT or existing EL0 probe property')
    chosen[0].props.append((launcher_gate.PROPERTY, 0, probe))
    if len(chosen[0].props) > 256:
        raise ValueError('GPU ADT exceeds the saved shim property limit')
    return adt.serialize(root)


def verify_tree_preservation(original, modified, zap_preflight=False, user_exec=False):
    before, _ = adt.parse(original)
    after, _ = adt.parse(modified)
    chosen = next(node for node in after.children if node.name == 'chosen')
    added = (PROPERTY, *ZAP_PROPERTIES) if zap_preflight else (PROPERTY,)
    if user_exec:
        added += (launcher_gate.PROPERTY,)
    chosen.props = [item for item in chosen.props if item[0] not in added]
    if adt.serialize(before) != adt.serialize(after):
        raise ValueError('GPU packaging altered other ADT/input/display properties')


def require_binary_audit(path, commit, run_id, kernel_sha, zap_preflight=False, zap_scm_probe=False,
                         zap_cache_preflight=False, stock_unsecure=False, stock_pixels=False, g3=False, session=False,
                         mode=None, user=False, user_preflight=False, user_exec=False, launcher_present=False, render_test=False):
    validate_probe_options(3, zap_preflight, zap_scm_probe, zap_cache_preflight,
                           stock_unsecure, stock_pixels, g3, session, user, user_preflight, user_exec, render_test)
    session_role = session or user or user_preflight or user_exec or render_test
    if not path.is_file():
        raise ValueError('run check_santoni_gpu_kernel.py first; a CI success alone is not GPU wiring proof')
    report = json.loads(path.read_text())
    launcher_gate.require_kernel_gates(report, mode, enabled=user_exec, present=launcher_present)
    scope = report.get('audit_scope', 'full')
    control = scope == 'mode1-control'
    if scope not in ('full', 'mode1-control'):
        raise ValueError('unrecognized binary audit scope')
    if control and (type(mode) is not int or mode != 1 or
            report.get('permitted_modes') != [1] or
            any(type(value) is not int for value in report.get('permitted_modes', [])) or
            report.get(CONTROL_BINARY_GATE) is not True or
            any((zap_preflight, zap_scm_probe, zap_cache_preflight, stock_unsecure, stock_pixels,
                 g3, session, user, user_preflight, user_exec, render_test))):
        raise ValueError('mode1-only binary audit cannot authorize this mode/experimental role')
    if (report.get('commit'), report.get('ci_run'), report.get('kernel_sha256')) != (
            commit, run_id, kernel_sha):
        raise ValueError('GPU binary audit belongs to another CI/kernel')
    if control and report.get('scalar_user_client_present') and report.get(USER_CONTROL_BINARY_GATE) is not True:
        raise ValueError('mode1 control must prove the scalar user roles unreachable')
    for key in ('GPU_driver_linked_and_BSD_startup_hook_present',
                'checked_changed_code_is_Cortex_A53_compatible',
                'MMIO_stores_use_real_registers_and_barriers',
                'explicit_result_cache_invalidation_present',
                'first_failure_and_rollback_diagnostics_present',
                'power_clock_path_is_separately_auditable',
                'checked_translation_and_clock_halt_helpers_linked',
                'target_clock_setup_and_restore_wiring_checked',
                'a505_paired_stop_and_resume_wiring_checked',
                'a505_vendor_SP_RMW_release_and_partial_failure_hold_checked',
                'firmware_is_not_embedded_in_CI_kernel'):
        if report.get(key) is not True:
            raise ValueError(f'GPU binary gate is missing: {key}')
    if zap_preflight and report.get(ZAP_BINARY_GATE) is not True:
        raise ValueError('zap preflight needs actual-binary allocator/opt-in wiring evidence')
    if zap_scm_probe and report.get(SCM_BINARY_GATE) is not True:
        raise ValueError('SCM capability probe needs actual-binary opt-in/scalar-frame/SMC wiring evidence')
    if zap_cache_preflight and report.get(CACHE_BINARY_GATE) is not True:
        raise ValueError('PAS cache preflight needs actual-binary alias/cache/lifetime wiring evidence')
    if (stock_unsecure or stock_pixels or g3 or session_role or report.get('stock_transition_present')) and report.get(STOCK_BINARY_GATE) is not True:
        raise ValueError('stock transition needs actual-binary opt-in/one-write/retention wiring evidence')
    if (stock_pixels or g3 or session_role or report.get('stock_pixels_present')) and report.get(PIXEL_BINARY_GATE) is not True:
        raise ValueError('stock pixels need actual-binary opt-in/readiness/submission/retention wiring evidence')
    if (g3 or session_role or report.get('g3_present')) and report.get(G3_BINARY_GATE) is not True:
        raise ValueError('G3 requires actual-binary opt-in/cold-mapping/checked-submission/retention wiring evidence')
    if (session_role or report.get('persistent_session_present')) and not control and report.get(SESSION_BINARY_GATE) is not True:
        raise ValueError('persistent session requires its own actual-binary lifetime/queue/submission gate')
    if (user or user_preflight or user_exec or report.get('scalar_user_client_present')) and not control and report.get(USER_BINARY_GATE) is not True:
        raise ValueError('scalar user client requires its own actual-binary ownership/copy/queue gate')
    if user_preflight and report.get(USER_PREFLIGHT_BINARY_GATE) is not True:
        raise ValueError('automatic user preflight requires its own actual-binary opt-in/waves/deadline gate')


def verify_proven_components(base):
    manifest = json.loads((base / 'SHA256.json').read_text())
    if manifest != PROVEN_COMPONENT_SHA256:
        raise ValueError('saved component manifest is incomplete or differs from the proven identity')
    for name, digest in PROVEN_COMPONENT_SHA256.items():
        if sha((base / name).read_bytes()) != digest:
            raise ValueError(f'known-good component changed: {name}')


def require_hardware_power(ci, commit, run_id, kernel_sha, remoted_platform=False):
    """CP/render delivery needs an identified USER result, never model success."""
    if type(remoted_platform) is not bool:
        raise ValueError('explicit boolean remoted hardware context required')
    path = ci / 'power-hardware-result.json'
    if not path.is_file():
        raise ValueError('CP/render requires an identified, input-confirmed successful mode-1 hardware result')
    gate = json.loads(path.read_text())
    if (not isinstance(gate, dict) or
            (gate.get('commit'), gate.get('ci_run'), gate.get('kernel_sha256')) !=
            (commit, run_id, kernel_sha) or
            any(gate.get(key) is not True for key in ('user_confirmed', 'identified', 'input_confirmed'))):
        raise ValueError('power hardware result is unidentified, unconfirmed or belongs to another kernel')
    required = {'pass': 1, 'stage': 3, 'error': 0, 'markers': 0, 'pixels': 0,
                'restored': 1, 'retained': 0, 'trust_read': 0, 'quiescent': 1,
                'smmu_restored': 1, 'power_pending': 0}
    result = gate.get('result')
    if (not isinstance(result, dict) or
            any(type(result.get(key)) is not int or result[key] != value for key, value in required.items())):
        raise ValueError('mode-1 hardware result did not pass power/readback, idle and complete restoration')
    name = gate.get('manifest')
    prefix = 'gpu-power-remoted-platform' if remoted_platform else 'gpu-power'
    if name not in (prefix + '-4core/manifest.json', prefix + '-trace-4core/manifest.json'):
        raise ValueError('hardware gate must identify a named four-core power-only manifest')
    manifest_path = ci / name
    manifest = json.loads(manifest_path.read_text())
    if (not isinstance(manifest, dict) or
            (manifest.get('commit'), manifest.get('ci_run'), manifest.get('kernel_sha256')) !=
            (commit, run_id, kernel_sha) or manifest.get('role') != 'power' or
            manifest.get('remoted_platform', False) is not remoted_platform or
            type(manifest.get('gpu_mode')) is not int or manifest['gpu_mode'] != 1 or
            type(manifest.get('cpus')) is not int or manifest['cpus'] != 4):
        raise ValueError('hardware result identifies a different kernel or non-power image')
    digest = gate.get('boot_sha256')
    power_image = (manifest_path.parent / 'boot.img').read_bytes()
    if (not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest) or
            digest != manifest.get('boot_sha256') or
            sha(power_image) != digest):
        raise ValueError('identified power image checksum differs from the tested manifest')
    if remoted_platform:
        if len(power_image) < 1632 or power_image[:8] != b'ANDROID!':
            raise ValueError('remoted power gate must bind an actual Android boot header')
        outer = (power_image[64:576] + power_image[608:1632]).split(b'\0', 1)[0].decode('ascii')
        args = command_args(outer)
        if (manifest.get('cmdline') != outer or args.get('santoni_remoted_platform') != '1' or
                args.get('santonigpu') != '1' or args.get('cpus') != '4'):
            raise ValueError('tested power image did not enable the exact remoted workaround context')


def command_args(line):
    """Use an unambiguous subset of XNU's grammar: ASCII, spaces, unique keys.

    XNU treats bare names as value 1 and does not use Python's generic whitespace
    splitting. Reject these ambiguities instead of validating a different parse.
    """
    if not line or any(ord(char) < 32 or ord(char) > 126 for char in line):
        raise ValueError('boot arguments must be printable single-line ASCII')
    args = {}
    for token in line.split(' '):
        if not token:
            continue
        name, equals, value = token.partition('=')
        if token in ('-v', 'santoni'):
            name, value = token, '1'
        elif (not equals or not value or '=' in value or
              not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*', name)):
            raise ValueError(f'unsupported or bare boot argument: {name}')
        if name in args:
            raise ValueError(f'duplicate boot argument: {name}')
        args[name] = value
    return args


def command_line(commit, mode, visible_console=False, zap_preflight=False, zap_scm_probe=False,
                 zap_cache_preflight=False, stock_unsecure=False, stock_pixels=False, g3=False, session=False,
                 user=False, user_preflight=False, user_exec=False, remoted_platform=False,
                 render_test=False, ui_presentation=False, ui_hz=30, graphics_renderer=False):
    if not re.fullmatch(r'[0-9a-f]{40}', commit) or type(mode) is not int or mode not in range(4):
        raise ValueError('exact commit SHA and integer mode 0..3 required')
    validate_probe_options(mode, zap_preflight, zap_scm_probe, zap_cache_preflight,
                           stock_unsecure, stock_pixels, g3, session, user, user_preflight, user_exec, render_test)
    remoted_gate.validate(mode, user_exec, remoted_platform, render_test)
    ui_gate.validate(mode, render_test, ui_presentation, ui_hz)
    renderer_gate.validate(mode, render_test, ui_presentation, graphics_renderer)
    session_role = session or user or user_preflight or user_exec or render_test
    recipe = subprocess.check_output(['git', 'show', f'{commit}:shim/build.sh'],
                                     cwd=ROOT, text=True)
    lines = re.findall(r'^CMDLINE="([^"]+)"$', recipe, re.MULTILINE)
    if len(lines) != 1:
        raise ValueError('committed recipe has an ambiguous command line')
    original = command_args(lines[0])
    if original.get('cpus') not in ('4', '8') or any(key in original for key in (
            'santonigpu', 'santonigpu_zap', 'santonigpu_scm', 'santonigpu_cache', 'santonigpu_stock',
            'santonigpu_pixels', 'santonigpu_submit', 'santonigpu_session', 'santonigpu_user', 'santonigpu_user_test',
            'santonigpu_user_exec', 'santonigpu_render', 'santonigpu_ui', 'santoni_remoted_platform',
            'santonigpu_graphics', 'santonigpu_raster', 'santonigpu_gles', 'santonigpu_renderer')):
        raise ValueError('unexpected CPU/GPU options in the committed recipe')
    line, count = re.subn(r'(?<!\S)cpus=[48](?!\S)', 'cpus=4', lines[0])
    if count != 1 or re.search(r'(?<!\S)santonigpu=', line):
        raise ValueError('unexpected CPU/GPU options in the committed recipe')
    if visible_console:
        line, replacements = re.subn(r'(?<!\S)sweetfb_noconsole=1(?!\S)',
                                      'sweetfb_noconsole=0', line)
        if replacements != 1:
            raise ValueError('trace image requires one explicit normal console-mute option')
    if not re.search(r'(?<!\S)santoniperf=', line):
        line += ' santoniperf=1'  # preserve the selected four-core baseline's read-only probe
    line += f' santonigpu={mode}'
    if zap_preflight or zap_scm_probe or zap_cache_preflight:
        line += ' santonigpu_zap=1'
    if zap_scm_probe:
        line += ' santonigpu_scm=1'
    if zap_cache_preflight:
        line += ' santonigpu_cache=1'
    if stock_unsecure or stock_pixels or g3 or session_role:
        line += ' santonigpu_stock=1'
    if stock_pixels or g3 or session_role:
        line += ' santonigpu_pixels=1'
    if g3 or session_role:
        line += ' santonigpu_submit=1'
    if session_role:
        line += ' santonigpu_session=1'
    if user or user_preflight or user_exec:
        line += ' santonigpu_user=1'
    if user_preflight:
        line += ' santonigpu_user_test=1'
    if user_exec:
        if original.get('launchdsuffix') not in (None, 'release'):
            raise ValueError('EL0 wrapper requires the original release launchd selection')
        if 'launchdsuffix' not in original:
            line += ' launchdsuffix=release'
        line += ' santonigpu_user_exec=1'
    if render_test:
        line += ' santonigpu_render=1'
    if graphics_renderer:
        line += (' santonigpu_ui=0 santonigpu_graphics=1 santonigpu_raster=1'
                 ' santonigpu_gles=1 santonigpu_renderer=1')
    if ui_presentation:
        line += ' santonigpu_ui=1'
        if ui_hz == 60:
            line, replacements = re.subn(r'(?<!\S)sweetfb_hz=30(?!\S)', 'sweetfb_hz=60', line)
            if replacements != 1:
                raise ValueError('60 Hz candidate requires the exact committed 30 Hz baseline')
    if remoted_platform:
        line += ' santoni_remoted_platform=1'
    args = command_args(line)
    if any(args.get(key) != value for key, value in (
            ('cpus', '4'), ('sweethidtest', '0'),
            ('sweetfb_noconsole', '0' if visible_console else '1'),
            ('sweetfb_hz', str(ui_hz)), ('sweetcpufreq', '0'), ('sweetfb_native', '1'),
            ('sweetfb_stayon', '1'), ('sweetlog', '1'), ('santoniperf', '1'),
            ('santonigpu', str(mode)), ('sweetbattery', '0'), ('santoni_varfix', '1'),
            ('rd', 'emmcroot0'), ('emmcrw', '1'), ('rootrw', '1'))):
        raise ValueError('GPU test must retain the normal four-core input/display settings')
    if len(line.encode()) >= 608:
        raise ValueError('command line would be truncated by the saved shim')
    return line


def package(commit, mode, bundle, visible_console=False, zap_preflight=False, zap_scm_probe=False,
            zap_cache_preflight=False, stock_unsecure=False, stock_pixels=False, g3=False, session=False,
            user=False, user_preflight=False, user_exec=False, probe_dir=None, probe_evidence=None,
            remoted_platform=False, skip_mode1=False, render_test=False, ui_presentation=False, ui_hz=30, graphics_renderer=False):
    if not re.fullmatch(r'[0-9a-f]{40}', commit) or type(mode) is not int or mode not in range(4):
        raise ValueError('exact commit SHA and mode 0..3 required')
    if type(skip_mode1) is not bool or (skip_mode1 and mode != 3):
        raise ValueError('--skip-mode1 requires explicit mode3 and a boolean opt-in')
    validate_probe_options(mode, zap_preflight, zap_scm_probe, zap_cache_preflight,
                           stock_unsecure, stock_pixels, g3, session, user, user_preflight, user_exec, render_test)
    remoted_gate.validate(mode, user_exec, remoted_platform, render_test)
    ui_gate.validate(mode, render_test, ui_presentation, ui_hz)
    renderer_gate.validate(mode, render_test, ui_presentation, graphics_renderer, skip_mode1)
    if user_exec and (probe_dir is None or probe_evidence is None):
        raise ValueError('EL0 launcher requires an explicit probe directory and completed linked evidence')
    if not user_exec and (probe_dir is not None or probe_evidence is not None):
        raise ValueError('probe inputs require the separate --user-exec role')
    session_role = session or user or user_preflight or user_exec or render_test
    ci = ROOT / f'out/ci-{commit[:7]}'
    run = json.loads((ci / 'run.json').read_text())
    if (run.get('headSha'), run.get('status'), run.get('conclusion')) != (
            commit, 'completed', 'success') or not run.get('repository_private'):
        raise ValueError('verified successful CI and restored repository privacy required')
    gate = json.loads((ROOT / 'out/active-boot.json').read_text())
    if gate.get('input_gate_confirmed') is not True or gate.get('selected_cpus') != 4:
        raise ValueError('physical-input/four-core prerequisite is not recorded')
    verify_proven_components(BASE)
    kernel = ci / 'kernel/kernel.development.santoni'
    sums = {}
    for line in (ci / 'kernel/SHA256SUMS').read_text().splitlines():
        digest, name = line.split(None, 1)
        sums[name.lstrip('*')] = digest
    kernel_data = kernel.read_bytes()
    kernel_sha = sha(kernel_data)
    if sums.get(kernel.name) != kernel_sha:
        raise ValueError('CI kernel checksum mismatch')
    require_binary_audit(ci / 'gpu-binary-audit.json', commit, run['databaseId'], kernel_sha,
                         zap_preflight, zap_scm_probe, zap_cache_preflight, stock_unsecure, stock_pixels, g3, session,
                         mode=mode, user=user, user_preflight=user_preflight, user_exec=user_exec,
                         launcher_present=launcher_gate.MARKER in kernel_data, render_test=render_test)
    remoted_audit = remoted_gate.require_audit(ci, commit, run['databaseId'], kernel_sha,
                                             remoted_gate.MARKER in kernel_data, remoted_platform)
    late_launch_audit = late_launch_gate.require_audit(ci, commit, run['databaseId'], kernel_sha,
                                                      late_launch_gate.MARKER in kernel_data,
                                                      late_launch_gate.DIAG_MARKER in kernel_data)
    user_fault_audit = user_fault_gate.require_audit(ci, commit, run['databaseId'], kernel_sha,
        user_fault_gate.MARKER in kernel_data or user_fault_gate.DETAIL_MARKER in kernel_data)
    readiness_audit = readiness_gate.require_audit(ci, commit, run['databaseId'], kernel_sha,
        readiness_gate.SYMBOL in kernel_data)
    from santoni_gpu_live_gate import require_audit as require_live_audit, MARKER as LIVE_MARKER, CP_MARKER
    live_audit = require_live_audit(ci,commit,run['databaseId'],kernel_sha,LIVE_MARKER in kernel_data,render_test,
                                  cp_readback_v2=CP_MARKER in kernel_data)
    ui_audit = ui_gate.require_audit(ci, commit, run['databaseId'], kernel_sha,
                                   ui_gate.MARKER in kernel_data, ui_presentation)
    renderer_audit = renderer_gate.require_audit(ci, commit, run['databaseId'], kernel_sha) if graphics_renderer else None
    command = command_line(commit, mode, visible_console, zap_preflight, zap_scm_probe,
                           zap_cache_preflight, stock_unsecure, stock_pixels, g3, session,
                           user, user_preflight, user_exec, remoted_platform, render_test, ui_presentation, ui_hz, graphics_renderer)
    if mode >= 2 and not skip_mode1:
        require_hardware_power(ci, commit, run['databaseId'], kernel_sha, remoted_platform)
    has_gpu_firmware = bool(mode and not (zap_scm_probe or zap_cache_preflight))
    blob, firmware = firmware_blob(bundle) if has_gpu_firmware else (b'', [])
    zap_inputs, zap_evidence = zap_preflight_inputs(bundle) if zap_preflight else ({}, None)
    probe_data, probe_delivery = launcher_gate.consume_probe(probe_dir, probe_evidence) if user_exec else (None, None)
    tree = (BASE / 'santoni.adt').read_bytes()
    if has_gpu_firmware:
        original = tree
        tree = add_firmware(tree, blob)
        if zap_preflight:
            tree = add_zap_inputs(tree, zap_inputs)
        if user_exec:
            tree = add_probe_input(tree, probe_data)
        verify_tree_preservation(original, tree, zap_preflight, user_exec)
    role = ('control', 'power', 'cp', 'render')[mode]
    if zap_preflight:
        role = 'zap-preflight'
    if zap_scm_probe:
        role = 'zap-scm-probe'
    if zap_cache_preflight:
        role = 'zap-cache-preflight'
    if stock_unsecure:
        role = 'stock-unsecure'
    if stock_pixels:
        role = 'stock-pixels'
    if g3:
        role = 'g3-submit'
    if session:
        role = 'g3-session'
    if user:
        role = 'user-client'
    if user_preflight:
        role = 'user-preflight'
    if user_exec:
        role = 'user-exec'
    if render_test:
        role = 'render-live'
    if ui_presentation:
        role = 'ui-presentation' + ('-60hz' if ui_hz == 60 else '')
    if graphics_renderer:
        role = 'ui-gles-renderer'
    trace_suffix = '-trace' if visible_console else ''
    remoted_suffix = '-remoted-platform' if remoted_platform else ''
    power_suffix = '-skip-mode1' if skip_mode1 else ''
    dest = ci / f'gpu-{role}{remoted_suffix}{trace_suffix}{power_suffix}-4core'
    if dest.exists() and any(dest.iterdir()):
        raise ValueError(f'refusing to overwrite existing GPU output: {dest}')
    dest.mkdir(parents=True, exist_ok=True)
    (dest / 'santoni.adt').write_bytes(tree)
    payload, info = mkpayload.build(str(kernel), str(dest / 'santoni.adt'), command,
                                    str(BASE / 'init.macho'))
    (dest / 'payload.bin').write_bytes(payload)
    subprocess.run(['python3', str(ROOT / 'tools/mkbootimg.py'), '--kernel', str(BASE / 'Image'),
                    '--ramdisk', str(dest / 'payload.bin'), '--output', str(dest / 'boot.img'),
                    '--base', '0x80000000', '--pagesize', '2048', '--header_version', '0',
                    '--cmdline', command], check=True, cwd=ROOT, timeout=60)
    image = (dest / 'boot.img').read_bytes()
    magic, ks, ka, rs, ra, ss, sa, tags, page, hv, osv = struct.unpack_from('<8s10I', image)
    if (magic, page, hv, ss, ka, ra) != (b'ANDROID!', 2048, 0, 0, 0x80008000, 0x81000000):
        raise ValueError('boot image header differs from the verified normal recipe')
    if image[page:page + ks] != (BASE / 'Image').read_bytes():
        raise ValueError('saved working shim/DTB changed')
    offset = page + (ks + page - 1) // page * page
    if image[offset:offset + rs] != payload:
        raise ValueError('boot image payload mismatch')
    outer = (image[64:576] + image[608:1632]).split(b'\0', 1)[0]
    inner = payload[0x48:0x2a8].split(b'\0', 1)[0]
    if outer != inner or inner != command.encode():
        raise ValueError('outer/inner command lines disagree')
    # Verify the final embedded ADT, after the normal RAMDisk addition.
    adt_offset, adt_size = struct.unpack_from('<2Q', payload, 0x20)
    final_tree, _ = adt.parse(payload[adt_offset:adt_offset + adt_size])
    chosen = next(node for node in final_tree.children if node.name == 'chosen')
    if chosen.prop(PROPERTY) != (blob if has_gpu_firmware else None):
        raise ValueError('firmware payload property missing or changed')
    if any(chosen.prop(name) != zap_inputs.get(name) for name in ZAP_PROPERTIES):
        raise ValueError('zap payload properties missing, changed or unexpectedly present')
    if chosen.prop(launcher_gate.PROPERTY) != probe_data:
        raise ValueError('EL0 probe payload missing, changed or unexpectedly present')
    if info['kernel_end'] is None:
        raise ValueError('payload has no reserved kernel-data boundary')
    boot_sha = sha(image)
    shared = SHARED
    staged = []
    if shared.is_dir():
        named = shared / f'boot-gpu-{role}{remoted_suffix}{trace_suffix}{power_suffix}-{commit[:7]}-4core.img'
        if named.exists() and sha(named.read_bytes()) != boot_sha:
            raise ValueError(f'refusing to overwrite a different image: {named}')
        if not named.exists():
            shutil.copy2(dest / 'boot.img', named)
        if sha(named.read_bytes()) != boot_sha:
            raise ValueError('shared image checksum mismatch')
        staged.append(str(named))
    manifest = {'commit': commit, 'ci_run': run['databaseId'], 'kernel_sha256': kernel_sha,
                'binary_audit_scope': json.loads((ci / 'gpu-binary-audit.json').read_text()).get('audit_scope', 'full'),
                'boot_sha256': boot_sha, 'boot_bytes': len(image), 'cmdline': command,
                'cpus': 4, 'gpu_mode': mode, 'role': role, 'firmware': firmware,
                'visible_console': visible_console,
                'firmware_blob_sha256': sha(blob) if blob else None,
                'hardware_verified': False, 'UI_acceleration_enabled': False,
                'mode1_hardware_validation_skipped': skip_mode1,
                'mode1_hardware_check': 'skipped-explicitly' if skip_mode1 else
                                        'passed' if mode >= 2 else 'not-required',
                'secure_mode_control_writes': stock_unsecure or stock_pixels or g3 or session_role, 'staged': staged,
                 'baseline_image_preserved': gate['image']}
    if remoted_platform:
        manifest.update(remoted_platform=True,
                        remoted_platform_scope='successful exec of exact /usr/libexec/remoted regular root vnode only',
                        remoted_platform_signature_authentication_granted=False,
                        remoted_platform_audit_kernel_sha256=remoted_audit['kernel_sha256'])
    if late_launch_audit is not None:
        manifest.update(late_launch_observation=True,
                        late_launch_observation_scope='mode3 CPU readiness/mount snapshot after user publication and mutex release',
                        late_launch_observation_kernel_sha256=late_launch_audit['kernel_sha256'])
    if user_fault_audit is not None:
        manifest.update(pid1_user_fault_observation=True,
                        pid1_user_fault_observation_scope='first terminal user exception frame on the explicit mode3 launcher role',
                        pid1_user_fault_observation_kernel_sha256=user_fault_audit['kernel_sha256'])
    if readiness_audit is not None:
        manifest.update(EL0_trace_pause_policy_checked=True,
                        EL0_trace_pause_policy_kernel_sha256=readiness_audit['kernel_sha256'],
                        EL0_trace_pauses_skipped_for_prepared_role=True)
    if zap_preflight:
        manifest.update(zap_preflight=True, zap=zap_evidence, SCM_calls_enabled=False)
    if zap_scm_probe:
        manifest.update(zap_scm_probe=True, zap_preflight=False, SCM_calls_enabled=True,
                        SCM_scope='scalar convention/availability/PAS-ID13 support only',
                        PAS_load_auth_reset_enabled=False, GPU_probe_continuation_enabled=False,
                        firmware_addresses_sent=False)
    if zap_cache_preflight:
        manifest.update(zap_cache_preflight=True, zap_preflight=False, SCM_calls_enabled=False,
                        PAS_load_auth_reset_enabled=False, GPU_probe_continuation_enabled=False,
                        firmware_addresses_sent=False)
    if stock_unsecure:
        manifest.update(stock_unsecure=True, SCM_calls_enabled=False,
                        PAS_load_auth_reset_enabled=False, GPU_render_continuation_enabled=False,
                        security_scope='A505 only: one checked TRUST_CNTL=0 after owned CP proof',
                        post_attempt_state='held until reboot, no MMIO/reset/cleanup after echo',
                        hardware_safety_verified=False)
    if stock_pixels or g3 or session_role:
        manifest.update(stock_pixels=True, stock_unsecure=True, SCM_calls_enabled=False,
                        PAS_load_auth_reset_enabled=False, GPU_render_continuation_enabled=True,
                        rendering_scope='fixed owned 16x16 RGBA copy/fence/CPU comparison only',
                        post_attempt_state='held until reboot; no reset/cleanup after pixel success or failure',
                        hardware_safety_verified=False)
    if g3 or session_role:
        manifest.update(g3=True, kernel_IB_only=True, user_submission_API=False,
                        G3_scope='cold guard-paged owned BOs, two whitelisted memory-write IBs and sequence fences',
                        live_PTE_updates=False, physical_pool_bytes=98304,
                        post_attempt_state='held until reboot; no live unmap/reset/release after exposure')
    if session_role:
        manifest.update(session=True, session_request_limit=32, session_outstanding_limit=4,
                        session_scope='persistent kernel WRITE4 queue; fixed cold mappings; 32 further IBs; no user API',
                        session_control_cap_bytes=16384, ring_wrap_enabled=False,
                        callback_nonreturn_bounded=False)
    if render_test:
        manifest.update(render_test=True, live_PTE_updates=True, session=False,
                        session_bootstrap_used=True, session_request_limit=0, session_outstanding_limit=0,
                        session_scope='legacy bootstrap only; two full owned BGRA copies; no queue/client/EL0 workload',
                        kernel_IB_only=False, user_submission_API=False,
                        rendering_scope='two owned 720x1280 BGRA copies, stride3072, sequence fences and pixel/padding readback',
                        render_source_bytes=3932160, render_destination_bytes=3932160,
                        render_retained_new_bytes=7892992, render_retained_legacy_bytes=98304,
                        live_render_binary_kernel_sha256=live_audit['kernel_sha256'],
                        GPU_presentation_enabled=False, UI_acceleration_verified=False,
                        post_attempt_state='all old/new referenced storage retained until reboot; no live unmap')
    if ui_presentation:
        manifest.update(ui_presentation=True, GPU_presentation_enabled=True,
                        UI_refresh_hz_requested=ui_hz, sustained_UI_fps_verified=False,
                        UI_acceleration_verified=False, GLES_enabled=False,
                        Mesa_enabled=False, user_submission_API=False,
                        rendering_scope='eligible retained 720x1280 BGRA IOSurface GPU copies; CPU BGR24 panel conversion',
                        ring_wrap_enabled=True, UI_import_PTE='read-only',
                        UI_binary_kernel_sha256=ui_audit['kernel_sha256'],
                        UI_binary_audit_sha256=sha((ci / 'ui-binary-audit.json').read_bytes()),
                        post_attempt_state='owned backing and current import retained; failure quarantines both imports; no retry')
    if user or user_preflight or user_exec:
        manifest.update(scalar_client_interface_present=True, scalar_packet_bytes=128,
                        user_submission_API=not user_preflight,
                        user_scope='one retained root-open task; four copied values; sanitized results; no BO maps',
                        user_preflight=user_preflight, manual_user_open_allowed=not user_preflight,
                        preflight_caller='kernel' if user_preflight else None,
                        userspace_syscall_boundary_exercised=False,
                        session_scope='scalar WRITE4 admission into the persistent worker; fixed cold mappings; 32 further IBs')
    if user_exec:
        manifest.update(user_exec=True, probe_delivery=probe_delivery,
                        launcher_path='/dev/sgpu/sbin/launchd', original_init='/sbin/launchd',
                        persistent_rootfs_writes=False, launcher_CPU_backing='retained until reboot',
                        launcher_hardware_verified=False)
    if graphics_renderer:
        manifest.update(graphics_renderer=True, GLES_enabled=True, Mesa_enabled=True,
                        UI_acceleration_enabled=True,
                        UI_acceleration_requested=True, UI_acceleration_verified=False,
                        UI_refresh_hz_requested=30, sustained_UI_fps_verified=False,
                        renderer_client_audit_kernel_sha256=renderer_audit['kernel_sha256'],
                        renderer_client_audit_sha256=sha((ci/'renderer-client-binary-audit.json').read_bytes()),
                        renderer_scope='opted-in EAGL/Mesa shaders through owner-bound BO/IB client; hardware trial',
                        required_rootfs='audited EAGL/loader and both backboardd launch plists installed')
    (dest / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('commit')
    parser.add_argument('--mode', type=int, choices=range(4), required=True,
                        help='explicit mode required; CP/render requires a mode1 hardware pass unless mode3 uses --skip-mode1')
    parser.add_argument('--skip-mode1', action='store_true',
                        help='explicit mode3 packaging without a mode1 hardware run; retains binary audits and records the skipped check')
    parser.add_argument('--bundle', type=Path, default=ROOT / 'out/santoni-gpu-msm49-fw-working')
    parser.add_argument('--visible-console', action='store_true',
                         help='explicit diagnostic: keep kernel text visible over UI; preserve normal image')
    probes = parser.add_mutually_exclusive_group()
    probes.add_argument('--zap-preflight', action='store_true',
                        help='mode-3 opt-in allocation-only probe; no PAS/SMC or secure-mode packets')
    probes.add_argument('--zap-scm-probe', action='store_true',
                        help='mode-3 opt-in REAL SCM scalar capability queries; no PAS load/auth or GPU work')
    probes.add_argument('--zap-cache-preflight', action='store_true',
                        help='mode-3 owned alias/cache/restore preflight; no firmware, SCM or GPU work')
    probes.add_argument('--stock-unsecure', action='store_true',
                        help='mode-3 stock A505 checked TRUST transition ONLY; no PAS/pixels, holds state until reboot')
    probes.add_argument('--stock-pixels', action='store_true',
                        help='separate mode-3 stock transition plus owned 256-pixel test; no PAS/UI/cleanup')
    probes.add_argument('--g3-submit', action='store_true',
                        help='mode-3 stock/pixel proof then two owned validated kernel IBs; no user API or PAS')
    probes.add_argument('--g3-session', action='store_true',
                        help='separate kernel-only persistent WRITE4 session; requires its own binary/hardware gates')
    probes.add_argument('--user-client', action='store_true',
                        help='separate root-open scalar client; requires new binary and same-kernel mode1 gates')
    probes.add_argument('--user-preflight', action='store_true',
                        help='automatic KERNEL caller of scalar client; userspace boundary remains unproven')
    probes.add_argument('--user-exec', action='store_true',
                        help='separate boot-only EL0 launcher; needs new exact-kernel gates and linked probe evidence')
    probes.add_argument('--render-test', action='store_true',
                        help='mode3 full owned BGRA copy/readback worker; no display integration; requires own-kernel live audit')
    parser.add_argument('--ui-presentation', action='store_true',
                        help='with mode3 --render-test: IOSurface GPU copy + CPU panel conversion; requires own-kernel UI audit')
    parser.add_argument('--graphics-renderer', action='store_true',
                        help='mode3/render-test EAGL/Mesa renderer trial; requires own-kernel client audit and power evidence unless --skip-mode1')
    parser.add_argument('--ui-hz', type=int, choices=(30, 60), default=30,
                        help='UI-copy cadence on the existing 60 Hz timer; 60 creates a distinct candidate, sustained FPS unverified')
    parser.add_argument('--probe-dir', type=Path)
    parser.add_argument('--probe-evidence', type=Path)
    parser.add_argument('--remoted-platform', action='store_true',
                        help='explicit0212 root-vnode remoted platform workaround; separate named mode1/EL0 image')
    args = parser.parse_args()
    print(json.dumps(package(args.commit, args.mode, args.bundle, args.visible_console,
                             args.zap_preflight, args.zap_scm_probe,
                             zap_cache_preflight=args.zap_cache_preflight,
                             stock_unsecure=args.stock_unsecure, stock_pixels=args.stock_pixels,
                             g3=args.g3_submit, session=args.g3_session,
                             user=args.user_client, user_preflight=args.user_preflight,
                             user_exec=args.user_exec, probe_dir=args.probe_dir,
                             probe_evidence=args.probe_evidence,
                             remoted_platform=args.remoted_platform, skip_mode1=args.skip_mode1,
                             render_test=args.render_test, ui_presentation=args.ui_presentation,
                             ui_hz=args.ui_hz, graphics_renderer=args.graphics_renderer), indent=2))


if __name__ == '__main__':
    main()
