#!/usr/bin/env python3
"""Portable preflight tests: no kernel builds, firmware or output images needed."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'tests'))
import santoni_gpu_boot as boot
from test_santoni_gpu_prepare import mdt32

TMP = Path('/data/data/com.termux/files/usr/tmp/opencode')
SHA = 'a' * 40
RUN = 123
KERNEL = b'synthetic audited kernel, not executable'
KERNEL_SHA = hashlib.sha256(KERNEL).hexdigest()
KEYS = ('GPU_driver_linked_and_BSD_startup_hook_present',
        'checked_changed_code_is_Cortex_A53_compatible',
        'MMIO_stores_use_real_registers_and_barriers',
        'explicit_result_cache_invalidation_present',
        'first_failure_and_rollback_diagnostics_present',
        'power_clock_path_is_separately_auditable',
        'checked_translation_and_clock_halt_helpers_linked',
        'target_clock_setup_and_restore_wiring_checked',
        'a505_paired_stop_and_resume_wiring_checked',
        'a505_vendor_SP_RMW_release_and_partial_failure_hold_checked',
        'firmware_is_not_embedded_in_CI_kernel')
RECIPE = ('CMDLINE="-v santoni cpus=8 sweethidtest=0 sweetfb_noconsole=1 '
          'sweetfb_hz=30 sweetcpufreq=0 sweetfb_native=1 sweetfb_stayon=1 '
          'sweetlog=1 sweetbattery=0 santoni_varfix=1 rd=emmcroot0 emmcrw=1 rootrw=1"\n')


class StopBeforeFirmware(RuntimeError):
    pass


class BootGates(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gpu-preflight-', dir=TMP if TMP.is_dir() else None)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / 'proven'
        self.base.mkdir()
        self.proven = {}
        for name in boot.PROVEN_COMPONENT_SHA256:
            data = ('synthetic fixed component: ' + name).encode()
            (self.base / name).write_bytes(data)
            self.proven[name] = hashlib.sha256(data).hexdigest()
        (self.base / 'SHA256.json').write_text(json.dumps(self.proven))
        context = patch.object(boot, 'PROVEN_COMPONENT_SHA256', self.proven)
        context.start()
        self.addCleanup(context.stop)
        self.ci = self.root / 'out/ci-aaaaaaa'
        kernel = self.ci / 'kernel/kernel.development.santoni'
        kernel.parent.mkdir(parents=True)
        kernel.write_bytes(KERNEL)
        (kernel.parent / 'SHA256SUMS').write_text(KERNEL_SHA + '  ' + kernel.name + '\n')
        (self.ci / 'run.json').write_text(json.dumps({
            'headSha': SHA, 'status': 'completed', 'conclusion': 'success',
            'repository_private': True, 'databaseId': RUN}))
        (self.root / 'out/active-boot.json').write_text(json.dumps({
            'input_gate_confirmed': True, 'selected_cpus': 4, 'image': 'untouched normal baseline'}))
        (self.ci / 'gpu-binary-audit.json').write_text(json.dumps({
            'commit': SHA, 'ci_run': RUN, 'kernel_sha256': KERNEL_SHA, **{key: True for key in KEYS}}))
        image = self.ci / 'gpu-power-trace-4core/boot.img'
        image.parent.mkdir()
        image.write_bytes(b'synthetic identified power image, not bootable')
        self.image = image
        self.manifest = {'commit': SHA, 'ci_run': RUN, 'kernel_sha256': KERNEL_SHA,
                         'role': 'power', 'gpu_mode': 1, 'cpus': 4,
                         'boot_sha256': hashlib.sha256(image.read_bytes()).hexdigest()}
        self.manifest_path = image.parent / 'manifest.json'
        self.manifest_path.write_text(json.dumps(self.manifest))
        self.gate = {'commit': SHA, 'ci_run': RUN, 'kernel_sha256': KERNEL_SHA,
                     'user_confirmed': True, 'identified': True, 'input_confirmed': True,
                     'manifest': 'gpu-power-trace-4core/manifest.json',
                     'boot_sha256': self.manifest['boot_sha256'],
                     'result': {'pass': 1, 'stage': 3, 'error': 0, 'markers': 0, 'pixels': 0,
                                'restored': 1, 'retained': 0, 'trust_read': 0, 'quiescent': 1,
                                'smmu_restored': 1, 'power_pending': 0}}

    def write_gate(self, gate=None):
        (self.ci / 'power-hardware-result.json').write_text(json.dumps(self.gate if gate is None else gate))

    def test_fixed_components_pass_but_empty_partial_or_rewritten_manifests_fail(self):
        boot.verify_proven_components(self.base)
        bad = [{}, [], {**self.proven, '../unowned': 'b' * 64}]
        bad.extend({name: value for name, value in self.proven.items() if name != missing}
                   for missing in self.proven)
        bad.append({**self.proven, 'Image': 'c' * 64})
        for manifest in bad:
            with self.subTest(manifest=manifest):
                (self.base / 'SHA256.json').write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    boot.verify_proven_components(self.base)

    def test_changed_components_fail_even_if_the_manifest_is_rehashed(self):
        for name in self.proven:
            path = self.base / name
            original = path.read_bytes()
            path.write_bytes(original + b'changed')
            for rehash in (False, True):
                manifest = dict(self.proven)
                if rehash:
                    manifest[name] = hashlib.sha256(path.read_bytes()).hexdigest()
                (self.base / 'SHA256.json').write_text(json.dumps(manifest))
                with self.subTest(name=name, rehash=rehash), self.assertRaises(ValueError):
                    boot.verify_proven_components(self.base)
            path.write_bytes(original)

    def test_only_a_positive_identified_user_power_result_is_accepted(self):
        with self.assertRaises(ValueError):
            boot.require_hardware_power(self.ci, SHA, RUN, KERNEL_SHA)
        self.write_gate()
        boot.require_hardware_power(self.ci, SHA, RUN, KERNEL_SHA)
        invalid = []
        for key in ('user_confirmed', 'identified', 'input_confirmed'):
            invalid.extend(({**self.gate, key: False}, {**self.gate, key: 1}))
        invalid.extend(({**self.gate, 'commit': 'd' * 40}, {**self.gate, 'ci_run': RUN + 1},
                        {**self.gate, 'kernel_sha256': 'd' * 64},
                        {**self.gate, 'manifest': '../unowned/manifest.json'}))
        for key in self.gate['result']:
            for value in (None, True, self.gate['result'][key] + 1):
                item = copy.deepcopy(self.gate)
                item['result'][key] = value
                invalid.append(item)
        for item in invalid:
            with self.subTest(gate=item):
                self.write_gate(item)
                with self.assertRaises(ValueError):
                    boot.require_hardware_power(self.ci, SHA, RUN, KERNEL_SHA)

    def test_power_manifest_and_image_identity_are_checked(self):
        self.write_gate()
        for key, value in (('commit', 'd' * 40), ('ci_run', RUN + 1), ('kernel_sha256', 'd' * 64),
                           ('role', 'render'), ('gpu_mode', 0), ('gpu_mode', True), ('cpus', 8),
                           ('boot_sha256', 'd' * 64)):
            with self.subTest(key=key, value=value):
                self.manifest_path.write_text(json.dumps({**self.manifest, key: value}))
                with self.assertRaises(ValueError):
                    boot.require_hardware_power(self.ci, SHA, RUN, KERNEL_SHA)
        self.manifest_path.write_text(json.dumps(self.manifest))
        self.image.write_bytes(b'changed image')
        with self.assertRaises(ValueError):
            boot.require_hardware_power(self.ci, SHA, RUN, KERNEL_SHA)

    def test_packaging_checks_the_hardware_gate_before_firmware_or_output(self):
        with patch.object(boot, 'ROOT', self.root), patch.object(boot, 'BASE', self.base), \
                patch.object(boot, 'command_line', return_value='cpus=4 santonigpu=1'), \
                patch.object(boot, 'firmware_blob', side_effect=StopBeforeFirmware) as firmware:
            for mode in (2, 3):
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    boot.package(SHA, mode, self.root / 'absent-firmware')
            firmware.assert_not_called()
            self.assertFalse((self.ci / 'gpu-cp-4core').exists())
            self.assertFalse((self.ci / 'gpu-render-4core').exists())
            with self.assertRaises(StopBeforeFirmware):
                boot.package(SHA, 1, self.root / 'absent-firmware')
            self.write_gate()
            for mode in (2, 3):
                with self.subTest(mode=mode), self.assertRaises(StopBeforeFirmware):
                    boot.package(SHA, mode, self.root / 'absent-firmware')

    def test_CLI_does_not_default_to_render(self):
        with patch.object(sys, 'argv', ['santoni_gpu_boot.py', SHA]), \
                patch.object(boot, 'package') as package, patch('sys.stderr'):
            with self.assertRaises(SystemExit) as raised:
                boot.main()
            self.assertEqual(raised.exception.code, 2)
            package.assert_not_called()

    def test_skip_mode1_is_explicit_mode3_only(self):
        for mode, skip in ((0, True), (1, True), (2, True), (3, 1), (3, None), (3, 'true')):
            with self.subTest(mode=mode, skip=skip), self.assertRaises(ValueError):
                boot.package(SHA, mode, self.root / 'absent', skip_mode1=skip)
        with patch.object(sys, 'argv', ['boot', SHA, '--mode', '3', '--skip-mode1']), \
                patch.object(boot, 'package', return_value={}) as package, patch('sys.stdout'):
            boot.main()
            self.assertTrue(package.call_args.kwargs['skip_mode1'])

    def test_skip_mode1_retains_binary_audit_and_creates_no_hardware_result(self):
        audit = self.ci / 'gpu-binary-audit.json'
        original = json.loads(audit.read_text())
        with patch.object(boot, 'ROOT', self.root), patch.object(boot, 'BASE', self.base), \
                patch.object(boot, 'command_line', return_value='cpus=4 santonigpu=3'), \
                patch.object(boot, 'firmware_blob', side_effect=StopBeforeFirmware) as firmware:
            with self.assertRaisesRegex(ValueError, 'mode-1 hardware result'):
                boot.package(SHA, 3, self.root / 'absent')
            firmware.assert_not_called()
            with self.assertRaises(StopBeforeFirmware):
                boot.package(SHA, 3, self.root / 'absent', skip_mode1=True)
            self.assertFalse((self.ci / 'power-hardware-result.json').exists())
            self.assertFalse((self.ci / 'gpu-render-skip-mode1-4core').exists())
            audit.write_text(json.dumps({**original, 'kernel_sha256': '0'*64}))
            firmware.reset_mock()
            with self.assertRaises(ValueError):
                boot.package(SHA, 3, self.root / 'absent', skip_mode1=True)
            firmware.assert_not_called()

    def test_stock_role_requires_mode3_and_excludes_every_zap_role(self):
        for mode in range(4):
            for opt in (False, True, 0, 1, None, '1'):
                good = type(opt) is bool and (not opt or mode == 3)
                with self.subTest(mode=mode, opt=opt):
                    if good:
                        boot.validate_probe_options(mode, False, False, False, opt)
                    else:
                        with self.assertRaises(ValueError):
                            boot.validate_probe_options(mode, False, False, False, opt)
        for role in range(3):
            flags = [False, False, False]; flags[role] = True
            with self.assertRaises(ValueError):
                boot.validate_probe_options(3, *flags, stock_unsecure=True)
        with patch.object(boot.subprocess, 'check_output', return_value=RECIPE):
            power = boot.command_args(boot.command_line(SHA, 1, visible_console=True))
            stock = boot.command_args(boot.command_line(SHA, 3, visible_console=True, stock_unsecure=True))
            self.assertEqual(stock, {**power, 'santonigpu': '3', 'santonigpu_stock': '1'})
            self.assertFalse(set(stock) & {'santonigpu_zap', 'santonigpu_scm', 'santonigpu_cache'})
        for role in ('--zap-preflight', '--zap-scm-probe', '--zap-cache-preflight'):
            with patch.object(sys, 'argv', ['boot', SHA, '--mode', '3', '--stock-unsecure', role]), \
                    patch.object(boot, 'package') as package, patch('sys.stderr'):
                with self.assertRaises(SystemExit):
                    boot.main()
                package.assert_not_called()

    def test_stock_packaging_requires_binary_gate_and_new_kernel_power_first(self):
        audit = self.ci / 'gpu-binary-audit.json'
        original = json.loads(audit.read_text())
        for value in (None, False, 1):
            audit.write_text(json.dumps({**original, boot.STOCK_BINARY_GATE: value}))
            with self.assertRaises(ValueError):
                boot.require_binary_audit(audit, SHA, RUN, KERNEL_SHA, stock_unsecure=True)
        audit.write_text(json.dumps({**original, boot.STOCK_BINARY_GATE: True}))
        boot.require_binary_audit(audit, SHA, RUN, KERNEL_SHA, stock_unsecure=True)
        with patch.object(boot, 'ROOT', self.root), patch.object(boot, 'BASE', self.base), \
                patch.object(boot, 'command_line', return_value='cpus=4 santonigpu=3 santonigpu_stock=1'), \
                patch.object(boot, 'firmware_blob', side_effect=StopBeforeFirmware) as firmware:
            with self.assertRaises(ValueError):
                boot.package(SHA, 3, self.root / 'absent', stock_unsecure=True)
            firmware.assert_not_called()
            self.assertFalse((self.ci / 'gpu-stock-unsecure-4core').exists())
            self.write_gate()
            with self.assertRaises(StopBeforeFirmware):
                boot.package(SHA, 3, self.root / 'absent', stock_unsecure=True)
        audit.write_text(json.dumps({**original, 'stock_transition_present': True}))
        # The modified write callback affects all modes: also require its gate for mode1.
        with self.assertRaises(ValueError):
            boot.require_binary_audit(audit, SHA, RUN, KERNEL_SHA)

    def test_pixels_are_a_distinct_exact_opt_in_not_a_stock_only_alias(self):
        with patch.object(boot.subprocess,'check_output',return_value=RECIPE):
            power=boot.command_args(boot.command_line(SHA,1,visible_console=True))
            only=boot.command_args(boot.command_line(SHA,3,visible_console=True,stock_unsecure=True))
            pixels=boot.command_args(boot.command_line(SHA,3,visible_console=True,stock_pixels=True))
            self.assertEqual(pixels,{**power,'santonigpu':'3','santonigpu_stock':'1','santonigpu_pixels':'1'})
            self.assertEqual(only,{**power,'santonigpu':'3','santonigpu_stock':'1'})
            for mode in (0,1,2):
                with self.assertRaises(ValueError): boot.command_line(SHA,mode,stock_pixels=True)
            for value in (1,0,None,'1'):
                with self.assertRaises(ValueError): boot.command_line(SHA,3,stock_pixels=value)
            for field in ('zap_preflight','zap_scm_probe','zap_cache_preflight','stock_unsecure'):
                with self.assertRaises(ValueError): boot.command_line(SHA,3,stock_pixels=True,**{field:True})

    def test_pixels_require_their_binary_gate_and_exact_new_kernel_power(self):
        audit=self.ci/'gpu-binary-audit.json'; original=json.loads(audit.read_text())
        original[boot.STOCK_BINARY_GATE]=True
        audit.write_text(json.dumps(original))
        for value in (False,1,None):
            audit.write_text(json.dumps({**original,boot.PIXEL_BINARY_GATE:value}))
            with self.assertRaises(ValueError): boot.require_binary_audit(audit,SHA,RUN,KERNEL_SHA,stock_pixels=True)
        audit.write_text(json.dumps({**original,boot.PIXEL_BINARY_GATE:True}))
        boot.require_binary_audit(audit,SHA,RUN,KERNEL_SHA,stock_pixels=True)
        with patch.object(boot,'ROOT',self.root),patch.object(boot,'BASE',self.base), \
                patch.object(boot,'command_line',return_value='cpus=4 santonigpu=3 santonigpu_stock=1 santonigpu_pixels=1'), \
                patch.object(boot,'firmware_blob',side_effect=StopBeforeFirmware) as firmware:
            with self.assertRaises(ValueError): boot.package(SHA,3,self.root/'absent',stock_pixels=True)
            firmware.assert_not_called()
            self.assertFalse((self.ci/'gpu-stock-pixels-4core').exists())
            self.write_gate()
            with self.assertRaises(StopBeforeFirmware): boot.package(SHA,3,self.root/'absent',stock_pixels=True)
        audit.write_text(json.dumps({**original,'stock_pixels_present':True}))
        with self.assertRaises(ValueError): boot.require_binary_audit(audit,SHA,RUN,KERNEL_SHA)

    def test_pixel_CLI_excludes_every_other_diagnostic_role(self):
        for role in ('--stock-unsecure','--zap-preflight','--zap-scm-probe','--zap-cache-preflight'):
            with patch.object(sys,'argv',['boot',SHA,'--mode','3','--stock-pixels',role]), \
                    patch.object(boot,'package') as package,patch('sys.stderr'):
                with self.assertRaises(SystemExit): boot.main()
                package.assert_not_called()

    def test_g3_is_a_separate_mode3_role(self):
        with patch.object(boot.subprocess,'check_output',return_value=RECIPE):
            power=boot.command_args(boot.command_line(SHA,1))
            g3=boot.command_args(boot.command_line(SHA,3,g3=True))
            self.assertEqual(g3,{**power,'santonigpu':'3','santonigpu_stock':'1',
                                  'santonigpu_pixels':'1','santonigpu_submit':'1'})
            for mode in (0,1,2):
                with self.assertRaises(ValueError):boot.command_line(SHA,mode,g3=True)
            for role in ('zap_preflight','zap_scm_probe','zap_cache_preflight','stock_unsecure','stock_pixels'):
                with self.assertRaises(ValueError):boot.command_line(SHA,3,g3=True,**{role:True})
            for value in (1,0,None,'1'):
                with self.assertRaises(ValueError):boot.command_line(SHA,3,g3=value)

    def test_g3_requires_new_binary_gate_and_same_kernel_power(self):
        path=self.ci/'gpu-binary-audit.json';audit=json.loads(path.read_text())
        audit.update({boot.STOCK_BINARY_GATE:True,boot.PIXEL_BINARY_GATE:True})
        for value in (False,1,None):
            path.write_text(json.dumps({**audit,boot.G3_BINARY_GATE:value}))
            with self.assertRaises(ValueError):boot.require_binary_audit(path,SHA,RUN,KERNEL_SHA,g3=True)
        path.write_text(json.dumps({**audit,boot.G3_BINARY_GATE:True}))
        boot.require_binary_audit(path,SHA,RUN,KERNEL_SHA,g3=True)
        with patch.object(boot,'ROOT',self.root),patch.object(boot,'BASE',self.base), \
                patch.object(boot,'command_line',return_value='cpus=4 santonigpu=3'), \
                patch.object(boot,'firmware_blob',side_effect=StopBeforeFirmware) as firmware:
            with self.assertRaises(ValueError):boot.package(SHA,3,self.root/'absent',g3=True)
            firmware.assert_not_called();self.write_gate()
            with self.assertRaises(StopBeforeFirmware):boot.package(SHA,3,self.root/'absent',g3=True)
        path.write_text(json.dumps({**audit,'g3_present':True}))
        with self.assertRaises(ValueError):boot.require_binary_audit(path,SHA,RUN,KERNEL_SHA)

    def test_g3_cli_excludes_older_roles(self):
        for role in ('--stock-pixels','--stock-unsecure','--zap-preflight','--zap-scm-probe','--zap-cache-preflight'):
            with patch.object(sys,'argv',['boot',SHA,'--mode','3','--g3-submit',role]), \
                    patch.object(boot,'package') as package,patch('sys.stderr'):
                with self.assertRaises(SystemExit):boot.main()
                package.assert_not_called()

    def make_zap_bundle(self, metadata=None):
        bundle = self.root / 'zap-bundle'
        firmware = bundle / 'firmware'
        firmware.mkdir(parents=True, exist_ok=True)
        if metadata is None:
            rows = [(0, 0, 0, 0, 148, 0, 0x07000000, 0),
                    (0, 0x1000, 0x7000, 0x7000, 6536, 8192, 0x02200000, 4096),
                    (1, 0x3000, 0x5000, 0x5000, 5204, 5204, 0x08000007, 0x100000)]
            metadata = mdt32(rows, machine=164) + bytes(6536)
        (firmware / 'a506_zap.mdt').write_bytes(metadata)
        (firmware / 'a506_zap.b02').write_bytes(bytes(i % 251 for i in range(5204)))
        (bundle / 'target.json').write_text(json.dumps({'chipid': 0x05000500,
            'kernel_page_bytes': 4096, 'vendor_zap_subsystem': 'a506_zap'}))
        report, _ = boot.zap_segments(firmware, 'a506_zap')
        (bundle / 'firmware-intake.json').write_text(json.dumps({'zap': report}))
        return bundle

    def test_zap_inputs_preserve_exact_firmware_and_attested_hashes(self):
        bundle = self.make_zap_bundle()
        inputs, evidence = boot.zap_preflight_inputs(bundle)
        self.assertEqual(inputs[boot.ZAP_PROPERTIES[0]], (bundle / 'firmware/a506_zap.mdt').read_bytes())
        self.assertEqual(inputs[boot.ZAP_PROPERTIES[1]], (bundle / 'firmware/a506_zap.b02').read_bytes())
        self.assertEqual(evidence['image_span_bytes'], 8192)
        self.assertEqual(evidence['physical_alignment_bytes'], 0x100000)
        self.assertFalse(evidence['signature_or_TZ_acceptance_verified'])
        for name in ('a506_zap.mdt', 'a506_zap.b02'):
            with self.subTest(name=name):
                path = bundle / 'firmware' / name
                original = path.read_bytes()
                changed = bytearray(original); changed[-1] ^= 1
                path.write_bytes(changed)
                with self.assertRaisesRegex(ValueError, 'differ'):
                    boot.zap_preflight_inputs(bundle)
                path.write_bytes(original)

    def test_rehashed_zap_intake_cannot_bypass_kernel_layout_limits(self):
        bundle = self.make_zap_bundle()
        original = (bundle / 'firmware/a506_zap.mdt').read_bytes()
        # Host generic ELF syntax may accept these; the narrow adapter must not.
        invalid = ((18, 40, 'H'), (128, 0x5001, 'I'), (136, 65537, 'I'),
                   (140, 7, 'I'), (144, 0x200000, 'I'), (144, 3, 'I'), (40, 51, 'H'))
        for offset, value, kind in invalid:
            with self.subTest(offset=offset, value=value):
                changed = bytearray(original)
                struct.pack_into('<' + kind, changed, offset, value)
                self.make_zap_bundle(bytes(changed))
                with self.assertRaises(ValueError):
                    boot.zap_preflight_inputs(bundle)

    def test_zap_ADT_delta_is_only_the_two_input_properties(self):
        root, chosen, hid = boot.adt.Node(), boot.adt.Node(), boot.adt.Node()
        root.props = [('name', 0, b'device-tree\0')]
        chosen.props = [('name', 0, b'chosen\0'), ('existing', 0, b'unchanged')]
        hid.props = [('name', 0, b'hid\0'), ('config', 0, b'input-unchanged')]
        root.children = [chosen, hid]
        original = boot.adt.serialize(root)
        inputs, _ = boot.zap_preflight_inputs(self.make_zap_bundle())
        modified = boot.add_zap_inputs(boot.add_firmware(original, b'pm4-pfp'), inputs)
        boot.verify_tree_preservation(original, modified, zap_preflight=True)
        with self.assertRaises(ValueError):
            boot.verify_tree_preservation(original, modified)
        with self.assertRaises(ValueError):
            boot.add_zap_inputs(modified, inputs)
        with self.assertRaises(ValueError):
            boot.add_zap_inputs(original, {boot.ZAP_PROPERTIES[0]: b'partial'})
        with self.assertRaises(ValueError):
            boot.add_zap_inputs(original, {**inputs, 'santoni-gpu-zapmem': bytes(4096)})
        after, _ = boot.adt.parse(modified)
        after.children[1].props.append(('unauthorized', 0, b'new'))
        with self.assertRaises(ValueError):
            boot.verify_tree_preservation(original, boot.adt.serialize(after), zap_preflight=True)

    def test_zap_opt_in_is_mode3_only_and_never_inherited_from_recipe(self):
        # Portable strict committed recipe; no images/artifacts are fabricated.
        recipe = ('CMDLINE="-v santoni cpus=8 sweethidtest=0 sweetfb_noconsole=1 '
                  'sweetfb_hz=30 sweetcpufreq=0 sweetfb_native=1 sweetfb_stayon=1 '
                  'sweetlog=1 sweetbattery=0 santoni_varfix=1 rd=emmcroot0 emmcrw=1 rootrw=1"\n')
        with patch.object(boot.subprocess, 'check_output', return_value=recipe):
            normal = boot.command_line(SHA, 3)
            opted = boot.command_line(SHA, 3, zap_preflight=True)
            self.assertEqual(opted, normal + ' santonigpu_zap=1')
            self.assertNotIn('santonigpu_zap', normal)
            for mode in (0, 1, 2):
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    boot.command_line(SHA, mode, zap_preflight=True)
            for value in (1, None, 'true'):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    boot.command_line(SHA, 3, zap_preflight=value)
        with patch.object(boot.subprocess, 'check_output', return_value=recipe.replace('rootrw=1', 'rootrw=1 santonigpu_zap=1')):
            with self.assertRaises(ValueError):
                boot.command_line(SHA, 3)

    def test_zap_requires_additional_binary_gate_then_the_same_kernel_power_gate(self):
        path = self.ci / 'gpu-binary-audit.json'
        report = json.loads(path.read_text())
        with self.assertRaises(ValueError):
            boot.require_binary_audit(path, SHA, RUN, KERNEL_SHA, zap_preflight=True)
        for value in (1, False, 'true'):
            path.write_text(json.dumps({**report, boot.ZAP_BINARY_GATE: value}))
            with self.assertRaises(ValueError):
                boot.require_binary_audit(path, SHA, RUN, KERNEL_SHA, zap_preflight=True)
        path.write_text(json.dumps({**report, boot.ZAP_BINARY_GATE: True}))
        with patch.object(boot, 'ROOT', self.root), patch.object(boot, 'BASE', self.base), \
                patch.object(boot, 'command_line', return_value='santonigpu=3 santonigpu_zap=1'), \
                patch.object(boot, 'zap_preflight_inputs') as zap_inputs, \
                patch.object(boot, 'firmware_blob', side_effect=StopBeforeFirmware):
            with self.assertRaises(ValueError):
                boot.package(SHA, 3, self.root / 'absent', zap_preflight=True)
            zap_inputs.assert_not_called()
            self.assertFalse((self.ci / 'gpu-zap-preflight-4core').exists())
            self.write_gate()
            with self.assertRaises(StopBeforeFirmware):
                boot.package(SHA, 3, self.root / 'absent', zap_preflight=True)

    def test_cache_preflight_exact_opt_in_is_separate_and_preserves_command_arguments(self):
        with patch.object(boot.subprocess, 'check_output', return_value=RECIPE):
            for visible in (False, True):
                ordinary = boot.command_line(SHA, 3, visible)
                cache = boot.command_line(SHA, 3, visible, zap_cache_preflight=True)
                self.assertEqual(cache, ordinary + ' santonigpu_zap=1 santonigpu_cache=1')
                self.assertNotIn('santonigpu_scm', cache)
            for mode in (0, 1, 2, 4, True):
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    boot.command_line(SHA, mode, zap_cache_preflight=True)
            for value in (1, 0, None, 'true'):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    boot.command_line(SHA, 3, zap_cache_preflight=value)
            for extra in ({'zap_preflight': True}, {'zap_scm_probe': True}):
                with self.assertRaises(ValueError):
                    boot.command_line(SHA, 3, zap_cache_preflight=True, **extra)
        for option in ('santonigpu_cache=0', 'santonigpu_cache=1', 'santonigpu_cache'):
            with patch.object(boot.subprocess, 'check_output', return_value=RECIPE.replace('rootrw=1', 'rootrw=1 ' + option)):
                with self.assertRaises(ValueError):
                    boot.command_line(SHA, 3, zap_cache_preflight=True)

    def test_cache_preflight_requires_its_binary_gate_and_same_kernel_power_without_firmware(self):
        path = self.ci / 'gpu-binary-audit.json'
        ordinary = json.loads(path.read_text())
        for value in (None, False, 1, 'true'):
            path.write_text(json.dumps({**ordinary, boot.CACHE_BINARY_GATE: value, boot.SCM_BINARY_GATE: True}))
            with self.assertRaises(ValueError):
                boot.require_binary_audit(path, SHA, RUN, KERNEL_SHA, zap_cache_preflight=True)
        path.write_text(json.dumps({**ordinary, boot.CACHE_BINARY_GATE: True}))
        with patch.object(boot, 'ROOT', self.root), patch.object(boot, 'BASE', self.base), \
                patch.object(boot.subprocess, 'check_output', return_value=RECIPE), \
                patch.object(boot.mkpayload, 'build', side_effect=StopBeforeFirmware), \
                patch.object(boot, 'firmware_blob', side_effect=AssertionError('firmware read')), \
                patch.object(boot, 'zap_preflight_inputs', side_effect=AssertionError('zap firmware read')):
            with self.assertRaisesRegex(ValueError, 'hardware result'):
                boot.package(SHA, 3, self.root / 'absent', zap_cache_preflight=True)
            self.write_gate({**self.gate, 'kernel_sha256': 'b' * 64})
            with self.assertRaisesRegex(ValueError, 'another kernel'):
                boot.package(SHA, 3, self.root / 'absent', zap_cache_preflight=True)
            self.write_gate()
            with self.assertRaises(StopBeforeFirmware):
                boot.package(SHA, 3, self.root / 'absent', zap_cache_preflight=True)

    def test_cache_preflight_CLI_is_explicit_and_excludes_the_other_diagnostics(self):
        for option in ('--zap-preflight', '--zap-scm-probe'):
            with patch.object(sys, 'argv', ['santoni_gpu_boot.py', SHA, '--mode', '3', '--zap-cache-preflight', option]), \
                    patch.object(boot, 'package') as package, patch('sys.stderr'):
                with self.assertRaises(SystemExit):
                    boot.main()
                package.assert_not_called()
        with patch.object(sys, 'argv', ['santoni_gpu_boot.py', SHA, '--mode', '3', '--zap-cache-preflight']), \
                patch.object(boot, 'package', return_value={}) as package, patch('sys.stdout'):
            boot.main()
            self.assertIs(package.call_args.kwargs['zap_cache_preflight'], True)
            self.assertFalse(package.call_args.args[-1])
            self.assertFalse(package.call_args.args[-2])

    def test_scm_mode_and_exact_opt_in_preserve_all_normal_command_arguments(self):
        with patch.object(boot.subprocess, 'check_output', return_value=RECIPE):
            for visible in (False, True):
                ordinary = boot.command_line(SHA, 3, visible)
                scm = boot.command_line(SHA, 3, visible, zap_scm_probe=True)
                self.assertEqual(scm, ordinary + ' santonigpu_zap=1 santonigpu_scm=1')
                self.assertNotIn('santonigpu_scm', boot.command_line(SHA, 3, visible, zap_preflight=True))
            for mode in (0, 1, 2, 4, True):
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    boot.command_line(SHA, mode, zap_scm_probe=True)
            for value in (1, 0, None, 'true'):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    boot.command_line(SHA, 3, zap_scm_probe=value)
            with self.assertRaises(ValueError):
                boot.command_line(SHA, 3, zap_preflight=True, zap_scm_probe=True)
        for option in ('santonigpu_scm=0', 'santonigpu_scm=1', 'santonigpu_scm', 'santonigpu_scm=2'):
            with patch.object(boot.subprocess, 'check_output', return_value=RECIPE.replace('rootrw=1', 'rootrw=1 ' + option)):
                for enabled in (False, True):
                    with self.subTest(option=option, enabled=enabled), self.assertRaises(ValueError):
                        boot.command_line(SHA, 3, zap_scm_probe=enabled)

    def test_scm_needs_its_own_binary_gate_and_same_kernel_power_before_output(self):
        path = self.ci / 'gpu-binary-audit.json'
        ordinary = json.loads(path.read_text())
        for value in (None, False, 1, 'true'):
            path.write_text(json.dumps({**ordinary, boot.SCM_BINARY_GATE: value, boot.ZAP_BINARY_GATE: True}))
            with self.subTest(value=value), self.assertRaises(ValueError):
                boot.require_binary_audit(path, SHA, RUN, KERNEL_SHA, zap_scm_probe=True)
        path.write_text(json.dumps({**ordinary, boot.SCM_BINARY_GATE: True}))
        boot.require_binary_audit(path, SHA, RUN, KERNEL_SHA, zap_scm_probe=True)
        with patch.object(boot, 'ROOT', self.root), patch.object(boot, 'BASE', self.base), \
                patch.object(boot.subprocess, 'check_output', return_value=RECIPE), \
                patch.object(boot.mkpayload, 'build', side_effect=StopBeforeFirmware) as payload, \
                patch.object(boot, 'firmware_blob') as firmware, \
                patch.object(boot, 'zap_preflight_inputs') as allocations:
            with self.assertRaisesRegex(ValueError, 'hardware result'):
                boot.package(SHA, 3, self.root / 'absent', zap_scm_probe=True)
            payload.assert_not_called()
            firmware.assert_not_called()
            allocations.assert_not_called()
            self.assertFalse((self.ci / 'gpu-zap-scm-probe-4core').exists())
            self.write_gate({**self.gate, 'kernel_sha256': 'b' * 64})
            with self.assertRaisesRegex(ValueError, 'another kernel'):
                boot.package(SHA, 3, self.root / 'absent', zap_scm_probe=True)
            self.write_gate()
            with self.assertRaises(StopBeforeFirmware):
                boot.package(SHA, 3, self.root / 'absent', zap_scm_probe=True)
            firmware.assert_not_called()
            allocations.assert_not_called()

    def test_scm_CLI_is_explicit_and_mutually_exclusive_with_allocation_only(self):
        with patch.object(sys, 'argv', ['santoni_gpu_boot.py', SHA, '--mode', '3',
                                        '--zap-scm-probe', '--zap-preflight']), \
                patch.object(boot, 'package') as package, patch('sys.stderr'):
            with self.assertRaises(SystemExit) as raised:
                boot.main()
            self.assertEqual(raised.exception.code, 2)
            package.assert_not_called()
        with patch.object(sys, 'argv', ['santoni_gpu_boot.py', SHA, '--mode', '3', '--zap-scm-probe']), \
                patch.object(boot, 'package', return_value={}) as package, patch('sys.stdout'):
            boot.main()
            self.assertTrue(package.call_args.args[-1])
            self.assertFalse(package.call_args.args[-2])

    def test_scm_packaging_keeps_ADT_bytes_no_firmware_and_distinct_outputs(self):
        # Synthetic CI/input evidence stays in a temporary fixture. No real
        # kernel, firmware, shared storage or accepted hardware gate is written.
        root, chosen, hid = boot.adt.Node(), boot.adt.Node(), boot.adt.Node()
        root.props = [('name', 0, b'device-tree\0')]
        chosen.props = [('name', 0, b'chosen\0'), ('existing', 0, b'unchanged')]
        hid.props = [('name', 0, b'hid\0'), ('config', 0, b'input-unchanged')]
        root.children = [chosen, hid]
        original = boot.adt.serialize(root)
        (self.base / 'santoni.adt').write_bytes(original)
        self.proven['santoni.adt'] = boot.sha(original)
        (self.base / 'SHA256.json').write_text(json.dumps(self.proven))
        audit = self.ci / 'gpu-binary-audit.json'
        audit.write_text(json.dumps({**json.loads(audit.read_text()), boot.SCM_BINARY_GATE: True}))
        self.write_gate()
        shared = self.root / 'shared'
        shared.mkdir()
        preserved = {}
        for role in ('render', 'zap-preflight'):
            path = self.ci / ('gpu-' + role + '-trace-4core')
            path.mkdir()
            (path / 'manifest.json').write_bytes(b'preserve existing manifest')
            preserved[path / 'manifest.json'] = b'preserve existing manifest'

        def payload(kernel, tree_path, command, init):
            tree = Path(tree_path).read_bytes()
            self.assertEqual(tree, original)
            data = bytearray(0x300 + len(tree))
            struct.pack_into('<2Q', data, 0x20, 0x300, len(tree))
            data[0x48:0x48 + len(command)] = command.encode()
            data[0x300:] = tree
            return bytes(data), {'kernel_end': 0x100000}

        def image(args, **kwargs):
            # Exercise the real Android image writer using absolute script paths.
            tool = list(args)
            tool[1] = str(ROOT / 'tools/mkbootimg.py')
            return real_run(tool, **kwargs)

        real_run = boot.subprocess.run
        with patch.object(boot, 'ROOT', self.root), patch.object(boot, 'BASE', self.base), \
                patch.object(boot, 'SHARED', shared), \
                patch.object(boot.subprocess, 'check_output', return_value=RECIPE), \
                patch.object(boot.subprocess, 'run', side_effect=image), \
                patch.object(boot.mkpayload, 'build', side_effect=payload), \
                patch.object(boot, 'firmware_blob', side_effect=AssertionError('firmware read')), \
                patch.object(boot, 'zap_preflight_inputs', side_effect=AssertionError('allocation input')):
            result = boot.package(SHA, 3, self.root / 'absent', visible_console=True, zap_scm_probe=True)
            self.assertEqual(result['role'], 'zap-scm-probe')
            self.assertEqual(result['firmware'], [])
            self.assertIsNone(result['firmware_blob_sha256'])
            for key in ('SCM_calls_enabled', 'zap_scm_probe'):
                self.assertIs(result[key], True)
            for key in ('zap_preflight', 'PAS_load_auth_reset_enabled', 'GPU_probe_continuation_enabled',
                        'firmware_addresses_sent', 'hardware_verified', 'UI_acceleration_enabled'):
                self.assertIs(result[key], False)
            self.assertEqual(result['cpus'], 4)
            named = shared / ('boot-gpu-zap-scm-probe-trace-' + SHA[:7] + '-4core.img')
            self.assertEqual(result['staged'], [str(named)])
            self.assertEqual(boot.sha(named.read_bytes()), result['boot_sha256'])
            dest = self.ci / 'gpu-zap-scm-probe-trace-4core'
            before = {p: p.read_bytes() for p in dest.iterdir()}
            with self.assertRaisesRegex(ValueError, 'overwrite'):
                boot.package(SHA, 3, self.root / 'absent', visible_console=True, zap_scm_probe=True)
            self.assertEqual({p: p.read_bytes() for p in dest.iterdir()}, before)
        self.assertEqual({p: p.read_bytes() for p in preserved}, preserved)
        self.assertEqual((self.base / 'santoni.adt').read_bytes(), original)


if __name__ == '__main__':
    unittest.main(verbosity=2)
