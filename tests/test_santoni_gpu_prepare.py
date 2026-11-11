#!/usr/bin/env python3
"""Host-only checks of vendor A505 preparation, packets and firmware boundaries."""
import importlib.util
import os
import re
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PREFERRED_TMP = Path('/data/data/com.termux/files/usr/tmp/opencode')
TMP_ROOT = PREFERRED_TMP if PREFERRED_TMP.is_dir() else None
spec = importlib.util.spec_from_file_location('gpu_prepare', ROOT / 'tools/santoni_gpu_prepare.py')
gpu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gpu)


def source_function(text, name):
    import re
    found = re.search(r'\b' + re.escape(name) + r'\([^;{}]*\)\s*\n\{', text)
    if not found:
        raise ValueError(name)
    line = text.rfind('\n', 0, found.start()) + 1
    start = line if text[line:found.start()].strip() else text.rfind('\n', 0, line - 1) + 1
    opening = text.index('{', found.start())
    depth = 0
    for end in range(opening, len(text)):
        depth += (text[end] == '{') - (text[end] == '}')
        if depth == 0:
            return text[start:end + 1]
    raise ValueError(name)


def mdt32(headers, machine=40):
    ident = b'\x7fELF' + bytes([1, 1, 1]) + bytes(9)
    ehdr = struct.pack('<HHIIIIIHHHHHH', 2, machine, 1, 0, 52, 0, 0, 52, 32, len(headers), 0, 0, 0)
    return ident + ehdr + b''.join(struct.pack('<8I', *row) for row in headers)


class PreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vendor = Path(os.environ.get('SANTONI_GPU_VENDOR', str(gpu.VENDOR)))
        cls.target = gpu.vendor_target(cls.vendor) if (cls.vendor / gpu.SOURCES['catalog']).is_file() else None

    def require_vendor(self):
        if self.target is None:
            self.skipTest('local MSM4.9 source tree not supplied; portable firmware/packet gates still run')

    def test_exact_a505_identity_and_geometry(self):
        self.require_vendor()
        target = self.target
        self.assertEqual((target['chipid'], target['gmem_bytes'], target['kernel_page_bytes']),
                         (0x05000500, 139264, 4096))
        self.assertEqual((target['gpu_pa'], target['gpu_intid'], target['smmu_pa']),
                         (0x1c00000, 65, 0x1c40000))
        self.assertEqual(target['vendor_zap_subsystem'], 'a506_zap')
        self.assertFalse(target['hardware_activation_ready'])

    def test_soc_gdsc_override_and_byte_offsets(self):
        self.require_vendor()
        self.assertEqual(self.target['cx_gdsc_pa'], 0x1859044)
        self.assertEqual(self.target['gx_gdsc_pa'], 0x185901c)
        self.assertNotEqual(self.target['cx_gdsc_pa'], 0x1800000 + self.target['gcc_byte_offsets']['OXILI_AON_CBCR'])
        self.assertEqual(self.target['gpu_byte_offsets']['A5XX_CP_RB_BASE'], 0x800 * 4)
        self.assertEqual(len(self.target['hwcg']), 38)
        self.assertEqual(len(self.target['vbif']), 1)
        for entry in self.target['hwcg'] + self.target['vbif']:
            self.assertEqual(entry['byte_offset'], entry['word_offset'] * 4)
            self.assertLess(entry['byte_offset'], self.target['gpu_bytes'])

    def test_clock_requirements_come_from_device_not_shared_controller(self):
        gpu_dt = 'clocks=<&clock_gcc clk_core>, <&clock_gcc clk_iface>; clock-names="core_clk", "iface_clk";'
        gcc = '''static struct branch_clk core={.cbcr_reg=CORE_CBCR};
static struct branch_clk iface={.cbcr_reg=IFACE_CBCR};
static struct gate_clk unused_gmem={.en_reg=GMEM_CBCR};'''
        registers = {'CORE_CBCR': 0x59020, 'IFACE_CBCR': 0x59028, 'GMEM_CBCR': 0x59024}
        clocks = gpu.required_gpu_clocks(gpu_dt, gcc, registers)
        self.assertEqual([entry['byte_offset'] for entry in clocks], [0x59020, 0x59028])
        for bad in (gpu_dt.replace('"iface_clk"', '"core_clk"'),
                    gpu_dt.replace('clock_gcc', 'other_controller'),
                    gpu_dt.replace('<&clock_gcc clk_iface>', '<&clock_gcc clk_missing>'),
                    gpu_dt.replace('<&clock_gcc clk_iface>', '<&clock_gcc clk_iface 1>'),
                    gpu_dt.replace(', "iface_clk"', ''),
                    gpu_dt.replace('"iface_clk";', '"iface_clk", unparsed;')):
            with self.assertRaises(ValueError):
                gpu.required_gpu_clocks(bad, gcc, registers)
        for expression in ('CORE_CBCR + 4', 'CORE_CBCR | 4', 'OFFSET(CORE_CBCR)',
                           '1 ? CORE_CBCR : GMEM_CBCR', '(CORE_CBCR)', 'CORE_CBCR << 1'):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                gpu.required_gpu_clocks(gpu_dt, gcc.replace('=CORE_CBCR', '=' + expression), registers)

    def test_actual_santoni_gpu_has_no_separate_gmem_gate(self):
        self.require_vendor()
        clocks = self.target['gpu_required_clocks']
        self.assertEqual(len(clocks), 6)
        self.assertEqual({entry['byte_offset'] for entry in clocks},
                         {0x59020, 0x59028, 0x59034, 0x59030, 0x59040, 0x5904c})
        self.assertEqual(self.target['shared_gcc_registers_not_required_by_gpu'], ['OXILI_GMEM_CBCR'])
        self.assertNotIn('OXILI_GMEM_CBCR', [entry['register'] for entry in clocks])

    def test_santoni_include_closure_preserves_the_reviewed_clock_consumers(self):
        self.require_vendor()
        dts = self.vendor / 'arch/arm64/boot/dts'
        pending = [dts / 'xiaomi-msm8937/santoni.dts']
        sources = {}
        while pending:
            path = pending.pop().resolve()
            if path in sources:
                continue
            text = gpu.uncomment(path.read_text())
            sources[path] = text
            for line in text.splitlines():
                if not re.match(r'\s*#\s*include\b', line):
                    continue
                include = re.fullmatch(r'\s*#\s*include\s*["<]([^">]+)[">]\s*', line)
                self.assertIsNotNone(include, f'unreviewed macro include in {path}')
                name = include.group(1)
                candidates = (path.parent / name, dts / name, dts / 'qcom' / name,
                              self.vendor / 'include' / name)
                target = next((item for item in candidates if item.is_file()), None)
                self.assertIsNotNone(target, f'unresolved include {name} in {path}')
                pending.append(target)
        self.assertIn((self.vendor / gpu.SOURCES['gpu_dt']).resolve(), sources)
        self.assertGreaterEqual(len(sources), 100)
        for path, text in sources.items():
            with self.subTest(path=path):
                # The shared binding header declares GMEM, but no DT consumes it.
                consumers = '\n'.join(line for line in text.splitlines()
                                      if not re.match(r'\s*#\s*define\b', line))
                self.assertNotRegex(consumers, r'\bclk_gcc_oxili_gmem_clk\b|\bOXILI_GMEM_CBCR\b')
                for match in re.finditer(r'&msm_gpu\s*\{', text):
                    overlay = gpu.block(text[match.start():], '&msm_gpu')
                    self.assertNotRegex(overlay, r'\b(?:clocks|clock-names)\s*[=;]')
        soc = sources[(self.vendor / gpu.SOURCES['soc_dt']).resolve()]
        self.assertIn('clk_gcc_oxili_gfx3d_clk', gpu.block(soc, '&gdsc_oxili_cx'))
        self.assertIn('clk_gfx3d_clk_src', gpu.block(soc, '&gdsc_oxili_gx'))

    def test_ucode_strips_one_word_and_preserves_bytes(self):
        raw = struct.pack('<4I', 0xdeadbeef, 0x12345674, 0x55667788, 0xabcdef01)
        info, payload = gpu.ucode(raw, 'a530_pm4.fw')
        self.assertEqual(payload, raw[4:])
        self.assertEqual(info['version'], 0x12345674)
        self.assertEqual(info['payload_dwords'], 3)
        self.assertFalse(info['authenticity_verified'])

    def test_extended_ucode_version_matches_vendor(self):
        raw = struct.pack('<4I', 0, 0xabc00a, 0, 0x123000)
        self.assertEqual(gpu.ucode(raw, 'a530_pfp.fw')[0]['version'], 0xabc123)
        with self.assertRaises(ValueError):
            gpu.ucode(raw[:12], 'a530_pfp.fw')

    def test_ucode_bad_bounds(self):
        for data in (b'', bytes(4), bytes(9), bytes(gpu.MAX_UCODE_BYTES + 4)):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                gpu.ucode(data, 'a530_pm4.fw')

    def test_packet_bounds(self):
        for opcode, count in ((-1, 8), (128, 8), (0x48, -1), (0x48, 0x4000)):
            with self.assertRaises(ValueError):
                gpu.type7(opcode, count)

    def test_vendor_packet_and_ordinals_native_oracle(self):
        fixture = ROOT / 'tests/fixtures/santoni_gpu_packets.c'
        code = fixture.read_text()
        if self.target is not None:
            vendor = self.vendor / 'drivers/gpu/msm'
            packets = (vendor / 'adreno_pm4types.h').read_text()
            a5xx = (vendor / 'adreno_a5xx.c').read_text()
            for name, origin in (('pm4_calc_odd_parity_bit', packets), ('cp_type7_packet', packets),
                                 ('_me_init_ucode_workarounds', a5xx), ('_set_ordinals', a5xx)):
                normalize = lambda text: re.sub(r'\s+', '', gpu.uncomment(text))
                self.assertEqual(normalize(source_function(code, name)), normalize(source_function(origin, name)))
        with tempfile.TemporaryDirectory(prefix='a505-packets-', dir=TMP_ROOT) as tmp:
            binary = Path(tmp) / 'oracle'
            subprocess.run([*shlex.split(os.environ.get('HOST_CC', 'clang')), '-std=c11', '-O2',
                            '-Wall', '-Wextra', '-Werror', str(fixture), '-o', str(binary)], check=True, timeout=60)
            actual = [int(line) for line in subprocess.check_output([str(binary)], text=True, timeout=10).splitlines()]
        self.assertEqual(actual, [gpu.type7(0x48, 8), 0x2f, 3, 0x20000000, 0, 0, 0xb, 0, 0])

    def test_zap_split_and_bss(self):
        rows = [(1, 0, 0, 0, 16, 16, 0x02000000, 0),
                (1, 0x1000, 0x85000000, 0x85000000, 16, 32, 5, 4096),
                (1, 0x2000, 0x85001000, 0x85001000, 0, 16, 6, 4096)]
        with tempfile.TemporaryDirectory(prefix='a506-zap-', dir=TMP_ROOT) as tmp:
            root = Path(tmp)
            (root / 'a506_zap.mdt').write_bytes(mdt32(rows))
            (root / 'a506_zap.b01').write_bytes(bytes(range(16)))
            result, copies = gpu.zap_segments(root, 'a506_zap')
            self.assertEqual(len(result['segments']), 2)
            self.assertEqual(result['segments'][1]['zero_fill_bytes'], 16)
            self.assertIsNone(result['segments'][1]['file'])
            self.assertEqual(len(copies), 2)
            self.assertFalse(result['signature_or_TZ_acceptance_verified'])

    def test_zap_malformed_headers_and_segments(self):
        valid = (1, 0x1000, 0x85000000, 0x85000000, 16, 16, 5, 4096)
        fixtures = [b'bad', mdt32([]), mdt32([valid])[:-1],
                    mdt32([valid, valid]), mdt32([(1, 0, 0, 0, 17, 16, 5, 0)]),
                    mdt32([(1, 0, 0, 0xfffffff0, 16, 32, 5, 0)])]
        with tempfile.TemporaryDirectory(prefix='a506-bad-', dir=TMP_ROOT) as tmp:
            root = Path(tmp)
            (root / 'a506_zap.b00').write_bytes(bytes(16))
            for data in fixtures:
                (root / 'a506_zap.mdt').write_bytes(data)
                with self.subTest(size=len(data)), self.assertRaises(ValueError):
                    gpu.zap_segments(root, 'a506_zap')

    def test_zap_qdsp6_metadata_and_b02_layout(self):
        # Synthetic contents with the supplied a506_zap ELF layout. No vendor
        # firmware/signature bytes are stored in the repository.
        rows = [(0, 0, 0, 0, 148, 0, 0x07000000, 0),
                (0, 0x1000, 0x7000, 0x7000, 6536, 8192, 0x02200000, 4096),
                (1, 0x3000, 0x5000, 0x5000, 5204, 5204, 0x08000007, 0x100000)]
        metadata = mdt32(rows, machine=164) + bytes(6536)
        payload = bytes(index % 251 for index in range(5204))
        self.assertEqual(len(metadata), 6684)
        with tempfile.TemporaryDirectory(prefix='a506-qdsp6-', dir=TMP_ROOT) as tmp:
            root = Path(tmp)
            (root / 'a506_zap.mdt').write_bytes(metadata)
            (root / 'a506_zap.b02').write_bytes(payload)
            result, copies = gpu.zap_segments(root, 'a506_zap')
            self.assertEqual(result['segments'], [{'file': 'a506_zap.b02',
                'sha256': gpu.sha(payload), 'bytes': 5204, 'zero_fill_bytes': 0}])
            self.assertEqual(copies, [('a506_zap.mdt', metadata), ('a506_zap.b02', payload)])
            self.assertFalse(result['signature_or_TZ_acceptance_verified'])
            # A correctly named ELF does not make a truncated segment usable.
            (root / 'a506_zap.b02').write_bytes(payload[:-1])
            with self.assertRaisesRegex(ValueError, 'segment size mismatch'):
                gpu.zap_segments(root, 'a506_zap')

    def test_zap_rejects_unrelated_elf_machines(self):
        row = (1, 4096, 0x5000, 0x5000, 16, 16, 0x08000007, 4096)
        with tempfile.TemporaryDirectory(prefix='a506-machine-', dir=TMP_ROOT) as tmp:
            root = Path(tmp)
            (root / 'a506_zap.b00').write_bytes(bytes(16))
            for machine in (0, 3, 62, 165):
                (root / 'a506_zap.mdt').write_bytes(mdt32([row], machine=machine))
                with self.subTest(machine=machine), self.assertRaisesRegex(ValueError, 'ELF is not'):
                    gpu.zap_segments(root, 'a506_zap')

    def test_zap_elf64(self):
        ident = b'\x7fELF' + bytes([2, 1, 1]) + bytes(9)
        header = struct.pack('<HHIQQQIHHHHHH', 2, 183, 1, 0, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        phdr = struct.pack('<II6Q', 1, 5, 4096, 0x85000000, 0x85000000, 16, 32, 4096)
        with tempfile.TemporaryDirectory(prefix='a506-64-', dir=TMP_ROOT) as tmp:
            root = Path(tmp)
            (root / 'a506_zap.mdt').write_bytes(ident + header + phdr)
            (root / 'a506_zap.b00').write_bytes(bytes(16))
            result, copies = gpu.zap_segments(root, 'a506_zap')
            self.assertEqual(result['segments'][0]['zero_fill_bytes'], 16)
            self.assertEqual(len(copies), 2)

    def test_zap_missing_or_wrong_payload(self):
        row = (1, 4096, 0x85000000, 0x85000000, 16, 16, 5, 4096)
        with tempfile.TemporaryDirectory(prefix='a506-missing-', dir=TMP_ROOT) as tmp:
            root = Path(tmp)
            (root / 'a506_zap.mdt').write_bytes(mdt32([row]))
            with self.assertRaises(ValueError):
                gpu.zap_segments(root, 'a506_zap')
            (root / 'a506_zap.b00').write_bytes(bytes(15))
            with self.assertRaises(ValueError):
                gpu.zap_segments(root, 'a506_zap')

    def test_prepare_no_firmware_and_refuse_overwrite(self):
        self.require_vendor()
        with tempfile.TemporaryDirectory(prefix='a505-prepare-', dir=TMP_ROOT) as tmp:
            root = Path(tmp) / 'output'
            target, intake = gpu.prepare(self.vendor, root)
            self.assertEqual(intake['state'], 'firmware not supplied')
            self.assertFalse(target['hardware_activation_ready'])
            self.assertEqual((root / 'me-init.bin').read_bytes(), struct.pack('<9I', *target['me_init_words']))
            for name, digest in target['source_sha256'].items():
                self.assertEqual(gpu.sha((root / 'vendor-source' / name).read_bytes()), digest)
            with self.assertRaises(ValueError):
                gpu.prepare(self.vendor, root)

    def test_prepare_ucode_only_does_not_claim_secure_readiness(self):
        self.require_vendor()
        with tempfile.TemporaryDirectory(prefix='a505-intake-', dir=TMP_ROOT) as tmp:
            root = Path(tmp)
            raw = struct.pack('<4I', 0, 123, 456, 789)
            for name in ('a530_pm4.fw', 'a530_pfp.fw'):
                (root / name).write_bytes(raw)
            target, intake = gpu.prepare(self.vendor, root / 'output', root)
            self.assertFalse(target['hardware_activation_ready'])
            self.assertIn('not supplied', intake['zap']['state'])
            self.assertEqual((root / 'output/firmware/a530_pm4.fw.payload').read_bytes(), raw[4:])

    def test_firmware_output_cannot_land_in_tracked_source(self):
        with tempfile.TemporaryDirectory(prefix='a505-output-guard-', dir=TMP_ROOT) as tmp:
            with self.assertRaisesRegex(ValueError, 'must stay under ignored out'):
                gpu.prepare(self.vendor, ROOT / 'tests/forbidden-firmware-output', Path(tmp))

    def test_generated_header_native_compilation(self):
        self.require_vendor()
        with tempfile.TemporaryDirectory(prefix='a505-header-', dir=TMP_ROOT) as tmp:
            root = Path(tmp)
            (root / 'santoni_gpu_target.h').write_text(gpu.header(self.target))
            (root / 'header.c').write_text('''#include "santoni_gpu_target.h"
_Static_assert(SGPU_GPU_INTID==65 && SGPU_GMEM_BYTES==139264, "A505 target");
_Static_assert(SGPU_KERNEL_PAGE_BYTES==4096, "no Pixel 16K assumption");
_Static_assert(SGPU_CX_GDSC_PA==0x1859044, "apply SoC CX override");
_Static_assert(SGPU_GPU_CLOCK_COUNT==6, "only clocks consumed by the actual GPU DT");
int main(void) {
    for(unsigned i=0;i<SGPU_GPU_CLOCK_COUNT;i++)
        if(sgpu_gpu_clock_offsets[i]==SGPU_GCC_OXILI_GMEM_CBCR) return 2;
    for(unsigned i=0;i<sizeof(sgpu_hwcg)/sizeof(sgpu_hwcg[0]);i++)
        if(sgpu_hwcg[i].byte_offset>=SGPU_GPU_BYTES) return 1;
    return sgpu_vbif[0].value!=3 || sgpu_me_init[6]!=0xb;
}
''')
            binary = root / 'header'
            subprocess.run([*shlex.split(os.environ.get('HOST_CC', 'clang')), '-std=c11', '-O2',
                            '-Wall', '-Wextra', '-Werror', str(root / 'header.c'), '-o', str(binary)], check=True, timeout=60)
            subprocess.run([str(binary)], check=True, timeout=10)


if __name__ == '__main__':
    unittest.main(verbosity=2)
