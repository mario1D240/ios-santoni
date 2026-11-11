#!/usr/bin/env python3
"""Prepare vendor-backed A505 tables and firmware intake; never access hardware."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / 'resources/msm-4.9-main'
GPU = 'drivers/gpu/msm/'
DT = 'arch/arm64/boot/dts/qcom/'
SOURCES = {
    'catalog': GPU + 'adreno-gpulist.h',
    'a5xx': GPU + 'adreno_a5xx.c',
    'registers': GPU + 'a5xx_reg.h',
    'packets': GPU + 'adreno_pm4types.h',
    'iommu': GPU + 'kgsl_iommu.c',
    'gpu_dt': DT + 'msm8937-gpu.dtsi',
    'soc_dt': DT + 'msm8937.dtsi',
    'gdsc_dt': DT + 'msm-gdsc-8916.dtsi',
    'gcc': 'drivers/clk/msm/clock-gcc-8952.c',
    'gcc_registers': 'include/dt-bindings/clock/msm-clocks-hwio-8952.h',
}
MAX_UCODE_BYTES = 1024 * 1024
MAX_ZAP_BYTES = 8 * 1024 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_limited(path, maximum):
    if not path.is_file():
        raise ValueError(f'firmware is not a regular file: {path.name}')
    with path.open('rb') as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError(f'firmware size limit exceeded: {path.name}')
    return data


def uncomment(text):
    return re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.DOTALL)


def block(text, marker, preceding=False):
    """Return one balanced source block, not executable source evaluation."""
    start = text.index(marker)
    opening = text.rfind('{', 0, start) if preceding else text.index('{', start)
    depth = 0
    for end in range(opening, len(text)):
        depth += (text[end] == '{') - (text[end] == '}')
        if depth == 0:
            return text[opening + 1:end]
    raise ValueError(f'unclosed source block: {marker}')


def cells(text, prop):
    found = re.search(r'(?<![\w,-])' + re.escape(prop) + r'\s*=\s*<([^>]+)>\s*;', text)
    if not found:
        raise ValueError(f'missing numeric DT property: {prop}')
    tokens = found.group(1).split()
    if not all(re.fullmatch(r'0x[0-9a-fA-F]+|[0-9]+', token) for token in tokens):
        raise ValueError(f'non-numeric DT property: {prop}')
    return [int(token, 0) for token in tokens]


def defines(text):
    return {name: int(value, 0) for name, value in re.findall(
        r'^\s*#define\s+(\w+)\s+(0x[0-9a-fA-F]+|[0-9]+)\s*$', text, re.MULTILINE)}


def table(text, name, registers):
    result = []
    for reg, value in re.findall(r'\{\s*(A5XX_\w+)\s*,\s*(0x[0-9a-fA-F]+)\s*\}', block(text, name)):
        word = registers[reg]
        if word * 4 >= 0x40000:
            raise ValueError(f'GPU register outside target window: {reg}')
        result.append({'name': reg, 'word_offset': word, 'byte_offset': word * 4, 'value': int(value, 0)})
    if not result:
        raise ValueError(f'empty vendor table: {name}')
    return result


def type7(opcode, count):
    if not 0 <= opcode <= 0x7f or not 0 <= count <= 0x3fff:
        raise ValueError('type7 opcode/count out of bounds')
    parity = lambda value: 1 ^ (value.bit_count() & 1)
    return 0x70000000 | count | (parity(count) << 15) | (opcode << 16) | (parity(opcode) << 23)


def required_gpu_clocks(gpu_dt, gcc, registers):
    """Resolve clocks actually consumed by the GPU, not every shared GCC definition."""
    values = re.search(r'(?<![\w,-])clocks\s*=\s*([^;]+);', gpu_dt)
    names = re.search(r'(?<![\w,-])clock-names\s*=\s*([^;]+);', gpu_dt)
    if not values or not names:
        raise ValueError('GPU device clock bindings are missing')
    reference = r'<\s*&(\w+)\s+(\w+)\s*>'
    quoted_name = r'"([^"\n]+)"'
    references = re.findall(reference, values.group(1))
    clock_names = re.findall(quoted_name, names.group(1))
    if (not references or len(references) != len(clock_names) or
            len(set(clock_names)) != len(clock_names) or
            re.sub(reference, '', values.group(1)).strip(' ,\t\r\n') or
            re.sub(quoted_name, '', names.group(1)).strip(' ,\t\r\n')):
        raise ValueError('ambiguous or unsupported GPU clock bindings')
    result = []
    for name, (provider, symbol) in zip(clock_names, references):
        if provider != 'clock_gcc' or not symbol.startswith('clk_'):
            raise ValueError('GPU clock is not a reviewed GCC binding')
        identifier = symbol.removeprefix('clk_')
        declaration = re.search(r'\bstruct\s+(?:branch_clk|gate_clk|local_vote_clk)\s+' +
                                re.escape(identifier) + r'\s*=\s*\{', gcc)
        if not declaration:
            raise ValueError(f'GPU clock declaration missing: {symbol}')
        body = block(gcc, declaration.group(0)[:-1])
        register_names = [value.strip() for value in re.findall(
            r'\.(?:cbcr_reg|en_reg)\s*=\s*([^,}]+)(?=,|$)', body)]
        if (len(register_names) != 1 or not re.fullmatch(r'[A-Za-z_]\w*', register_names[0]) or
                register_names[0] not in registers):
            raise ValueError(f'GPU clock register is not uniquely resolved: {symbol}')
        register = register_names[0]
        result.append({'clock_name': name, 'binding': symbol, 'register': register,
                       'byte_offset': registers[register]})
    return result


def vendor_target(vendor=VENDOR):
    raw = {key: (vendor / path).read_bytes() for key, path in SOURCES.items()}
    text = {key: uncomment(data.decode()) for key, data in raw.items()}
    if text['catalog'].count('.gpurev = ADRENO_REV_A505') != 1:
        raise ValueError('vendor catalog does not identify exactly one A505')
    entry = block(text['catalog'], '.gpurev = ADRENO_REV_A505', preceding=True)
    strings = {}
    for name in ('pm4fw_name', 'pfpfw_name', 'zap_name'):
        strings[name] = re.search(r'\.' + name + r'\s*=\s*"([^"/]+)"', entry).group(1)
    if strings != {'pm4fw_name': 'a530_pm4.fw', 'pfpfw_name': 'a530_pfp.fw', 'zap_name': 'a506_zap'}:
        raise ValueError('A505 firmware bindings changed; review vendor provenance')
    identity = [int(re.search(r'\.' + name + r'\s*=\s*([0-9]+)', entry).group(1))
                for name in ('core', 'major', 'minor')]
    if identity != [5, 0, 5] or not re.search(r'\.gmem_size\s*=\s*\(SZ_128K\s*\+\s*SZ_8K\)', entry):
        raise ValueError('unexpected A505 identity/GMEM; review the vendor source')
    gpu = block(text['gpu_dt'], 'msm_gpu:')
    iommu = block(text['gpu_dt'], 'kgsl_msm_iommu:')
    gpu_reg, iommu_reg = cells(gpu, 'reg'), cells(iommu, 'reg')
    if cells(gpu, 'qcom,chipid') != [0x05000500] or gpu_reg[:2] != [0x1c00000, 0x40000]:
        raise ValueError('GPU DT/catalog mismatch')
    if iommu_reg != [0x1c40000, 0x10000] or cells(gpu, 'interrupts')[:2] != [0, 33]:
        raise ValueError('unexpected GPU SMMU/interrupt geometry')
    user = block(iommu, 'gfx3d_user:')
    gcc_regs, regs = defines(text['gcc_registers']), defines(text['registers'])
    if '{ adreno_is_a505, a50x_hwcg_regs,' not in text['a5xx']:
        raise ValueError('A505 HWCG selector changed')
    if '{ adreno_is_a505, a530_vbif }' not in text['a5xx']:
        raise ValueError('A505 VBIF selector changed')
    if 'if (!device->mmu.secured)' not in text['a5xx']:
        raise ValueError('vendor secure-mode loading policy changed')
    gx = cells(block(text['gdsc_dt'], 'gdsc_oxili_gx:'), 'reg')[0]
    # MSM8937 overrides the common 8916 CX address, which aliases AON_CBCR.
    cx = cells(block(text['soc_dt'], '&gdsc_oxili_cx'), 'reg')[0]
    clocks = {name: gcc_regs[name] for name in (
        'GFX3D_CMD_RCGR', 'OXILI_GFX3D_CBCR', 'OXILI_GMEM_CBCR', 'OXILI_AHB_CBCR',
        'OXILI_TIMER_CBCR', 'OXILI_AON_CBCR', 'BIMC_GFX_CBCR', 'BIMC_GPU_CBCR', 'GX_DOMAIN_MISC')}
    required_clocks = required_gpu_clocks(gpu, text['gcc'], gcc_regs)
    if ([entry['clock_name'] for entry in required_clocks] != [
            'core_clk', 'iface_clk', 'mem_iface_clk', 'alt_mem_iface_clk',
            'rbbmtimer_clk', 'alwayson_clk'] or
            {entry['register'] for entry in required_clocks} != {
                'OXILI_GFX3D_CBCR', 'OXILI_AHB_CBCR', 'BIMC_GFX_CBCR', 'BIMC_GPU_CBCR',
                'OXILI_TIMER_CBCR', 'OXILI_AON_CBCR'}):
        raise ValueError('MSM8937 GPU clock requirements changed; review the target before activation')
    if cx == 0x1800000 + clocks['OXILI_AON_CBCR']:
        raise ValueError('CX GDSC aliases the AON clock; missing SoC DT override')
    selected_regs = {name: regs[name] * 4 for name in (
        'A5XX_RBBM_STATUS', 'A5XX_RBBM_ALWAYSON_COUNTER_LO', 'A5XX_RBBM_ALWAYSON_COUNTER_HI',
        'A5XX_CP_RB_BASE', 'A5XX_CP_RB_BASE_HI', 'A5XX_CP_RB_CNTL', 'A5XX_CP_RB_RPTR',
        'A5XX_CP_RB_WPTR', 'A5XX_CP_ME_CNTL', 'A5XX_CP_PM4_INSTR_BASE_LO',
        'A5XX_CP_PM4_INSTR_BASE_HI', 'A5XX_CP_PFP_INSTR_BASE_LO', 'A5XX_CP_PFP_INSTR_BASE_HI',
        'A5XX_VBIF_VERSION')}
    return {
        'target': 'MSM8937/MSM8940 Santoni Adreno 505', 'chipid': 0x05000500,
        'chipid_mask': 0xffffff00, 'gmem_bytes': 136 * 1024, 'kernel_page_bytes': 4096,
        'gpu_pa': gpu_reg[0], 'gpu_bytes': gpu_reg[1], 'gpu_intid': 33 + 32,
        'smmu_pa': iommu_reg[0], 'smmu_bytes': iommu_reg[1],
        'user_context_gpu_offset': cells(user, 'qcom,gpu-offset')[0],
        'highest_bank_bit': cells(gpu, 'qcom,highest-bank-bit')[0],
        'gcc_pa': 0x1800000, 'gx_gdsc_pa': gx, 'cx_gdsc_pa': cx,
        'gcc_byte_offsets': clocks, 'gpu_byte_offsets': selected_regs,
        'gpu_required_clocks': required_clocks,
        'shared_gcc_registers_not_required_by_gpu': ['OXILI_GMEM_CBCR'],
        'pm4_firmware': strings['pm4fw_name'], 'pfp_firmware': strings['pfpfw_name'],
        'vendor_zap_subsystem': strings['zap_name'],
        'zap_policy': 'vendor loads it only with secure MMU; live TZ/MMU policy unverified',
        'hwcg': table(text['a5xx'], 'a50x_hwcg_regs[]', regs),
        'vbif': table(text['a5xx'], 'a530_vbif[]', regs),
        'me_init_words': [type7(0x48, 8), 0x2f, 3, 0x20000000, 0, 0, 0xb, 0, 0],
        'initial_client_limit_bytes': 32 * 1024 * 1024,
        'initial_total_limit_bytes': 64 * 1024 * 1024,
        'source_sha256': {SOURCES[key]: sha(value) for key, value in raw.items()},
        'hardware_activation_ready': False,
        'pending': ['device firmware provenance', 'live TZ/secure-MMU policy',
                    'power/clock readback and RPM corner sequencing',
                    'guarded SMMU mappings and GPU fence execution'],
    }


def ucode(data, name):
    if len(data) < 8 or len(data) > MAX_UCODE_BYTES or len(data) % 4:
        raise ValueError(f'{name}: invalid ucode size/alignment')
    header, version = struct.unpack_from('<II', data)
    if version & 0xf == 0xa:
        if len(data) < 16:
            raise ValueError(f'{name}: truncated extended version header')
        version = (version & ~0xfff) | ((struct.unpack_from('<I', data, 12)[0] & 0xfff000) >> 12)
    payload = data[4:]  # Vendor _load_firmware strips exactly the first dword.
    return {'file': name, 'file_sha256': sha(data), 'payload_sha256': sha(payload),
            'header_word': header, 'version': version, 'payload_bytes': len(payload),
            'payload_dwords': len(payload) // 4, 'authenticity_verified': False}, payload


def zap_segments(directory, subsystem):
    name = subsystem + '.mdt'
    data = read_limited(directory / name, MAX_ZAP_BYTES)
    if len(data) < 52 or len(data) > MAX_ZAP_BYTES or data[:4] != b'\x7fELF' or data[5:7] != b'\x01\x01':
        raise ValueError('invalid little-endian zap ELF metadata')
    kind = data[4]
    if kind == 1:
        phoff = struct.unpack_from('<I', data, 28)[0]
        entsize, count = struct.unpack_from('<HH', data, 42)
        minimum = 32
    elif kind == 2 and len(data) >= 64:
        phoff = struct.unpack_from('<Q', data, 32)[0]
        entsize, count = struct.unpack_from('<HH', data, 54)
        minimum = 56
    else:
        raise ValueError('unsupported zap ELF class')
    # EM_ARM, EM_QDSP6 (a506_zap), EM_AARCH64. This is a format check,
    # not evidence that the signature or TrustZone will accept this image.
    if struct.unpack_from('<H', data, 18)[0] not in (40, 164, 183):
        raise ValueError('zap ELF is not ARM/AArch64/QDSP6')
    if not 1 <= count <= 64 or entsize != minimum or phoff < (52 if kind == 1 else 64) or phoff + count * entsize > len(data):
        raise ValueError('zap ELF program table out of bounds')
    records, copies, ranges = [], [(name, data)], []
    total = 0
    for index in range(count):
        off = phoff + index * entsize
        if kind == 1:
            ptype, _, _, paddr, size, memsz, flags, _ = struct.unpack_from('<8I', data, off)
        else:
            ptype, flags, _, _, paddr, size, memsz, _ = struct.unpack_from('<II6Q', data, off)
        if ptype != 1 or (flags & 0x07000000) == 0x02000000 or memsz == 0:
            continue  # Qualcomm hash segment / non-load entries are not bXX payloads.
        if size > memsz or memsz > MAX_ZAP_BYTES or paddr + memsz > (1 << (32 if kind == 1 else 64)):
            raise ValueError('invalid zap load-segment range')
        if any(paddr < end and start < paddr + memsz for start, end in ranges):
            raise ValueError('overlapping zap load segments')
        ranges.append((paddr, paddr + memsz))
        total += memsz
        if total > MAX_ZAP_BYTES:
            raise ValueError('zap memory budget exceeded')
        filename = f'{subsystem}.b{index:02d}' if size else None
        contents = read_limited(directory / filename, size) if size else b''
        if len(contents) != size:
            raise ValueError(f'{filename}: segment size mismatch')
        records.append({'file': filename, 'sha256': sha(contents), 'bytes': size, 'zero_fill_bytes': memsz - size})
        if size:
            copies.append((filename, contents))
    if not any(record['bytes'] for record in records):
        raise ValueError('zap metadata has no load payloads')
    return {'metadata': name, 'sha256': sha(data), 'segments': records,
            'signature_or_TZ_acceptance_verified': False}, copies


def header(target):
    text = '/* Generated vendor target data only: not a GPU initialization sequence. */\n'
    text += '#ifndef SANTONI_GPU_PREP_TARGET_H\n#define SANTONI_GPU_PREP_TARGET_H\n#include <stdint.h>\n'
    for key in ('chipid', 'chipid_mask', 'gmem_bytes', 'kernel_page_bytes', 'gpu_pa', 'gpu_bytes',
                'gpu_intid', 'smmu_pa', 'smmu_bytes', 'gx_gdsc_pa', 'cx_gdsc_pa'):
        text += f'#define SGPU_{key.upper()} 0x{target[key]:x}u\n'
    for name, value in target['gcc_byte_offsets'].items():
        text += f'#define SGPU_GCC_{name} 0x{value:x}u\n'
    text += '/* Shared GCC definitions above are not all required GPU clocks. */\n'
    text += f'#define SGPU_GPU_CLOCK_COUNT {len(target["gpu_required_clocks"])}u\n'
    text += 'static const uint32_t sgpu_gpu_clock_offsets[SGPU_GPU_CLOCK_COUNT] = {'
    text += ', '.join(f'0x{entry["byte_offset"]:x}u' for entry in target['gpu_required_clocks']) + '};\n'
    for name, value in target['gpu_byte_offsets'].items():
        text += f'#define SGPU_{name} 0x{value:x}u\n'
    text += 'struct sgpu_regval { uint32_t byte_offset, value; };\n'
    for name in ('hwcg', 'vbif'):
        text += f'static const struct sgpu_regval sgpu_{name}[] = {{\n'
        for item in target[name]:
            text += f'    {{0x{item["byte_offset"]:x}u, 0x{item["value"]:x}u}},\n'
        text += '};\n'
    text += 'static const uint32_t sgpu_me_init[9] = {'
    text += ', '.join(f'0x{value:x}u' for value in target['me_init_words']) + '};\n#endif\n'
    return text


def prepare(vendor, output, firmware=None):
    if firmware:
        resolved = output.resolve()
        if resolved.is_relative_to(ROOT) and not resolved.is_relative_to(ROOT / 'out'):
            raise ValueError('firmware bundles inside this repository must stay under ignored out/')
    target = vendor_target(vendor)
    source_copies = {}
    for path, digest in target['source_sha256'].items():
        data = (vendor / path).read_bytes()
        if sha(data) != digest:
            raise ValueError(f'vendor source changed during preparation: {path}')
        source_copies[path] = data
    copies, intake = [], {'state': 'firmware not supplied'}
    if firmware:
        intake = {'state': 'syntax checked; device provenance/TZ acceptance still unverified', 'ucode': []}
        for key in ('pm4_firmware', 'pfp_firmware'):
            name = target[key]
            data = read_limited(firmware / name, MAX_UCODE_BYTES)
            info, payload = ucode(data, name)
            intake['ucode'].append(info)
            copies += [(name, data), (name + '.payload', payload)]
        mdt = firmware / (target['vendor_zap_subsystem'] + '.mdt')
        if mdt.exists():
            intake['zap'], split = zap_segments(firmware, target['vendor_zap_subsystem'])
            copies += split
        else:
            intake['zap'] = {'state': 'not supplied; live secure-MMU policy must be resolved'}
    if output.exists() and any(output.iterdir()):
        raise ValueError(f'refusing to overwrite nonempty preparation: {output}')
    output.mkdir(parents=True, exist_ok=True)
    (output / 'target.json').write_text(json.dumps(target, indent=2) + '\n')
    (output / 'santoni_gpu_target.h').write_text(header(target))
    (output / 'me-init.bin').write_bytes(struct.pack('<9I', *target['me_init_words']))
    (output / 'firmware-intake.json').write_text(json.dumps(intake, indent=2) + '\n')
    for path, data in source_copies.items():
        dest = output / 'vendor-source' / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    if copies:
        dest = output / 'firmware'
        dest.mkdir()
        for name, data in copies:
            (dest / name).write_bytes(data)
    return target, intake


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vendor', type=Path, default=VENDOR)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--firmware-dir', type=Path)
    args = parser.parse_args()
    target, intake = prepare(args.vendor, args.out, args.firmware_dir)
    print(f'A505 preparation: {args.out}')
    print(f'GMEM={target["gmem_bytes"]} page={target["kernel_page_bytes"]} IRQ={target["gpu_intid"]}')
    print(f'HWCG={len(target["hwcg"])} VBIF={len(target["vbif"])} vendor register entries')
    print(f'Firmware: {intake["state"]}; secure subsystem={target["vendor_zap_subsystem"]}')
    print('No hardware initialization, firmware execution or UI injection performed.')


if __name__ == '__main__':
    main()
