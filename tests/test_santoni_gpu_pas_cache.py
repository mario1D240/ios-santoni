#!/usr/bin/env python3
"""Host contracts for actual PAS cache, pmap and physical-aperture sources."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from urllib.request import urlopen

from reconstruct_santoni_smp import reconstruct as reconstruct_vm
from reconstruct_santoni_touch import reconstruct as reconstruct_gpu
from test_santoni_gpu_prepare import source_function

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = {
    'osfmk/arm/pmap/pmap.c': '78cdd8a97fae341dd2b757c8def4799e824f56e79ccb8d1b654f92cd6c78e375',
    'osfmk/arm64/arm_vm_init.c': '3aef6df1e86fea3061ef4b5b83053502e2c50bf2e636d6949c4d55a58181e3f5',
}
VARIANTS = (('O0', ['-O0']), ('O2', ['-O2']),
            ('ubsan', ['-O2', '-fsanitize=undefined', '-fno-sanitize-recover=all']))


def sources(work, candidate=None, upstream=None):
    if candidate:
        return {name: (candidate / name).read_text() for name in
                (*UPSTREAM, 'bsd/dev/santoni_gpu.c')}
    pristine = {}
    for name, digest in UPSTREAM.items():
        if upstream:
            data = (upstream / name).read_bytes()
        else:
            with urlopen('https://raw.githubusercontent.com/apple-oss-distributions/xnu/xnu-8796.141.3/' + name,
                         timeout=45) as response:
                data = response.read()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('Unrecognized pristine XNU source: ' + name)
        pristine[name] = data
    reconstruct_vm(work / 'vm', source=pristine)
    reconstruct_gpu(work / 'gpu', targets=('bsd/dev/santoni_gpu.c',))
    return {**{name: (work / 'vm' / name).read_text() for name in UPSTREAM},
            'bsd/dev/santoni_gpu.c': (work / 'gpu/bsd/dev/santoni_gpu.c').read_text()}


def headers(source):
    adapter = source['bsd/dev/santoni_gpu.c']
    prefix = adapter[adapter.index('#define SG_PAS_MAX_BYTES'):adapter.index('struct sgpu_zap_layout {')]
    policy = adapter[adapter.index('/* PAS cache policy:'):adapter.index('/* SCM query policy:')]
    barrier = '__asm__ volatile("dsb sy" ::: "memory");'
    assert policy.count(barrier) == 1
    policy = policy.replace(barrier, 'host_barrier();')
    assert '__asm__' not in policy
    cache = prefix + '\n' + source_function(adapter, 'sgpu_pas_allocate') + '\n' + \
        source_function(adapter, 'sgpu_pas_release') + '\n' + policy
    pmap = source['osfmk/arm/pmap/pmap.c']
    pmap = '\n'.join(source_function(pmap, name) for name in
                     ('pmap_santoni_pas_aperture_pte', 'pmap_santoni_pas_cache_control'))
    vm = source['osfmk/arm64/arm_vm_init.c']
    assert vm.index('arm_vm_physmap_init(args);') < vm.index('kva_active = TRUE;')
    assert vm.index('arm_vm_physmap_init(args);') < vm.index('set_mmu_ttb_alternate(cpu_ttep & TTBR_BADDR_MASK);')
    vm = vm[vm.rindex('static void\narm_vm_physmap_init('):]
    return {'cache': cache, 'pmap': pmap, 'physmap': source_function(vm, 'arm_vm_physmap_init')}


def run_contract(work, name, header, flags, suffix, expected_success=True):
    folder = work / (name + '-' + suffix)
    folder.mkdir()
    header_name = {'cache': 'santoni_gpu_pas_cache_actual.h', 'pmap': 'santoni_gpu_pas_pmap_actual.h',
                   'physmap': 'santoni_gpu_pas_physmap_actual.h'}[name]
    test_name = {'cache': 'test_santoni_gpu_pas_cache.c', 'pmap': 'test_santoni_gpu_pas_cache_pmap.c',
                 'physmap': 'test_santoni_gpu_pas_physmap.c'}[name]
    (folder / header_name).write_text(header)
    binary = folder / 'test'
    compiled = subprocess.run([*shlex.split(os.environ.get('HOST_CC', 'clang')), '-std=c11', *flags,
        '-Wall', '-Wextra', '-Werror', '-I', str(folder), str(ROOT / 'tests' / test_name),
        '-o', str(binary)], text=True, capture_output=True, timeout=60)
    if compiled.returncode:
        raise RuntimeError(f'{name}/{suffix} did not compile:\n{compiled.stderr}')
    ran = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30)
    if expected_success and (ran.returncode or 'PASS actual' not in ran.stdout):
        raise RuntimeError(f'{name}/{suffix}: {ran.stderr}\n{ran.stdout}')
    if not expected_success and ran.returncode == 0:
        raise RuntimeError('Unsafe compiled mutation survived: ' + name + '/' + suffix)
    return ran.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, help='explicit uncommitted draft for pre-patch verification')
    parser.add_argument('--upstream', type=Path, help='hash-checked pristine XNU inputs')
    parser.add_argument('--skip-mutations', action='store_true')
    args = parser.parse_args()
    preferred = Path('/data/data/com.termux/files/usr/tmp/opencode')
    with tempfile.TemporaryDirectory(prefix='pas-cache-', dir=preferred if preferred.is_dir() else None) as tmp:
        work = Path(tmp); source = sources(work, args.candidate, args.upstream); actual = headers(source)
        for variant, flags in VARIANTS:
            for name, header in actual.items():
                extra = ['-DARM64_BOARD_CONFIG_SANTONI'] if name == 'physmap' else []
                run_contract(work, name, header, [*flags, *extra], variant)
            run_contract(work, 'physmap', actual['physmap'], flags, variant + '-generic')
        mutations = (
            ('cache', 'uncertain', 'span->uncertain = true; /* a failed', 'span->uncertain = false; /* a failed'),
            ('cache', 'release-first', 'while (span->converted_pages)', 'while (0 && span->converted_pages)'),
            ('cache', 'cleanup-return', 'VM_WIMG_WCOMB, VM_WIMG_DEFAULT) ||', 'VM_WIMG_WCOMB, VM_WIMG_DEFAULT) &&'),
            ('cache', 'one-shot', 'if (!trial || trial->attempted) return;', 'if (!trial) return;'),
            ('cache', 'release-bounds', 'span->memory.bytes > SG_PAS_MAX_BYTES ||', 'span->memory.bytes == 999u ||'),
            ('cache', 'zap-opt-in', 'zap != 1 || scm != 0', 'zap == 99 || scm != 0'),
            ('cache', 'scm-exclusion', 'zap != 1 || scm != 0', 'zap != 1 || scm == 99'),
            ('pmap', 'hint', '!(*pte & ARM_PTE_HINT_MASK)', 'true'),
            ('pmap', 'aperture-store', 'write_pte_strong(pte, entry);', 'if (0) write_pte_strong(pte, entry);'),
            ('pmap', 'sync', 'sync_tlb_flush();', 'if (0) sync_tlb_flush();'),
            ('pmap', 'cas-bound', 'retry < 64', 'retry < 65'),
            ('physmap', 'block-alias', '    0);', '    ARM64_GRANULE_ALLOW_BLOCK | ARM64_GRANULE_ALLOW_HINT);'),
        )
        rejected = 0
        if not args.skip_mutations:
            for name, label, old, new in mutations:
                assert old in actual[name], label
                changed = actual[name].replace(old, new)
                for variant, flags in VARIANTS:
                    extra = ['-DARM64_BOARD_CONFIG_SANTONI'] if name == 'physmap' else []
                    run_contract(work, name, changed, [*flags, *extra], label + '-' + variant, False)
                    rejected += 1
        print(json.dumps({'source_kind': 'explicit_candidate' if args.candidate else 'production_patch_reconstruction',
              'source_sha256': {name: hashlib.sha256(text.encode()).hexdigest() for name, text in source.items()},
              'native_runs_passed': 12, 'compiled_unsafe_variants_rejected': rejected,
              'hardware_verified': False}, indent=2))


if __name__ == '__main__':
    main()
