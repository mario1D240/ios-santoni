#!/usr/bin/env python3
"""Validate iOS config and execute the real optional CPU probe on a host."""
import argparse
import os
from pathlib import Path
import shlex
import re
import subprocess
import tempfile

from reconstruct_santoni_touch import ROOT, reconstruct
from reconstruct_santoni_smp import reconstruct as reconstruct_startup, originals
from test_santoni_ui import function

CPU = 'iokit/Kernel/arm/SweetCPU.cpp'
CONFIG = 'config/MASTER.arm64.santoni'
HEADER = 'pexpert/pexpert/arm64/SANTONI.h'
BOARD = 'pexpert/pexpert/arm64/board_config.h'
MACHINE = 'osfmk/arm64/machine_routines.c'
PRIM = 'osfmk/kern/sched_prim.c'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--through', type=int)
    args = parser.parse_args()
    preferred = Path('/data/data/com.termux/files/usr/tmp/opencode')
    with tempfile.TemporaryDirectory(prefix='santoni-performance-', dir=preferred if preferred.is_dir() else None) as tmp:
        work = Path(tmp)
        reconstruct(work / 'src', args.through, targets=(CPU, CONFIG, HEADER))
        config = (work / 'src' / CONFIG).read_text()
        assert 'config_ext_resolver' not in config, 'iOS build still enables absent external resolver'
        assert 'sweet_hfs' in config and 'config_macf' in config
        cpu = (work / 'src' / CPU).read_text()
        actual = function(cpu, 'void\nSweetCPU::probePerformance(')
        binding = re.search(r'^extern "C" processor_t thread_bind[^\n]*;', cpu, re.MULTILINE)
        if binding:
            actual = binding.group(0) + '\n' + actual
        (work / 'santoni_performance_actual.h').write_text(actual)
        binary = work / 'performance-host'
        subprocess.run([*shlex.split(os.environ.get('HOST_CXX', 'clang++')), '-std=c++14', '-O2',
                        '-Wall', '-Wextra', '-Werror', '-I', str(work),
                        str(ROOT / 'tests/test_santoni_performance.cpp'), '-o', str(binary)], check=True, timeout=60)
        for case in ('normal', 'allocation-fails', 'clock-map-fails', 'bind-fails'):
            subprocess.run([str(binary), case], check=True, timeout=15)
        print('ok   Santoni iOS config: no absent resolver, HFS/MAC policy retained')
        reconstruct_startup(work / 'topology', args.through, source=originals(startup=True))
        board = (work / 'topology' / BOARD).read_text()
        begin = board.index('#ifdef ARM64_BOARD_CONFIG_SANTONI')
        end = board.index('#endif  /* ARM64_BOARD_CONFIG_SANTONI */', begin)
        header = (work / 'src' / HEADER).read_text()
        block = board[begin:end] + '\n#endif\n'
        block = block.replace('#include <pexpert/arm64/SANTONI.h>', header)
        machine = (work / 'topology' / MACHINE).read_text()
        anchor = machine.index('Since we want to keep a linear cluster ID space')
        start = machine.index('#if defined(SANTONI)', anchor)
        end = machine.index('\n#endif', start) + len('\n#endif')
        classifier = machine[start:end]
        assert 'cpu->phys_id = (uint32_t)ml_readprop(child, "reg"' in machine
        assert 'cpu->l2_cache_id = (uint32_t)ml_readprop' in machine
        prim = (work / 'topology' / PRIM).read_text()
        stealing = function(prim, 'bool\nsched_steal_thread_enabled(')
        fixture = '''#include <cstdint>
#include <cassert>
#define ARM64_BOARD_CONFIG_SANTONI 1
'''
        fixture += block + '''
static_assert(MAX_CPUS == 8 && MAX_CPU_CLUSTERS == 1, "one ordinary-clutch root, eight CPUs");
static_assert(HAS_CLUSTER == 0 && NO_ECORE == 1, "no Apple control/AMP path");
#ifdef __ARM_AMP__
#error Santoni must stay ordinary SMP
#endif
struct cpu_info { uint32_t phys_id; unsigned cluster_type; };
static uint32_t classify(cpu_info *cpu, int santoni_flat) {
(void)cpu; (void)santoni_flat;
'''
        fixture += classifier + '''
return phys_cluster_id;
}
struct pset_node { uint64_t pset_map; };
struct processor_set { pset_node *node; };
using processor_set_t = processor_set *;
#define bit_count(value) __builtin_popcountll(value)
'''
        fixture += stealing + '''
int main() {
    const uint32_t ids[] = {0x100,0x101,0x102,0x103,0,1,2,3};
    int mapping[2] = {-1,-1}; unsigned next = 0, count[2] = {};
    for (unsigned i=0;i<8;i++) {
        cpu_info cpu = {ids[i],0};
        uint32_t phys = classify(&cpu,0);
        assert(phys == 0 && cpu.phys_id == ids[i]);
        if(mapping[phys]<0) mapping[phys]=(int)next++;
        count[mapping[phys]]++;
        assert(classify(&cpu,1)==0);
    }
    assert(next==1 && count[0]==8 && count[1]==0);
    pset_node node = {1}; processor_set pset = {&node};
    assert(!sched_steal_thread_enabled(&pset));
    node.pset_map = 3; /* old second pset arms the broken callback, even offline */
    assert(sched_steal_thread_enabled(&pset));
    return 0;
}
'''
        source = work / 'topology.cpp'
        source.write_text(fixture)
        target = work / 'topology-host'
        subprocess.run([*shlex.split(os.environ.get('HOST_CXX', 'clang++')), '-std=c++14', '-O2',
                        '-Wall', '-Wextra', '-Werror', str(source), '-o', str(target)], check=True, timeout=60)
        subprocess.run([str(target)], check=True, timeout=10)
        print('ok   actual classifier: eight CPUs in one clutch root, physical IDs retained; unsafe steal path disabled')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
