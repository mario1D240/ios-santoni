#!/usr/bin/env python3
"""Host control-flow tests of actual reset assembly; never assembles a kernel."""
import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

from reconstruct_santoni_smp import CPU, ROOT, originals, reconstruct

ASM = 'osfmk/arm64/start.s'
TRACE = 0x10000000
IDS = [0x100, 0x101, 0x102, 0x103, 0, 1, 2, 3]


def preprocess(text, gic, santoni=True):
    flags = ['-DSWEET=1', '-DSWEET_SMP_MAX_CPUS=8', '-DMAX_CPUS=8',
             f'-DHAS_GIC_V3={gic}', '-DEXT(x)=x', '-DLEXT(x)=x:',
             '-DCPU_NUMBER_GS=4', '-DCPU_PHYS_ID=8', '-DCPU_RESET_HANDLER=16',
             '-DCPU_DATA_PADDR=8', '-DCPU_DATA_ENTRIES=16', '-DDAIFSC_ALL=15']
    if santoni:
        flags.append('-DSANTONI=1')
    # Native preprocessing only: no -target, assembly, object or kernel build.
    command = [*shlex.split(os.environ.get('HOST_CC', 'clang')),
               '-E', '-P', '-x', 'assembler-with-cpp', *flags, '-']
    return subprocess.check_output(command, input=text, text=True, timeout=30)


class UnsupportedRegister(Exception):
    pass


class Machine:
    """Limited instruction fixture, not a CPU/MMU/weak-memory emulator."""
    def __init__(self, text, el, mpidr, context, gic):
        self.reg = {'x0': context}
        self.el, self.mpidr, self.gic = el, mpidr, gic
        self.sys = {}
        self.mem, self.writes, self.accesses = {}, [], []
        self.labels, self.code = {}, []
        for raw in text.splitlines():
            line = raw.split('//', 1)[0].strip()
            if not line or line.startswith('.'):
                continue
            if line.endswith(':'):
                self.labels[line[:-1]] = len(self.code)
            else:
                self.code.append(line)
        self.external = {'sweet_secondary_trace': TRACE,
                         'LowExceptionVectorBase': 0x80010000,
                         'LowResetVectorBase': 0x80020000,
                         'ResetHandlerData': 0x50000000,
                         'const_boot_args': 0x51000000,
                         'start_cpu': 0x80030000,
                         'resume_idle_cpu': 0x80031000}
        self.compare = (0, 0)

    def value(self, text):
        text = text.strip().lstrip('#')
        if text in ('xzr', 'wzr'):
            return 0
        if re.fullmatch('[xw][0-9]+', text):
            return self.reg.get('x' + text[1:], 0) & (0xffffffff if text[0] == 'w' else 0xffffffffffffffff)
        if '@page' in text:
            name, suffix = text.split('@', 1)
            addr = self.external.get(name, 0x80000000 + self.labels.get(name, 0) * 4)
            return addr & 0xfff if suffix == 'pageoff' else addr & ~0xfff
        if not re.fullmatch(r'[0-9a-fA-FxX()\s*+<>|&-]+', text):
            raise ValueError('unsupported fixture value: ' + text)
        return int(eval(text, {'__builtins__': {}}, {}))

    def put(self, name, value):
        if name not in ('xzr', 'wzr'):
            self.reg['x' + name[1:]] = value & (0xffffffff if name.startswith('w') else 0xffffffffffffffff)

    def jump(self, label, pc):
        if label == '1f':
            return self.labels['1']
        return self.labels[label]

    def run(self, entry):
        pc = self.labels[entry]
        for _ in range(1000):
            line = self.code[pc]
            parts = line.split(None, 1)
            op, operands = parts[0], parts[1] if len(parts) > 1 else ''
            args = [part.strip() for part in operands.split(',')]
            next_pc = pc + 1
            if op == 'mrs':
                name = args[1]
                self.accesses.append(name)
                if name.startswith('ICC_') and not self.gic:
                    raise UnsupportedRegister(name)
                value = self.el if name == 'CurrentEL' else self.mpidr if name == 'MPIDR_EL1' else 0x410fd034 if name == 'MIDR_EL1' else self.sys.get(name, 0)
                self.put(args[0], value)
            elif op == 'msr':
                name = args[0]
                self.accesses.append(name)
                if name.startswith('ICC_') and not self.gic:
                    raise UnsupportedRegister(name)
                self.sys[name] = self.value(args[1])
            elif op in ('mov', 'MOV64'):
                self.put(args[0], self.value(args[1]))
            elif op == 'adrp':
                self.put(args[0], self.value(args[1]))
            elif op in ('add', 'orr', 'and'):
                a, b = self.value(args[1]), self.value(args[2])
                if len(args) == 4:
                    assert args[3].startswith('lsl ')
                    b <<= self.value(args[3][4:])
                self.put(args[0], a + b if op == 'add' else a | b if op == 'orr' else a & b)
            elif op == 'cmp':
                self.compare = self.value(args[0]), self.value(args[1])
            elif op.startswith('b.') or op in ('beq', 'bne'):
                a, b = self.compare
                take = a == b if op in ('b.eq', 'beq') else a != b if op in ('b.ne', 'bne') else a >= b if op == 'b.hs' else None
                if take is None:
                    raise ValueError('unsupported fixture branch: ' + op)
                if take:
                    next_pc = self.jump(operands.strip(), pc)
            elif op in ('cbz', 'cbnz'):
                take = self.value(args[0]) == 0
                if take == (op == 'cbz'):
                    next_pc = self.jump(args[1], pc)
            elif op == 'b':
                label = operands.strip()
                if label == '.':
                    return 'hang'
                if label == 'LowResetVectorBase':
                    return 'reset'
                next_pc = self.jump(label, pc)
            elif op == 'eret':
                assert self.el == 8 and (self.sys['SPSR_EL2'] & 0x1f) == 5
                self.el = 4
                addr = self.sys['ELR_EL2']
                next_pc = (addr - 0x80000000) // 4
            elif op in ('ldr', 'ldrh', 'str'):
                assert args[1].startswith('[') and args[-1].endswith(']')
                base = self.value(args[1][1:].rstrip(']'))
                offset = self.value(args[2].rstrip(']')) if len(args) > 2 else 0
                addr = base + offset
                if op == 'str':
                    assert TRACE <= addr <= TRACE + 8 * 64 - 8, 'out-of-range reset trace write'
                    self.mem[addr] = self.value(args[0])
                    self.writes.append(addr)
                else:
                    value = self.mem.get(addr, 0)
                    self.put(args[0], value & 0xffff if op == 'ldrh' else value)
            elif op == 'blr':
                assert self.value(args[0]) in (self.external['start_cpu'], self.external['resume_idle_cpu'])
                return 'handler'
            elif op not in ('dsb', 'isb'):
                raise ValueError('unsupported fixture instruction: ' + line)
            pc = next_pc
        raise AssertionError('fixture did not terminate')


def check_asm(text):
    entry = text[text.index('\t.globl EXT(sweet_secondary_entry)'):text.index('#endif /* SWEET */', text.index('LEXT(sweet_secondary_entry)'))]
    lookup = text[text.index('LEXT(reset_vector)'):text.index('LEXT(LowResetVectorEnd)')]
    failures, count = [], 0
    def case(name, run):
        nonlocal count
        count += 1
        try:
            run()
        except (AssertionError, UnsupportedRegister, ValueError) as error:
            failures.append((name, str(error)))
    gic2 = preprocess(entry, 0)
    gic3 = preprocess(entry, 1, False)
    for cpu, phys in enumerate(IDS):
        for el in (4, 8):
            def valid(cpu=cpu, phys=phys, el=el):
                vm = Machine(gic2, el, phys | 0x80000000, cpu, 0)
                assert vm.run('sweet_secondary_entry') == 'reset' and vm.el == 4
                assert not any(name.startswith('ICC_') for name in vm.accesses)
                if el == 8:
                    assert vm.sys['HCR_EL2'] == 1 << 31 and vm.sys['CNTVOFF_EL2'] == 0
                    assert vm.sys.get('VMPIDR_EL2') == (phys | 0x80000000)
                    assert vm.sys.get('VPIDR_EL2') == 0x410fd034
            case(f'gic2-el{el // 4}-cpu{cpu}', valid)
            def trace(cpu=cpu, phys=phys, el=el):
                vm = Machine(gic2, el, phys, cpu, 0)
                assert vm.run('sweet_secondary_entry') == 'reset'
                assert vm.mem.get(TRACE + 64 * cpu) == 0x304
                assert vm.mem.get(TRACE + 64 * cpu + 8) == phys
                assert all(TRACE + 64 * cpu <= addr < TRACE + 64 * (cpu + 1) for addr in vm.writes)
            case(f'private-trace-el{el // 4}-cpu{cpu}', trace)
    for context in (8, 64, 0xffffffffffffffff):
        def invalid(context=context):
            vm = Machine(gic2, 8, 0, context, 0)
            assert vm.run('sweet_secondary_entry') == 'reset' and not vm.writes
        case(f'invalid-context-{context}', invalid)
    def v3():
        vm = Machine(gic3, 8, 0x100, 0, 1)
        assert vm.run('sweet_secondary_entry') == 'reset'
        assert vm.sys['ICC_SRE_EL2'] == 9 and not vm.writes
        assert vm.sys.get('VMPIDR_EL2') == 0x100 and vm.sys.get('VPIDR_EL2') == 0x410fd034
    case('gic3-el2-control', v3)
    def bad_el():
        vm = Machine(gic2, 12, 0, 4, 0)
        assert vm.run('sweet_secondary_entry') == 'hang'
        assert not any(name.endswith('_EL2') for name in vm.accesses)
    case('invalid-el-is-not-accepted', bad_el)
    reset = preprocess(lookup, 0)
    for cpu, phys in enumerate(IDS):
        def find(cpu=cpu, phys=phys, require_trace=False):
            vm = Machine(reset, 4, phys | 0x80000000, 0, 0)
            vm.mem[vm.external['ResetHandlerData'] + 16] = 0x30000000
            for i, pid in enumerate(IDS):
                data = 0x20000000 + i * 0x1000
                vm.mem[0x30000000 + i * 16 + 8] = data
                vm.mem[data + 4], vm.mem[data + 8] = i, pid
                vm.mem[data + 16] = vm.external['start_cpu']
            assert vm.run('reset_vector') == 'handler'
            assert vm.reg['x21'] == 0x20000000 + cpu * 0x1000
            if require_trace:
                assert vm.mem.get(TRACE + cpu * 64) == 0x404
        case(f'physical-lookup-control-cpu{cpu}', find)
        case(f'lookup-trace-cpu{cpu}', lambda cpu=cpu, phys=phys: find(cpu, phys, True))
    return count, failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--through', type=int)
    parser.add_argument('--upstream', type=Path)
    args = parser.parse_args()
    preferred = Path('/data/data/com.termux/files/usr/tmp/opencode')
    with tempfile.TemporaryDirectory(prefix='santoni-secondary-', dir=preferred if preferred.is_dir() else None) as tmp:
        work = Path(tmp)
        manifest = reconstruct(work / 'src', args.through, originals(args.upstream, True))
        text = (work / 'src' / ASM).read_text()
        count, failures = check_asm(text)
        cpp = (work / 'src' / CPU).read_text()
        # Carry the actual declaration into C++ and link against a real C
        # translation unit. A C++ fixture definition used to hide this ABI bug.
        declaration = re.search(r'^extern "C" void CleanPoC_DcacheRegion_Force[^\n]*;', cpp, re.MULTILINE)
        if declaration:
            cache_declaration = declaration.group(0)
        else:
            header = (work / 'src/osfmk/arm/caches_internal.h').read_text()
            cache_declaration = re.search(r'^extern void CleanPoC_DcacheRegion_Force[^\n]*;', header, re.MULTILINE).group(0)
        marker = 'struct sweet_cpu_reset_trace {'
        prefix = ''
        if marker in cpp:
            start = cpp.index(marker)
            end = cpp.index(';', cpp.index('extern "C" sweet_cpu_reset_trace', start)) + 1
            prefix = '#define SANTONI_HOST_HAS_RESET_TRACE 1\n' + cpp[start:end] + '\n'
        signature = 'kern_return_t\nSweetCPU::startCPU('
        start = cpp.index(signature)
        end = cpp.index('\n}\n', start) + 3
        (work / 'santoni_start_cpu_actual.h').write_text(cache_declaration + '\n' + prefix + cpp[start:end])
        binary = work / 'start-cpu-host'
        cache_object = work / 'cache-mock.o'
        subprocess.run([*shlex.split(os.environ.get('HOST_CC', 'clang')), '-std=c11', '-O2',
                        '-Wall', '-Wextra', '-Werror', '-c', str(ROOT / 'tests/santoni_cache_mock.c'),
                        '-o', str(cache_object)], check=True, timeout=30)
        linked = subprocess.run([*shlex.split(os.environ.get('HOST_CXX', 'clang++')), '-std=c++14', '-O2',
                        '-Wall', '-Wextra', '-Werror', '-I', str(work),
                        str(ROOT / 'tests/test_santoni_start_cpu.cpp'), str(cache_object), '-o', str(binary)],
                                capture_output=True, text=True, timeout=60)
        if linked.returncode:
            print('FAIL cache C/C++ ABI link:', linked.stderr.strip())
            failures.append(('startCPU', linked.stderr.strip()))
        else:
            print('ok   cache C/C++ ABI link')
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
            print(result.stdout.strip())
            if result.returncode:
                print('FAIL startCPU:', result.stderr.strip())
                failures.append(('startCPU', result.stderr.strip()))
        for name, detail in failures[:12]:
            print('FAIL', name, detail)
        print(f'Actual secondary assembly checks: {count - len([f for f in failures if f[0] != "startCPU"])}/{count} passed')
        print('Patched start.s SHA256:', manifest['sha256'][ASM])
        return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
