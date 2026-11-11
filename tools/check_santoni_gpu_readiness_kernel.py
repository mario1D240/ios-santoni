#!/usr/bin/env python3
"""Bind the trace-pause policy to actual kernel words and prepared EL0 getters."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from check_santoni_gpu_user_fault_kernel import FaultModel, FaultMachine, require_acyclic
from santoni_gpu_binary_model import integer
from santoni_gpu_launcher_replay import require
from santoni_gpu_scalar_certificate import load_inputs, identity_of

HELPER = '_sgpu_trace_pause_required'
FUNCTIONS = (HELPER, '_trace', '_santoni_gpu_user_launch_options_ok',
    '_santoni_gpu_user_launch_worker_ready', '_santoni_gpu_user_launch_mount_published',
    '_launch_options', '_sgpu_launch_role')
CASES = ('normal', 'disabled', 'bad-enable', 'mode0', 'mode1', 'mode2', 'mode4',
         'unready', 'unmounted', 'zap', 'scm', 'cache', 'user-test', 'bad-suffix',
         'missing-enable', 'stock', 'pixels', 'submit', 'session', 'user')


class TraceModel(FaultModel):
    MESSAGE = 0x63000000

    def __init__(self, codes, image, names, e, case, before):
        self.e, self.case = e, case
        self.vm = FaultMachine({n: codes[n] for n in FUNCTIONS}, image, names, e)
        self.m = self.vm.memory
        launch = next(iter(names['_launch']))
        self.m.map(launch, 88)
        self.m.put(launch + 64, 1 if case == 'unready' else 2, 4)
        self.m.put(launch + 78, int(case != 'unmounted'), 1)
        self.m.readonly.append((launch, launch + 88))
        self.options = {'santonigpu': 3, 'santonigpu_user_exec': 1, 'santonigpu_stock': 1,
            'santonigpu_pixels': 1, 'santonigpu_submit': 1, 'santonigpu_session': 1,
            'santonigpu_user': 1, 'santonigpu_user_test': 0, 'santonigpu_zap': 0,
            'santonigpu_scm': 0, 'santonigpu_cache': 0, 'launchdsuffix': 'release'}
        if case == 'disabled': self.options['santonigpu_user_exec'] = 0
        if case == 'bad-enable': self.options['santonigpu_user_exec'] = 2
        if case in ('zap', 'scm', 'cache', 'user-test'):
            self.options['santonigpu_' + ('user_test' if case == 'user-test' else case)] = 1
        if case == 'bad-suffix': self.options['launchdsuffix'] = 'debug'
        self.sg = next(iter(names['_sg']))
        self.m.map(self.sg, 128)
        mode = int(case[4:]) if case.startswith('mode') else 3
        self.m.put(self.sg + 84, mode, 4)
        self.m.readonly.append((self.sg, self.sg + 128))
        if case == 'missing-enable': del self.options['santonigpu_user_exec']
        if case in ('stock', 'pixels', 'submit', 'session', 'user'):
            self.options['santonigpu_' + case] = 0
        self.message = b'before synthetic stage\0' if before else b'after synthetic stage\0'
        self.m.map(self.MESSAGE, len(self.message)); self.m.write(self.MESSAGE, self.message)
        self.m.readonly.append((self.MESSAGE, self.MESSAGE + len(self.message)))
        self.waits, self.printf_count, self.before = [], 0, before
        self.vm.external = self.external; self.m.write_hook = self.write

    def write(self, address, size):
        require(self.vm.STACK <= address < address + size <= self.vm.STACK + self.vm.STACK_SIZE,
                'trace-pause policy writes outside its stack')

    def external(self, target, state, probe=False, before=None):
        name = self.vm.by_address.get(target)
        handled = ('_printf', '_strncmp', '_clock_interval_to_deadline', '_assert_wait_deadline', '_thread_block')
        if name not in handled:
            if name == '_PE_parse_boot_argn' and self.case == 'missing-enable':
                if probe: return True
                if self.text(integer(before, 'x0')) == 'santonigpu_user_exec':
                    require(integer(before, 'x2') == 4, 'enable parse width differs')
                    state.put('x0', self.e._Value(64, 0)); return True
            return super().external(target, state, probe, before)
        if probe: return True
        a = lambda i: integer(before, 'x' + str(i))
        result = 0
        if name == '_printf':
            require(self.text(a(0)) == 'SANTONI GPU: %s [%08x %08x %08x]\n', 'trace print format differs')
            sp = integer(before, 'sp')
            require(self.m.get(sp, 8) == self.MESSAGE and
                    [self.m.get(sp + off, 4) for off in (8, 16, 24)] == [0x80000001, 0xffffffff, 0x76543210],
                    'trace message/scalar printf ABI differs')
            self.printf_count += 1
        elif name == '_strncmp':
            require(a(0) == self.MESSAGE and self.text(a(1)) == 'before ' and a(2) == 7,
                    'trace prefix check differs')
            result = int(not self.before)
        elif name == '_clock_interval_to_deadline':
            require((a(0), a(1)) == (11000000, 1000), 'trace wait duration/unit differs')
            require(self.vm.STACK <= a(2) < a(2) + 8 <= self.vm.STACK + self.vm.STACK_SIZE,
                    'trace deadline pointer escapes stack')
            self.m.put(a(2), 123456789, 8); self.waits.append('deadline')
        elif name == '_assert_wait_deadline':
            require((a(0), a(1), a(2)) == (self.sg + 92, 0, 123456789), 'trace sleep event/interrupt/deadline differs')
            self.waits.append('assert')
        else:
            require(a(0) == 0, 'trace continuation changed'); self.waits.append('block')
        state.put('x0', self.e._Value(64, result)); return True

    def run(self):
        self.vm.run('_trace', (0xabcdef, self.MESSAGE, 0x80000001, 0xffffffff, 0x76543210), budget=4096)
        require(self.printf_count == 1, 'trace print missing/repeated')
        expected = ['deadline', 'assert', 'block'] if self.before and self.case != 'normal' else []
        require(self.waits == expected, 'trace pauses escaped prepared exact EL0 role')
        return {'success': True, 'printf_count': 1, 'wait_calls': self.waits}


def audit(ci):
    ci = Path(ci).resolve()
    base, codes, image, names, e = load_inputs(ci)
    kernel = ci / 'kernel/kernel.development.santoni'
    directory = ci / 'readiness-components'; directory.mkdir(exist_ok=False)
    for name in FUNCTIONS:
        require(len(names.get(name, ())) == 1, 'missing/ambiguous readiness symbol: ' + name)
        disassembly = subprocess.check_output(['llvm-objdump', '--disassemble', '--disassemble-zeroes',
            '--disassemble-symbols=' + name, str(kernel)], text=True)
        (directory / (name[1:] + '.asm')).write_text(disassembly)
        code = e._Code(disassembly, name, next(iter(names[name])), noreturn=names.get('___stack_chk_fail', ()))
        words = {int(pc, 16): int(word, 16) for pc, word in re.findall(
            r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s', disassembly, re.M)}
        require(set(words) == set(code.ins) | set(code.padding) and
                all(image.read(pc, 4) == word for pc, word in words.items()), 'readiness words differ from kernel')
        end = max(words) + 4
        require(any(s['initprot'] == 5 and s['vmaddr'] <= code.entry < end <= s['vmaddr'] + s['filesize']
                    for s in image.segs), 'readiness code is not bounded read-only executable file bytes')
        require(all(not e._unsupported(op, ','.join(args)) for op, args in code.ins.values()),
                'readiness policy uses unsupported A53 code')
        require_acyclic(code); codes[name] = code
    require(len(codes['_trace'].calls_to(names[HELPER])) == 1, 'trace lacks exact pause-policy call')
    results = {}
    for case in CASES:
        for before in (False, True):
            label = case + ('-before' if before else '-after')
            results[label] = TraceModel(codes, image, names, e, case, before).run()
            print('Actual trace policy passed:', label, flush=True)
    record = {**identity_of(base), 'success': True, 'hardware_verified': False, 'cases': len(results),
        'actual_trace_and_getters_checked': True, 'stack_only_writes_checked': True,
        'printf_and_wait_ABI_checked': True, 'exact_EL0_role_checked': True, 'acyclic_A53_checked': True,
        'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'results': results}
    (ci / 'readiness-binary-audit.json').write_text(json.dumps(record, indent=2)+'\n')
    return record


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('ci', type=Path)
    print(json.dumps(audit(p.parse_args().ci), indent=2))
