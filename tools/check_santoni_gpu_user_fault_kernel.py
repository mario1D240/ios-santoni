#!/usr/bin/env python3
"""Audit the new PID1 observation in the exact CI kernel; hardware remains unproven."""
import argparse
import ast
import hashlib
import inspect
import json
from pathlib import Path
import re
import subprocess
import textwrap
from datetime import datetime, timezone

from santoni_gpu_binary_model import Machine, integer
from santoni_gpu_launcher_replay import LauncherMachine, require
from santoni_gpu_scalar_certificate import load_inputs, identity_of
from santoni_gpu_launcher_audit import _data_sections

ROOT = '_santoni_gpu_user_fault'
HELPERS = ('_proc_isinitproc', '_santoni_gpu_user_launch_mount_published',
           '_santoni_gpu_user_launch_worker_ready', '_launch_options', '_sgpu_launch_role')
ROUTES = ('_handle_pc_align', '_handle_sp_align', '_handle_user_abort')
FIRST = b'SANTONI GPU: USER FAULT pc=%016llx sp=%016llx lr=%016llx\n\0'
SECOND = b'SANTONI GPU: USER FAULT esr=%08x far=%016llx exc=%u code=%016llx address=%016llx\n\0'


def require_acyclic(code):
    """Backward edges to a shared return are bounded; actual cycles are refused."""
    indegree = {pc: 0 for pc in code.ins}
    for targets in code.succ.values():
        for target in targets:
            indegree[target] += 1
    pending = [pc for pc, count in indegree.items() if not count]
    visited = 0
    while pending:
        pc = pending.pop(); visited += 1
        for target in code.succ[pc]:
            indegree[target] -= 1
            if not indegree[target]: pending.append(target)
    require(visited == len(indegree), 'fault helper contains a retry/cyclic path')


def bounded_section(image, names):
    sections = [s for s in _data_sections(image) if s['section'] == b'__sgpu_fault']
    require(len(sections) == 1 and len(names.get(ROOT, ())) == 1, 'fault section/entry identity differs')
    section = sections[0]; entry = next(iter(names[ROOT]))
    require(section['segment'] == section['owner'] == b'__TEXT_EXEC' and section['initprot'] == 5 and
            section['address'] == entry and entry % 16 == 0 and 0 < section['size'] <= 4096 and
            section['size'] % 4 == 0 and
            section['vmaddr'] <= entry < entry + section['size'] <= section['vmaddr'] + section['filesize'] and
            section['offset'] == section['fileoff'] + entry - section['vmaddr'],
            'fault helper section must be bounded executable/read-only file-backed code')
    require(not any(entry <= a < entry + section['size'] for n, addresses in names.items()
                    for a in addresses if n != ROOT), 'another symbol lies inside the fault helper section')
    return section


class FaultMachine(LauncherMachine):
    def atomic_step(self, op, args, state):
        if op == 'clrex':
            require(not args, 'unreviewed CLREX operands')
            self.exclusive = None
            return
        require(op in ('ldxr', 'stxr') and len(args) == (2 if op == 'ldxr' else 3),
                'unreviewed fault atomic instruction')
        address, pre = state.address(args[-1])
        require(address is not None and not pre and address.expr == self.flag,
                'fault atomic touched another object')
        if op == 'ldxr':
            require(args[0].startswith('w'), 'fault atomic load width')
            state.put(args[0], self.e._Value(32, self.memory.get(self.flag, 4)))
            self.exclusive = self.flag
        else:
            require(all(a.startswith('w') for a in args[:2]) and self.exclusive == self.flag,
                    'fault atomic store width/reservation')
            value = integer(state, args[1])
            failed = self.fail_exclusive
            state.put(args[0], self.e._Value(32, int(failed)))
            self.exclusive = None
            if not failed:
                require(value == 1, 'fault flag value differs')
                self.memory.put(self.flag, 1, 4)


# Only this diagnostic model learns the exact 32-bit exclusive instructions.
# The shared interpreter and its unknown-instruction policy stay intact.
tree = ast.parse(textwrap.dedent(inspect.getsource(Machine.run)))
loops = [n for n in ast.walk(tree) if isinstance(n, ast.For) and
         isinstance(n.iter, ast.Call) and n.iter.args and
         isinstance(n.iter.args[0], ast.Name) and n.iter.args[0].id == 'budget']
require(len(loops) == 1, 'shared interpreter loop changed')
loop = loops[0]
index = next(i for i, n in enumerate(loop.body) if isinstance(n, ast.If) and
             ast.dump(n.test) == ast.dump(ast.parse("op == 'svc'", mode='eval').body))
loop.body[index:index] = ast.parse(
    "if op in ('ldxr', 'stxr', 'clrex'):\n self.atomic_step(op,args,state)\n pc+=4\n continue\n"
    "if op in ('rev', 'mvn', 'cinc', 'ldar', 'stlr'):\n state=self.extra_step(pc,state)\n pc+=4\n continue\n").body
ast.fix_missing_locations(tree)
namespace = dict(Machine.run.__globals__)
exec(compile(tree, '<fault-only-atomic-model>', 'exec'), namespace)
FaultMachine.run = namespace['run']


class FaultModel:
    FRAME, PROC, OTHER = 0x61000000, 0x61001000, 0x61002000
    VALUES = (0x100001638, 0x16ffffff000, 0x10000261c, 0x92000021, 0x16ffffff044)

    def __init__(self, codes, image, names, e, case):
        self.e, self.case = e, case
        self.vm = FaultMachine({n: codes[n] for n in (ROOT, *HELPERS)}, image, names, e)
        self.m = self.vm.memory
        self.flag, self.launch, self.init = (next(iter(names[n])) for n in
            ('_santoni_gpu_user_fault_reported', '_launch', '_initproc'))
        self.m.map(self.FRAME, 304)
        self.m.put(self.FRAME, 20 if case == '32bit' else 21, 4)
        self.m.put(self.FRAME + 4, 72, 4)
        pc, sp, lr, esr, far = self.VALUES
        for offset, value in ((264, pc), (256, sp), (248, lr), (280, far)):
            self.m.put(self.FRAME + offset, value, 8)
        self.m.put(self.FRAME + 272, 4 if case == 'kernel' else 0, 4)
        self.m.put(self.FRAME + 288, esr, 4)
        self.m.map(self.flag, 4)
        self.m.put(self.flag, int(case == 'repeated'), 4)
        self.m.map(self.init, 8); self.m.put(self.init, self.PROC, 8)
        self.m.map(self.launch, 88)
        self.m.put(self.launch + 64, 1 if case == 'unready' else 2, 4)
        self.m.put(self.launch + 78, int(case != 'unmounted'), 1)
        self.m.readonly += [(self.FRAME, self.FRAME + 304), (self.init, self.init + 8),
                            (self.launch, self.launch + 88)]
        self.options = {'santonigpu': 3, 'santonigpu_user_exec': 1, 'santonigpu_stock': 1,
                        'santonigpu_pixels': 1, 'santonigpu_submit': 1, 'santonigpu_session': 1,
                        'santonigpu_user': 1, 'santonigpu_user_test': 0, 'santonigpu_zap': 0,
                        'santonigpu_scm': 0, 'santonigpu_cache': 0, 'launchdsuffix': 'release'}
        if case.startswith('mode'):
            self.options['santonigpu'] = int(case[4:])
        if case in ('disabled', 'bad-enable'):
            self.options['santonigpu_user_exec'] = 0 if case == 'disabled' else 2
        if case in ('zap', 'scm', 'user-test', 'cache'):
            self.options['santonigpu_' + {'user-test': 'user_test'}.get(case, case)] = 1
        if case == 'bad-suffix': self.options['launchdsuffix'] = 'debug'
        if case == 'missing-mode': del self.options['santonigpu']
        self.vm.flag, self.vm.fail_exclusive = self.flag, case == 'exclusive-failed'
        self.vm.exclusive = None
        self.prints, self.writes = [], []
        self.vm.external = self.external; self.m.write_hook = self.write

    def text(self, address):
        result = bytearray()
        for i in range(256):
            b = self.m.get(address + i, 1)
            if not b: return result.decode()
            result.append(b)
        raise ValueError('fault-model string is not bounded')

    def write(self, address, size):
        if self.vm.STACK <= address < address + size <= self.vm.STACK + self.vm.STACK_SIZE:
            return
        require(address == self.flag and size == 4, 'fault observation writes another object')
        self.writes.append((address, size))

    def external(self, target, state, probe=False, before=None):
        name = self.vm.by_address.get(target)
        if name not in ('_current_proc', '_PE_parse_boot_argn', '_strcmp', '_bzero', '_memset', '_printf'):
            return False
        if probe: return True
        a = lambda i: integer(before, 'x' + str(i))
        result = 0
        if name == '_current_proc':
            result = 0 if self.case == 'null-proc' else self.OTHER if self.case == 'other-proc' else self.PROC
        elif name == '_PE_parse_boot_argn':
            key, dest, width = self.text(a(0)), a(1), a(2)
            require(self.vm.STACK <= dest < dest + width <= self.vm.STACK + self.vm.STACK_SIZE,
                    'fault options copied outside stack')
            require(key in self.options or key == 'santonigpu', 'unknown fault option')
            if key in self.options:
                value = self.options[key]; result = 1
                if isinstance(value, str):
                    require(width == 64, 'fault suffix width'); self.m.write(dest, value.encode() + b'\0')
                else:
                    require(width == 4, 'fault option width'); self.m.put(dest, value, 4)
        elif name == '_strcmp': result = int(self.text(a(0)) != self.text(a(1)))
        elif name in ('_bzero', '_memset'):
            size = a(1) if name == '_bzero' else a(2)
            require(name == '_bzero' or a(1) == 0, 'nonzero fault initializer')
            require(self.vm.STACK <= a(0) < a(0) + size <= self.vm.STACK + self.vm.STACK_SIZE,
                    'fault initialization outside stack'); self.m.write(a(0), bytes(size))
        else:
            require(self.m.get(self.flag, 4) == 1, 'fault print before one-shot claim')
            pc, sp, lr, esr, far = self.VALUES
            stack = integer(before, 'sp'); fmt = self.text(a(0))
            if fmt == FIRST[:-1].decode():
                values = [self.m.get(stack + 8 * i, 8) for i in range(3)]
                require(not self.prints and values == [pc, sp, lr], 'fault PC/SP/LR order or width differs')
            else:
                require(fmt == SECOND[:-1].decode() and len(self.prints) == 1, 'fault second format/order differs')
                values = [self.m.get(stack + 8 * i, width) for i, width in enumerate((4, 8, 4, 8, 8))]
                require(values == [esr, far, 1, 0x101, 0xfedcba9876543210], 'fault ESR/FAR/exception tuple differs')
            self.prints.append(values)
        state.put('x0', self.e._Value(64, result))
        return True

    def run(self):
        self.vm.run(ROOT, (0 if self.case == 'null-frame' else self.FRAME, 1, 0x101, 0xfedcba9876543210), budget=4096)
        positive = self.case == 'normal'
        require(len(self.prints) == (2 if positive else 0), 'fault observation escaped its gate')
        require(len(self.writes) == int(positive), 'fault flag store count differs')
        return {'success': True, 'prints': self.prints, 'flag_writes': len(self.writes)}


class Triaged(Exception):
    pass


class RouteModel(FaultModel):
    CODES = 0x61003000

    def __init__(self, codes, image, names, e, route):
        super().__init__(codes, image, names, e, 'normal')
        self.route = route
        code = codes[route]
        self.vm.codes[route] = code
        self.vm.by_entry[code.entry] = code
        self.vm.by_pc.update({pc: code for pc in code.ins})
        self.m.map(self.CODES, 16)
        # XNU8796 osfmk/mach/arm/exception.h: SP_ALIGN=0x103, DA_ALIGN=0x101.
        self.expected_code = 0x103 if route == '_handle_sp_align' else 0x101
        self.expected_address = self.VALUES[0] if route == '_handle_pc_align' else self.VALUES[1] if route == '_handle_sp_align' else self.VALUES[4]
        self.m.write_hook = None
        self.m.put(self.CODES, self.expected_code, 8)
        self.m.readonly.append((self.CODES, self.CODES + 8))
        self.m.write_hook = self.write
        self.triages = 0

    def write(self, address, size):
        if address == self.CODES + 8 and size == 8:
            return
        super().write(address, size)

    def external(self, target, state, probe=False, before=None):
        name = self.vm.by_address.get(target)
        if name not in ('_printf', '_exception_triage'):
            return super().external(target, state, probe, before)
        if probe: return True
        arg = lambda i: integer(before, 'x' + str(i))
        if name == '_exception_triage':
            require(arg(0) == 1 and arg(2) == 2 and len(self.prints) == 2 and
                    self.m.get(arg(1), 8) == self.expected_code and
                    self.m.get(arg(1) + 8, 8) == self.expected_address,
                    'terminal route changed exception record/order/triage ABI')
            self.triages += 1
            raise Triaged()
        require(self.m.get(self.flag, 4) == 1, 'route print before one-shot claim')
        fmt, stack = self.text(arg(0)), integer(before, 'sp')
        if fmt == FIRST[:-1].decode():
            values = [self.m.get(stack + 8*i, 8) for i in range(3)]
            require(not self.prints and values == list(self.VALUES[:3]), 'route frame tuple changed')
        else:
            values = [self.m.get(stack + 8*i, width) for i, width in enumerate((4, 8, 4, 8, 8))]
            require(fmt == SECOND[:-1].decode() and len(self.prints) == 1 and
                    values == [self.VALUES[3], self.VALUES[4], 1, self.expected_code, self.expected_address],
                    'route exception/printf arguments changed')
        self.prints.append(values); state.put('x0', self.e._Value(64, 0)); return True

    def run(self):
        arguments = (self.CODES, self.expected_address, self.FRAME, self.expected_code) if '.cold.' in self.route else (self.FRAME,)
        try:
            self.vm.run(self.route, arguments, budget=4096)
        except Triaged:
            pass
        require(self.triages == 1 and len(self.prints) == 2 and len(self.writes) == 1,
                'terminal route did not preserve observation/triage')
        return {'success': True, 'prints': self.prints, 'triages': self.triages, 'flag_writes': len(self.writes)}


def audit(ci):
    ci = Path(ci).resolve()
    require(not (ci / 'user-fault-binary-audit.json').exists(),
            'completed fault certificate exists; preserve it without replay')
    base, codes, image, names, e = load_inputs(ci)
    kernel = ci / 'kernel/kernel.development.santoni'
    require(FIRST in image.data and SECOND in image.data, 'fault diagnostic markers missing')
    section = bounded_section(image, names)
    for name in ('_santoni_gpu_user_fault_reported', '_initproc', '_launch'):
        require(len(names.get(name, ())) == 1, 'ambiguous fault data identity: ' + name)
    directory = ci / ('user-fault-attempt-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    directory.mkdir(exist_ok=False)
    cold_route = '_handle_user_abort.cold.1'
    for name in (ROOT, *HELPERS, *ROUTES, cold_route):
        require(len(names.get(name, ())) == 1, 'ambiguous/missing fault symbol: ' + name)
        if name in codes: continue
        # Custom Mach-O sections are not tagged as __text. Decode every byte of
        # this proven RX section with LLVM, without trimming or admitting UDFs.
        text = subprocess.check_output(['llvm-objdump', '--disassemble-all' if name == ROOT else '--disassemble', '--disassemble-zeroes',
                                       '--disassemble-symbols=' + name, str(kernel)], text=True)
        (directory / (name[1:] + '.asm')).write_text(text)
        noreturn = names.get('_exception_triage', set()) | names.get('_panic', set()) | names.get('_thread_exception_return', set())
        code = e._Code(text, name, next(iter(names[name])), noreturn=noreturn)
        words = {int(pc, 16): int(word, 16) for pc, word in re.findall(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s', text, re.M)}
        require(set(words) == set(code.ins) | set(code.padding) and
                all(image.read(pc, 4) == word for pc, word in words.items()), 'fault words differ from actual kernel')
        codes[name] = code
    helper = codes[ROOT]
    require(set(helper.ins) | set(helper.padding) ==
            set(range(section['address'], section['address'] + section['size'], 4)),
            'fault helper section has an undecoded hole or extra code')
    require(all(not e._unsupported(op, ','.join(args)) for name in (ROOT, *HELPERS)
                for op, args in codes[name].ins.values()), 'new fault helper uses an unsupported A53 instruction')
    require_acyclic(helper)
    require(sum(op == 'ldxr' for op, args in helper.ins.values()) == 1 and
            sum(op == 'stxr' for op, args in helper.ins.values()) == 1, 'weak CAS instruction inventory differs')
    route_calls = {}
    for name in ROUTES:
        target = codes[cold_route].entry if name == '_handle_user_abort' else helper.entry
        calls = [pc for pc, (op, args) in codes[name].ins.items() if op == 'bl' and e._number(args[-1]) == target]
        require(len(calls) == 1, 'fault route must call exactly one observation helper')
        route_calls[name] = hex(calls[0])
    require(sum(op == 'bl' and e._number(args[-1]) == helper.entry for op, args in codes[cold_route].ins.values()) == 1,
            'outlined terminal route lost its unique helper call')
    cases = ('normal', 'null-frame', '32bit', 'kernel', 'null-proc', 'other-proc',
             'mode0', 'mode1', 'mode2', 'mode4', 'missing-mode', 'disabled', 'bad-enable',
             'unmounted', 'unready', 'repeated', 'exclusive-failed', 'zap', 'scm', 'cache', 'user-test', 'bad-suffix')
    results = {}
    cache = ci / 'user-fault-helper-cases.json'
    semantics = {name: hashlib.sha256(inspect.getsource(value).encode()).hexdigest() for name, value in
                 (('model', FaultModel), ('atomic', FaultMachine.atomic_step))}
    semantics['shared_model'] = hashlib.sha256(Path(__file__).with_name('santoni_gpu_binary_model.py').read_bytes()).hexdigest()
    graph = hashlib.sha256(json.dumps({n: {'entry': codes[n].entry, 'ins': codes[n].ins}
                                      for n in (ROOT, *HELPERS)}, sort_keys=True).encode()).hexdigest()
    if cache.exists():
        saved = json.loads(cache.read_text())
        require(identity_of(saved) == identity_of(base) and saved.get('success') is True and
                saved.get('hardware_verified') is False and saved.get('semantic_pins') == semantics and
                saved.get('decoded_graph_sha256') == graph and set(saved.get('results', ())) == set(cases),
                'completed fault helper proof changed or belongs to another kernel')
        results = saved['results']
    for case in cases:
        if case in results:
            require(results[case].get('success') is True, 'completed helper case failed')
            print('Consumed passed helper:', case, '0 executions', flush=True)
            continue
        results[case] = FaultModel(codes, image, names, e, case).run()
        (directory / (case + '.json')).write_text(json.dumps(results[case], indent=2) + '\n')
        print('New actual user-fault helper:', case, 'passed', flush=True)
    if not cache.exists():
        with cache.open('x') as stream:
            stream.write(json.dumps({**identity_of(base), 'success': True, 'hardware_verified': False,
                'semantic_pins': semantics, 'decoded_graph_sha256': graph, 'results': results}, indent=2) + '\n')
    route_cache = ci / 'user-fault-route-cases.json'
    completed = json.loads(route_cache.read_text()) if route_cache.exists() else {
        **identity_of(base), 'success': True, 'hardware_verified': False, 'routes': {}}
    require(identity_of(completed) == identity_of(base) and completed.get('success') is True and
            completed.get('hardware_verified') is False, 'terminal route proof identity changed')
    for route in ('_handle_pc_align', '_handle_sp_align', cold_route):
        model = RouteModel(codes, image, names, e, route)
        pins = {'methods': {n: hashlib.sha256(inspect.getsource(getattr(RouteModel, n)).encode()).hexdigest()
                            for n in ('run', 'external', 'write')},
                'graph': hashlib.sha256(json.dumps({n: codes[n].ins for n in (ROOT, *HELPERS, route)}, sort_keys=True).encode()).hexdigest(),
                'initial_frame': model.m.bytes(model.FRAME, 304).hex(),
                'initial_record': model.m.bytes(model.CODES, 16).hex(), 'options': model.options}
        saved = completed['routes'].get(route)
        if saved is not None:
            require(saved.get('pins') == pins and saved['result'].get('success') is True,
                    'completed terminal route code/model/state changed')
            print('Consumed passed terminal route:', route, '0 executions', flush=True)
            continue
        result = model.run()
        (directory / (route[1:] + '.json')).write_text(json.dumps(result, indent=2) + '\n')
        completed['routes'][route] = {'pins': pins, 'result': result}
        route_cache.write_text(json.dumps(completed, indent=2) + '\n')
        print('New actual terminal route:', route, 'passed', flush=True)
    record = {**identity_of(base), 'success': True, 'hardware_verified': False, 'cases': len(cases),
              'actual_helper_and_getters_checked': True, 'mode1_fault_observation_unreachable_checked': True,
              'immutable_frame_and_bounded_weak_CAS_checked': True, 'three_terminal_routes_linked_checked': True,
              'actual_printf_tuple_checked': True, 'changed_code_A53_checked': True,
                  'bounded_executable_section_checked': True,
                  'actual_terminal_route_arguments_checked': True, 'terminal_route_cases': 3,
              'route_calls': route_calls, 'tool_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (ci / 'user-fault-binary-audit.json').write_text(json.dumps(record, indent=2) + '\n')
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ci', type=Path)
    print(json.dumps(audit(parser.parse_args().ci), indent=2))
