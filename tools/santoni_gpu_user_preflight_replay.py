"""Linked kernel-caller preflight replay; no application/GPU/scheduler proof."""
import struct

from santoni_gpu_binary_model import Machine, integer
from santoni_gpu_session_replay import QUEUE_NAMES
from santoni_gpu_user_audit import ScalarModel, COMMANDS, _require, scalar_storage

EXTRA = ('_sgpu_user_preflight', '_sgpu_user_preflight_time')
REPORT = b'SANTONI GPU: USER API PREFLIGHT pass=%u sent=%u verified=%u; KERNEL CALLER; userspace boundary unproven; NO UI\n\0'
NO_OWNER = b'SANTONI GPU: USER API PREFLIGHT pass=0 sent=0 verified=0; owner unavailable; KERNEL CALLER; NO UI\n\0'


class PreflightModel(ScalarModel):
    def __init__(self, codes, image, names, e, storage):
        self.clock, self.step, self.waits, self.clock_calls = 1000, 10000, 0, 0
        self.report, self.worker_enabled, self.active_packet = None, True, None
        self.requests, self.polls, self.info_calls = [], [], 0
        self.after_reply, self.after_wait = None, None
        self.attempt_boundary = None
        super().__init__(codes, image, names, e, storage, EXTRA)
        self.setup(self.sg + 112, 1)
        self.setup(self.idle, 1)
        # Queue progress at returning waits is injected, using actual linked
        # CPU queue code on a distinct stack. GPU result values are inputs.
        self.worker = Machine({n: codes[n] for n in QUEUE_NAMES}, image, names, e,
                              memory=self.m, stack_base=0x50040000)
        self.worker.external = self.external

    def write_hook(self, address, size):
        super().write_hook(address, size)
        if self.active_packet is not None and address < self.active_packet + 128 and self.active_packet < address + size:
            _require(self.locked, 'preflight reply copied outside admission mutex')

    def observe(self, pc, state):
        super().observe(pc, state)
        if self.attempt_boundary is not None and pc == self.attempt_boundary:
            _require(integer(state, 'w19') == 0, 'terminal attempt fixture did not start from zero')
            state.put('w19', self.e._Value(32, 9999))
            self.attempt_boundary = None
        code = self.vm.codes['_sgpu_client_call']
        if pc == code.entry:
            command, packet = integer(state, 'w3'), integer(state, 'x4')
            _require(integer(state, 'x2') == self.TASK and command in COMMANDS,
                     'preflight command/retained identity differs')
            _require(self.vm.STACK <= packet and packet + 128 <= self.vm.STACK + self.vm.STACK_SIZE,
                     'preflight packet is not an owned stack copy')
            self.active_packet = packet
            self.active_command = command
            if command == COMMANDS[0]: self.info_calls += 1
            elif command == COMMANDS[1]:
                values = struct.unpack('<4I', self.m.bytes(packet + 16, 16))
                expected = tuple(0xa5070000 ^ ((len(self.requests) + 1) << 8) ^ i for i in range(4))
                _require(values == expected, 'preflight WRITE4 pattern differs')
            elif command == COMMANDS[2]:
                self.polls.append(self.m.get(packet + 8))
        if pc in code.ins and code.ins[pc][0] == 'ret' and self.active_packet is not None:
            packet, command = self.active_packet, self.active_command
            if command == COMMANDS[1] and self.m.get(packet + 12) == 0:
                self.requests.append((self.m.get(packet + 8), self.m.get(packet + 92)))
            if self.after_reply: self.after_reply(self, command, packet)
            self.active_packet = None

    def progress(self):
        _require(not self.locked, 'modeled worker scheduled under producer mutex')
        self.locked = True
        try:
            while self.worker.run('_sgpu_session_take', (self.q, self.REQUEST)).expr:
                id = self.m.get(self.REQUEST)
                _require(self.worker.run('_sgpu_session_commit', (self.q, id)).expr == 1,
                         'modeled worker cannot commit')
                self.m.write(self.RESULT, bytes(76))
                for off, value in ((0, 4), (4, id + 2), (8, 170 + 11 * id), (12, 4)):
                    self.m.put(self.RESULT + off, value)
                self.m.put(self.RESULT + 24, 1, 1)
                _require(self.worker.run('_sgpu_session_finish', (self.q, id, self.RESULT)).expr == 1,
                         'modeled worker cannot finish')
            self.setup(self.idle, self.m.get(self.idle) + 1)
        finally: self.locked = False

    def external(self, target, state, probe=False, before=None):
        name = self.vm.by_address.get(target)
        if name not in ('_mach_absolute_time', '_absolutetime_to_nanoseconds', '_sgpu_kernel_wait_us', '_printf'):
            return super().external(target, state, probe, before)
        if probe: return True
        arg = lambda i: integer(before, 'x' + str(i))
        put = lambda value, bits=64: state.put('x0' if bits == 64 else 'w0', self.e._Value(bits, value))
        _require(not self.locked, 'preflight clock/wait/report under mutex')
        self.calls.append(name)
        if name == '_mach_absolute_time':
            self.clock_calls += 1
            put(0x1234)
        elif name == '_absolutetime_to_nanoseconds':
            _require(arg(0) == 0x1234 and self.vm.STACK <= arg(1) < self.vm.STACK + self.vm.STACK_SIZE - 7,
                     'preflight clock conversion ABI')
            self.m.put(arg(1), self.clock * 1000, 8)
        elif name == '_sgpu_kernel_wait_us':
            # Optimized source does not preserve the unused x0 argument.
            _require(integer(before, 'w1') == 10000, 'preflight wait budget differs')
            self.waits += 1
            self.clock += self.step
            if self.worker_enabled: self.progress()
            if self.after_wait: self.after_wait(self)
            put(0, 32)
        elif name == '_printf':
            literal = REPORT if self.vm.image.read(arg(0), len(REPORT)) == int.from_bytes(REPORT, 'little') else NO_OWNER
            _require(self.vm.image.read(arg(0), len(literal)) == int.from_bytes(literal, 'little'),
                     'unreviewed preflight report')
            _require(self.report is None, 'preflight reports repeatedly')
            if literal == REPORT:
                sp = integer(before, 'sp')
                self.report = tuple(self.m.get(sp + i * 8, 8) for i in range(3))
            else: self.report = (0, 0, 0)
            put(0, 32)
        return True


def audit_preflight_clock(codes, image, names, e):
    vm = Machine({EXTRA[1]: codes[EXTRA[1]]}, image, names, e)
    last_pointer = 0x51000000
    vm.memory.map(last_pointer, 8)
    stamp, calls = 0, []
    def external(target, state, probe=False, before=None):
        name = vm.by_address.get(target)
        if name not in ('_mach_absolute_time', '_absolutetime_to_nanoseconds'): return False
        if probe: return True
        calls.append(name)
        if name == '_mach_absolute_time': state.put('x0', e._Value(64, 0x1234))
        else:
            _require(integer(before, 'x0') == 0x1234, 'preflight clock loses time identity')
            vm.memory.put(integer(before, 'x1'), stamp, 8)
        return True
    vm.external = external
    cases = ((1000, 1000, 1000000), (1000, 1001, 1000000), (1000, 1000, 1000999),
             (1000, 1000, 1001000), (1000, 1000, 100000999999),
             (1000, 1000, 100001000000), (1000, 1000, 999000),
             (0, 0, 0), (0, 0, 99999999999), (0, 0, 100000000000),
             (1000, 1000, (1 << 64) - 1))
    for start, last, stamp in cases:
        calls.clear(); vm.memory.put(last_pointer, last, 8)
        valid = stamp // 1000 >= last and ((stamp // 1000 - start) & ((1 << 64) - 1)) < 100000000
        _require(vm.run(EXTRA[1], (start, last_pointer)).expr == int(valid) and
                 vm.memory.get(last_pointer, 8) == (stamp // 1000 if valid else last) and
                 calls == ['_mach_absolute_time', '_absolutetime_to_nanoseconds'],
                 'preflight monotonic/returning-call deadline differs')
    return {'cases': len(cases), 'success': True, 'hardware_verified': False,
            'single_call_or_scheduler_bounded': False}


def audit_preflight_attempt_bound(codes, image, names, e):
    """Prove the outer returning-call loop's compiler-emitted counter pattern.

    All paths to the outer backedge must pass its increment and exact10000
    comparison. Other writes to that counter inside the loop reject. External
    calls consume the same callee-saved-register ABI as the concrete Machine.
    This does not bound a single stalled call or real scheduler delay.
    """
    code = codes[EXTRA[0]]
    # Recorded Clang15/16 kernels use the same w19 counter. Clang16 holds
    # exact10000 in w26 and places the increment immediately before CMP;
    # the earlier w27 allocation has one intervening instruction.
    layouts = {'w27': 12, 'w26': 8}
    edges = [(pc, e._number(args[-1])) for pc, (op, args) in code.ins.items()
             if op == 'b.ne' and e._number(args[-1]) in code.ins and e._number(args[-1]) < pc and
             code.ins.get(pc - 4, (None, ()))[0] == 'cmp' and
             code.ins[pc - 4][1] in tuple(('w19', register) for register in layouts)]
    _require(len(edges) == 1, 'missing/ambiguous preflight outer loop')
    edge, head = edges[0]
    limit_register = code.ins[edge - 4][1][1]
    increment = edge - layouts[limit_register]
    _require(code.ins.get(increment) == ('add', ('w19', 'w19', '#0x1')),
             'preflight outer counter increment differs')
    limits = [pc for pc, (op, args) in code.ins.items()
              if op == 'mov' and args[0] == limit_register and e._number(args[1]) == 10000]
    _require(len(limits) == 1, 'preflight exact10000 bound differs')
    limit = limits[0]
    _require(head < limit < edge, 'preflight bound outside loop')
    # Only nodes which both follow the head and can reach the backedge belong
    # to this cycle. Failure cleanup paths are outside this counter lifetime.
    forward, pending = set(), [head]
    while pending:
        pc = pending.pop()
        if pc in forward: continue
        forward.add(pc)
        if pc != edge: pending.extend(code.succ[pc])
    reverse = {}
    for pc, children in code.succ.items():
        if pc == edge: continue
        for child in children: reverse.setdefault(child, []).append(pc)
    ancestors, pending = set(), [edge]
    while pending:
        pc = pending.pop()
        if pc in ancestors: continue
        ancestors.add(pc); pending.extend(reverse.get(pc, ()))
    loop = forward & ancestors
    _require(head in loop and limit in loop and increment in loop, 'outer cycle shape differs')
    read_only_ops = {'cmp', 'cmn', 'tst', 'ccmp', 'ret', 'stp', 'str', 'strb', 'stur', 'sturb'}
    def writes_counter(op, args):
        destinations = args[:2] if op == 'ldp' else args[:1] if op not in read_only_ops else ()
        return any(register in ('w19', 'x19') for register in destinations)
    for pc in loop:
        op, args = code.ins[pc]
        if writes_counter(op, args):
            _require(pc == increment, 'outer counter overwritten inside cycle')
    for required in (limit, increment, edge - 4):
        reachable, pending = set(), [head]
        while pending:
            pc = pending.pop()
            if pc == required or pc in reachable: continue
            reachable.add(pc)
            if pc != edge: pending.extend(code.succ[pc])
        _require(edge not in reachable, 'outer backedge bypasses bound/increment/comparison')
    after_limit, pending = set(), list(code.succ[limit])
    while pending:
        pc = pending.pop()
        if pc == edge - 4 or pc in after_limit: continue
        after_limit.add(pc)
        if pc != edge: pending.extend(code.succ[pc])
    for pc in after_limit & loop:
        op, args = code.ins[pc]
        destinations = args[:2] if op == 'ldp' else args[:1] if op not in read_only_ops else ()
        _require(not any(register in (limit_register, 'x' + limit_register[1:]) for register in destinations),
                 'outer limit overwritten before comparison')
    # First entry must define zero before reaching the head; the outer backedge
    # is removed when checking this initial counter lifetime.
    zeros = {pc for pc, ins in code.ins.items() if ins == ('mov', ('w19', 'wzr')) and pc < head}
    _require(len(zeros) == 1, 'preflight initial attempt counter differs')
    zero = next(iter(zeros))
    reachable, pending = set(), [code.entry]
    while pending:
        pc = pending.pop()
        if pc == zero or pc in reachable: continue
        reachable.add(pc)
        if pc != edge: pending.extend(code.succ[pc])
    _require(head not in reachable, 'preflight loop bypasses zero initialization')
    initial, pending = set(), list(code.succ[zero])
    while pending:
        pc = pending.pop()
        if pc == head or pc in initial: continue
        initial.add(pc)
        if pc != edge: pending.extend(code.succ[pc])
    for pc in initial & ancestors:
        _require(not writes_counter(*code.ins[pc]), 'attempt counter overwritten between zero and loop head')
    return {'success': True, 'limit': 10000, 'counter': 'w19', 'loop_head': head,
            'limit_register': limit_register, 'increment': increment,
            'loop_nodes_checked': len(loop), 'counter_zero_dominates_entry': True,
            'increment_and_limit_dominate_backedge': True,
            'scope': 'decoded outer-loop counter/CFG, callee-saved ABI contract',
            'single_call_or_scheduler_bounded': False, 'hardware_verified': False}


def audit_preflight(codes, image, names, e, scenarios=None, record=None, attempt_proof=None):
    storage = scalar_storage(image, names)
    scenarios = scenarios or ('normal', 'user0', 'test0', 'test2', 'null_owner',
                              'unpublished', 'deadline', 'backward', 'final_info_late', 'final_poll_late')
    results = {}
    for scenario in scenarios:
        m = PreflightModel(codes, image, names, e, storage)
        if scenario == 'user0': m.setup(m.sg + 108, 0)
        elif scenario == 'test0': m.setup(m.sg + 112, 0)
        elif scenario == 'test2': m.setup(m.sg + 112, 2)
        elif scenario == 'null_owner': m.task = 0
        elif scenario == 'unpublished': m.setup(m.published, 0, 1)
        elif scenario == 'deadline': m.worker_enabled, m.step = False, 100000000
        elif scenario == 'backward': m.worker_enabled, m.step = False, -1
        elif scenario in ('final_info_late', 'final_poll_late'):
            def late(m, command, packet):
                if (scenario == 'final_info_late' and command == COMMANDS[0] and m.m.get(packet + 60) == 32 or
                    scenario == 'final_poll_late' and command == COMMANDS[2] and m.m.get(packet + 8) == 32):
                    m.clock = 100001000
            m.after_reply = late
        elif scenario == 'stopped_clock_last_attempt':
            bound = attempt_proof if attempt_proof is not None else audit_preflight_attempt_bound(codes, image, names, e)
            _require(bound.get('success') is True and bound.get('limit') == 10000 and
                     type(bound.get('loop_head')) is int, 'completed preflight attempt proof missing')
            m.worker_enabled, m.step, m.attempt_boundary = False, 0, bound['loop_head']
        elif scenario.startswith(('info_bad_', 'poll_bad_', 'terminal_bad_', 'submit_bad_')):
            kind, _, offset_text = scenario.partition('_bad_')
            offset = int(offset_text)
            valid_offsets = {'info': (64, 68, 84), 'poll': (12, 96, 100, 104, 108, 112, 120),
                             'terminal': (36, 40, 44, 48, 52, 56, 60, 72, 76, 80, 92), 'submit': (8, 12)}
            _require(offset in valid_offsets[kind], 'unknown malformed preflight field')
            def bad_reply(m, command, packet):
                match = command == {'info': COMMANDS[0], 'poll': COMMANDS[2],
                                    'terminal': COMMANDS[0], 'submit': COMMANDS[1]}[kind]
                if match and (kind != 'terminal' or m.m.get(packet + 60) == 32):
                    m.m.put(packet + offset, 1 if kind == 'terminal' and offset == 92 else
                            m.m.get(packet + offset) ^ 1)
            m.after_reply = bad_reply
        elif scenario != 'normal': raise ValueError('unknown preflight scenario ' + scenario)
        m.call(EXTRA[0])
        disabled = scenario in ('user0', 'test0', 'test2')
        _require(m.report is None if disabled else m.report is not None,
                 'preflight disabled/report path differs')
        if disabled:
            _require(not m.calls and not m.requests and m.refs == 0, 'disabled preflight does work')
        elif scenario == 'normal':
            _require(m.report == (1, 32, 32) and m.refs == 1 and
                     [id for id, idle in m.requests] == list(range(1, 33)) and
                     m.polls == list(range(1, 33)) and m.m.get(m.client + 9, 1) == 1 and
                     m.m.get(m.q + 4) == 4 and m.m.get(m.q + 8) == 1,
                     'normal preflight does not complete quota/close once')
            _require(m.requests[16][1] > m.requests[15][1], 'second wave bypasses new worker idle')
        else:
            _require(m.report[0] == 0, 'negative preflight falsely passes ' + scenario)
            _require(m.refs == int(scenario not in ('null_owner', 'unpublished')),
                     'preflight failure task retention differs')
            if scenario == 'stopped_clock_last_attempt':
                _require(m.waits == 1 and m.clock == 1000 and m.report == (0, 1, 0),
                         'stopped-clock terminal-attempt fixture does not exit at bound')
        result = {'success': True, 'report': m.report, 'requests': len(m.requests),
                  'polls': len(m.polls), 'waits': m.waits, 'clock_calls': m.clock_calls,
                  'executed_instruction_addresses': len(m.vm.visited), 'hardware_verified': False,
                  'worker_progress_and_gpu_results': 'injected CPU queue progress, not GPU execution',
                  'preflight_path_certified': False}
        if scenario == 'stopped_clock_last_attempt':
            result['fixture'] = 'counter9999 injected at first loop head after verifying zero; not10000 iterations'
        results[scenario] = result
        if record: record(scenario, result)
    return results


def main():
    import argparse
    from datetime import datetime, timezone
    import hashlib
    import json
    from pathlib import Path
    import traceback
    from santoni_gpu_user_audit import load_saved_boundaries
    from santoni_gpu_scalar_certificate import proof, PREFLIGHT_COMPONENTS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--clock', action='store_true', help='run the missing preflight-clock component')
    parser.add_argument('--attempt-bound', action='store_true', help='check the missing decoded outer-loop bound')
    parser.add_argument('--scenarios', nargs='*', default=['normal', 'user0', 'test0', 'test2',
                        'null_owner', 'unpublished', 'deadline', 'backward', 'final_info_late', 'final_poll_late'])
    args = parser.parse_args()
    output = args.evidence / ('scalar-preflight-attempt-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    output.mkdir()
    try:
        codes, image, names, e, identity = load_saved_boundaries(args.evidence, EXTRA)
        cache = args.evidence / 'scalar-preflight-components'
        cache.mkdir(exist_ok=True)
        (output / 'preflight-source.py').write_bytes(Path(__file__).read_bytes())
        def record(name, result):
            result.update(identity, source_record=str((output / 'preflight-source.py').relative_to(args.evidence)),
                          source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
            with (cache / (name + '.json')).open('x') as stream:
                stream.write(json.dumps(result, indent=2) + '\n')
            (output / (name + '.json')).write_text(json.dumps(result, indent=2) + '\n')
            print('Saved passed preflight component:', name, flush=True)
        def cached(name):
            path = cache / (name + '.json')
            if path.exists():
                result = proof(args.evidence, str(path.relative_to(args.evidence)), identity)
                print('Reused completed preflight component:', name, '0 executions', flush=True)
                return result
            return None
        if args.clock and cached('clock') is None:
            record('clock', audit_preflight_clock(codes, image, names, e))
        if args.attempt_bound and cached('attempt_bound') is None:
            record('attempt_bound', audit_preflight_attempt_bound(codes, image, names, e))
        _require(set(args.scenarios) <= set(PREFLIGHT_COMPONENTS) - {'clock', 'attempt_bound'},
                 'unreviewed requested preflight scenario')
        missing = [name for name in args.scenarios if cached(name) is None]
        bound = proof(args.evidence, 'scalar-preflight-components/attempt_bound.json', identity) if (
            'stopped_clock_last_attempt' in missing) else None
        results = audit_preflight(codes, image, names, e, missing, record, bound) if missing else {}
        result = {'success': True, 'scenarios': list(results), **identity}
    except Exception as error:
        result = {'success': False, 'error': str(error)}
        (output / 'traceback.txt').write_text(traceback.format_exc())
    result['tool_sha256'] = {name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
                            for name in ('santoni_gpu_user_audit.py', 'santoni_gpu_user_preflight_replay.py',
                                         'santoni_gpu_binary_model.py')}
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'evidence': str(output), 'result': result}, indent=2))
    return 0 if result['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
