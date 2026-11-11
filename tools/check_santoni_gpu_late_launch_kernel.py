#!/usr/bin/env python3
"""Replay the new late CPU snapshot with actual linked launcher getters.

Explicit XNU registration, mutex, boot-option and printf contracts are inputs.
No native kernel, GPU, device or scheduler executes in this model.
"""
import argparse
import hashlib
import inspect
import json
from pathlib import Path

from santoni_gpu_binary_model import integer
from santoni_gpu_launcher_replay import LauncherMachine, require
from santoni_gpu_el0_trace_audit import guard_diagnostic_loads
from santoni_gpu_scalar_certificate import load_inputs, identity_of

ROOTS = ('_sgpu_user_publish', '_santoni_gpu_user_launch_worker_ready',
         '_santoni_gpu_user_launch_mount_published', '_launch_options', '_sgpu_launch_role')
DIAG_ROOT = '_santoni_gpu_user_launch_trace_snapshot'
NORMAL = b'SANTONI GPU: USER ready /dev/santonigpu; root, one task, WRITE4; no user DMA maps; NO UI\n\0'
LATE = b'SANTONI GPU: USER LAUNCH LATE mode=%u worker_ready=%u mounted=%u; CPU snapshot; EL0 RESULT still required\n\0'
DIAG = (b'SANTONI GPU: USER TRACE DIAG open=%u/%u/%u ioctl=%u/%u/%u refuse=%u,%u seen=%u,%u; '
        b'EL0 RESULT still required\n\0')


def scenarios():
    result = {}
    diag = [3, 1, 2, 9, 5, 4, 3, 4, 1, 1]
    for mode in range(4):
        for ready in range(2):
            for mounted in range(2):
                result[f'mode{mode}-ready{ready}-mounted{mounted}'] = {
                    'mode': mode, 'user': 1, 'stage': 2 if ready else 1,
                    'mounted': mounted, 'expected_ready': ready, 'success': True,
                    'diag': diag if mode == 3 else [0] * 10}
        for user in (0, 2, 0xffffffff):
            result[f'mode{mode}-user{user}-off'] = {'mode': mode, 'user': user, 'success': False}
    for major in range(3):
        result[f'already-published-{major}'] = {'mode': 3, 'user': 1, 'major': major, 'success': False}
    result['registration-failed'] = {'mode': 3, 'user': 1, 'add_major': -1, 'success': False}
    result['node-failed-no-retry'] = {'mode': 3, 'user': 1, 'node': 0, 'success': False}
    return result


class LateModel:
    def __init__(self, codes, image, names, e, case):
        self.e, self.names, self.case = e, names, case
        self.vm = LauncherMachine({n: codes[n] for n in (*ROOTS, DIAG_ROOT)}, image, names, e)
        self.m = self.vm.memory
        self.sg, self.launch, self.major, self.published, self.lock, self.table = (
            self.address(n) for n in ('_sg', '_launch', '_sgpu_user_major',
                                     '_sgpu_user_published', '_sgpu_session_lock', '_sgpu_user_cdevsw'))
        self.m.map(self.sg, 120); self.m.map(self.launch, 88)
        self.m.map(self.major, 4); self.m.map(self.published, 1)
        self.diag, self.diag_lock = (self.address(n) for n in
                                    ('_mockfs_santoni_trace_diag', '_mockfs_santoni_diag_lock'))
        self.m.map(self.diag, 40)
        for i, value in enumerate(case.get('diag', [0] * 10)):
            self.m.put(self.diag + 4 * i, value, 4)
        self.m.readonly.append((self.diag, self.diag + 40))
        self.m.put(self.sg + 84, case['mode']); self.m.put(self.sg + 108, case['user'])
        self.m.put(self.launch + 64, case.get('stage', 0))
        self.m.put(self.launch + 78, case.get('mounted', 0), 1)
        self.m.put(self.major, case.get('major', -1))
        self.m.readonly += [(self.sg, self.sg + 120), (self.launch, self.launch + 88)]
        self.locked, self.registered, self.nodes = False, 0, 0
        self.add_major, self.node = case.get('add_major', 42), case.get('node', 0x59300000)
        self.diag_locked, self.diag_locks, self.diag_unlocks = False, 0, 0
        guard_diagnostic_loads(self)
        self.events, self.prints, self.writes = [], [], []
        self.m.write_hook = self.write
        self.vm.external = self.external

    def address(self, name):
        require(len(self.names.get(name, ())) == 1, 'late snapshot identity: ' + name)
        return next(iter(self.names[name]))

    def text(self, address):
        output = bytearray()
        for i in range(256):
            byte = self.m.get(address + i, 1)
            if not byte: return output.decode()
            output.append(byte)
        raise ValueError('unterminated late-snapshot contract string')

    def write(self, address, size):
        if address == self.published:
            require(size == 1 and self.locked, 'late publication write outside mutex/width')
            self.writes.append(('published', size))
        elif address == self.major:
            require(size == 4 and not self.locked, 'late registration write width/order')
            self.writes.append(('major', size))
        else:
            require(self.vm.STACK <= address < address + size <= self.vm.STACK + self.vm.STACK_SIZE,
                    'late observation writes another CPU object')

    def external(self, target, state, probe=False, before=None):
        name = self.vm.by_address.get(target)
        allowed = ('_cdevsw_add', '_devfs_make_node', '_lck_mtx_lock', '_lck_mtx_unlock',
                   '_printf', '_PE_parse_boot_argn', '_strcmp', '_bzero', '_memset')
        if name not in allowed: return False
        if probe: return True
        arg = lambda i: integer(before, 'x' + str(i))
        self.events.append(name)
        result = 0
        if name == '_cdevsw_add':
            require(not self.locked and arg(0) & 0xffffffff == 0xffffffff and arg(1) == self.table,
                    'late cdev registration ABI differs')
            self.registered += 1; result = self.add_major
        elif name == '_devfs_make_node':
            require(not self.locked and self.registered == 1 and
                    tuple(arg(i) for i in range(5)) == ((self.add_major << 24) & 0xffffffff, 0, 0, 0, 0o600) and
                    self.text(arg(5)) == 'santonigpu', 'late publication namespace/permissions differ')
            self.nodes += 1; result = self.node
        elif name == '_lck_mtx_lock':
            if arg(0) == self.diag_lock:
                require(not self.locked and not self.diag_locked and self.case['mode'] == 3 and
                        self.m.get(self.published, 1) == 1 and len(self.prints) == 2,
                        'diagnostic getter mutex before publication/readiness or inverted lock order')
                self.diag_locked = True; self.diag_locks += 1
            else:
                require(arg(0) == self.lock and not self.locked and not self.diag_locked and self.node,
                        'late mutex identity/order')
                self.locked = True
        elif name == '_lck_mtx_unlock':
            if arg(0) == self.diag_lock:
                require(self.diag_locked and not self.locked, 'diagnostic getter mutex release differs')
                self.diag_locked = False; self.diag_unlocks += 1
            else:
                require(arg(0) == self.lock and self.locked and not self.diag_locked, 'late mutex release differs')
                self.locked = False
        elif name == '_PE_parse_boot_argn':
            require(not self.locked and self.m.get(self.published, 1) == 1 and
                    self.case['mode'] == 3, 'late option query before publication or in control mode')
            key, dest, width = self.text(arg(0)), arg(1), arg(2)
            options = {'santonigpu_user_exec': 1, 'santonigpu_stock': 1, 'santonigpu_pixels': 1,
                       'santonigpu_submit': 1, 'santonigpu_session': 1, 'santonigpu_user': 1,
                       'santonigpu_user_test': 0, 'santonigpu_zap': 0, 'santonigpu_scm': 0,
                       'santonigpu_cache': 0, 'launchdsuffix': 'release'}
            require(key in options, 'late helper parses an unreviewed option')
            value = options[key]
            require(width == (64 if isinstance(value, str) else 4), 'late option query width differs')
            if isinstance(value, str): self.m.write(dest, value.encode() + b'\0')
            else: self.m.put(dest, value, 4)
            result = 1
        elif name == '_strcmp':
            result = int(self.text(arg(0)) != self.text(arg(1)))
        elif name in ('_bzero', '_memset'):
            dest, length = arg(0), arg(1 if name == '_bzero' else 2)
            require(0 < length <= 64 and (name == '_bzero' or arg(1) == 0), 'late stack initializer differs')
            self.m.write(dest, bytes(length)); result = dest
        elif name == '_printf':
            require(not self.locked and not self.diag_locked and self.m.get(self.published, 1) == 1,
                    'late printf before publication/unlock')
            fmt = self.text(arg(0)).encode() + b'\0'
            if fmt == NORMAL:
                require(not self.prints, 'late ordinary publication print repeats')
                self.prints.append({'kind': 'normal'})
            elif fmt == LATE:
                require(self.prints == [{'kind': 'normal'}], 'late print prefix/order differs')
                stack = integer(before, 'sp')
                values = [self.m.get(stack + 8 * i, 8) & 0xffffffff for i in range(3)]
                require(values == [3, self.case['expected_ready'], self.case['mounted']],
                        'late printf changes mode/readiness/mount scalar order')
                self.prints.append({'kind': 'late', 'values': values})
            else:
                require(fmt == DIAG and [p['kind'] for p in self.prints] == ['normal', 'late'] and
                        self.diag_locks == self.diag_unlocks == 1, 'diagnostic print order/snapshot differs')
                stack = integer(before, 'sp')
                require(self.vm.STACK <= stack < stack + 80 <= self.vm.STACK + self.vm.STACK_SIZE,
                        'diagnostic Darwin printf varargs stack extent')
                values = [self.m.get(stack + 8 * i, 4) for i in range(10)]
                require(values == self.case.get('diag', [0] * 10),
                        'diagnostic printf scalar arguments differ from the snapshot')
                self.prints.append({'kind': 'diag', 'values': values})
        state.put('x0', self.e._Value(64, result))
        return True

    def run(self):
        sg_before, launch_before = self.m.bytes(self.sg, 120), self.m.bytes(self.launch, 88)
        result = self.vm.run('_sgpu_user_publish', (), budget=200000)
        success = self.case['success']
        require(result is not None and result.expr == int(success) and not self.locked and
                self.m.bytes(self.sg, 120) == sg_before and self.m.bytes(self.launch, 88) == launch_before,
                'late observation changed publication outcome or immutable launcher/control state')
        late = success and self.case['mode'] == 3
        count = lambda name: sum(target == self.address(name) for _, target in self.vm.calls)
        snapshots = count(DIAG_ROOT)
        require(count(ROOTS[1]) == int(late) and count(ROOTS[2]) == int(late) and
                snapshots == int(late) and
                self.diag_locks == self.diag_unlocks == int(late) and not self.diag_locked and
                len(self.prints) == int(success) + 2 * int(late) and
                self.m.get(self.published, 1) == int(success), 'late getter/print/publication counts differ')
        return {'success': True, 'publication': success, 'late': late, 'prints': self.prints,
                'events': self.events, 'writes': self.writes, 'immutable_state_preserved': True,
                'mutex_released_before_getters_and_print': True}


def audit(ci):
    ci = Path(ci).resolve(); base, codes, image, names, e = load_inputs(ci)
    identity = identity_of(base)
    require(base.get('checked_changed_code_is_Cortex_A53_compatible') is True and
            base.get('EL0_launcher_changed_code_A53_checked') is True and
            LATE in image.data and DIAG in image.data,
            'new late observation/control ISA prerequisite absent')
    directory = ci / 'late-launch-components'; directory.mkdir(exist_ok=True)
    tool_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    guard_sha = hashlib.sha256(inspect.getsource(guard_diagnostic_loads).encode()).hexdigest()
    graph_sha = hashlib.sha256(json.dumps({n: {'entry': codes[n].entry, 'ins': codes[n].ins}
                                         for n in (*ROOTS, DIAG_ROOT)}, sort_keys=True).encode()).hexdigest()
    records = []
    for label, case in scenarios().items():
        path = directory / (label + '.json')
        if path.exists():
            record = json.loads(path.read_text())
            require(all(record.get(k) == v for k, v in identity.items()) and
                    record.get('case') == case and record.get('success') is True and
                    record.get('tool_sha256') == tool_sha and record.get('decoded_graph_sha256') == graph_sha and
                    record.get('diagnostic_load_guard_sha256') == guard_sha,
                    'late component stale or partial')
        else:
            result = LateModel(codes, image, names, e, case).run()
            record = {**identity, 'case': case, 'success': True, 'result': result,
                      'hardware_verified': False, 'tool_sha256': tool_sha, 'decoded_graph_sha256': graph_sha,
                      'diagnostic_load_guard_sha256': guard_sha}
            with path.open('x') as stream: stream.write(json.dumps(record, indent=2) + '\n')
            print('New compiled late observation:', label, 'passed', flush=True)
        records.append(record)
    result = {**identity, 'success': True, 'cases': len(records), 'hardware_verified': False,
              'changed_code_A53_checked': True, 'mode3_publication_scope_checked': True,
              'actual_getter_linkage_and_scalars_checked': True, 'publication_and_mutex_order_checked': True,
              'immutable_CPU_state_checked': True, 'single_API_return_bounded_on_hardware': False,
              'diagnostic_getter_linkage_and_scalars_checked': True,
              'diagnostic_mutex_and_printf_arguments_checked': True,
              'diagnostic_reads_mutex_checked': True,
              'scope': 'late CPU publication snapshot; no child execution or hardware proof'}
    with (ci / 'late-launch-binary-audit.json').open('x') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ci', type=Path)
    print(json.dumps(audit(parser.parse_args().ci), indent=2))
