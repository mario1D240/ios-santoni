"""Exact-kernel enabled EL0 observer replay with explicit CPU/VFS contracts.

This executes saved, byte-bound A53 instructions in a CPU model. Prepared
launcher/mount objects are seeded inputs; allocation, exec, BSD syscalls,
console visibility, real mutex ordering and GPU/hardware execution are unproved.
Accepted scenarios are checkpointed and consumed without replay on resume.
"""
import argparse
import ast
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct
import traceback

from santoni_gpu_binary_model import integer
from santoni_gpu_launcher_replay import LauncherMachine, require

ROOTS = ('_santoni_gpu_user_launch_trace_ready', '_mockfs_santoni_trace_mount',
         '_mockfs_santoni_trace_access', '_mockfs_santoni_open', '_mockfs_santoni_close',
         '_mockfs_santoni_ioctl', '_launch_options', '_sgpu_launch_role',
          '_mockfs_santoni_diag_inc', '_mockfs_santoni_diag_note',
          '_mockfs_santoni_diag_refuse', '_santoni_gpu_user_launch_trace_snapshot')
DIAG_FIELDS = ('open_attempts', 'open_accepted', 'open_refused', 'ioctl_attempts',
               'ioctl_accepted', 'ioctl_refused', 'open_refuse_stage', 'ioctl_refuse_stage',
               'seen_open', 'seen_ioctl')
COMMAND, RECORD_BYTES, LIMIT = 0x804047f0, 64, 16
TRACE_UAPI_SHA256 = '5f57025e6344bebd14b3777ae4f49e78cf6261194f066f78cc57f3fbc8dc2405'
TRACE_FORMAT = 'SANTONI GPU USERSPACE: TRACE event=%u pid=%d status=%u value=%u record=%u\n'
RESULT_FORMAT = ('SANTONI GPU USERSPACE: RESULT pass=%u pid=%d sent=%u verified=%u '
                 'negative=%u error=%u errno=%u; EL0 trace ioctl; NO UI\n')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def scenario_specs():
    """Independent input/output contracts for the new compiled receiver."""
    result = {}
    entry = [1, 64, 1, 0, 42, *([0] * 11)]
    final = [1, 64, 6, 0, 0, 1, 32, 32, 7, 0, 0, *([0] * 5)]
    def add(name, *, expected=0, kind='ioctl', settings=None, record=None):
        result[name] = {'case': name, 'kind': kind, 'expected': expected,
                        'settings': settings or {}, 'record': list(record or entry)}
    add('open_read_cloexec', kind='open', settings={'flags': 0x01000001})
    add('close_after_original_exec', kind='close', settings={'executable': 'other', 'root': False, 'ctx': 0})
    add('result_pass', record=final)
    failure = final.copy()
    failure[5:11] = [0, 2, 1, 6, 1, 45]
    add('result_failure', record=failure)
    for event in (1, 2, 3, 4, 5, 7, 8, 9):
        record = entry.copy(); record[2] = event
        add('event_' + str(event), record=record)
    for status in (1, 2):
        record = entry.copy(); record[2:5] = [7, status, 0xffffffff]
        add('console_write_status_' + str(status), record=record)
    add('quota_16_then_two_denials', kind='quota')
    add('quota_already_full', expected=16, settings={'counter': 16})
    add('quota_uint32_max', expected=16, settings={'counter': 0xffffffff})
    for name, settings in (
        ('off', {'option.santonigpu_user_exec': 0}),
        ('absent', {'option.santonigpu_user_exec': None}),
        ('mode1', {'option.santonigpu': 1}), ('mode2', {'option.santonigpu': 2}),
        ('wrong_enabled', {'option.santonigpu_user_exec': 2}),
        ('wrong_role', {'option.santonigpu_user_test': 1}),
        ('no_suffix', {'option.launchdsuffix': None}), ('wrong_suffix', {'option.launchdsuffix': 'debug'}),
        ('preparing', {'stage': 1}), ('failed', {'stage': 3}), ('unmounted', {'mounted': 0}),
        ('null_backing', {'kva': 0}), ('wrong_backing', {'kva': 0x60001000}),
        ('wrong_eof', {'file': 16634}), ('wrong_span', {'span': 4096}),
        ('null_vnode', {'vnode': 0}), ('other_vnode', {'vnode': 'other'}),
        ('directory', {'vtype': 2}), ('null_node', {'node': 0}), ('wrong_node_type', {'node_type': 0}),
        ('null_node_mount', {'node_mount': 0}), ('foreign_vnode_mount', {'vnode_mount': 'other'}),
        ('null_mount_data', {'mount_data': 0}), ('pager_failed', {'pager_failed': 1}),
        ('null_args', {'args': 0}), ('wrong_command', {'command': COMMAND + 1}),
        ('wide_command', {'command': COMMAND + (1 << 32)})):
        add(name, expected=45, settings=settings)
    for name, settings in (
        ('kernel_context', {'kernel_context': True}), ('null_context', {'ctx': 0}),
        ('null_process', {'context_proc': 0}), ('foreign_process', {'context_proc': 'other'}),
        ('different_current_process', {'current_proc': 'other'}), ('pid_zero', {'pid': 0}),
        ('pid_negative', {'pid': -1}), ('nonroot', {'root': False}),
        ('missing_executable', {'executable': 0}), ('other_executable', {'executable': 'other'})):
        add(name, expected=13, settings=settings)
    add('null_record', expected=22, settings={'data': 0})
    for flags in (0, 2, 3):
        add('ioctl_flags_' + str(flags), expected=22, settings={'flags': flags})
        add('open_flags_' + str(flags), expected=13, kind='open', settings={'flags': flags})
    add('close_write', expected=45, kind='close', settings={'flags': 2})
    add('close_null_args', expected=45, kind='close', settings={'args': 0})
    add('open_null_args', expected=45, kind='open', settings={'args': 0})
    malformed = [(0, n) for n in (0, 2, 0xffffffff)] + [(1, n) for n in (0, 63, 65, 0xffffffff)]
    malformed += [(2, n) for n in (0, 10, 0xffffffff)] + [(3, n) for n in (2, 3, 0xffffffff)]
    for index, value in malformed:
        record = entry.copy(); record[index] = value
        add(f'header_{index}_{value}', expected=22, record=record)
    for offset in range(44, 64):
        record = entry.copy(); record[offset // 4] = 1 << (8 * (offset % 4))
        add('reserved_byte_' + str(offset), expected=22, record=record)
    for index in range(5, 11):
        record = entry.copy(); record[index] = 1
        add('nonresult_field_' + str(index), expected=22, record=record)
    for index, value in ((3, 1), (4, 1), (5, 2), (6, 33), (6, 31), (7, 31),
                         (7, 33), (8, 6), (8, 8), (9, 1), (9, 7), (10, 45)):
        record = final.copy(); record[index] = value
        add(f'result_field_{index}_{value}', expected=22, record=record)
    add('diagnostic_silent_snapshot', kind='snapshot')
    add('diagnostic_null_snapshot', kind='snapshot', settings={'args': 0})
    add('diagnostic_saturation', settings={'diag_seed': [0, 0, 0, 0xffffffff, 0xffffffff, 0, 0, 0, 0, 0]})
    add('diagnostic_first_refusal', expected=22, settings={
        'flags': 2, 'diag_seed': [0, 0, 0, 7, 0, 7, 0, 1, 0, 1]})
    return result


SCENARIOS = scenario_specs()


def guard_diagnostic_loads(model):
    """Observe concrete CPU reads without modifying the shared interpreter."""
    base = model.vm.State
    class GuardedState(base):
        def copy(self):
            return GuardedState(self.backing, dict(self.regs), self.flags)

        def load(self, address, size, image):
            if address is not None and isinstance(address.expr, int):
                start = address.expr
                if start < model.diag + 40 and model.diag < start + size:
                    require(model.diag_locked and model.diag <= start < start + size <= model.diag + 40,
                            'diagnostic CPU read outside its mutex/record')
            return super().load(address, size, image)

        load_copy = load
    model.vm.State = GuardedState


def expected_diagnostics(spec):
    """Independent observations implied by the existing admission contract."""
    result = list(spec['settings'].get('diag_seed', [0] * 10))
    kind, error = spec['kind'], spec['expected']
    if kind in ('close', 'snapshot') or spec['settings'].get('args', 1) == 0:
        return result
    if spec['case'] in ('wrong_command', 'wide_command', 'open_null_args'):
        return result
    if error == 45:
        if kind == 'ioctl':
            result[5] = min(0xffffffff, result[5] + 1)
            result[7] = result[7] or 1; result[9] = 1
        return result
    if kind == 'quota':
        return [0, 0, 0, 18, 16, 2, 0, 5, 0, 1]
    offset = 0 if kind == 'open' else 3
    result[offset] = min(0xffffffff, result[offset] + 1)
    result[8 if kind == 'open' else 9] = 1
    index = offset + (1 if error == 0 else 2)
    result[index] = min(0xffffffff, result[index] + 1)
    if error:
        stage = 3 if error == 13 else 5 if error == 16 else 4
        if spec['case'].startswith(('open_flags_', 'ioctl_flags_')) or spec['case'] == 'null_record':
            stage = 2
        index = 6 if kind == 'open' else 7
        result[index] = result[index] or stage
    return result


class TraceModel:
    """Owned CPU objects and narrow platform services; no allocator/GPU APIs."""
    ARGS, RECORD, VNODE, OTHER_VNODE, NODE, MOUNT, MOUNT_DATA, CTX, PROC, OTHER = (
        0x61000000, 0x61001000, 0x61002000, 0x61003000, 0x61004000,
        0x61005000, 0x61006000, 0x61007000, 0x61008000, 0x61009000)
    KVA, FILE, SPAN = 0x60000000, 16635, 20480
    SERVICES = ('_PE_parse_boot_argn', '_strcmp', '_bzero', '_memset',
        '_vnode_vtype', '_vnode_fsnode', '_vnode_mount', '_vfs_context_iskernel',
        '_vfs_context_proc', '_current_proc', '_proc_pid', '_vfs_context_issuser',
        '_proc_getexecutablevnode', '_vnode_put', '_lck_mtx_lock', '_lck_mtx_unlock',
        '_printf', '_err_open', '_err_close', '_err_ioctl')

    def __init__(self, codes, image, names, e):
        require(all(n in codes and len(names.get(n, ())) == 1 for n in ROOTS), 'trace roots missing/ambiguous')
        self.e = e
        self.vm = LauncherMachine({n: codes[n] for n in ROOTS}, image, names, e)
        self.m = self.vm.memory
        self.launch = next(iter(names['_launch']))
        self.counter = next(iter(names['_mockfs_santoni_trace_events']))
        self.diag = next(iter(names['_mockfs_santoni_trace_diag']))
        self.diag_lock = next(iter(names['_mockfs_santoni_diag_lock']))
        for address, size in ((self.launch, 88), (self.counter, 4), (self.diag, 40),
                (self.ARGS, 48), (self.RECORD, 64), (self.VNODE, 256), (self.OTHER_VNODE, 256),
                (self.NODE, 56), (self.MOUNT, 4096), (self.MOUNT_DATA, 72),
                (self.CTX, 128), (self.PROC, 128), (self.OTHER, 128)):
            self.m.map(address, size)
        self.options = {'santonigpu': 3, 'santonigpu_user_exec': 1, 'santonigpu_stock': 1,
            'santonigpu_pixels': 1, 'santonigpu_submit': 1, 'santonigpu_session': 1,
            'santonigpu_user': 1, 'santonigpu_user_test': 0, 'santonigpu_zap': 0,
            'santonigpu_scm': 0, 'santonigpu_cache': 0, 'launchdsuffix': 'release'}
        self.pid, self.vtype, self.node_pointer, self.vnode_mount = 2, 1, self.NODE, self.MOUNT
        self.context_proc, self.current_proc, self.executable = self.PROC, self.PROC, self.VNODE
        self.kernel_context, self.root, self.locked = False, True, False
        self.refs = {self.VNODE: 0, self.OTHER_VNODE: 0}
        self.calls, self.prints, self.writes, self.diag_writes = [], [], [], []
        self.locks, self.unlocks = 0, 0
        self.diag_locked, self.diag_locks, self.diag_unlocks = False, 0, 0
        guard_diagnostic_loads(self)
        # Offsets are from this kernel's saved instructions: launch mount48 /
        # ready64 / mounted78; fsnode type8/mount16; mount data0x8f8; payload48.
        self.m.put(self.launch + 48, self.KVA, 8)
        self.m.put(self.launch + 56, self.FILE)
        self.m.put(self.launch + 60, self.SPAN)
        self.m.put(self.launch + 64, 2)
        self.m.put(self.launch + 78, 1, 1)
        self.m.put(self.NODE + 8, 2, 1)
        self.m.put(self.NODE + 16, self.MOUNT, 8)
        self.m.put(self.MOUNT + 0x8f8, self.MOUNT_DATA, 8)
        self.m.put(self.MOUNT_DATA + 48, self.KVA, 8)
        self.m.put(self.MOUNT_DATA + 56, self.FILE)
        self.m.put(self.MOUNT_DATA + 60, self.SPAN)
        self.vm.external = self.external

    def text(self, address):
        data = bytearray()
        for offset in range(256):
            value = self.m.get(address + offset, 1)
            if not value:
                return data.decode()
            data.append(value)
        raise ValueError('trace service string exceeds its bound')

    def write_guard(self, address, size):
        if self.vm.STACK <= address < address + size <= self.vm.STACK + self.vm.STACK_SIZE:
            return
        if self.diag <= address < address + size <= self.diag + 40:
            require(size == 4 and (address - self.diag) % 4 == 0 and self.diag_locked,
                    'trace diagnostic scalar width/alignment/mutex')
            self.diag_writes.append({'address': hex(address), 'bytes': size, 'locked': True})
            return
        require(address == self.counter and size == 4 and self.locked, 'trace write outside locked CPU counter')
        self.writes.append({'address': hex(address), 'bytes': size, 'locked': self.locked})

    def external(self, target, state, probe=False, before=None):
        name = self.vm.by_address.get(target)
        if name not in self.SERVICES:
            return False
        if probe:
            return True
        self.calls.append(name)
        arg = lambda index: integer(before, 'x' + str(index))
        require(not self.diag_locked or name == '_lck_mtx_unlock',
                'trace VFS/printf/service or nested lock inside diagnostic mutex')
        put = lambda value, bits=32: state.put('w0' if bits == 32 else 'x0',
                                               self.e._Value(bits, value & ((1 << bits) - 1)))
        if name == '_PE_parse_boot_argn':
            key, dest, size = self.text(arg(0)), arg(1), arg(2)
            require(key in self.options and size == (64 if key == 'launchdsuffix' else 4), 'trace boot parser ABI')
            require(self.vm.STACK <= dest < dest + size <= self.vm.STACK + self.vm.STACK_SIZE,
                    'trace boot parser writes outside stack')
            value = self.options[key]
            if value is not None:
                if isinstance(value, str):
                    require(len(value.encode()) + 1 <= size, 'trace suffix fixture exceeds extent')
                    self.m.write(dest, value.encode() + b'\0')
                else:
                    self.m.put(dest, value)
            put(int(value is not None))
        elif name == '_strcmp':
            put(int(self.text(arg(0)) != self.text(arg(1))))
        elif name in ('_bzero', '_memset'):
            dest, count = arg(0), arg(1 if name == '_bzero' else 2)
            require(0 < count <= 128 and self.vm.STACK <= dest < dest + count <=
                    self.vm.STACK + self.vm.STACK_SIZE and (name != '_memset' or arg(1) == 0),
                    'trace zero initializer extent/value')
            self.m.write(dest, bytes(count)); put(dest, 64)
        elif name in ('_vnode_vtype', '_vnode_fsnode', '_vnode_mount'):
            require(arg(0) in (self.VNODE, self.OTHER_VNODE), 'trace vnode service identity')
            own = arg(0) == self.VNODE
            value = (self.vtype if own else 2) if name == '_vnode_vtype' else (
                self.node_pointer if own else 0) if name == '_vnode_fsnode' else self.vnode_mount
            put(value, 32 if name == '_vnode_vtype' else 64)
        elif name in ('_vfs_context_iskernel', '_vfs_context_proc', '_vfs_context_issuser'):
            require(arg(0) == self.CTX, 'trace context service identity')
            put(self.context_proc if name == '_vfs_context_proc' else int(
                self.kernel_context if name == '_vfs_context_iskernel' else self.root),
                64 if name == '_vfs_context_proc' else 32)
        elif name == '_current_proc':
            put(self.current_proc, 64)
        elif name in ('_proc_pid', '_proc_getexecutablevnode'):
            require(arg(0) == self.PROC, 'trace process service identity')
            if name == '_proc_pid':
                put(self.pid)
            else:
                require(self.executable in (0, self.VNODE, self.OTHER_VNODE), 'trace executable service identity')
                if self.executable:
                    self.refs[self.executable] += 1
                put(self.executable, 64)
        elif name == '_vnode_put':
            require(arg(0) in self.refs and self.refs[arg(0)] == 1 and not self.locked,
                    'trace executable iocount release')
            self.refs[arg(0)] -= 1; put(0)
        elif name == '_lck_mtx_lock':
            if arg(0) == self.diag_lock:
                require(not self.diag_locked, 'trace diagnostic mutex already held')
                self.diag_locked = True; self.diag_locks += 1
            else:
                require(arg(0) == self.MOUNT_DATA and not self.locked, 'trace mutex identity/double lock')
                self.locked = True; self.locks += 1
            put(0)
        elif name == '_lck_mtx_unlock':
            if arg(0) == self.diag_lock:
                require(self.diag_locked, 'trace diagnostic mutex unheld unlock')
                self.diag_locked = False; self.diag_unlocks += 1
            else:
                require(arg(0) == self.MOUNT_DATA and self.locked and not self.diag_locked,
                        'trace mutex identity/unheld unlock')
                self.locked = False; self.unlocks += 1
            put(0)
        elif name == '_printf':
            require(not self.locked and not any(self.refs.values()), 'trace print before mutex/iocount release')
            format_text = self.text(arg(0))
            require(format_text in (TRACE_FORMAT, RESULT_FORMAT), 'trace print format differs')
            count = 5 if format_text == TRACE_FORMAT else 7
            stack = integer(before, 'sp')
            require(self.vm.STACK <= stack < stack + count * 8 <= self.vm.STACK + self.vm.STACK_SIZE,
                    'trace Darwin varargs stack extent')
            values = [self.m.get(stack + 8 * index, 8) for index in range(count)]
            require(values[1] == self.pid, 'trace print PID was not obtained from the current process')
            self.prints.append({'format': format_text, 'values': values}); put(0)
        else:
            # Retained XNU8796 vfs_support.c err_open/close/ioctl return ENOTSUP.
            require(arg(0) in (0, self.ARGS), 'trace fallback argument identity')
            put(45)
        return True

    def configure(self, spec):
        self.m.write(self.RECORD, struct.pack('<16I', *spec['record']))
        fields = {'args': self.ARGS, 'vnode': self.VNODE, 'ctx': self.CTX,
                  'command': COMMAND, 'data': self.RECORD, 'flags': 1}
        for key, value in spec['settings'].items():
            if key.startswith('option.'):
                self.options[key[7:]] = value
                continue
            if value == 'other':
                value = self.OTHER_VNODE if key in ('vnode', 'executable') else self.OTHER
            if key in fields:
                fields[key] = value
            elif key in ('stage', 'mounted'):
                self.m.put(self.launch + (64 if key == 'stage' else 78), value, 4 if key == 'stage' else 1)
            elif key in ('kva', 'file', 'span', 'pager_failed'):
                offset = {'kva': 48, 'file': 56, 'span': 60, 'pager_failed': 64}[key]
                self.m.put(self.MOUNT_DATA + offset, value, 8 if key == 'kva' else 4)
            elif key == 'node_type': self.m.put(self.NODE + 8, value, 1)
            elif key == 'node_mount': self.m.put(self.NODE + 16, value, 8)
            elif key == 'mount_data': self.m.put(self.MOUNT + 0x8f8, value, 8)
            elif key == 'node': self.node_pointer = value
            elif key == 'counter': self.m.put(self.counter, value)
            elif key == 'diag_seed':
                require(len(value) == 10 and all(type(v) is int and 0 <= v <= 0xffffffff for v in value),
                        'diagnostic seed word contract')
                for i, word in enumerate(value): self.m.put(self.diag + 4 * i, word, 4)
            else:
                require(key in ('pid', 'vtype', 'vnode_mount', 'context_proc', 'current_proc',
                                'executable', 'root', 'kernel_context'), 'unknown trace fixture setting')
                setattr(self, key, value)
        self.m.put(self.ARGS + 8, fields['vnode'], 8)
        self.m.put(self.ARGS + 16, fields['command'] if spec['kind'] in ('ioctl', 'quota') else fields['flags'], 8)
        if spec['kind'] in ('ioctl', 'quota'):
            self.m.put(self.ARGS + 24, fields['data'], 8)
            self.m.put(self.ARGS + 32, fields['flags'])
            self.m.put(self.ARGS + 40, fields['ctx'], 8)
        else:
            self.m.put(self.ARGS + 24, fields['ctx'], 8)
        self.m.readonly.extend((address, address + len(data)) for address, data, _ in self.m.regions
                               if address not in (self.counter, self.diag, self.vm.STACK))
        self.m.write_hook = self.write_guard
        return fields


def run_case(spec, codes, image, names, e):
    model = TraceModel(codes, image, names, e)
    fields = model.configure(spec)
    before_record = model.m.bytes(model.RECORD, 64)
    before_counter = model.m.get(model.counter)
    kind = 'ioctl' if spec['kind'] == 'quota' else spec['kind']
    outputs = []
    for index in range(18 if spec['kind'] == 'quota' else 1):
        expected = (0 if index < 16 else 16) if spec['kind'] == 'quota' else spec['expected']
        if kind == 'snapshot':
            model.vm.run('_santoni_gpu_user_launch_trace_snapshot',
                         (model.vm.STACK + 0x100 if fields['args'] else 0,), budget=2000)
            actual = 0  # void getter; only copy/mutex contracts are checked
        else:
            model.vm.run('_mockfs_santoni_' + kind, (fields['args'],), budget=20000)
            actual = integer(model.vm.state, 'w0')
        require(actual == expected, 'trace outcome differs: ' + spec['case'])
        require(not model.locked and not model.diag_locked and model.locks == model.unlocks and
                model.diag_locks == model.diag_unlocks and not any(model.refs.values()),
                'trace leaves mutex or executable iocount held')
        require(model.m.bytes(model.RECORD, 64) == before_record, 'trace modifies IOC_IN record')
        outputs.append(actual)
    admitted = outputs.count(0) if kind == 'ioctl' else 0
    require(len(model.prints) == admitted and model.m.get(model.counter) == before_counter + admitted and
            len(model.writes) == admitted, 'trace print/counter/locked-write count differs')
    words = spec['record']
    for index, printed in enumerate(model.prints):
        expected = ([words[5], model.pid, *words[6:11]] if words[2] == 6 else
                    [words[2], model.pid, words[3], words[4], before_counter + index + 1])
        require(printed['values'] == expected and printed['format'] == (RESULT_FORMAT if words[2] == 6 else TRACE_FORMAT),
                'trace scalar result/terminal prefix differs')
    diag_words = [model.m.get(model.diag + 4 * i) for i in range(10)]
    require(diag_words == expected_diagnostics(spec), 'trace diagnostic observations differ')
    destination = model.vm.STACK + 0x100
    model.m.write(destination, bytes([0xa5]) * 40)
    model.vm.run('_santoni_gpu_user_launch_trace_snapshot', (destination,), budget=2000)
    require([model.m.get(destination + 4 * i) for i in range(10)] == diag_words and
            not model.diag_locked and model.diag_locks == model.diag_unlocks,
            'trace getter copy differs or leaves diagnostic mutex held')
    return {'case': spec['case'], 'success': True, 'outputs': outputs, 'print_count': len(model.prints),
            'counter_before': before_counter, 'counter_after': model.m.get(model.counter),
            'locked_counter_writes': model.writes, 'diagnostic_writes': model.diag_writes,
            'diagnostic_snapshot': diag_words, 'record_immutable': True,
            'diagnostic_address': hex(model.diag),
            'diagnostic_getter_checked': True, 'diagnostic_mutex_checked': True,
            'other_CPU_storage_immutable': True, 'iocounts_released': True, 'mutex_balanced': True,
            'service_calls': model.calls, 'printed_records': model.prints,
            'decoded_instruction_addresses': len(model.vm.visited), 'atomic_events': model.vm.atomic_events,
            'hardware_verified': False}


def consume_case(record, identity, spec, probe_sha, graph_sha):
    require(isinstance(record, dict) and record.get('success') is True and
            {k: record.get(k) for k in identity} == identity and
            record.get('probe_sha256') == probe_sha and record.get('decoded_graph_sha256') == graph_sha and
            record.get('spec_sha256') == digest(spec) and record.get('result', {}).get('case') == spec['case'] and
            record['result'].get('success') is True, 'trace cached scenario is absent/stale/different-kernel')
    return record


def assemble(records, identity, probe_sha, trace_uapi_sha):
    require(set(records) == set(SCENARIOS), 'enabled trace needs every exact receiver scenario')
    graphs = {record.get('decoded_graph_sha256') for record in records.values()}
    require(len(graphs) == 1 and isinstance(next(iter(graphs)), str) and
            re.fullmatch(r'[0-9a-f]{64}', next(iter(graphs))), 'trace mixes or lacks decoded graph identities')
    for name, record in records.items():
        require(isinstance(record.get('result'), dict), 'trace scenario result is absent')
        result = record['result']
        spec = SCENARIOS[name]
        outputs = [0] * 16 + [16] * 2 if spec['kind'] == 'quota' else [spec['expected']]
        admitted = outputs.count(0) if spec['kind'] in ('ioctl', 'quota') else 0
        before = spec['settings'].get('counter', 0)
        pid, words = spec['settings'].get('pid', 2), spec['record']
        printed = [{'format': RESULT_FORMAT if words[2] == 6 else TRACE_FORMAT,
                    'values': [words[5], pid, *words[6:11]] if words[2] == 6 else
                    [words[2], pid, words[3], words[4], before + index + 1]}
                   for index in range(admitted)]
        require(record.get('success') is True and {k: record.get(k) for k in identity} == identity and
                record.get('probe_sha256') == probe_sha and record.get('spec_sha256') == digest(spec) and
                result.get('case') == name and result.get('success') is True and
                all(result.get(key) is True for key in ('record_immutable', 'other_CPU_storage_immutable',
                                                       'iocounts_released', 'mutex_balanced')) and
                result.get('hardware_verified') is False and result.get('outputs') == outputs and
                result.get('counter_before') == before and result.get('counter_after') == before + admitted and
                result.get('print_count') == admitted and result.get('printed_records') == printed and
                len(result.get('locked_counter_writes', ())) == admitted and
                set(result.get('service_calls', ())) <= set(TraceModel.SERVICES) and
                type(result.get('decoded_instruction_addresses')) is int and
                0 < result['decoded_instruction_addresses'] <= 20000,
                'enabled trace scenario contract incomplete')
        require(result.get('diagnostic_snapshot') == expected_diagnostics(spec) and
                all(type(v) is int and 0 <= v <= 0xffffffff for v in result['diagnostic_snapshot']) and
                result.get('diagnostic_getter_checked') is True and
                result.get('diagnostic_mutex_checked') is True and
                isinstance(result.get('diagnostic_writes'), list) and
                all(w.get('bytes') == 4 and w.get('locked') is True and
                    isinstance(w.get('address'), str) for w in result['diagnostic_writes']),
                'trace diagnostic receiver/copy/mutex evidence incomplete')
        address = result.get('diagnostic_address')
        require(isinstance(address, str) and re.fullmatch(r'0x[0-9a-f]+', address) and
                int(address, 16) % 4 == 0 and
                all(re.fullmatch(r'0x[0-9a-f]+', w['address']) and
                    int(address, 16) <= int(w['address'], 16) <= int(address, 16) + 36 and
                    (int(w['address'], 16) - int(address, 16)) % 4 == 0 for w in result['diagnostic_writes']),
                'trace diagnostic writes escape the aligned diagnostic record')
    quota = records['quota_16_then_two_denials']['result']
    require(quota['outputs'] == [0] * 16 + [16] * 2 and quota['counter_after'] == 16 and
            quota['print_count'] == len(quota['locked_counter_writes']) == 16,
            'enabled trace requires the saturating locked16-record proof')
    addresses = {write.get('address') for record in records.values()
                 for write in record['result']['locked_counter_writes']}
    require(len(addresses) == 1 and isinstance(next(iter(addresses)), str) and
            all(write.get('bytes') == 4 and write.get('locked') is True for record in records.values()
                for write in record['result']['locked_counter_writes']), 'trace writes escape its locked CPU counter')
    return {**identity, 'success': True, 'enabled_receiver_complete': True,
            'probe_sha256': probe_sha, 'trace_uapi_sha256': trace_uapi_sha,
            'roots': list(ROOTS), 'ioctl_command': COMMAND, 'record_bytes': RECORD_BYTES, 'record_limit': LIMIT,
            'cases': records, 'case_count': len(records), 'hardware_verified': False,
            'counter_address': next(iter(addresses)), 'decoded_graph_sha256': next(iter(graphs)),
            'diagnostic_receiver_checked': True,
            'scope': 'exact linked CPU vnode observer; prepared storage/process/VFS/printf/mutex contracts modeled'}


def replay_scope(source):
    """Bind executed fixtures/interpreter dispatch while consumption can grow."""
    tree = ast.parse(source)
    definitions = {'scenario_specs', 'guard_diagnostic_loads', 'expected_diagnostics', 'TraceModel', 'run_case'}
    constants = {'ROOTS', 'COMMAND', 'RECORD_BYTES', 'LIMIT', 'TRACE_FORMAT', 'RESULT_FORMAT'}
    selected = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and
                node.name in definitions or isinstance(node, ast.Assign) and
                any(isinstance(child, ast.Name) and child.id in constants
                    for target in node.targets for child in ast.walk(target))]
    require({node.name for node in selected if isinstance(node, (ast.FunctionDef, ast.ClassDef))} == definitions,
            'trace executed source scope is missing')
    return ast.dump(ast.Module(body=selected, type_ignores=[]))


def validate_component(record, identity, probe_sha, counter, folder, diagnostic=None):
    """Consume the retained receiver, validating its full scope and sources."""
    require(isinstance(record, dict) and record.get('success') is True and
            record.get('enabled_receiver_complete') is True and
            {k: record.get(k) for k in identity} == identity and
            record.get('probe_sha256') == probe_sha and record.get('trace_uapi_sha256') == TRACE_UAPI_SHA256 and
            record.get('roots') == list(ROOTS) and record.get('ioctl_command') == COMMAND and
            record.get('record_bytes') == RECORD_BYTES and record.get('record_limit') == LIMIT and
            record.get('diagnostic_receiver_checked') is True and
            record.get('case_count') == len(SCENARIOS) and record.get('hardware_verified') is False,
            'enabled trace receiver identity/ABI/scope incomplete')
    probe = record.get('independent_probe', {})
    require(probe.get('probe_sha256') == probe_sha and probe.get('probe_bytes') == 16635 and
            probe.get('consumed_linked_cases') == 22 and probe.get('executed_linked_cases') == 0 and
            probe.get('kernel_certified') is False and probe.get('hardware_verified') is False,
            'enabled trace needs its paired completed independent probe')
    verified = assemble(record['cases'], identity, probe_sha, TRACE_UAPI_SHA256)
    require(verified['counter_address'] == counter and verified['decoded_graph_sha256'] == record.get('decoded_graph_sha256'),
            'enabled trace receiver counter/decoded graph differs from its control record')
    if diagnostic is not None:
        require({case['result']['diagnostic_address'] for case in record['cases'].values()} == {diagnostic},
                'trace diagnostic storage differs from its linked control binding')
    require(folder is not None, 'enabled trace source evidence folder is required')
    folder = Path(folder).resolve()
    source_scope = replay_scope(Path(__file__).read_bytes())
    sources = {}
    for case in record['cases'].values():
        relative, source_sha = case.get('source_record'), case.get('tool_sha256')
        require(isinstance(relative, str) and not Path(relative).is_absolute() and
                (folder / relative).resolve().is_relative_to(folder) and
                isinstance(source_sha, str) and re.fullmatch(r'[0-9a-f]{64}', source_sha),
                'trace source evidence is absent or escapes its folder')
        if relative not in sources:
            source = (folder / relative).read_bytes()
            require(hashlib.sha256(source).hexdigest() == source_sha and replay_scope(source) == source_scope,
                    'trace executed source/interpreter fixture changed')
            sources[relative] = source_sha
        require(sources[relative] == source_sha, 'trace source evidence identity aliases')
    return {**record, **verified, 'executed_source_records': sources,
            'source_evidence_checked': True, 'completed_receiver_consumed_without_replay': True}


def main():
    from santoni_gpu_launcher_gate import consume_probe
    from santoni_gpu_scalar_certificate import identity_of, load_inputs
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--probe-dir', type=Path, required=True)
    parser.add_argument('--probe-evidence', type=Path, required=True)
    parser.add_argument('--scenarios', nargs='*', choices=tuple(SCENARIOS), default=list(SCENARIOS))
    parser.add_argument('--aggregate', action='store_true')
    args = parser.parse_args()
    folder, cache = args.evidence, args.evidence / 'el0-trace-components'
    cache.mkdir(exist_ok=True)
    attempt = cache / ('attempt-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    attempt.mkdir()
    source = Path(__file__).read_bytes()
    (attempt / 'trace-source.py').write_bytes(source)
    completed, executed = {}, []
    try:
        base, codes, image, names, e = load_inputs(folder)
        identity = identity_of(base)
        default = base.get('wiring_evidence', {}).get('EL0_launcher_default_off', {})
        require(default.get('trace_present') is True and default.get('trace_bindings', {}).get('success') is True,
                'enabled trace needs its new-kernel control/dispatch proof')
        _, probe_evidence = consume_probe(args.probe_dir, args.probe_evidence)
        build = json.loads((args.probe_dir / 'build.json').read_text())
        probe_sha = probe_evidence['probe_sha256']
        trace_uapi_sha = build['trace_uapi_sha256']
        graph = {n: {'entry': codes[n].entry, 'ins': codes[n].ins} for n in ROOTS}
        graph_sha = digest(graph)
        pins = {**identity, 'probe_sha256': probe_sha, 'decoded_graph_sha256': graph_sha,
                'trace_uapi_sha256': trace_uapi_sha, 'tool_sha256': hashlib.sha256(source).hexdigest(),
                'source_record': str((attempt / 'trace-source.py').relative_to(folder))}
        case_dir = cache / 'scenarios'
        case_dir.mkdir(exist_ok=True)
        for name, spec in SCENARIOS.items():
            path = case_dir / (name + '.json')
            if path.exists():
                completed[name] = consume_case(json.loads(path.read_text()), identity, spec, probe_sha, graph_sha)
                print('Consumed completed trace scenario:', name, '; 0 executions', flush=True)
            elif name in args.scenarios:
                print('Running missing trace scenario:', name, flush=True)
                result = run_case(deepcopy(spec), codes, image, names, e)
                record = {**pins, 'spec_sha256': digest(spec), 'success': True, 'result': result}
                with path.open('x') as stream: stream.write(json.dumps(record, indent=2) + '\n')
                completed[name] = record; executed.append(name)
                print('Saved passed trace scenario:', name, flush=True)
        if args.aggregate:
            report = assemble(completed, identity, probe_sha, trace_uapi_sha)
            report.update(tool_sha256=hashlib.sha256(source).hexdigest(), decoded_graph_sha256=graph_sha,
                          independent_probe=probe_evidence)
            target = cache / 'receiver.json'
            with target.open('x') as stream: stream.write(json.dumps(report, indent=2) + '\n')
        outcome = {**identity, 'success': True, 'completed': list(completed), 'executed_this_attempt': executed,
                   'aggregate_emitted': args.aggregate, 'hardware_verified': False}
    except Exception as error:
        outcome = {'success': False, 'error': str(error), 'completed': list(completed),
                   'executed_this_attempt': executed, 'hardware_verified': False}
        (attempt / 'traceback.txt').write_text(traceback.format_exc())
        print(traceback.format_exc(), flush=True)
    (attempt / 'result.json').write_text(json.dumps(outcome, indent=2) + '\n')
    print(json.dumps({'evidence': str(attempt), 'result': outcome}, indent=2), flush=True)
    return 0 if outcome['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
