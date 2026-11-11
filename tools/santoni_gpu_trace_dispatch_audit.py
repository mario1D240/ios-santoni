"""Exact-kernel fo_ioctl/vn_ioctl/VNOP_IOCTL boundary, with receiver ABI pinned.

The receiver is an injected return contract here; its same-kernel instruction
proof is separate. Runtime vnode/file tables, thread identity, MAC policies and
mutex returns are modeled. This certifies routing, not EL0 or hardware success.
"""
import ast
import hashlib
import inspect
import json
import re
import struct
import subprocess
import textwrap
from pathlib import Path

from santoni_gpu_binary_model import Machine, integer

ROOTS = ('_fo_ioctl', '_vn_ioctl', '_VNOP_IOCTL')
COMMAND = 0x804047f0
CASES = ('entry', 'result', 'receiver-error', 'other-vector', 'directory',
         'other-command', 'wide-command', 'mac-error', 'get-error',
         'mount32', 'character', 'block', 'fifo', 'write-flags')
SERVICES = ('_fg_get_data_volatile', '_vnode_getwithref', '_mac_vnode_check_ioctl',
            '_vfs_context_proc', '_lck_mtx_lock', '_lck_mtx_unlock', '_vnode_put',
            '_current_uthread', '_uthread_is64bit', '_get_bsdthread_info',
            '_mockfs_santoni_ioctl', '_dispatch_device_fixture')


class DispatchMachine(Machine):
    def guarded_switch_target(self, pc, state):
        code = self.by_pc[pc]
        # LLVM's VREG/VDIR/device switch uses seven unsigned byte offsets.
        # Admit this exact guarded sequence only; BR keeps registers, flags,
        # LR and the caller's stack, unlike an external function call.
        fixed = {
            -36: ('ldrh', ('w8', '[x19, #0x70]')),
            -32: ('sub', ('w9', 'w8', '#0x1')),
            -28: ('cmp', ('w9', '#0x6')),
            -8: ('ldrb', ('w12', '[x10, x9]')),
            -4: ('add', ('x11', 'x11', 'x12', 'lsl #2')),
            0: ('br', ('x11',)),
        }
        require(code.symbol == '_vn_ioctl' and all(code.ins.get(pc + off) == ins
                for off, ins in fixed.items()), 'unreviewed interior branch sequence')
        require(all(code.pred[pc + off] == {pc + off - 4}
                for off in range(-32, 1, 4)), 'branch enters switch after its bounds guard')
        guard, page, offset, base = (code.ins[pc + off] for off in (-24, -20, -16, -12))
        require(guard[0] == 'b.hi' and len(guard[1]) == 1 and
                self.e._number(guard[1][0]) in code.ins and
                page[0] == 'adrp' and len(page[1]) == 2 and page[1][0] == 'x10' and
                offset[0] == 'add' and len(offset[1]) == 3 and offset[1][:2] == ('x10', 'x10') and
                offset[1][2].startswith('#') and
                base[0] == 'adr' and len(base[1]) == 2 and base[1][0] == 'x11',
                'switch table address/guard geometry differs')
        table_page, table_offset, target_base = (self.e._number(v) for v in
                (page[1][1], offset[1][2], base[1][1]))
        require(all(type(v) is int for v in (table_page, table_offset, target_base)) and
                table_page % 4096 == 0 and 0 <= table_offset < 4096 and target_base == pc + 4,
                'switch address is unknown or not the next instruction')
        table = table_page + table_offset
        segments = [s for s in self.image.segs if s['vmaddr'] <= table and
                    table + 7 <= s['vmaddr'] + min(s['vmsize'], s['filesize'])]
        require(len(segments) == 1 and segments[0]['initprot'] == 1,
                'switch table is missing, ambiguous or writable')
        raw = self.image.read(table, 7)
        require(type(raw) is int, 'switch table bytes missing')
        entries = list(raw.to_bytes(7, 'little'))
        targets = [target_base + 4 * value for value in entries]
        require(all(t in code.ins and t not in code.padding for t in targets),
                'switch table escapes decoded function or targets padding')
        index = integer(state, 'x9')
        require(0 <= index < 7 and integer(state, 'x10') == table and
                integer(state, 'x12') == entries[index] and integer(state, 'x11') == targets[index],
                'concrete switch index/table/target differs')
        return targets[index]

    def signed_slot_load(self, pc, state):
        op, args = self.by_pc[pc].ins[pc]
        require(op == 'ldrsw' and len(args) == 2 and re.fullmatch(r'x(?:[12]?\d|30)', args[0]) and
                re.fullmatch(r'\[x(?:[12]?\d|30)(?:, #(?:0x[0-9a-f]+|\d+))?\]', args[1]),
                'unreviewed signed descriptor load geometry')
        address, pre = state.address(args[1])
        require(not pre and address is not None and isinstance(address.expr, int) and address.expr % 4 == 0,
                'signed descriptor address unknown/unaligned')
        value = self.memory.get(address.expr, 4)
        if value & 0x80000000:
            value -= 1 << 32
        state.put(args[0], self.e._Value(64, value & ((1 << 64) - 1)))
        return state


# Keep the shared interpreter and prior probe evidence unchanged. Add only
# the actual VNOP descriptor's signed scalar load, with separate semantics tests.
_tree = ast.parse(textwrap.dedent(inspect.getsource(Machine.run)))
_loops = [n for n in ast.walk(_tree) if isinstance(n, ast.For) and isinstance(n.iter, ast.Call) and
          isinstance(n.iter.func, ast.Name) and n.iter.func.id == 'range' and
          len(n.iter.args) == 1 and isinstance(n.iter.args[0], ast.Name) and n.iter.args[0].id == 'budget']
if len(_loops) != 1:
    raise ValueError('shared dispatch interpreter budget loop changed')
_loop = _loops[0]
_index = next(i for i, n in enumerate(_loop.body) if isinstance(n, ast.If) and
              ast.dump(n.test) == ast.dump(ast.parse("op == 'svc'", mode='eval').body))
_loop.body[_index:_index] = ast.parse(
    "if op == 'br' and engine.call(pc,state) in code.ins:\n"
    " pc=self.guarded_switch_target(pc,state)\n continue\n"
    "if op == 'ldrsw':\n state=self.signed_slot_load(pc,state)\n pc+=4\n continue\n").body
ast.fix_missing_locations(_tree)
_namespace = dict(Machine.run.__globals__)
exec(compile(_tree, '<trace-dispatch-signed-descriptor-load>', 'exec'), _namespace)
DispatchMachine.run = _namespace['run']


def require(ok, message):
    if not ok:
        raise ValueError('trace common dispatch: ' + message)


def decode(folder, image, names, e):
    codes = {}
    for name in ROOTS:
        require(len(names.get(name, ())) == 1, 'missing/ambiguous root ' + name)
        assembly = subprocess.check_output(['llvm-objdump', '--disassemble', '--disassemble-zeroes',
            '--disassemble-symbols=' + name, str(folder / 'kernel/kernel.development.santoni')], text=True)
        code = e._Code(assembly, name, next(iter(names[name])))
        words = {int(pc, 16): int(word, 16) for pc, word in re.findall(
            r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s', assembly, re.M) if int(pc, 16) in code.ins}
        require(set(words) == set(code.ins) and all(image.read(pc, 4) == word for pc, word in words.items()),
                'decoded instruction does not match linked bytes')
        (folder / (name[1:] + '.asm')).write_text(assembly)
        codes[name] = code
    return codes


def audit(codes, image, names, e, *, expect_route=True):
    require(type(expect_route) is bool and set(codes) == set(ROOTS), 'unreviewed scope')
    require(all(len(names.get(n, ())) == 1 for n in ('_vnops', '_mockfs_vnodeop_p',
            '_mockfs_santoni_ioctl', '_vnop_ioctl_desc', '_dead_mountp')), 'table identity missing/ambiguous')
    # file_internal.h's const vnops table must bind its ioctl callback to vn_ioctl.
    require(image.read(next(iter(names['_vnops'])) + 24, 8) == codes['_vn_ioctl'].entry,
            'linked fileops ioctl callback differs')
    from santoni_gpu_launcher_audit import trace_bindings
    binding = trace_bindings(image, names)
    FP, FG, FOPS, VP, MOUNT, CONF, CTX, PROC, UTHREAD, VECTOR, OTHER, RECORD = (
        0x62000000 + i * 0x1000 for i in range(12))
    SLOT, DEVICE = 7, 0x62100000
    reports = []
    for case in CASES:
        vm = DispatchMachine(codes, image, names, e)
        m = vm.memory
        for address, size in ((FP, 64), (FG, 128), (FOPS, 64), (VP, 256),
                (MOUNT, 4096), (CONF, 128), (CTX, 128), (PROC, 256), (UTHREAD, 128),
                (VECTOR, 512), (OTHER, 512), (RECORD, 64)):
            m.map(address, size)
        # These offsets match XNU8796 structs and actual compiled loads. Changes
        # fail on unmapped/unknown reads or callback/argument identity assertions.
        m.put(FP + 24, FG, 8); m.put(FG + 16, 3 if case == 'write-flags' else 1)
        m.put(FG + 40, FOPS, 8); m.put(FG + 56, VP, 8)
        m.put(FOPS + 24, codes['_vn_ioctl'].entry, 8)
        vtype = {'directory': 2, 'character': 4, 'block': 3, 'fifo': 7}.get(case, 1)
        m.put(VP + 0x70, vtype, 2)
        m.put(VP + 0xd0, OTHER if case == 'other-vector' else VECTOR, 8)
        m.put(VP + 0xd8, MOUNT, 8); m.put(MOUNT + 48, CONF, 8)
        m.put(CONF + 64, 0x04 if case == 'mount32' else 0x104)
        descriptor = next(iter(names['_vnop_ioctl_desc']))
        # Kernel startup constructs these mutable runtime tables. Their static
        # callback and fileops origins are verified above, not guessed as data.
        for address, value, size in ((next(iter(names['_mockfs_vnodeop_p'])), VECTOR, 8),
                (descriptor, SLOT, 4), (next(iter(names['_dead_mountp'])), OTHER, 8)):
            m.map(address, size); m.put(address, value, size)
        callback = DEVICE if vtype in (3, 4, 7) else next(iter(names['_mockfs_santoni_ioctl']))
        m.put(VECTOR + 8 * SLOT, callback, 8); m.put(OTHER + 8 * SLOT, DEVICE, 8)
        words = [1, 64, 6, 0, 0, 1, 32, 32, 7, 0, 0, *([0] * 5)] if case == 'result' else [1, 64, 1, 0, 2, *([0] * 11)]
        m.write(RECORD, struct.pack('<16I', *words))
        original = m.bytes(RECORD, 64)
        m.readonly.extend((a, a + len(data)) for a, data, _ in m.regions if a != vm.STACK)
        vm.by_address[DEVICE] = '_dispatch_device_fixture'
        command = COMMAND + (1 << 32) if case == 'wide-command' else COMMAND + 1 if case == 'other-command' else COMMAND
        calls, receivers, devices, writes = [], [], [], []
        refs, fdlocked = 0, True
        def write_guard(address, size):
            require(vm.STACK <= address < address + size <= vm.STACK + vm.STACK_SIZE,
                    'write escapes common-dispatch stack')
            writes.append((address, size))
        m.write_hook = write_guard
        def external(target, state, probe=False, before=None):
            nonlocal refs, fdlocked
            name = vm.by_address.get(target)
            if name not in SERVICES:
                return False
            if probe:
                return True
            calls.append(name)
            arg = lambda i: integer(before, 'x' + str(i))
            put = lambda value, bits=32: state.put('w0' if bits == 32 else 'x0', e._Value(bits, value))
            if name == '_vfs_context_proc':
                require(arg(0) == CTX, 'fileops context changed'); put(PROC, 64)
            elif name in ('_lck_mtx_lock', '_lck_mtx_unlock'):
                require(arg(0) == PROC + 0xd0, 'file descriptor mutex identity differs')
                require(fdlocked == (name == '_lck_mtx_unlock'), 'file descriptor mutex imbalance')
                fdlocked = name == '_lck_mtx_lock'; put(0)
            elif name == '_fg_get_data_volatile':
                require(arg(0) == FG and not fdlocked, 'fileglob identity/lock differs'); put(VP, 64)
            elif name == '_vnode_getwithref':
                require(arg(0) == VP and refs == 0 and not fdlocked, 'vnode acquisition differs')
                refs = 0 if case == 'get-error' else 1; put(2 if case == 'get-error' else 0)
            elif name == '_mac_vnode_check_ioctl':
                require(tuple(arg(i) for i in range(3)) == (CTX, VP, command) and refs == 1,
                        'MAC check absent, reordered or arguments changed'); put(1 if case == 'mac-error' else 0)
            elif name == '_vnode_put':
                require(arg(0) == VP and refs == 1 and not fdlocked, 'vnode iocount release differs')
                refs = 0; put(0)
            elif name == '_current_uthread':
                put(UTHREAD, 64)
            elif name == '_uthread_is64bit':
                require(arg(0) == UTHREAD, 'LP64 thread identity changed'); put(1)
            elif name == '_get_bsdthread_info':
                raise ValueError('unmodeled nonzero thread fixture')
            else:
                require(refs == 1 and not fdlocked and '_mac_vnode_check_ioctl' in calls,
                        'callback precedes MAC/acquisition or retains fd lock')
                a = arg(0)
                require(vm.STACK <= a < a + 48 <= vm.STACK + vm.STACK_SIZE,
                        'VNOP callback argument frame missing')
                expected = (descriptor, VP, command, RECORD,
                            3 if case == 'write-flags' else 1, CTX)
                actual = tuple(m.get(a + off, size) for off, size in ((0, 8), (8, 8), (16, 8),
                                    (24, 8), (32, 4), (40, 8)))
                require(actual == expected, 'trace receiver ABI/scalars differ')
                (receivers if name == '_mockfs_santoni_ioctl' else devices).append(actual)
                put(13 if case == 'receiver-error' else 22 if case == 'write-flags' else 0)
            return True
        vm.external = external
        vm.run('_fo_ioctl', (FP, command, RECORD, CTX), budget=5000)
        admitted = case in ('entry', 'result', 'receiver-error', 'write-flags') and expect_route
        dev = case in ('character', 'block', 'fifo')
        expected = (2 if case == 'get-error' else 1 if case == 'mac-error' else
                    13 if admitted and case == 'receiver-error' else 22 if admitted and case == 'write-flags' else
                    0 if admitted or dev else 25)
        require(integer(vm.state, 'w0') == expected and len(receivers) == int(admitted) and
                len(devices) == int(dev), 'dispatch outcome/callback differs: ' + case)
        require(refs == 0 and fdlocked and calls.count('_lck_mtx_unlock') == calls.count('_lck_mtx_lock') == 1 and
                m.bytes(RECORD, 64) == original, 'refs/fd mutex/IOC_IN lifetime differs')
        if case != 'get-error':
            require(calls.count('_mac_vnode_check_ioctl') == calls.count('_vnode_put') == 1,
                    'missing balanced MAC/iocount boundary')
        reports.append({'case': case, 'result': expected, 'receiver_calls': len(receivers),
            'device_calls': len(devices), 'receiver_arguments': [list(a) for a in receivers],
            'service_calls': calls, 'instruction_addresses': len(vm.visited),
            'record_immutable': True, 'refs_released': True, 'fd_mutex_restored': True})
    graph = {n: {'entry': c.entry, 'ins': c.ins} for n, c in codes.items()}
    return {'success': True, 'common_dispatch_checked': expect_route, 'diagnosis_only': not expect_route,
        'kernel_sha256': hashlib.sha256(image.data).hexdigest(), 'roots': list(ROOTS),
        'decoded_graph_sha256': hashlib.sha256(json.dumps(graph, sort_keys=True).encode()).hexdigest(),
        'cases': reports, 'ioctl_command': COMMAND, 'record_bytes': 64, 'binding': binding,
        'ioctl_descriptor': hex(descriptor),
        'hardware_verified': False, 'scope': __doc__}


def validate(record, identity, binding):
    require(isinstance(record, dict) and record.get('success') is True and
            record.get('common_dispatch_checked') is True and record.get('diagnosis_only') is False and
            record.get('hardware_verified') is False and record.get('roots') == list(ROOTS) and
            record.get('ioctl_command') == COMMAND and record.get('record_bytes') == 64 and
            record.get('binding') == binding and binding.get('success') is True and
            {k: record.get(k) for k in identity} == identity and
            record.get('tool_sha256') == hashlib.sha256(Path(__file__).read_bytes()).hexdigest() and
            re.fullmatch(r'0x[0-9a-f]+', record.get('ioctl_descriptor', '')) and
            re.fullmatch(r'[0-9a-f]{64}', record.get('decoded_graph_sha256', '')),
            'incomplete/different-kernel/stale compiled routing proof')
    rows = record.get('cases')
    require(isinstance(rows, list) and [r.get('case') for r in rows] == list(CASES),
            'missing/unreviewed dispatch cases')
    for row in rows:
        case = row['case']
        recv = int(case in ('entry', 'result', 'receiver-error', 'write-flags'))
        dev = int(case in ('character', 'block', 'fifo'))
        expected = (2 if case == 'get-error' else 1 if case == 'mac-error' else
                    13 if case == 'receiver-error' else 22 if case == 'write-flags' else 0 if recv or dev else 25)
        calls = row.get('service_calls', [])
        require(row.get('result') == expected and row.get('receiver_calls') == recv and
                row.get('device_calls') == dev and
                all(row.get(n) is True for n in ('record_immutable', 'refs_released', 'fd_mutex_restored')) and
                type(row.get('instruction_addresses')) is int and 0 < row['instruction_addresses'] <= 5000 and
                isinstance(calls, list) and set(calls) <= set(SERVICES) and
                calls.count('_lck_mtx_unlock') == calls.count('_lck_mtx_lock') == 1 and
                calls.index('_lck_mtx_unlock') < calls.index('_lck_mtx_lock') and
                calls.count('_vnode_getwithref') == 1,
                'dispatch callback/outcome/lifetime evidence differs: ' + case)
        if case == 'get-error':
            require('_mac_vnode_check_ioctl' not in calls and '_vnode_put' not in calls,
                    'failed acquisition has MAC/release traffic')
        else:
            require(calls.count('_mac_vnode_check_ioctl') == calls.count('_vnode_put') == 1 and
                    calls.index('_mac_vnode_check_ioctl') < calls.index('_vnode_put'), 'MAC/iocount order differs')
        require(calls.count('_mockfs_santoni_ioctl') == recv and
                calls.count('_dispatch_device_fixture') == dev, 'unbound callback count')
        if recv or dev:
            target = '_mockfs_santoni_ioctl' if recv else '_dispatch_device_fixture'
            require(calls.index('_mac_vnode_check_ioctl') < calls.index(target) < calls.index('_vnode_put'),
                    'callback does not follow MAC within vnode reference')
        require(row.get('receiver_arguments') == ([] if not recv else [[
            # Owned fixture addresses and exact IOC_IN ABI, never hardware PAs.
            int(record['ioctl_descriptor'], 16), 0x62003000, COMMAND, 0x6200b000,
            3 if case == 'write-flags' else 1, 0x62006000]]), 'receiver parameter proof differs')
    return record
