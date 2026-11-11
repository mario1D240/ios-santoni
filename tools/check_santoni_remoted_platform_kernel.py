#!/usr/bin/env python3
"""Audit only the new0212 CPU workaround in an exact CI kernel.

Decoded instructions run under explicit CPU/VFS/process contracts. No hardware,
filesystem authentication, scheduler progress or individual API return is proved.
The shared kernel decoder and launcher interpreter remain unchanged.
"""
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess

import check_santoni_gpu_kernel as e
import santoni_gpu_launcher_replay as launcher
from santoni_gpu_binary_model import integer

ROOT = Path(__file__).resolve().parents[1]
PLATFORM, SIGNED, VALID, KILLED = 0x04000000, 0x20000000, 1, 0x01000000
TARGET = b'/usr/libexec/remoted\0'
KEY = b'santoni_remoted_platform\0'


def require(condition, message):
    if not condition:
        raise ValueError('remoted binary audit: ' + message)


class RootMachine(launcher.LauncherMachine):
    def __init__(self, *args, log_addr=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.log_addr = log_addr
        self.reservation = None
        self.exclusive_failures = 0
        self.exclusive_attempts = 0

    def root_step(self, pc, state):
        op, args = self.by_pc[pc].ins[pc]
        reg = r'w(?:[12]?\d|30)'
        if op == 'csinc':
            require(len(args) == 4 and re.fullmatch(reg, args[0]) and
                    re.fullmatch(reg, args[1]) and args[2:] == ('wzr', 'ne'),
                    'unreviewed scalar CSINC geometry')
            truth = state.truth(state.condition('ne'))
            require(truth is not None, 'CSINC unknown condition')
            value = integer(state, args[1]) if truth else 1
            state.put(args[0], self.e._Value(32, value))
            return state
        require(op in ('ldxr', 'stxr') and len(args) == (2 if op == 'ldxr' else 3),
                'unreviewed exclusive operation')
        require(re.fullmatch(reg, args[0]) and
                (op == 'ldxr' or re.fullmatch(reg + r'|wzr', args[1])) and
                re.fullmatch(r'\[(?:x(?:[12]?\d|30)|sp)\]', args[-1]),
                'unreviewed exclusive register/address geometry')
        address, pre = state.address(args[-1])
        require(not pre and address is not None and isinstance(address.expr, int) and
                address.expr == self.log_addr and address.expr % 4 == 0,
                'exclusive operation escaped the owned four-byte counter')
        if op == 'ldxr':
            self.reservation = address.expr
            state.put(args[0], self.e._Value(32, self.memory.get(address.expr, 4)))
        else:
            require(self.reservation == address.expr, 'STXR without matching reservation')
            self.exclusive_attempts += 1
            failed = self.exclusive_failures > 0
            if failed:
                self.exclusive_failures -= 1
            else:
                self.memory.put(address.expr, integer(state, args[1]), 4)
            state.put(args[0], self.e._Value(32, int(failed)))
            self.reservation = None
        return state


# Extend a copy of the already checked launcher dispatcher, never its source.
_tree = copy.deepcopy(launcher._tree)
_loop = next(n for n in ast.walk(_tree) if isinstance(n, ast.For) and
             isinstance(n.iter, ast.Call) and isinstance(n.iter.func, ast.Name) and
             n.iter.func.id == 'range' and n.iter.args and isinstance(n.iter.args[0], ast.Name) and
             n.iter.args[0].id == 'budget')
_index = next(i for i, n in enumerate(_loop.body) if isinstance(n, ast.If) and
              ast.dump(n.test) == ast.dump(ast.parse("op == 'svc'", mode='eval').body))
_loop.body[_index:_index] = ast.parse(
    "if op in ('ldxr','stxr','csinc'):\n state=self.root_step(pc,state)\n pc+=4\n continue\n").body
ast.fix_missing_locations(_tree)
_namespace = dict(launcher.LauncherMachine.run.__globals__)
exec(compile(_tree, '<remoted-only-interpreter-extension>', 'exec'), _namespace)
RootMachine.run = _namespace['run']


class RootModel:
    # Synthetic CPU objects, never device addresses or physical allocations.
    PROC, VP, MOUNT, BLOB, TASK = (0x59100000, 0x59110000, 0x59120000, 0x59130000, 0x59140000)

    def __init__(self, codes, image, names, binding, case):
        self.names, self.binding, self.case = names, binding, case
        self.vm = RootMachine(codes, image, names, e, log_addr=binding['logged'])
        self.m = self.vm.memory
        self.flags = case.get('flags', SIGNED | VALID)
        self.pid, self.name = 43, case.get('name', 'remoted')
        self.path = case.get('path', TARGET[:-1].decode()).encode() + b'\0'
        self.locked, self.platform = False, case.get('task_platform', False)
        self.masks, self.logs, self.api_calls = [], [], []
        self.platform_calls = 0
        self.m.map(self.PROC, 4096)
        self.m.put(self.PROC + 0x5a0, 0 if case.get('null_vp') else self.VP, 8)
        self.m.put(self.PROC + 0x5a8, 0, 8)
        self.m.map(self.VP, 256)
        self.m.map(self.MOUNT, 256)
        self.m.map(self.BLOB, 512)
        self.m.map(self.TASK, 256)
        self.m.put(self.BLOB + 0x20, case.get('blob_valid', 1), 4)
        self.m.put(self.BLOB + 0xd4, case.get('blob_platform', 0), 1)
        self.blob_before = self.m.bytes(self.BLOB, 512)
        for address, size in ((self.PROC, 4096), (self.VP, 256), (self.MOUNT, 256),
                              (self.BLOB, 512), (self.TASK, 256)):
            self.m.readonly.append((address, address + size))
        for address, size in ((binding['spec'], 24), (binding['name'], len(KEY))):
            value = image.read(address, size)
            require(value is not None, 'tunable metadata is not file-backed')
            self.m.map(address, size)
            self.m.put(address, value, size)
            self.m.readonly.append((address, address + size))
        self.m.map(binding['flag'], 4)
        self.m.map(binding['logged'], 4)
        self.m.put(binding['logged'], case.get('logged', 0), 4)
        self.vm.external = self.external
        self.vm.exclusive_failures = case.get('exclusive_failures', 0)

    def text(self, address, limit=256):
        output = bytearray()
        for i in range(limit):
            value = self.m.get(address + i, 1)
            if value == 0:
                return output.decode()
            output.append(value)
        raise ValueError('unterminated modeled root string')

    def external(self, target, state, probe=False, before=None):
        name = self.vm.by_address.get(target)
        allowed = {'_PE_parse_boot_argn', '_proc_getpid', '_proc_name', '_strcmp',
                   '_proc_getcsflags', '_vnode_vtype', '_vnode_mount', '_vfs_flags',
                   '_vn_getpath', '_memcmp', '_ubc_cs_blob_get', '_proc_lock', '_proc_unlock',
                   '_proc_csflags_set', '_proc_task', '_task_set_platform_binary', '_printf'}
        if name not in allowed:
            return False
        if probe:
            return True
        args = [integer(before, 'x' + str(i)) if before.get('x' + str(i)) is not None else None for i in range(4)]
        self.api_calls.append(name)
        result = 0
        if name == '_PE_parse_boot_argn':
            require(self.text(args[0]) == KEY[:-1].decode() and args[1:3] == [self.binding['flag'], 4],
                    'tunable parse changed name/storage/width')
            option = self.case.get('option', 1)
            if option is not None:
                self.m.put(args[1], option, 4)
                result = 1
        elif name == '_proc_getpid':
            require(args[0] == self.PROC, 'PID lookup uses another process')
            result = self.pid
        elif name == '_proc_name':
            require(args[0] == self.pid and args[2] == 32, 'name lookup changed identity/width')
            self.m.write(args[1], (self.name.encode() + bytes(32))[:32])
        elif name == '_strcmp':
            result = int(self.text(args[0]) != self.text(args[1]))
        elif name == '_proc_getcsflags':
            require(args[0] == self.PROC, 'flags lookup uses another process')
            result = self.flags
        elif name == '_vnode_vtype':
            require(args[0] == self.VP, 'wrong executable vnode type lookup')
            result = self.case.get('vtype', 1)
        elif name == '_vnode_mount':
            require(args[0] == self.VP, 'wrong executable mount lookup')
            result = 0 if self.case.get('null_mount') else self.MOUNT
        elif name == '_vfs_flags':
            require(args[0] == self.MOUNT, 'flags lookup uses another mount')
            result = self.case.get('mount_flags', 0x4000)
        elif name == '_vn_getpath':
            require(args[0] == self.VP and self.m.get(args[2], 4) == 64 and not self.locked,
                    'path lookup changed vnode/budget or holds process lock')
            if len(self.path) > 64:
                result = 63  # explicit modeled ENAMETOOLONG contract; no filesystem enters
            else:
                value = self.path[:-1] + b'x' if self.case.get('missing_nul') else self.path
                self.m.write(args[1], value)
                self.m.put(args[2], self.case.get('path_len', len(self.path)), 4)
                result = self.case.get('path_error', 0)
        elif name == '_memcmp':
            require(args[2] == len(TARGET), 'path comparison changed its complete NUL-terminated width')
            result = int(self.m.bytes(args[0], args[2]) != self.m.bytes(args[1], args[2]))
        elif name == '_ubc_cs_blob_get':
            require(args[0] == self.VP and args[1] & 0xffffffff == 0xffffffff and
                    args[2] & 0xffffffff == 0xffffffff and args[3] == 0, 'wrong signature lookup ABI')
            result = 0 if self.case.get('no_blob') else self.BLOB
        elif name == '_proc_lock':
            require(args[0] == self.PROC and not self.locked, 'wrong or recursive process lock')
            self.locked = True
        elif name == '_proc_unlock':
            require(args[0] == self.PROC and self.locked, 'wrong/unbalanced process unlock')
            self.locked = False
        elif name == '_proc_csflags_set':
            require(args[:2] == [self.PROC, PLATFORM] and self.locked,
                    'workaround changed another flag/process or writes without its lock')
            self.flags |= args[1]
            self.masks.append(args[1])
        elif name == '_proc_task':
            require(args[0] == self.PROC and not self.locked, 'task lookup holds the process lock')
            result = self.TASK
        elif name == '_task_set_platform_binary':
            require(args[:2] == [self.TASK, 1] and not self.locked, 'wrong task/platform setter state')
            self.platform, self.platform_calls = True, self.platform_calls + 1
        else:
            require(self.text(args[0]).startswith('SANTONI PLATFORM: remoted pid='), 'wrong observation prefix')
            sp = integer(before, 'sp')
            self.logs.append([self.m.get(sp + i * 8, 8) & 0xffffffff for i in range(10)])
        state.put('x0', e._Value(64, result))
        return True

    def initialize(self):
        self.vm.run('_kernel_startup_tunable_init', (self.binding['spec'],), budget=200000)
        self.m.readonly.append((self.binding['flag'], self.binding['flag'] + 4))
        expected = self.case.get('option', 1)
        require(self.m.get(self.binding['flag'], 4) == (0 if expected is None else expected & 0xffffffff),
                'actual compiled tunable initialization disagrees')

    def helper(self):
        self.initialize()
        self.vm.run('_santoni_remoted_platform_exec', (0 if self.case.get('null_proc') else self.PROC,), budget=200000)
        promoted = self.case.get('promote', False)
        require(self.flags == (self.case.get('flags', SIGNED | VALID) | (PLATFORM if promoted else 0)),
                'helper altered signing flags or missed the intended platform update')
        require(self.masks == ([PLATFORM] if promoted else []) and self.platform_calls == int(promoted) and
                not self.locked and self.m.bytes(self.BLOB, 512) == self.blob_before,
                'helper changed signature storage/task/lock scope')
        if self.logs:
            values = self.logs[0]
            require(len(self.logs) == 1 and values[0:3] == [self.pid, self.case.get('flags', SIGNED | VALID),
                    int(bool(self.case.get('flags', SIGNED | VALID) & SIGNED))] and values[9] == int(promoted),
                    'observation does not preserve the pre-workaround state')
        return {'flags': self.flags, 'set_masks': self.masks, 'task_platform': self.platform,
                'platform_calls': self.platform_calls, 'logs': self.logs,
                'counter': self.m.get(self.binding['logged'], 4), 'blob_immutable': True,
                'api_calls': self.api_calls, 'exclusive_attempts': self.vm.exclusive_attempts,
                'visited_opcodes': sorted({self.vm.by_pc[pc].ins[pc][0] for pc in self.vm.visited})}


HELPER_CASES = {
    'default_off': {'option': None}, 'disabled_zero': {'option': 0}, 'optin_two': {'option': 2},
    'optin_full_width': {'option': 0xffffffff}, 'null_process': {'null_proc': True},
    'other_process': {'name': 'launchd'}, 'null_vnode': {'null_vp': True},
    'directory': {'vtype': 2}, 'device_vnode': {'vtype': 4}, 'null_mount': {'null_mount': True},
    'nonroot': {'mount_flags': 0}, 'other_root_path': {'path': '/private/tmp/remoted'},
    'path_suffix': {'path': '/usr/libexec/remoted2'},
    'cryptex_alias': {'path': '/private/preboot/Cryptexes/OS/usr/libexec/remoted'},
    'path_error': {'path_error': 5}, 'path_overflow': {'path': '/' + 'a' * 70 + '/remoted'},
    'zero_length': {'path_len': 0}, 'negative_length': {'path_len': -1},
    'short_length': {'path_len': len(TARGET) - 1}, 'oversized_length': {'path_len': 65},
    'missing_nul': {'missing_nul': True}, 'invalid_blob': {'blob_valid': 0},
    'killed': {'flags': SIGNED | VALID | KILLED},
    'signed_root': {'promote': True}, 'readonly_root': {'mount_flags': 0x4001, 'promote': True},
    'missing_blob': {'no_blob': True, 'promote': True},
    'unsigned_root': {'flags': VALID, 'no_blob': True, 'promote': True},
    'no_signature_claim': {'flags': 0, 'no_blob': True, 'promote': True},
    'existing_blob_platform': {'blob_platform': 1, 'task_platform': True},
    'existing_process_platform': {'flags': SIGNED | VALID | PLATFORM, 'task_platform': True},
    'logged_already': {'logged': 1, 'promote': True},
    'exclusive_retry': {'exclusive_failures': 1, 'promote': True},
}
GETTER_CASES = {
    'exec_platform': ({'flags': PLATFORM, 'no_blob': True}, 1),
    'disabled_exec_platform': ({'option': None, 'flags': PLATFORM, 'no_blob': True}, 0),
    'invalid_optin': ({'option': 2, 'flags': PLATFORM}, 0),
    'null_vnode': ({'flags': PLATFORM, 'null_vp': True}, 0),
    'null_process': ({'null_proc': True}, 0), 'missing_blob': ({'no_blob': True}, 0),
    'signed_platform': ({'option': None, 'blob_platform': 1}, 1),
    'signed_nonplatform': ({'option': None}, 0),
    'platform_word_low_bit': ({'option': None, 'blob_platform': 0xfe}, 0),
}


def success_callsite(caller, helper_address, thread_address):
    """Require the immediate zero-return edge to dominate the new hook.

    Walking the nonzero edge without propagating errno constants admits
    infeasible paths back through validation. Edge dominance proves that any
    hook entry passes the final signature call's zero-result guard instead.
    The complete source/native contracts separately exercise upstream failures.
    """
    calls = caller.calls_to({helper_address})
    require(len(calls) == 1, 'workaround has no unique compiled exec callsite')
    guards = []
    for call in caller.calls_to({thread_address}):
        pc = call + 4
        op, args = caller.ins.get(pc, ('', ()))
        if op not in ('cbz', 'cbnz') or args[0] != 'w0':
            continue
        zero = e._number(args[-1]) if op == 'cbz' else pc + 4
        nonzero = pc + 4 if op == 'cbz' else e._number(args[-1])
        if (caller.pred.get(zero) == {pc} and calls[0] in caller.walk(zero) and
                calls[0] not in caller.walk(caller.entry, exclude=(zero,))):
            guards.append({'call': hex(call), 'guard': hex(pc), 'zero': hex(zero),
                           'nonzero': hex(nonzero), 'zero_edge_dominates_hook': True})
    require(len(guards) == 1, 'compiled zero-return edge does not dominate the new exec hook')
    return guards


def audit(ci):
    run = json.loads((ci / 'run.json').read_text())
    require(run['status'] == 'completed' and run['conclusion'] == 'success' and
            run['repository_private'] is True, 'successful private CI metadata required')
    data = (ci / 'kernel/kernel.development.santoni').read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    sums = {name.lstrip('*'): digest for digest, name in
            (line.split(None, 1) for line in (ci / 'kernel/SHA256SUMS').read_text().splitlines())}
    require(sums['kernel.development.santoni'] == sha, 'new kernel checksum mismatch')
    output = ci / 'remoted-platform-components'
    output.mkdir(exist_ok=True)
    inventory = output / 'kernel.symbols.txt'
    if not inventory.exists():
        inventory.write_text(subprocess.check_output(['llvm-nm', '--defined-only',
                              str(ci / 'kernel/kernel.development.santoni')], text=True))
    names, image = e._symbols(inventory.read_text()), e._Image(data)

    def addr(name):
        require(len(names.get(name, ())) == 1, 'missing/ambiguous ' + name)
        return next(iter(names[name]))

    binding = {'flag': addr('_santoni_remoted_platform'), 'logged': addr('_santoni_remoted_platform_logged'),
               'name': addr('___startup_TUNABLES_name_santoni_remoted_platform'),
               'spec': addr('___startup_TUNABLES_spec_santoni_remoted_platform')}
    require(image.read(binding['flag'], 4) == 0 and image.read(binding['name'], len(KEY)) == int.from_bytes(KEY, 'little'),
            'tunable initial value/name differs')
    require(image.read(binding['spec'], 8) == binding['name'] and
            image.read(binding['spec'] + 8, 8) == binding['flag'] and image.read(binding['spec'] + 16, 4) == 4 and
            image.read(binding['spec'] + 20, 4) == 0, 'tunable storage/width/type descriptor differs')
    entries = [name for name in names if re.fullmatch(r'___startup_TUNABLES_entry_santoni_remoted_platform_\d+', name)]
    require(len(entries) == 1, 'missing/ambiguous startup descriptor')
    entry = addr(entries[0])
    require(image.read(entry + 8, 8) == addr('_kernel_startup_tunable_init') and
            image.read(entry + 16, 8) == binding['spec'], 'tunable initializer is not registered')
    codes = {}
    for symbol in ('_santoni_remoted_platform_exec', '_csproc_get_platform_binary',
                   '_kernel_startup_tunable_init', '_process_signature'):
        path = output / (symbol.strip('_') + '.asm')
        if not path.exists():
            path.write_text(subprocess.check_output(['llvm-objdump', '--disassemble', '--disassemble-zeroes',
                            '--disassemble-symbols=' + symbol, str(ci / 'kernel/kernel.development.santoni')], text=True))
        codes[symbol] = e._Code(path.read_text(), symbol, addr(symbol),
                               noreturn=names.get('___stack_chk_fail', set()) | names.get('_panic', set()))
    # Actual getter/helper fields are checked before supplying the corresponding model layout.
    getter, helper, caller = (codes[n] for n in ('_csproc_get_platform_binary', '_santoni_remoted_platform_exec', '_process_signature'))
    require(any(op == 'ldr' and any('#0x5a0]' in a for a in args) for op, args in getter.ins.values()) and
            any(op == 'ldrb' and any('#0xd4]' in a for a in args) for op, args in getter.ins.values()) and
            any(op == 'ldrb' and any('#0x20]' in a for a in args) for op, args in helper.ins.values()),
            'unreviewed process/signature ABI offsets')
    guards = success_callsite(caller, addr('_santoni_remoted_platform_exec'), addr('_thread_process_signature'))
    records = []
    for label, case in HELPER_CASES.items():
        path = output / ('helper-' + label + '.json')
        if path.exists():
            record = json.loads(path.read_text())
            require(record.get('success') is True and record.get('kernel_sha256') == sha and record.get('input') == case,
                    'stale/incomplete helper checkpoint')
        else:
            model = RootModel(codes, image, names, binding, case)
            observed = model.helper()
            record = {'success': True, 'kernel_sha256': sha, 'input': case, 'observed': observed,
                      'executed_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
            path.write_text(json.dumps(record, indent=2) + '\n')
            print('New linked helper:', label, 'passed', flush=True)
        records.append(record)
    for label, (case, expected) in GETTER_CASES.items():
        path = output / ('getter-' + label + '.json')
        if path.exists():
            record = json.loads(path.read_text())
            require(record.get('success') is True and record.get('kernel_sha256') == sha and record.get('input') == case,
                    'stale/incomplete getter checkpoint')
        else:
            model = RootModel(codes, image, names, binding, case)
            model.initialize()
            model.vm.run('_csproc_get_platform_binary', (0 if case.get('null_proc') else model.PROC,), budget=200000)
            value = integer(model.vm.state, 'w0')
            require(value == expected and not model.masks and not model.logs and
                    model.m.bytes(model.BLOB, 512) == model.blob_before, 'getter result/state changed')
            record = {'success': True, 'kernel_sha256': sha, 'input': case, 'result': value,
                      'executed_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
            path.write_text(json.dumps(record, indent=2) + '\n')
            print('New linked getter:', label, 'passed', flush=True)
        records.append(record)
    result = {'success': True, 'commit': run['headSha'], 'ci_run': run['databaseId'], 'kernel_sha256': sha,
              'hardware_verified': False, 'Cortex_A53_changed_code_checked': True, 'default_off_checked': True,
              'exact_root_exec_checked': True, 'signing_state_preserved_checked': True,
              'exec_success_callsite_checked': True, 'tunable_storage_binding_checked': True,
              'helper_cases': len(HELPER_CASES), 'getter_cases': len(GETTER_CASES), 'callsite': guards,
              'tunable': {name: hex(value) for name, value in binding.items()},
              'compiled_functions': {name: len(code.ins) for name, code in codes.items()},
              'platform_APIs_are_explicit_model_contracts': True,
              'single_instruction_or_API_return_bounded_on_hardware': False,
              'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    (ci / 'remoted-platform-binary-audit.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ci', type=Path)
    print(json.dumps(audit(parser.parse_args().ci.resolve()), indent=2))
