"""Exact linked VFS_MOUNT LP64 dispatch and immutable mockfs registration.

This checks only the newly uncovered VFS provider boundary. Thread identity
and callback returns are explicit CPU-model inputs, never hardware evidence.
"""
import hashlib
import re
import subprocess
from pathlib import Path

from santoni_gpu_binary_model import Machine, integer


def require(ok, message):
    if not ok: raise ValueError('mockfs VFS boundary: ' + message)


def registry(image, names):
    ops = next(iter(names['_mockfs_vfsops']))
    callback = next(iter(names['_mockfs_santoni_mount']))
    require(image.read(ops, 8) == callback, 'linked mount callback is missing or different')
    data = image.data
    candidates, cursor = [], 0
    while True:
        offset = data.find(b'mockfs\0', cursor)
        if offset < 0: break
        cursor = offset + 1
        if offset >= 8 and int.from_bytes(data[offset - 8:offset], 'little') == ops:
            address = offset - 8
            segments = [s for s in image.segs if s['fileoff'] <= address < s['fileoff'] + s['filesize']]
            require(len(segments) == 1, 'registry file/VM mapping ambiguous')
            seg = segments[0]
            address += seg['vmaddr'] - seg['fileoff']
            require(image.read(address + 24, 4) == 0x6d6f636b, 'mockfs type identity differs')
            candidates.append(address)
    require(len(candidates) == 1, 'linked mockfs registration missing or ambiguous')
    address = candidates[0]
    return {'address': address, 'vfsops': ops, 'callback': callback,
            'vfs_flags': image.read(address + 64, 4)}


def decode(folder, image, names, e):
    codes = {}
    kernel = folder / 'kernel/kernel.development.santoni'
    for name in ('_VFS_MOUNT', '_vfs_64bitready'):
        require(len(names.get(name, ())) == 1, 'missing/ambiguous ' + name)
        assembly = subprocess.check_output(['llvm-objdump', '--disassemble', '--disassemble-zeroes',
            '--disassemble-symbols=' + name, str(kernel)], text=True)
        code = e._Code(assembly, name, next(iter(names[name])))
        words = {int(pc, 16): int(word, 16) for pc, word in re.findall(
            r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s', assembly, re.M) if int(pc, 16) in code.ins}
        require(set(words) == set(code.ins) and all(image.read(pc, 4) == word for pc, word in words.items()),
                'unbound compiled VFS instruction')
        codes[name] = code
    return codes


def audit(folder, image, names, e, *, diagnose=False, codes=None):
    linked = registry(image, names)
    codes = decode(folder, image, names, e) if codes is None else {name: codes[name] for name in ('_VFS_MOUNT', '_vfs_64bitready')}
    MOUNT, TABLE, OPS, CONTEXT, UTHREAD, DATA, DEAD = (
        0x59000000, 0x59001000, 0x59002000, 0x59003000, 0x59004000, 0x59005000, 0x59006000)
    results = []
    cases = ('linked64', 'linked32', 'ready64', 'callee-error', 'wrong-bit', 'missing-callback', 'dead-mount')
    for case in cases:
        vm = Machine(codes, image, names, e)
        for address, size in ((MOUNT, 128), (TABLE, 96), (OPS, 8), (CONTEXT, 8), (DATA, 16)):
            vm.memory.map(address, size)
        vm.memory.map(next(iter(names['_dead_mountp'])), 8)
        vm.memory.put(next(iter(names['_dead_mountp'])), DEAD, 8)
        flags = linked['vfs_flags'] if case.startswith('linked') else 0x104
        if case == 'wrong-bit': flags = 0x84
        vm.memory.put(MOUNT + 40, OPS, 8); vm.memory.put(MOUNT + 48, TABLE, 8)
        vm.memory.put(TABLE + 64, flags)
        vm.memory.put(OPS, 0 if case == 'missing-callback' else linked['callback'], 8)
        calls, callback_calls = [], []
        context64 = case != 'linked32'
        mount = DEAD if case == 'dead-mount' else MOUNT
        def external(target, state, probe=False, before=None):
            by_address = vm.by_address.get(target)
            if by_address not in ('_current_uthread', '_uthread_is64bit', '_mockfs_santoni_mount'):
                return False
            if probe: return True
            calls.append(by_address)
            if by_address == '_current_uthread': state.put('x0', e._Value(64, UTHREAD))
            elif by_address == '_uthread_is64bit':
                require(integer(before, 'x0') == UTHREAD, 'context thread identity differs')
                state.put('w0', e._Value(32, int(context64)))
            else:
                require(tuple(integer(before, 'x' + str(i)) for i in range(4)) == (MOUNT, 0, DATA, CONTEXT) and
                        integer(before, 'sp') == vm.STACK + vm.STACK_SIZE,
                        'VFS tail callback loses mount/data/context or leaves a frame')
                callback_calls.append(target)
                state.put('w0', e._Value(32, 5 if case == 'callee-error' else 0))
            return True
        vm.external = external
        vm.run('_VFS_MOUNT', (mount, 0, DATA, CONTEXT), budget=1000)
        allowed = case not in ('wrong-bit', 'missing-callback', 'dead-mount') and (
            not context64 or bool(flags & 0x100))
        expected = 5 if allowed and case == 'callee-error' else 0 if allowed else 45
        require(integer(vm.state, 'w0') == expected and len(callback_calls) == int(allowed),
                'linked LP64 dispatch/refusal result differs: ' + case)
        results.append({'case': case, 'flags': flags, 'context64': context64, 'result': expected,
                        'mount_callback_calls': len(callback_calls), 'calls': calls,
                        'instruction_addresses': len(vm.visited)})
    if not diagnose:
        require(linked['vfs_flags'] == 0x104, 'Santoni mockfs is not registered LP64-ready')
    return {'success': True, 'cases': results, 'registration': {key: hex(value) for key, value in linked.items()},
            'enabled_LP64_mount_dispatch_checked': linked['vfs_flags'] == 0x104,
            'kernel_sha256': hashlib.sha256(image.data).hexdigest(), 'hardware_verified': False,
            'diagnosis_only': diagnose, 'scope': 'actual linked registry, VFS ABI and seven compiled dispatch scenarios; thread/callback contracts injected'}
