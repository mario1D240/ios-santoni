"""New exact-kernel launcher replay with explicit CPU/VFS service contracts.

No native kernel, device, scheduler or SMC executes. Original instruction
graphs remain immutable. The local extension adds scalar REV/MVN/CINC and acquire/release
loads/stores to a pinned copy of the shared interpreter's run method; the
previous probe's interpreter source and evidence are unchanged.
"""
import ast
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import inspect
import json
from pathlib import Path
import re
import textwrap
import traceback

from santoni_gpu_binary_model import Machine, integer
from santoni_gpu_launcher_audit import PUBLIC, CALLBACKS


def require(ok, message):
    if not ok:
        raise ValueError('linked launcher: ' + message)


class LauncherMachine(Machine):
    def extra_step(self, pc, state):
        op, args = self.by_pc[pc].ins[pc]
        require(len(args) == (3 if op == 'cinc' else 2), 'extra operation geometry')
        reg = re.fullmatch(r'([wx])(?:[12]?\d|30|zr)', args[0])
        require(reg is not None, 'extra operation register')
        width = 32 if reg[1] == 'w' else 64
        if op in ('rev', 'mvn', 'cinc'):
            require(re.fullmatch(r'[wx](?:[12]?\d|30|zr)', args[1]) and
                    args[1][0] == args[0][0], 'scalar extension source width')
            value = integer(state, args[1])
            if op == 'rev':
                value = int.from_bytes(value.to_bytes(width // 8, 'little'), 'big')
            elif op == 'mvn':
                # AArch64 MVN is ORN with the zero register as its first
                # operand. Admit only the unshifted scalar form actually used
                # by the linked launcher's whole-span overflow check.
                value ^= (1 << width) - 1
            else:
                require(args[2] in ('eq', 'ne'), 'CINC condition outside reviewed form')
                truth = state.truth(state.condition(args[2]))
                require(truth is not None, 'CINC unknown condition')
                value = (value + int(truth)) & ((1 << width) - 1)
            state.put(args[0], self.e._Value(width, value))
        else:
            require(op in ('ldar', 'stlr') and re.fullmatch(r'\[(?:x(?:[12]?\d|30)|sp)\]', args[1]),
                    'acquire/release address geometry')
            address, pre = state.address(args[1])
            require(not pre and address is not None and isinstance(address.expr, int),
                    'acquire/release unknown address')
            require(address.expr % (width // 8) == 0, 'acquire/release unaligned address')
            if op == 'ldar':
                state.put(args[0], state.load(address, width // 8, self.image))
            else:
                state.store(address, width // 8, state.get(args[0]))
            self.atomic_events.append({'pc': hex(pc), 'op': op, 'address': hex(address.expr),
                                       'width': width})
        return state

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.atomic_events = []


# Add only the five reviewed operations before the existing dispatch. Every
# existing instruction, budget, external-call and stack rule stays identical.
_run_source = textwrap.dedent(inspect.getsource(Machine.run))
_tree = ast.parse(_run_source)
_loops = [n for n in ast.walk(_tree) if isinstance(n, ast.For) and
          isinstance(n.iter, ast.Call) and isinstance(n.iter.func, ast.Name) and n.iter.func.id == 'range' and
          len(n.iter.args) == 1 and isinstance(n.iter.args[0], ast.Name) and n.iter.args[0].id == 'budget']
require(len(_loops) == 1, 'shared interpreter dispatch loop differs')
_loop = _loops[0]
_index = next(i for i, n in enumerate(_loop.body) if isinstance(n, ast.If) and
              ast.dump(n.test) == ast.dump(ast.parse("op == 'svc'", mode='eval').body))
_extension = ast.parse("if op in ('rev', 'mvn', 'cinc', 'ldar', 'stlr'):\n state=self.extra_step(pc,state)\n pc+=4\n continue\n").body
_loop.body[_index:_index] = _extension
ast.fix_missing_locations(_tree)
_namespace = dict(Machine.run.__globals__)
exec(compile(_tree, '<launcher-only-interpreter-extension>', 'exec'), _namespace)
LauncherMachine.run = _namespace['run']
BASE_RUN_SHA256 = hashlib.sha256(_run_source.encode()).hexdigest()

# This kernel's worker restores its frame and tail-calls terminate_self.
# Preserve the shared acyclic walker, adding only this named terminal edge;
# continue pending paths rather than accepting just the first terminal.
from santoni_gpu_control_audit import _paths as _base_paths
_paths_source = textwrap.dedent(inspect.getsource(_base_paths))
_paths_tree = ast.parse(_paths_source)
_paths_tree.body[0].name = 'launcher_paths'
_terminal_ifs = [node for node in ast.walk(_paths_tree) if isinstance(node, ast.If) and
                 ast.dump(node.test) == ast.dump(ast.parse('not successors', mode='eval').body)]
require(len(_terminal_ifs) == 1, 'shared path terminal dispatch differs')
_terminal_ifs[0].body[:0] = ast.parse("""
if op == 'b' and target in names.get('_thread_terminate_self', ()):
    require(after.get('sp') == initial.get('sp'), 'worker terminal leaves a live stack frame')
    finish(after, history)
    returns += 1
    continue
""").body
ast.fix_missing_locations(_paths_tree)
_paths_namespace = {**_base_paths.__globals__, 'require': require}
exec(compile(_paths_tree, '<launcher-only-worker-terminal>', 'exec'), _paths_namespace)
launcher_paths = _paths_namespace['launcher_paths']


class LauncherModel:
    IMAGE, KVA, OUT = 0x58000000, 0x58100000, 0x58200000
    PROC, ROOT_VNODE, ROOT_MOUNT, CHOSEN, MAP, PMAP, CTX = (
        0x58300000, 0x58310000, 0x58320000, 0x58330000, 0x58340000, 0x58350000, 0x58360000)
    MOUNT, MOUNT_DATA, VOPS, UBC = 0x58400000, 0x58410000, 0x58420000, 0x58430000
    USER_MAP, USER_SCRATCH = 0x58500000, 0x58600000
    PA = 0x92000000  # synthetic owned-memory input, never a device address
    SPAN, FILE, LAUNCH_BYTES = 20480, 16635, 88
    REQUIRED_MOUNT, KERNEL_MOUNT = 0x10000009, 0x1000
    FORBIDDEN_MOUNT = 0x54004

    def __init__(self, codes, image, names, e, probe):
        self.e, self.names, self.codes, self.image = e, names, codes, image
        self.vm = LauncherMachine(codes, image, names, e)
        self.m = self.vm.memory
        self.launch = self.address('_launch')
        segs = [s for s in image.segs if s['vmaddr'] <= self.launch and
                self.launch + self.LAUNCH_BYTES <= s['vmaddr'] + s['vmsize']]
        require(len(segs) == 1 and segs[0]['initprot'] == 3, 'launch storage extent/protection')
        self.m.map(self.launch, self.LAUNCH_BYTES)
        self.m.put(self.launch + 72, 0xffffffff)
        self.m.map(self.IMAGE, self.FILE)
        self.m.write(self.IMAGE, probe)
        self.m.readonly.append((self.IMAGE, self.IMAGE + self.FILE))
        self.m.map(self.KVA, self.SPAN, fill=0xa5)
        self.m.map(self.OUT, 4096)
        self.m.map(self.MOUNT, 4096)
        self.m.map(self.PROC, 4096)
        self.m.map(self.ROOT_VNODE, 256)
        self.options = {'santonigpu': 3, 'santonigpu_user_exec': 1, 'santonigpu_stock': 1,
            'santonigpu_pixels': 1, 'santonigpu_submit': 1, 'santonigpu_session': 1,
            'santonigpu_user': 1, 'santonigpu_user_test': 0, 'santonigpu_zap': 0,
            'santonigpu_scm': 0, 'santonigpu_cache': 0, 'launchdsuffix': 'release'}
        self.pid, self.fsname, self.page_bytes = 1, 'hfs', 4096
        self.alloc_error = self.major_error = self.node_error = self.mount_error = 0
        self.dt_error = self.pager_error = self.vnode_error = self.ubc_error = 0
        self.vnode_get_error = 0
        self.alloc_address = self.KVA
        self.missing_page = self.noncontig_page = None
        self.allocated, self.released, self.cleaned = 0, 0, 0
        self.pages, self.calls, self.events, self.view_sizes = [], [], [], {}
        self.nodes, self.adopted, self.destroyed, self.vnodes = {}, [], [], {}
        self.node_index, self.vnode_index, self.tree_alloc_error, self.adopt_error = 0, 0, 0, 0
        self.locked, self.puts, self.pagers, self.execs = False, 0, 0, []
        self.property_bytes, self.property_pointer = self.FILE, self.IMAGE
        self.nested = None
        self.user_copyouts, self.init_exec_requests, self.security_tokens = 0, [], 0
        self.copyout_error_at, self.init_exec_error = 0, 0
        self.init_vnode_vm = None
        for symbol, value, size in (('_kernel_map', self.MAP, 8), ('_kernel_pmap', self.PMAP, 8),
                ('_rootvnode', self.ROOT_VNODE, 8), ('_page_shift', 12, 4), ('_page_size', 4096, 8),
                ('_mockfs_vnodeop_p', self.VOPS, 8)):
            address = self.address(symbol)
            self.m.map(address, size); self.m.put(address, value, size)
            self.m.readonly.append((address, address + size))
        self.vm.external = self.external

    def address(self, name):
        require(len(self.names.get(name, ())) == 1, 'missing/ambiguous ' + name)
        return next(iter(self.names[name]))

    def text(self, pointer, limit=128):
        data = bytearray()
        for off in range(limit):
            byte = self.m.get(pointer + off, 1)
            if not byte:
                return data.decode()
            data.append(byte)
        raise ValueError('linked launcher: unterminated modeled string')

    def call(self, name, *args):
        self.vm.run(name, args, budget=200000)
        return integer(self.vm.state, 'x0')

    def stage(self):
        return self.m.get(self.launch + 64)

    def mount_input(self):
        self.m.put(self.launch + 48, self.KVA, 8)
        self.m.put(self.launch + 56, self.FILE)
        self.m.put(self.launch + 60, self.SPAN)
        self.m.put(self.launch + 64, 1)
        self.m.put(self.launch + 77, 1, 1)
        self.m.put(self.MOUNT + 0x70, self.REQUIRED_MOUNT)
        self.m.put(self.MOUNT + 0x74, self.KERNEL_MOUNT)

    def anchor(self, pointer):
        # XNU8796 cdevsw:13 pointers followed by d_type. All anchor methods deny.
        expected = ('_enodev',) * 7 + (None,) + ('_enodev',) * 2 + ('_enodev_strat',) + ('_enodev',) * 2
        for i, name in enumerate(expected):
            require(self.image.read(pointer + i * 8, 8) == (self.address(name) if name else 0),
                    'anchor cdevsw method differs')
        require(self.image.read(pointer + 104, 4) == 0, 'anchor cdevsw type differs')

    def external(self, target, state, probe=False, before=None):
        name = self.vm.by_address.get(target)
        allowed = ('_PE_parse_boot_argn', '_current_proc', '_proc_pid', '_vnode_mount', '_vfs_name',
            '_SecureDTLookupEntry', '_SecureDTGetProperty', '_kmem_alloc_contig_guard', '_pmap_find_phys',
            '_bzero', '_memcpy', '_memmove', '_strcmp', '_CleanPoC_DcacheRegion_Force', '_kmem_free_guard',
            '_cdevsw_add', '_devfs_make_node', '_vfs_context_kernel', '_kernel_mount', '_printf',
            '_vfs_context_iskernel', '_kalloc_type_impl_internal', '_kfree_type_impl_internal',
            '_lck_mtx_init', '_lck_mtx_destroy', '_lck_mtx_lock', '_lck_mtx_unlock',
            '_mockfs_fsnode_adopt', '_mockfs_fsnode_destroy', '_vnode_create', '_vnode_get',
            '_ubc_getobject', '_pager_map_to_phys_contiguous', '_vnode_put', '_vflush')
        init_services = ('_current_map', '_vm_map_page_size', '_mach_vm_allocate_kernel',
                         '_memorystatus_init_at_boot_snapshot', '_strlen', '_copyout',
                         '_proc_is64bit', '_set_security_token', '_memoryshot', '___mac_execve')
        if name in init_services:
            if probe: return True
            self.calls.append(name)
            return self.init_external(name, state, before)
        if name not in allowed:
            return False
        if probe:
            return True
        self.calls.append(name)
        arg = lambda i: integer(before, 'x' + str(i))
        put = lambda value, bits=64: state.put('w0' if bits == 32 else 'x0', self.e._Value(bits, value))
        if name == '_PE_parse_boot_argn':
            key, dest, size = self.text(arg(0)), arg(1), arg(2)
            require(key in self.options and size == (64 if key == 'launchdsuffix' else 4), 'boot option name/size')
            require(self.vm.STACK <= dest < dest + size <= self.vm.STACK + self.vm.STACK_SIZE,
                    'boot option storage not on stack')
            value = self.options[key]
            if value is not None:
                if isinstance(value, str):
                    data = value.encode() + b'\0'; require(len(data) <= size, 'suffix fixture oversized')
                    self.m.write(dest, data)
                else:
                    self.m.put(dest, value)
            put(int(value is not None), 32)
        elif name == '_current_proc': put(self.PROC)
        elif name == '_proc_pid':
            require(arg(0) == self.PROC, 'proc_pid identity'); put(self.pid, 32)
        elif name == '_vnode_mount':
            require(arg(0) == self.ROOT_VNODE, 'root vnode identity'); put(self.ROOT_MOUNT)
        elif name == '_vfs_name':
            require(arg(0) == self.ROOT_MOUNT, 'root mount identity')
            self.m.write(arg(1), self.fsname.encode() + b'\0'); put(0, 32)
        elif name == '_SecureDTLookupEntry':
            require(arg(0) == 0 and self.text(arg(1)) == '/chosen', 'chosen lookup')
            self.m.put(arg(2), self.CHOSEN, 8); put(0 if self.dt_error else 1, 32)
        elif name == '_SecureDTGetProperty':
            require(arg(0) == self.CHOSEN and self.text(arg(1)) == 'santoni-gpu-el0-probe', 'probe property')
            self.m.put(arg(2), self.property_pointer, 8); self.m.put(arg(3), self.property_bytes)
            put(0 if self.dt_error else 1, 32)
        elif name == '_kmem_alloc_contig_guard':
            require((arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6)) ==
                    (self.MAP, self.SPAN, 0, 0, 0, 0x8002, 3), 'owned contig allocation ABI')
            self.allocated += 1; require(self.allocated == 1, 'allocation repeated')
            put(self.alloc_error, 32); state.put('x1', self.e._Value(64, self.alloc_address if not self.alloc_error else 0))
            self.events.append('allocate')
        elif name == '_pmap_find_phys':
            kva = arg(1); require(arg(0) == self.PMAP and self.allocated == 1 and
                self.KVA <= kva < self.KVA + self.SPAN and kva % 4096 == 0, 'page ownership/range')
            off = kva - self.KVA; self.pages.append(off)
            pa = 0 if off == self.missing_page else self.PA + off + (4096 if off == self.noncontig_page else 0)
            put(pa >> 12, 32)
        elif name == '_bzero':
            self.m.write(arg(0), bytes(arg(1))); put(0, 32)
        elif name in ('_memcpy', '_memmove'):
            # LLVM lowered launch_copy's memcpy to the linked memmove entry.
            # Snapshot the source before writing so overlapping owned extents
            # retain memmove semantics. Memory enforces read/write bounds.
            self.m.write(arg(0), self.m.bytes(arg(1), arg(2))); put(arg(0))
        elif name == '_strcmp':
            put(int(self.text(arg(0)) != self.text(arg(1))), 32)
        elif name == '_CleanPoC_DcacheRegion_Force':
            require(arg(0) == self.KVA and arg(1) == self.SPAN and self.pages == list(range(0, self.SPAN, 4096)),
                    'clean before all page checks')
            require(self.m.bytes(self.KVA, self.FILE) == self.m.bytes(self.IMAGE, self.FILE) and
                    self.m.bytes(self.KVA + self.FILE, self.SPAN - self.FILE) == bytes(self.SPAN - self.FILE),
                    'copied executable/tail differs')
            self.cleaned += 1; self.events.append('clean'); put(0, 32)
        elif name == '_kmem_free_guard':
            require(arg(0) == self.MAP and arg(1) == self.KVA and arg(2) == self.SPAN and arg(3) == arg(4) == 0 and
                    self.m.get(self.launch + 40, 1) == 0, 'release after potential exposure')
            self.released += 1; self.events.append('release'); put(0, 32)
        elif name == '_cdevsw_add':
            require(arg(0) & 0xffffffff == 0xffffffff and self.cleaned == 1, 'anchor registration before clean')
            self.anchor(arg(1)); put(0xffffffff if self.major_error else 42, 32)
        elif name == '_devfs_make_node':
            require(tuple(arg(i) for i in range(5)) == (42 << 24, 0, 0, 0, 0o600) and
                    self.text(arg(5)) == 'sgpu/.mountpoint', 'anchor node ABI/path/permission')
            self.events.append('node'); put(0 if self.node_error else self.ROOT_VNODE + 128)
        elif name == '_vfs_context_kernel': put(self.CTX)
        elif name == '_kernel_mount':
            require(self.text(arg(0)) == 'mockfs' and arg(1) == arg(2) == 0 and
                    self.text(arg(3)) == '/dev/sgpu' and arg(4) == self.launch + 48 and arg(5) == 16 and
                    arg(6) == self.REQUIRED_MOUNT and arg(7) == 0 and
                    self.m.get(integer(before, 'sp'), 8) == self.CTX, 'kernel mount ABI/options')
            require(self.cleaned == 1 and not self.released and self.stage() == 1 and
                    self.m.get(self.launch + 77, 1) == 1 and self.m.get(self.launch + 40, 1) == 1 and
                    self.m.get(self.launch + 41, 1) == 1, 'mount publication/lifetime ordering')
            self.events.append('mount'); put(self.mount_error, 32)
            if self.nested is not None and not self.mount_error:
                # The modeled kernel_mount service supplies the mount object
                # and its checked flags before entering the actual callback.
                self.m.put(self.MOUNT + 0x70, arg(6))
                self.m.put(self.MOUNT + 0x74, self.KERNEL_MOUNT)
                require(self.nested() == 0, 'nested mount failed')
        elif name == '_printf': put(0, 32)
        else:
            return self.vfs_external(name, state, before)
        return True

    def init_external(self, name, state, before):
        arg = lambda i: integer(before, 'x' + str(i))
        put = lambda value, bits=64: state.put('w0' if bits == 32 else 'x0', self.e._Value(bits, value))
        if name == '_current_map': put(self.USER_MAP)
        elif name == '_vm_map_page_size':
            require(arg(0) == self.USER_MAP, 'PID1 current map identity'); put(4096, 32)
        elif name == '_mach_vm_allocate_kernel':
            require(arg(0) == self.USER_MAP and tuple(arg(i) for i in (2, 3, 4)) == (4096, 1, 0) and
                    self.m.get(arg(1), 8) == 0, 'PID1 scratch allocation ABI')
            self.m.put(arg(1), self.USER_SCRATCH, 8); put(0, 32)
        elif name == '_memorystatus_init_at_boot_snapshot': put(0, 32)
        elif name == '_strlen': put(len(self.text(arg(0)).encode()))
        elif name == '_copyout':
            destination, count = arg(1), arg(2)
            require(self.USER_SCRATCH <= destination < destination + count <= self.USER_SCRATCH + 4096,
                    'PID1 copyout escapes owned user scratch')
            self.user_copyouts += 1
            if self.user_copyouts == self.copyout_error_at:
                put(14, 32)
            else:
                self.m.write(destination, self.m.bytes(arg(0), count)); put(0, 32)
        elif name == '_proc_is64bit':
            require(arg(0) == self.PROC, 'PID1 exec process identity'); put(1, 32)
        elif name == '_set_security_token':
            require(arg(0) == self.PROC, 'PID1 root token process identity')
            self.security_tokens += 1; put(0, 32)
        elif name == '_memoryshot':
            require((arg(0), arg(1)) == (305, 0), 'compiled PID1 exec trace ABI'); put(0, 32)
        elif name == '___mac_execve':
            require(arg(0) == self.PROC, 'PID1 mac_exec process identity')
            block = arg(1)
            filename, argv, env = (self.m.get(block + offset, 8) for offset in (0, 8, 16))
            require(self.USER_SCRATCH <= filename < self.USER_SCRATCH + 4096 and
                    argv % 8 == 0 and self.USER_SCRATCH <= argv < argv + 24 <= self.USER_SCRATCH + 4096 and
                    env == 0 and self.m.get(block + 24, 8) == 0 and
                    self.m.get(argv, 8) == filename and self.m.get(argv + 16, 8) == 0,
                    'PID1 exec copied filename/argv/env ABI')
            path, second = self.text(filename), self.m.get(argv + 8, 8)
            arguments = [path] + ([self.text(second)] if second else [])
            require(arguments[1:] == (['-s'] if self.m.get(self.address('_boothowto')) & 2 else []),
                    'PID1 exec loses single-user argument')
            require(path in ('/dev/sgpu/sbin/launchd', '/sbin/launchd'), 'PID1 unexpected selected init')
            error = 0
            if path == '/dev/sgpu/sbin/launchd':
                require(self.init_vnode_vm is not None and self.stage() == 1 and
                        self.m.get(self.launch + 78, 1) == 1, 'PID1 wrapper exec before publication')
                root = self.m.get(self.MOUNT_DATA + 16, 8)
                file = self.m.get(root + 48, 8)
                error = self.init_vnode_vm.run('_mockfs_fsnode_vnode', (file, self.OUT), budget=200000).expr
                if not error: error = self.init_exec_error
            self.init_exec_requests.append({'path': path, 'argv': arguments, 'result': error})
            put(error, 32)
        else:
            raise ValueError('linked launcher: unreviewed PID1 service ' + name)
        return True

    def vfs_external(self, name, state, before):
        arg = lambda i: integer(before, 'x' + str(i))
        put = lambda value, bits=64: state.put('w0' if bits == 32 else 'x0', self.e._Value(bits, value))
        if name == '_vfs_context_iskernel':
            put(int(arg(0) == self.CTX), 32)
        elif name == '_kalloc_type_impl_internal':
            labels = [n for n, values in self.names.items() if arg(0) in values and '.kalloc_type_view_' in n]
            require(len(labels) == 1, 'typed allocation identity')
            label = labels[0]; size = self.image.read(arg(0) + 44, 4)
            # XNU8796 struct zone_view is32 bytes; kalloc_type_view then has
            # signature8,flags4,size4. Exact compiled type sizes are also pinned.
            if label.startswith('_mockfs_santoni_mount.'):
                require(size == 72 and arg(1) == 4 and not self.locked, 'mount typed allocation ABI')
                if self.tree_alloc_error:
                    put(0); return True
                address = self.MOUNT_DATA
            else:
                require(label.startswith('_mockfs_fsnode_create.') and size == 56 and arg(1) == 0x8004,
                        'fsnode typed allocation ABI')
                self.node_index += 1
                require(self.node_index <= 3, 'fsnode count exceeds owned tree')
                address = self.MOUNT_DATA + 0x100 + self.node_index * 0x100
                self.nodes[address] = size
            self.view_sizes[label] = size
            self.m.map(address, size); put(address)
        elif name == '_kfree_type_impl_internal':
            size = self.image.read(arg(0) + 44, 4)
            require(size == 72 and arg(1) == self.MOUNT_DATA and not self.locked and
                    self.m.get(self.MOUNT + 0x8f8, 8) == 0, 'mount metadata release ordering')
            self.events.append('metadata-free'); put(0, 32)
        elif name in ('_lck_mtx_init', '_lck_mtx_destroy'):
            require(arg(0) == self.MOUNT_DATA and not self.locked, 'mount mutex init/destroy identity')
            if name == '_lck_mtx_init': require(arg(2) == 0, 'mutex attributes')
            self.events.append(name); put(0, 32)
        elif name == '_lck_mtx_lock':
            require(arg(0) == self.MOUNT_DATA and not self.locked, 'mutex double/wrong lock')
            self.locked = True; self.events.append('lock'); put(0, 32)
        elif name == '_lck_mtx_unlock':
            require(arg(0) == self.MOUNT_DATA and self.locked, 'mutex wrong/unheld unlock')
            self.locked = False; self.events.append('unlock'); put(0, 32)
        elif name == '_mockfs_fsnode_adopt':
            parent, child = arg(0), arg(1)
            require(parent in self.nodes and child in self.nodes and self.m.get(child + 32, 8) == 0,
                    'tree adopt ownership')
            self.adopted.append((parent, child))
            if self.adopt_error == len(self.adopted):
                put(22, 32); return True
            self.m.put(child + 32, parent, 8)
            slot = 40 if self.m.get(parent + 40, 8) == 0 else 48
            require(self.m.get(parent + slot, 8) == 0, 'tree adopt overwrites child')
            self.m.put(parent + slot, child, 8); put(0, 32)
        elif name == '_mockfs_fsnode_destroy':
            def destroy(node):
                require(node in self.nodes and node not in self.destroyed and self.m.get(node + 24, 8) == 0,
                        'tree destroy live/unknown/duplicate node')
                for slot in (40, 48):
                    child = self.m.get(node + slot, 8)
                    if child: destroy(child)
                self.destroyed.append(node)
            destroy(arg(0)); put(0, 32)
        elif name == '_vnode_create':
            require(arg(0) == 0 and arg(1) == 88 and self.locked, 'vnode_create ABI/mutex')
            p, out = arg(2), arg(3)
            node = self.m.get(p + 32, 8)
            require(node in self.nodes and out == node + 24 and self.m.get(p, 8) == self.MOUNT,
                    'vnode_create node/mount/output')
            kind = self.m.get(node + 8, 1)
            require(self.m.get(p + 8) == (1 if kind == 2 else 2) and self.text(self.m.get(p + 16, 8)) == 'mockfs' and
                    self.m.get(p + 40, 8) == self.VOPS and self.m.get(p + 48) == int(kind == 0) and
                    self.m.get(p + 52) == self.m.get(p + 56) == 0 and
                    self.m.get(p + 64, 8) == (self.FILE if kind == 2 else 0) and
                    self.m.get(p + 72, 8) == 0 and self.m.get(p + 80) == 3,
                    'vnode_create type/file EOF/flags')
            if self.vnode_error:
                put(self.vnode_error, 32); return True
            self.vnode_index += 1
            vnode = self.MOUNT_DATA + 0x1000 + self.vnode_index * 0x1000
            self.m.map(vnode, 256); self.m.put(vnode + 0xe0, node, 8)
            self.vnodes[vnode] = {'node': node, 'refs': 1}
            self.m.put(out, vnode, 8); put(0, 32)
        elif name == '_vnode_get':
            require(arg(0) in self.vnodes and self.locked, 'vnode_get identity/mutex')
            if not self.vnode_get_error:
                self.vnodes[arg(0)]['refs'] += 1
            put(self.vnode_get_error, 32)
        elif name == '_ubc_getobject':
            require(arg(0) in self.vnodes and arg(1) == 0 and self.locked, 'UBC identity/flags/mutex')
            put(0 if self.ubc_error else self.UBC)
        elif name == '_pager_map_to_phys_contiguous':
            require(arg(0) == self.UBC and arg(1) == 0 and arg(2) == self.KVA and arg(3) == self.SPAN and
                    self.locked and self.allocated == 1 and self.cleaned == 1 and not self.released,
                    'pager receives KVA/whole-page span before ownership/clean')
            self.pagers += 1; self.events.append('pager'); put(self.pager_error, 32)
        elif name == '_vnode_put':
            require(arg(0) in self.vnodes and self.vnodes[arg(0)]['refs'] > 0 and not self.locked,
                    'vnode_put before mutex unlock/invalid iocount')
            self.vnodes[arg(0)]['refs'] -= 1; self.puts += 1; self.events.append('vnode-put'); put(0, 32)
        elif name == '_vflush':
            require(arg(0) == self.MOUNT and not self.locked, 'vflush mount/lock')
            self.events.append('vflush'); put(16, 32)
        else:
            raise ValueError('linked launcher: unfinished VFS contract ' + name)
        return True

    def summarize(self):
        return {'stage': self.stage(), 'errno': self.m.get(self.launch + 68),
            'allocated': self.allocated, 'released': self.released, 'cleaned': self.cleaned,
            'page_offsets': self.pages, 'events': self.events, 'typed_sizes': self.view_sizes,
            'pager_calls': self.pagers, 'vnode_puts': self.puts, 'atomic_events': self.vm.atomic_events,
            'CPU_backing_retained': bool(self.m.get(self.launch + 41, 1)),
            'decoded_instruction_addresses': len(self.vm.visited),
            'service_contracts_simulated': True, 'hardware_verified': False}


def make_model(codes, image, names, e, probe):
    return LauncherModel(codes, image, names, e, probe)


def audit_options(codes, image, names, e, probe):
    cases = [('valid', None, None)]
    for key in ('santonigpu', 'santonigpu_user_exec', 'santonigpu_stock', 'santonigpu_pixels',
                'santonigpu_submit', 'santonigpu_session', 'santonigpu_user', 'santonigpu_user_test',
                'santonigpu_zap', 'santonigpu_scm', 'santonigpu_cache'):
        for value in (None, 0, 1, 2, 3, 4, 0xffffffff):
            cases.append((key + '=' + str(value), key, value))
    cases += [('suffix=' + str(v), 'launchdsuffix', v) for v in (None, '', 'release', 'debug', 'release-extra')]
    results = []
    for label, key, value in cases:
        m = make_model(codes, image, names, e, probe)
        if key: m.options[key] = value
        before = m.m.bytes(m.launch, m.LAUNCH_BYTES)
        values = m.options
        off = not (values['santonigpu_user_exec'] or 0)
        valid = values['santonigpu_user_exec'] == 1 and values['santonigpu'] == 3 and all(
            values[n] == 1 for n in ('santonigpu_stock', 'santonigpu_pixels', 'santonigpu_submit',
                                    'santonigpu_session', 'santonigpu_user')) and not any(
            values[n] for n in ('santonigpu_user_test', 'santonigpu_zap', 'santonigpu_scm', 'santonigpu_cache'))
        valid = valid and values['launchdsuffix'] == 'release'
        result = m.call('_launch_options', values['santonigpu'] or 0)
        require(result == (0 if off else 1 if valid else 2), 'option role differs: ' + label)
        require(m.m.bytes(m.launch, m.LAUNCH_BYTES) == before and not m.allocated and
                set(m.calls) <= {'_PE_parse_boot_argn', '_strcmp'}, 'option parser mutates/publishes: ' + label)
        results.append({'case': label, 'role': result, 'calls': len(m.calls)})
    return {'success': True, 'cases': results, 'scope': 'exact compiled option/role/suffix matrix; simulated boot parser',
            'hardware_verified': False}


def audit_image(codes, image, names, e, probe, probe_build, *, saved_cases=None, save_case=None):
    # The retained build record identifies _start. The linked text base is
    # not necessarily the process entry PC, so never infer it from code start.
    require(isinstance(probe_build, dict) and
            probe_build.get('macho_sha256') == hashlib.sha256(probe).hexdigest() and
            probe_build.get('macho_bytes') == len(probe), 'probe build/image binding differs')
    expected_entry = probe_build.get('entry_vma')
    require(type(expected_entry) is int and 0 < expected_entry < (1 << 64),
            'probe build entry missing or invalid')
    cases = ('valid', 'null', 'short', 'oversized', 'cpu', 'writable-text', 'bad-entry', 'bad-thread', 'signature')
    results = []
    for case in cases:
        if saved_cases is not None and case in saved_cases:
            results.append(saved_cases[case])
            continue
        m = make_model(codes, image, names, e, probe)
        data, size = m.IMAGE, m.FILE
        if case == 'null': data = 0
        if case == 'short': size = 31
        if case == 'oversized': size = 32769
        if case in ('cpu', 'writable-text', 'bad-entry', 'bad-thread', 'signature'):
            readonly, m.m.readonly = m.m.readonly, []
            if case == 'cpu': m.m.put(m.IMAGE + 4, 0x01000007)
            if case == 'writable-text':
                m.m.put(m.IMAGE + 160, 7); m.m.put(m.IMAGE + 164, 7)
            if case == 'bad-entry': m.m.put(m.IMAGE + 600, 0x100004000, 8)
            if case == 'bad-thread': m.m.put(m.IMAGE + 344, 1, 8)
            if case == 'signature': m.m.put(m.IMAGE + 16384, m.m.get(m.IMAGE + 16384, 1) ^ 1, 1)
            m.m.readonly = readonly
        m.m.put(m.OUT, 0xa505a505a505a505, 8)
        result = m.call('_sgpu_launch_image', data, size, m.OUT)
        require(result == int(case == 'valid'), 'structural image result: ' + case)
        require(m.m.get(m.OUT, 8) == (expected_entry if result else 0xa505a505a505a505),
                'returned entry differs from build record or rejected intake changes output')
        require(not m.calls and not m.allocated, 'structural intake invokes service/allocation')
        results.append({'case': case, 'accepted': result, 'instruction_addresses': len(m.vm.visited)})
        if save_case is not None:
            save_case(results[-1])
    return {'success': True, 'cases': results, 'entry_vma': expected_entry,
            'probe_build_sha256': hashlib.sha256(json.dumps(probe_build, sort_keys=True).encode()).hexdigest(),
            'scope': 'structural Mach-O intake, not signature authenticity',
            'hardware_verified': False}


def audit_prepare(codes, image, names, e, probe, *, saved_cases=None, save_case=None):
    cases = ('valid', 'dt-missing', 'not-hfs', 'not-pid1', 'allocation', 'unaligned',
             'missing-first', 'missing-last', 'noncontig', 'major', 'node', 'mount')
    results = []
    for case in cases:
        if saved_cases is not None and case in saved_cases:
            results.append(saved_cases[case])
            continue
        m = make_model(codes, image, names, e, probe)
        if case == 'dt-missing': m.dt_error = 1
        if case == 'not-hfs': m.fsname = 'mockfs'
        if case == 'not-pid1': m.pid = 7
        if case == 'allocation': m.alloc_error = 3
        if case == 'unaligned': m.alloc_address = m.KVA + 1
        if case == 'missing-first': m.missing_page = 0
        if case == 'missing-last': m.missing_page = 16384
        if case == 'noncontig': m.noncontig_page = 4096
        if case == 'major': m.major_error = 1
        if case == 'node': m.node_error = 1
        if case == 'mount': m.mount_error = 5
        result = m.call('_santoni_gpu_user_launch_path')
        require(bool(result) == (case == 'valid'), 'prepare result differs: ' + case)
        if result:
            require(m.text(result) == '/dev/sgpu/sbin/launchd' and m.stage() == 1 and
                    m.m.get(m.launch + 42, 1) == 1 and m.m.get(m.launch + 78, 1) == 1 and
                    m.allocated == m.cleaned == 1 and m.released == 0, 'prepared path/lifetime/state')
            count = len(m.calls)
            require(m.call('_santoni_gpu_user_launch_path') == 0 and m.allocated == 1,
                    'second path attempt allocates/publishes again')
            require(not any(n in m.calls[count:] for n in ('_kmem_alloc_contig_guard', '_SecureDTLookupEntry', '_kernel_mount')),
                    'second path attempt repeats intake/mount')
        else:
            require(m.stage() == 3, 'prepare failure loses failed stage')
        exposed = case in ('valid', 'major', 'node', 'mount')
        require(m.m.get(m.launch + 40, 1) == int(exposed) and m.released == int(
                case in ('missing-first', 'missing-last', 'noncontig')), 'exposure/free classification')
        require(bool(m.m.get(m.launch + 41, 1)) == (exposed or case == 'unaligned'), 'retention classification')
        if exposed: require(m.cleaned == 1 and m.pages == list(range(0, m.SPAN, 4096)), 'publish before page/clean checks')
        results.append({'case': case, **m.summarize()})
        if save_case is not None:
            save_case(results[-1])
    return {'success': True, 'cases': results, 'scope': 'actual prepare/allocator/PA/copy/anchor/mount call wiring; services modeled',
            'hardware_verified': False, 'single_call_latency_bounded': False}


def audit_mount(codes, image, names, e, probe, *, saved_cases=None, save_case=None):
    cases = ('valid', 'context', 'kernel-flag', 'writable', 'suid', 'noexec', 'update', 'reload', 'root',
             'device', 'forged', 'outside', 'published', 'stage', 'bad-size', 'metadata-alloc', 'adopt1', 'adopt2')
    results = []
    for case in cases:
        if saved_cases is not None and case in saved_cases:
            results.append(saved_cases[case])
            continue
        m = make_model(codes, image, names, e, probe); m.mount_input()
        ctx, dev, data = m.CTX, 0, m.launch + 48
        if case == 'context': ctx += 8
        if case == 'kernel-flag': m.m.put(m.MOUNT + 0x74, 0)
        if case == 'writable': m.m.put(m.MOUNT + 0x70, m.REQUIRED_MOUNT & ~1)
        if case == 'suid': m.m.put(m.MOUNT + 0x70, m.REQUIRED_MOUNT & ~8)
        if case in ('noexec', 'update', 'reload', 'root'):
            m.m.put(m.MOUNT + 0x70, m.REQUIRED_MOUNT | {'noexec': 4, 'update': 0x10000, 'reload': 0x40000, 'root': 0x4000}[case])
        if case == 'device': dev = m.ROOT_VNODE
        if case == 'forged': data = m.OUT
        if case == 'outside': m.m.put(m.launch + 77, 0, 1)
        if case == 'published': m.m.put(m.launch + 78, 1, 1)
        if case == 'stage': m.m.put(m.launch + 64, 2)
        if case == 'bad-size': m.m.put(m.launch + 60, 16635)
        if case == 'metadata-alloc': m.tree_alloc_error = 1
        if case in ('adopt1', 'adopt2'): m.adopt_error = 1 if case == 'adopt1' else 2
        result = m.call('_mockfs_santoni_mount', m.MOUNT, dev, data, ctx)
        require(result == (0 if case == 'valid' else 12 if case == 'metadata-alloc' else 22), 'mount return: ' + case)
        if case == 'valid':
            root = m.m.get(m.MOUNT_DATA + 16, 8)
            require(m.m.get(m.MOUNT + 0x8f8, 8) == m.MOUNT_DATA and root in m.nodes and
                    m.m.get(root + 8, 1) == 0 and len(m.nodes) == 3 and len(m.adopted) == 2 and not m.destroyed,
                    'mount tree/root publication')
            file = m.m.get(root + 48, 8)
            require(m.m.get(file, 8) == m.FILE and m.m.get(m.MOUNT_DATA + 48, 8) == m.KVA and
                    m.m.get(m.MOUNT_DATA + 56) == m.FILE and m.m.get(m.MOUNT_DATA + 60) == m.SPAN,
                    'mount conflates file EOF/backing or loses KVA')
        elif case in ('adopt1', 'adopt2'):
            require(len(m.nodes) == len(m.destroyed) == 3 and len(set(m.destroyed)) == 3 and
                    m.m.get(m.MOUNT + 0x8f8, 8) == 0 and 'metadata-free' in m.events and not m.released,
                    'mount cleanup ownership/CPU backing')
        else:
            require(not m.nodes and not m.released and m.m.get(m.MOUNT + 0x8f8, 8) == 0,
                    'invalid mount allocates/publishes tree')
        require(not m.locked, 'mount retains mutex')
        results.append({'case': case, 'result': result, 'node_count': len(m.nodes), 'destroyed': len(m.destroyed),
                        'typed_sizes': m.view_sizes, 'events': m.events})
        if save_case is not None:
            save_case(results[-1])
    return {'success': True, 'cases': results, 'scope': 'actual mount/constructor/cleanup wiring; tree adopt/destroy modeled',
            'hardware_verified': False}


def prepared_model(codes, image, names, e, probe):
    """New component setup includes the actual mount body on a distinct stack."""
    m = make_model(codes, image, names, e, probe)
    child = LauncherMachine(codes, image, names, e, memory=m.m, stack_base=0x50040000)
    child.external = m.external
    m.nested = lambda: child.run('_mockfs_santoni_mount',
        (m.MOUNT, 0, m.launch + 48, m.CTX), budget=200000).expr
    require(m.call('_santoni_gpu_user_launch_path') != 0 and m.stage() == 1 and
            m.m.get(m.MOUNT + 0x8f8, 8) == m.MOUNT_DATA, 'component preparation/mount setup')
    m.nested_vm = child
    return m


def audit_pager(codes, image, names, e, probe, *, saved_cases=None, save_case=None):
    cases = ('valid', 'vnode-failure', 'ubc-null', 'pager-failure', 'bad-page', 'bad-span',
             'bad-eof', 'prelatched', 'null-node', 'null-output', 'vnode-get-failure',
             'published-unmount', 'unpublished-flush-failure', 'readonly-attrs')
    results = []
    for case in cases:
        if saved_cases is not None and case in saved_cases:
            results.append(saved_cases[case]); continue
        m = prepared_model(codes, image, names, e, probe)
        root = m.m.get(m.MOUNT_DATA + 16, 8)
        file = m.m.get(root + 48, 8)
        sentinel = 0xa505a505a505a505
        m.m.put(m.OUT, sentinel, 8)
        node, out = file, m.OUT
        if case == 'vnode-failure': m.vnode_error = 12
        if case == 'ubc-null': m.ubc_error = 1
        if case == 'pager-failure': m.pager_error = 3
        if case == 'bad-page':
            readonly, m.m.readonly = m.m.readonly, []
            m.m.put(m.address('_page_size'), 16384, 8)
            m.m.readonly = readonly
        if case == 'bad-span': m.m.put(m.MOUNT_DATA + 60, m.FILE)
        if case == 'bad-eof': m.m.put(m.MOUNT_DATA + 56, m.FILE - 1)
        if case == 'prelatched': m.m.put(m.MOUNT_DATA + 64, 1)
        if case == 'null-node': node = 0
        if case == 'null-output': out = 0
        result = m.call('_mockfs_fsnode_vnode', node, out)
        errno = 22 if case in ('null-node', 'null-output') else 12 if case == 'vnode-failure' else (
            5 if case in ('ubc-null', 'pager-failure', 'bad-page', 'bad-span', 'bad-eof', 'prelatched') else 0)
        require(result == errno and not m.locked and not m.released and m.cleaned == 1 and
                m.m.get(m.launch + 41, 1) == 1, 'pager outcome/retention/unlock: ' + case)
        if errno:
            require(m.m.get(m.OUT, 8) == sentinel, 'failed vnode creation changes output')
            if errno == 5:
                require(m.m.get(m.MOUNT_DATA + 64) == 1, 'private pager failure latch lost')
                count = (len(m.calls), m.pagers, m.puts, m.vnode_index)
                require(m.call('_mockfs_fsnode_vnode', file, m.OUT) == 5 and
                        (m.pagers, m.puts, m.vnode_index) == count[1:] and
                        m.calls[count[0]:] == ['_lck_mtx_lock', '_lck_mtx_unlock'],
                        'latched failure retries pager/vnode or retains mutex')
                require(m.puts == int(case != 'prelatched'), 'failed creation iocount drop differs')
        else:
            vnode = m.m.get(m.OUT, 8)
            require(vnode in m.vnodes and m.pagers == 1 and m.puts == 0 and
                    m.vnodes[vnode]['refs'] == 1 and m.m.get(m.MOUNT_DATA + 64) == 0,
                    'successful private-pager vnode identity/iocount')
            if case in ('valid', 'vnode-get-failure'):
                m.m.put(m.OUT, sentinel, 8)
                if case == 'vnode-get-failure': m.vnode_get_error = 16
                require(m.call('_mockfs_fsnode_vnode', file, m.OUT) == m.vnode_get_error and
                        m.pagers == 1 and m.m.get(m.OUT, 8) == (sentinel if m.vnode_get_error else vnode) and
                        m.vnodes[vnode]['refs'] == (1 if m.vnode_get_error else 2),
                        'cached vnode retries pager or loses get error/iocount')
            if case in ('published-unmount', 'unpublished-flush-failure'):
                count = len(m.calls)
                if case == 'unpublished-flush-failure': m.m.put(m.launch + 78, 0, 1)
                require(m.call('_mockfs_unmount', m.MOUNT, 0, m.CTX) == 16 and not m.released and
                        m.m.get(m.MOUNT + 0x8f8, 8) == m.MOUNT_DATA and not m.destroyed and
                        m.calls[count:].count('_vflush') == int(case == 'unpublished-flush-failure'),
                        'published mount or failed flush tears down CPU backing/tree')
            if case == 'readonly-attrs':
                attrs = m.OUT + 128
                m.m.write(attrs, b'\xa5' * 448)
                m.m.put(attrs - 8, sentinel, 8); m.m.put(attrs + 448, sentinel, 8)
                m.m.put(m.OUT + 8, vnode, 8); m.m.put(m.OUT + 16, attrs, 8)
                require(m.call('_mockfs_getattr', m.OUT) == 0 and
                        m.m.get(attrs + 76, 2) == 0o500 and
                        m.m.get(attrs + 64) == m.m.get(attrs + 68) == 0 and
                        all(m.m.get(attrs + offset, 8) == m.FILE for offset in (32, 40, 48, 56)) and
                        m.m.get(attrs - 8, 8) == m.m.get(attrs + 448, 8) == sentinel,
                        'regular executable mode/ownership/EOF/attribute bounds')
        require(m.pagers == int(case in ('valid', 'pager-failure', 'vnode-get-failure',
                                        'published-unmount', 'unpublished-flush-failure', 'readonly-attrs')),
                'invalid private pager reaches a mapping service')
        results.append({'case': case, 'result': result, 'failure_latched': m.m.get(m.MOUNT_DATA + 64),
                        'nested_mount_instructions': len(m.nested_vm.visited), **m.summarize()})
        if save_case is not None: save_case(results[-1])
    return {'success': True, 'cases': results, 'scope': 'linked mount/vnode/private-pager/attributes/unmount; XNU services modeled',
            'hardware_verified': False}


def audit_exec(codes, image, names, e, probe, *, saved_cases=None, save_case=None):
    from itertools import product
    results = []
    for stage, attempted, ready, mounted, error, prior_error in product(range(4), (0, 1), (0, 1), (0, 1), (0, 5), (0, 19)):
        label = f's{stage}-a{attempted}-r{ready}-m{mounted}-e{error}-p{prior_error}'
        if saved_cases is not None and label in saved_cases:
            results.append(saved_cases[label]); continue
        m = make_model(codes, image, names, e, probe)
        for off, value, size in ((64, stage, 4), (68, prior_error, 4), (76, attempted, 1),
                                 (42, ready, 1), (78, mounted, 1), (41, 1, 1)):
            m.m.put(m.launch + off, value, size)
        accepted = stage == 1 and attempted and ready and mounted
        expected_stage = (3 if error else 2) if accepted else stage
        expected_error = error if accepted and error and not prior_error else prior_error
        m.call('_santoni_gpu_user_launch_exec_result', error)
        require(m.stage() == expected_stage and m.m.get(m.launch + 68) == expected_error and
                m.calls == (['_printf'] if accepted else []) and not m.released and
                m.m.get(m.launch + 41, 1) == 1, 'exec result guard/first errno: ' + label)
        frozen = m.m.bytes(m.launch, m.LAUNCH_BYTES)
        count = len(m.calls)
        if accepted:
            m.call('_santoni_gpu_user_launch_exec_result', 0 if error else 5)
            require(m.m.bytes(m.launch, m.LAUNCH_BYTES) == frozen and len(m.calls) == count,
                    'second exec notification changes first terminal result')
        results.append({'case': label, 'accepted': bool(accepted), 'expected_stage': expected_stage,
                        'expected_errno': expected_error, **m.summarize()})
        if save_case is not None: save_case(results[-1])
    return {'success': True, 'cases': results, 'scope': 'linked exec-result guards, immutable terminal stage/first errno; storage inputs modeled',
            'hardware_verified': False}


def audit_worker(codes, image, names, e, probe, *, saved_cases=None, save_case=None):
    results = []
    cases = ('off', 'invalid-mode', 'invalid-flag', 'new', 'preparing', 'ready', 'failed', 'suffix',
             'reject-before-delay', 'reject-after-delay')
    for case in cases:
        if saved_cases is not None and case in saved_cases:
            results.append(saved_cases[case]); continue
        m = make_model(codes, image, names, e, probe)
        mode = 3
        if case == 'off': m.options['santonigpu_user_exec'] = 0
        if case in ('invalid-flag', 'reject-before-delay'): m.options['santonigpu_user_exec'] = 2
        if case == 'invalid-mode': mode = 2
        if case == 'suffix': m.options['launchdsuffix'] = 'debug'
        stage = {'new': 0, 'preparing': 1, 'ready': 2, 'failed': 3, 'reject-after-delay': 1}.get(case, 0)
        m.m.put(m.launch + 64, stage)
        frozen = m.m.bytes(m.launch, m.LAUNCH_BYTES)
        allowed = case not in ('invalid-mode', 'invalid-flag', 'suffix', 'reject-before-delay')
        ready = case in ('off', 'ready')
        options_result = m.call('_santoni_gpu_user_launch_options_ok', mode)
        ready_result = m.call('_santoni_gpu_user_launch_worker_ready', mode)
        require(options_result == int(allowed) and ready_result == int(ready) and
                m.m.bytes(m.launch, m.LAUNCH_BYTES) == frozen and
                set(m.calls) <= {'_PE_parse_boot_argn', '_strcmp'} and not m.allocated,
                'compiled worker guard result/storage/scope: ' + case)
        paths = None
        if case.startswith('reject-'):
            initial = e._initial('_sgpu_kernel_thread')
            initial.store(e._Value(64, next(iter(names['_sg'])) + 84), 4, e._Value(32, 3))
            def call(pc, target, before, after, history):
                name = m.vm.by_address.get(target)
                if name in (PUBLIC[0], PUBLIC[1]):
                    require(before.get('w0') == e._Value(32, 3), 'worker launcher guard mode')
                    after.put('w0', e._Value(32, options_result if name == PUBLIC[0] else ready_result))
                else:
                    require(name in ('_printf', '_thread_terminate_self', '_clock_interval_to_deadline',
                                     '_assert_wait_deadline', '_thread_block'), 'refused worker reaches ' + str(name))
            def finish(state, history):
                count = lambda name: sum(address in names[name] for address in history)
                require(count(PUBLIC[0]) == 1 and count(PUBLIC[1]) == int(allowed) and
                        count('_thread_terminate_self') == 1 and
                        count('_clock_interval_to_deadline') == int(allowed),
                        'worker refusal/termination/delay ordering')
            paths = launcher_paths(codes['_sgpu_kernel_thread'], image, names, e, initial, call, finish)
        results.append({'case': case, 'mode': mode, 'stage_input': stage, 'options_ok': options_result,
                        'worker_ready': ready_result, 'refusal_paths': paths, **m.summarize()})
        if save_case is not None: save_case(results[-1])
    return {'success': True, 'cases': results, 'scope': 'actual public launcher guards and compiled worker refusal/delay edges',
            'hardware_verified': False}


def audit_pid1(codes, image, names, e, probe, *, saved_cases=None, save_case=None):
    cases = ('valid', 'single-user', 'copy-path', 'copy-argv', 'exec-failure', 'pager-failure',
             'not-hfs', 'bad-role', 'dt-missing', 'allocation')
    results = []
    for case in cases:
        if saved_cases is not None and case in saved_cases:
            results.append(saved_cases[case]); continue
        m = make_model(codes, image, names, e, probe)
        m.m.map(m.USER_SCRATCH, 4096, fill=0xa5)
        m.m.map(m.address('_boothowto'), 4)
        m.m.put(m.address('_boothowto'), 2 if case == 'single-user' else 0)
        m.m.readonly.append((m.address('_boothowto'), m.address('_boothowto') + 4))
        child = LauncherMachine(codes, image, names, e, memory=m.m, stack_base=0x50040000)
        child.external = m.external
        m.nested = lambda: child.run('_mockfs_santoni_mount',
            (m.MOUNT, 0, m.launch + 48, m.CTX), budget=200000).expr
        m.init_vnode_vm = child
        if case == 'copy-path': m.copyout_error_at = 1
        if case == 'copy-argv': m.copyout_error_at = 2
        if case == 'exec-failure': m.init_exec_error = 8
        if case == 'pager-failure': m.pager_error = 3
        if case == 'not-hfs': m.fsname = 'mockfs'
        if case == 'bad-role': m.options['santonigpu_user_exec'] = 2
        if case == 'dt-missing': m.dt_error = 1
        if case == 'allocation': m.alloc_error = 3
        m.call('_load_init_program', m.PROC)
        success = case in ('valid', 'single-user')
        reached_exec = case in ('valid', 'single-user', 'exec-failure', 'pager-failure')
        expected_paths = (['/dev/sgpu/sbin/launchd'] if reached_exec else []) + ([] if success else ['/sbin/launchd'])
        require([request['path'] for request in m.init_exec_requests] == expected_paths and
                m.stage() == (2 if success else 3) and
                m.security_tokens == len(expected_paths) and not m.released and not m.locked,
                'PID1 wrapper/fallback/terminal/credentials order: ' + case)
        exposed = case in ('valid', 'single-user', 'copy-path', 'copy-argv', 'exec-failure', 'pager-failure')
        require(bool(m.m.get(m.launch + 41, 1)) == exposed and m.allocated == int(exposed or case == 'allocation') and
                m.cleaned == int(exposed) and
                m.call('_santoni_gpu_user_launch_worker_ready', 3) == int(success),
                'PID1 fallback frees exposed backing or admits failed worker: ' + case)
        expected_errno = 0 if success else 14 if case.startswith('copy-') else 8 if case == 'exec-failure' else (
            5 if case == 'pager-failure' else 2 if case == 'dt-missing' else 22)
        require(m.m.get(m.launch + 68) == expected_errno, 'PID1 first exec/preparation errno differs')
        results.append({'case': case, 'exec_requests': m.init_exec_requests, 'copyouts': m.user_copyouts,
                        'security_token_calls': m.security_tokens, 'nested_vfs_instructions': len(child.visited),
                        'real_EL0_or_launchd_execution_proven': False, **m.summarize()})
        if save_case is not None: save_case(results[-1])
    return {'success': True, 'cases': results, 'scope': 'actual PID1 wrapper/copyout/exec-result/fallback/worker linkage; BSD exec/VFS contracts simulated',
            'hardware_verified': False}


def audit_attributes(codes, image, names, e, probe, *, saved_cases=None, save_case=None):
    label = 'regular-file-supported-root-attributes'
    if saved_cases is not None and label in saved_cases:
        return {'success': True, 'cases': [saved_cases[label]], 'hardware_verified': False}
    m = prepared_model(codes, image, names, e, probe)
    root = m.m.get(m.MOUNT_DATA + 16, 8)
    file = m.m.get(root + 48, 8)
    require(m.call('_mockfs_fsnode_vnode', file, m.OUT) == 0, 'attribute vnode preparation')
    vnode = m.m.get(m.OUT, 8)
    attrs, sentinel = 0x58700000, 0xa505a505a505a505
    # The retained XNU8796 vnode.h puts iosize at64, UID68, GID72,
    # mode76. The linked initializer's exact zeroed extent is440 bytes.
    m.m.map(attrs - 8, 456, fill=0xa5)
    m.m.put(attrs - 8, sentinel, 8); m.m.put(attrs + 440, sentinel, 8)
    m.m.put(m.OUT + 8, vnode, 8); m.m.put(m.OUT + 16, attrs, 8)
    require(m.call('_mockfs_getattr', m.OUT) == 0 and m.m.get(attrs + 76, 2) == 0o500 and
            m.m.get(attrs + 68) == m.m.get(attrs + 72) == 0 and
            m.m.get(attrs, 8) & 0x380 == 0x380 and m.m.get(attrs + 8, 8) == 0 and
            all(m.m.get(attrs + offset, 8) == m.FILE for offset in (32, 40, 48, 56)) and
            m.m.get(attrs - 8, 8) == m.m.get(attrs + 440, 8) == sentinel,
            'executable UID/GID/mode supported bits/EOF/attribute extent')
    case = {'case': label, 'mode': 0o500, 'uid': 0, 'gid': 0, 'uid_gid_mode_supported': True,
            'attribute_bytes': 440, 'file_bytes': m.FILE, **m.summarize()}
    if save_case is not None: save_case(case)
    return {'success': True, 'cases': [case], 'scope': 'linked regular executable attributes and exact guarded ABI extent',
            'hardware_verified': False}


COMPONENTS = ('options', 'image', 'prepare', 'mount', 'pager', 'exec', 'worker', 'pid1', 'attributes')
from itertools import product
CASE_NAMES = {
    'options': {'valid', *(key + '=' + str(value) for key in (
        'santonigpu', 'santonigpu_user_exec', 'santonigpu_stock', 'santonigpu_pixels', 'santonigpu_submit',
        'santonigpu_session', 'santonigpu_user', 'santonigpu_user_test', 'santonigpu_zap', 'santonigpu_scm',
        'santonigpu_cache') for value in (None, 0, 1, 2, 3, 4, 0xffffffff)),
        *('suffix=' + str(value) for value in (None, '', 'release', 'debug', 'release-extra'))},
    'image': set(('valid', 'null', 'short', 'oversized', 'cpu', 'writable-text', 'bad-entry', 'bad-thread', 'signature')),
    'prepare': set(('valid', 'dt-missing', 'not-hfs', 'not-pid1', 'allocation', 'unaligned',
                    'missing-first', 'missing-last', 'noncontig', 'major', 'node', 'mount')),
    'mount': set(('valid', 'context', 'kernel-flag', 'writable', 'suid', 'noexec', 'update', 'reload', 'root',
                  'device', 'forged', 'outside', 'published', 'stage', 'bad-size', 'metadata-alloc', 'adopt1', 'adopt2')),
    'pager': set(('valid', 'vnode-failure', 'ubc-null', 'pager-failure', 'bad-page', 'bad-span', 'bad-eof',
                  'prelatched', 'null-node', 'null-output', 'vnode-get-failure', 'published-unmount',
                  'unpublished-flush-failure', 'readonly-attrs')),
    'exec': {f's{s}-a{a}-r{r}-m{m}-e{e}-p{p}' for s, a, r, m, e, p in
             product(range(4), (0, 1), (0, 1), (0, 1), (0, 5), (0, 19))},
    'worker': set(('off', 'invalid-mode', 'invalid-flag', 'new', 'preparing', 'ready', 'failed', 'suffix',
                   'reject-before-delay', 'reject-after-delay')),
    'pid1': set(('valid', 'single-user', 'copy-path', 'copy-argv', 'exec-failure', 'pager-failure',
                 'not-hfs', 'bad-role', 'dt-missing', 'allocation')),
    'attributes': {'regular-file-supported-root-attributes'},
}
CASE_COUNTS = {name: len(labels) for name, labels in CASE_NAMES.items()}


def assemble_components(records, identity):
    from santoni_gpu_scalar_certificate import consume
    require(set(records) == set(COMPONENTS), 'launcher aggregate missing/unreviewed component')
    hashes, paths, probe_hashes = set(), set(), set()
    for name, record in records.items():
        consume(record, identity)
        cases = record.get('cases')
        require(isinstance(cases, list) and len(cases) == CASE_COUNTS[name] and
                all(isinstance(case, dict) and isinstance(case.get('case'), str) for case in cases) and
                {case['case'] for case in cases} == CASE_NAMES[name], 'launcher scenario scope incomplete: ' + name)
        require(record.get('hardware_verified') is False and isinstance(record.get('probe_sha256'), str) and
                re.fullmatch(r'[0-9a-f]{64}', record.get('probe_sha256', '')) and
                isinstance(record.get('record_path'), str) and
                isinstance(record.get('record_sha256'), str) and
                re.fullmatch(r'[0-9a-f]{64}', record.get('record_sha256', '')),
                'launcher record provenance/scope missing: ' + name)
        hashes.add(record['record_sha256']); paths.add(record['record_path']); probe_hashes.add(record['probe_sha256'])
    require(len(paths) == len(hashes) == len(COMPONENTS) and len(probe_hashes) == 1,
            'launcher aggregate aliases records or mixes probes')
    workers = {case['case']: case for case in records['worker']['cases']}
    require(workers.get('off', {}).get('mode') == 3 and workers['off'].get('options_ok') == 1 and
            workers['off'].get('worker_ready') == 1 and
            all(isinstance(workers.get(name, {}).get('refusal_paths'), dict) and
                workers[name]['refusal_paths'].get('return_paths', 0) > 0
                for name in ('reject-before-delay', 'reject-after-delay')),
            'launcher worker off/refusal bridge missing')
    attrs = records['attributes']['cases'][0]
    require(attrs.get('mode') == 0o500 and attrs.get('uid') == attrs.get('gid') == 0 and
            attrs.get('uid_gid_mode_supported') is True and attrs.get('attribute_bytes') == 440,
            'executable supported permissions/attribute extent proof missing')
    return {**identity, 'success': True, 'components': records, 'probe_sha256': next(iter(probe_hashes)),
            'linked_components_complete': True, 'launcher_certificate_complete': False,
            'hardware_verified': False, 'scope': 'all nine exact-kernel linked launcher components; simulated services'}


def main():
    """Checkpoint accepted components/scenarios; never repeat a cached pass."""
    from santoni_gpu_scalar_certificate import load_inputs, identity_of, consume, proof
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--probe-dir', type=Path, required=True)
    parser.add_argument('--components', nargs='*', choices=COMPONENTS, default=[])
    parser.add_argument('--aggregate', action='store_true', help='consume all completed linked components; no delivery gate')
    parser.add_argument('--reuse', action='append', default=[], metavar='COMPONENT=RECORD')
    args = parser.parse_args()
    folder = args.evidence
    require(args.components or args.aggregate, 'request missing components or cached aggregation')
    base, codes, image, names, e = load_inputs(folder, decode=bool(args.components))
    identity = identity_of(base)
    probe = (args.probe_dir / 'probe.macho').read_bytes()
    build = json.loads((args.probe_dir / 'build.json').read_text())
    probe_sha = hashlib.sha256(probe).hexdigest()
    require(build.get('macho_sha256') == probe_sha and build.get('macho_bytes') == len(probe),
            'probe/build identity differs')
    reused = {}
    for item in args.reuse:
        name, separator, relative = item.partition('=')
        require(separator and name in COMPONENTS and name not in reused,
                'unreviewed/duplicate reuse component')
        record = proof(folder, relative, identity)
        require(record.get('probe_sha256') == probe_sha, 'reuse probe identity differs')
        reused[name] = record
        print('Reused completed launcher component:', name, len(record['cases']), 'cases; 0 executions', flush=True)
    cache = folder / 'launcher-components'
    cache.mkdir(exist_ok=True)
    attempt = cache / ('attempt-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
    attempt.mkdir()
    source = Path(__file__).read_bytes()
    (attempt / 'launcher-source.py').write_bytes(source)
    pins = {**identity, 'probe_sha256': probe_sha, 'tool_sha256': hashlib.sha256(source).hexdigest(),
            'source_record': str((attempt / 'launcher-source.py').relative_to(folder)),
            'probe_build_sha256': hashlib.sha256((args.probe_dir / 'build.json').read_bytes()).hexdigest(),
            'shared_run_sha256': BASE_RUN_SHA256, 'hardware_verified': False}
    completed = dict(reused)
    try:
        for name in (COMPONENTS if args.aggregate else args.components):
            if name in completed:
                continue
            path = cache / (name + '.json')
            if path.exists():
                completed[name] = proof(folder, str(path.relative_to(folder)), identity)
                require(completed[name].get('probe_sha256') == probe_sha, 'cached component probe differs')
                print('Reused completed launcher component:', name, '0 executions', flush=True)
                continue
            require(name in args.components, 'aggregate requires completed launcher component: ' + name)
            case_dir = cache / 'scenarios' / name
            case_dir.mkdir(parents=True, exist_ok=True)
            saved = {}
            for prior in sorted(case_dir.glob('*.json')):
                record = consume(json.loads(prior.read_text()), identity)
                require(record.get('probe_sha256') == probe_sha and record.get('component') == name and
                        record['result']['case'] == prior.stem, 'scenario identity differs')
                saved[prior.stem] = record['result']
            def save_case(case):
                record = {**pins, 'success': True, 'component': name, 'result': case}
                with (case_dir / (case['case'] + '.json')).open('x') as stream:
                    stream.write(json.dumps(record, indent=2) + '\n')
                print('Saved passed launcher scenario:', name, case['case'], flush=True)
            print('Running missing launcher component:', name, '; reused scenarios:', len(saved), flush=True)
            action = globals()['audit_' + name]
            extra = (build,) if name == 'image' else ()
            keywords = {} if name == 'options' else {'saved_cases': saved, 'save_case': save_case}
            result = action(codes, image, names, e, probe, *extra, **keywords)
            record = {**pins, **result, 'component': name, 'success': True,
                      'scenario_record_paths': [str(p.relative_to(folder)) for p in sorted(case_dir.glob('*.json'))]}
            with path.open('x') as stream:
                stream.write(json.dumps(record, indent=2) + '\n')
            completed[name] = proof(folder, str(path.relative_to(folder)), identity)
            print('Saved passed launcher component:', name, len(result['cases']), 'cases', flush=True)
        if args.aggregate:
            aggregate = assemble_components(completed, identity)
            (attempt / 'linked-components.json').write_text(json.dumps(aggregate, indent=2) + '\n')
            print('All nine linked launcher components aggregated; 0 new replay cases', flush=True)
        outcome = {**identity, 'success': True, 'completed': completed,
                   'launcher_certificate_complete': False, 'hardware_verified': False}
        (attempt / 'result.json').write_text(json.dumps(outcome, indent=2) + '\n')
        print('Completed requested launcher components:', ', '.join(completed), flush=True)
    except Exception:
        print(traceback.format_exc(), flush=True)
        raise


if __name__ == '__main__':
    main()
