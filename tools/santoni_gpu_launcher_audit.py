"""Exact-kernel launcher ISA and default-off component; no full launch certificate.

The six returning boundaries below execute decoded CPU instructions with one
explicit absent/zero boot-option contract. Kernel memory is never writable.
They do not model enabled mount/pager/exec or scheduler/hardware behavior.
"""
import struct

from santoni_gpu_binary_model import Machine, integer

PUBLIC = ('_santoni_gpu_user_launch_options_ok', '_santoni_gpu_user_launch_worker_ready',
          '_santoni_gpu_user_launch_mount_args', '_santoni_gpu_user_launch_mount_published',
          '_santoni_gpu_user_launch_path', '_santoni_gpu_user_launch_exec_result',
          '_sgpu_launch_role', '_sgpu_launch_image', '_sgpu_launch_prepare',
          '_santoni_gpu_user_launch_trace_ready')
DATA = ('_sgpu_launch_image.sizes', '_mockfs_santoni_trace_events', '_mockfs_vnodeop_entries')
CALLBACKS = ('_launch_allocate', '_launch_page_pa', '_launch_copy', '_launch_publish', '_launch_release')
CHANGED = ('_mockfs_santoni_mount', '_mockfs_fsnode_create', '_mockfs_fsnode_vnode',
           '_mockfs_unmount', '_mockfs_getattr', '_load_init_program', '_VFS_MOUNT', '_vfs_64bitready',
           '_mockfs_santoni_open', '_mockfs_santoni_close', '_mockfs_santoni_ioctl')
TRACE_HELPERS = ('_mockfs_santoni_trace_mount', '_mockfs_santoni_trace_access')
DIAG_PUBLIC = ('_santoni_gpu_user_launch_trace_snapshot',)
DIAG_HELPERS = ('_mockfs_santoni_diag_inc', '_mockfs_santoni_diag_note', '_mockfs_santoni_diag_refuse')
DIAG_DATA = ('_mockfs_santoni_trace_diag', '_mockfs_santoni_diag_lock', '_mockfs_santoni_diag_group')
# Separate data identities, never additional executable launcher boundaries.
# These are the allocation/free sites in the retained 0211 kernel.
ALLOCATION_DATA = ('_mockfs_santoni_mount.kalloc_type_view_60',
                   '_mockfs_santoni_mount.kalloc_type_view_82')


def _data_sections(image):
    """Read section extents without changing the shared instruction decoder."""
    try:
        header = struct.unpack_from('<8I', image.data)
        if (header[:2] != (0xfeedfacf, 0x100000c) or header[4] > 4096 or
                32 + header[5] > len(image.data)):
            raise ValueError('allocation metadata Mach-O header differs')
        sections, offset = [], 32
        for _ in range(header[4]):
            command, length = struct.unpack_from('<II', image.data, offset)
            if length < 8 or offset + length > 32 + header[5]:
                raise ValueError('allocation metadata load command out of bounds')
            if command == 0x19:
                if length < 72:
                    raise ValueError('allocation metadata segment is truncated')
                seg = struct.unpack_from('<II16s4Q4I', image.data, offset)
                if seg[9] > 4096 or length != 72 + 80 * seg[9]:
                    raise ValueError('allocation metadata section table differs')
                for index in range(seg[9]):
                    sec = struct.unpack_from('<16s16s2Q8I', image.data, offset + 72 + 80 * index)
                    sections.append({'section': sec[0].split(b'\0', 1)[0],
                        'segment': sec[1].split(b'\0', 1)[0], 'address': sec[2],
                        'size': sec[3], 'offset': sec[4], 'alignment': sec[5], 'flags': sec[8],
                        'owner': seg[2].split(b'\0', 1)[0], 'vmaddr': seg[3], 'vmsize': seg[4],
                        'fileoff': seg[5], 'filesize': seg[6], 'initprot': seg[8]})
            offset += length
        if offset != 32 + header[5]:
            raise ValueError('allocation metadata load commands are incomplete')
        return sections
    except (AttributeError, IndexError, struct.error) as error:
        raise ValueError('allocation metadata section bytes are unavailable') from error


def _readonly_data(image, sections, address, size, segment, section, flags):
    if type(address) is not int or not 0 < address < address + size <= 1 << 64:
        raise ValueError('allocation metadata data pointer differs')
    matches = [s for s in sections if s['address'] < address + size and
               address < s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('allocation metadata section extent missing or ambiguous')
    s = matches[0]
    mappings = [m for m in image.segs if m['vmaddr'] < address + size and
                address < m['vmaddr'] + m['vmsize']]
    if (s['segment'] != segment or s['owner'] != segment or s['section'] != section or
            s['flags'] != flags or s['initprot'] != 1 or len(mappings) != 1 or
            mappings[0]['initprot'] != 1 or not s['address'] <= address < address + size <=
                s['address'] + s['size'] or
            not mappings[0]['vmaddr'] <= address < address + size <=
                mappings[0]['vmaddr'] + min(mappings[0]['vmsize'], mappings[0]['filesize']) or
            s['alignment'] > 12 or
            s['address'] % (1 << s['alignment']) or
            not s['vmaddr'] <= s['address'] < s['address'] + s['size'] <=
                s['vmaddr'] + min(s['vmsize'], s['filesize']) or
            s['offset'] != s['fileoff'] + s['address'] - s['vmaddr'] or
            s['offset'] + s['size'] > len(image.data)):
        raise ValueError('allocation metadata data section/protection differs')
    value = image.read(address, size)
    if value is None:
        raise ValueError('allocation metadata data is not fully file-backed')
    return value


def allocation_data(image, names, codes):
    """Check only the two retained XNU8796 mount allocation descriptors.

    kalloc.h:304/1496 defines the 64-byte view and its static initializer.
    The retained linked type signature is 221222222, size72, shared flags0x64;
    all runtime zone/list fields are zero in this pre-boot binary. This proves
    compiler metadata identity, not allocation success or enabled execution.
    """
    found = {n for n in names if n.startswith('_mockfs_santoni_mount.kalloc_type_view_')}
    if not found:
        return {'success': True, 'records': [], 'scope': 'no allocation metadata names present'}
    if found != set(ALLOCATION_DATA) or any(len(names[n]) != 1 for n in found):
        raise ValueError('allocation metadata namespace missing, ambiguous or unreviewed')
    if image is None or any(n in codes for n in found):
        raise ValueError('allocation metadata needs a data image and cannot be executable code')
    sections, records = _data_sections(image), []
    for name in ALLOCATION_DATA:
        address = next(iter(names[name]))
        if address % 8 or any(address <= other < address + 64 for n, values in names.items()
                              for other in values if n != name):
            raise ValueError('allocation metadata identity is unaligned, aliased or overlapping')
        raw = _readonly_data(image, sections, address, 64, b'__DATA_CONST', b'__kalloc_type', 0)
        fields = struct.unpack('<5Q2I2Q', raw.to_bytes(64, 'little'))
        if any(fields[i] for i in (0, 1, 3, 7, 8)) or fields[5:7] != (0x64, 72):
            raise ValueError('allocation metadata initializer/type size differs')
        for pointer, literal in ((fields[2], b'site.struct mockfs_mount\0'),
                                 (fields[4], b'221222222\0')):
            if (_readonly_data(image, sections, pointer, len(literal), b'__TEXT', b'__cstring', 2) !=
                    int.from_bytes(literal, 'little')):
                raise ValueError('allocation metadata type name/signature differs')
        records.append({'symbol': name, 'address': hex(address), 'bytes': 64,
                        'section': '__DATA_CONST,__kalloc_type', 'kt_size': 72, 'kt_flags': '0x64',
                        'type_name': 'site.struct mockfs_mount', 'type_signature': '221222222'})
    return {'success': True, 'records': records,
            'scope': 'read-only compiler allocation metadata; no executable namespace extension'}


def init_default_off(code, image, names, e):
    """The compiled PID1 hook cannot take its wrapper branch with a NULL path."""
    V = e._Value
    allocs = code.calls_to(names.get('_mach_vm_allocate_kernel', ()))
    paths = code.calls_to(names[PUBLIC[4]])
    parses = code.calls_to(names.get('_PE_parse_boot_argn', ()))
    if len(allocs) != 1 or len(paths) != 1:
        raise ValueError('compiled PID1 launcher hook missing or repeated')
    results = []
    for scratch in (0, 0x60000000):
        def allocate(after, before):
            dest = before.get('x1')
            if (dest is None or not isinstance(dest.expr, tuple) or dest.expr[0] != 'stack' or
                    before.load(dest, 8, image) != V(64, 0)):
                raise ValueError('PID1 scratch allocation destination/default differs')
            after.store(dest, 8, V(64, scratch))
            after.put('w0', V(32, 0))
        def path(after, before):
            after.put('x0', V(64, 0))  # independently decoded NULL-return component
        def parse(after, before):
            pointer = before.get('x0')
            literal = b'launchdsuffix\0'
            if (pointer is None or not isinstance(pointer.expr, int) or
                    image.read(pointer.expr, len(literal)) != int.from_bytes(literal, 'little') or
                    before.get('x2') != V(64, 64)):
                raise ValueError('PID1 original-init option parser differs')
            after.put('w0', V(32, 0))  # controlled mode1 recipe has no suffix
        effects = {allocs[0]: allocate, paths[0]: path, **{pc: parse for pc in parses}}
        flow = e._Flow(code, image, names, effects=effects)
        if len(code.calls_to(names[PUBLIC[4]], flow.before)) != int(scratch != 0):
            raise ValueError('PID1 scratch guard bypasses or repeats the launcher')
        forbidden = (*PUBLIC[:4], PUBLIC[5], *PUBLIC[6:], *CALLBACKS, '_mockfs_santoni_mount')
        if any(code.calls_to(names.get(n, ()), flow.before) for n in forbidden):
            raise ValueError('mode1 PID1 hook reaches an enabled launcher operation')
        results.append({'scratch': scratch, 'launcher_path_calls': int(scratch != 0),
                        'wrapper_exec_result_calls': 0, 'instruction_states': len(flow.before)})
    return {'cases': results, 'scope': 'NULL decoded launcher path; original init remains selected'}


def load_launcher(load, codes, names, image=None, data_evidence=None):
    found = {n for n in names if n.startswith(('_santoni_gpu_user_launch_', '_sgpu_launch_'))}
    if not found:
        return False
    diagnostics = bool(set(DIAG_PUBLIC + DIAG_DATA) & set(names))
    extra = DIAG_PUBLIC if diagnostics else ()
    if diagnostics and any(len(names.get(n, ())) != 1 for n in (*DIAG_PUBLIC, *DIAG_DATA)):
        raise ValueError('trace diagnostic getter/storage missing or ambiguous')
    expected = {n for n in (*PUBLIC, *DATA, *extra) if n.startswith(('_santoni_gpu_user_launch_', '_sgpu_launch_'))}
    mockfs = {n for n in names if n.startswith('_mockfs_santoni_') and '.cold.' not in n}
    allowed = {'_mockfs_santoni_mount', *CHANGED[-3:], *TRACE_HELPERS, DATA[1], *ALLOCATION_DATA}
    if diagnostics: allowed.update((*DIAG_HELPERS, *DIAG_DATA))
    if (found != expected or not mockfs <= allowed or
            any(len(names.get(n, ())) != 1 for n in (*PUBLIC, *DATA, *CALLBACKS, *CHANGED))):
        raise ValueError('new launcher namespace missing, ambiguous or unreviewed')
    if len({next(iter(names[n])) for n in (*PUBLIC, *CALLBACKS, *CHANGED)}) != len((*PUBLIC, *CALLBACKS, *CHANGED)):
        raise ValueError('new launcher entry identities alias')
    metadata = allocation_data(image, names, codes)
    if data_evidence is not None:
        data_evidence.update(metadata)
    for name in (*PUBLIC, *CALLBACKS, *CHANGED, *TRACE_HELPERS, *extra,
                 *(DIAG_HELPERS if diagnostics else ()),
                 '_launch_options', '_launch_error', '_load_init_program_at_path'):
        if name in names:
            load(name)
    return True


def trace_bindings(image, names):
    """Bind the three new indirect vnode roots and their separate CPU counter."""
    table = next(iter(names[DATA[2]]))
    descriptors = {}
    for index in range(64):
        descriptor, callback = image.read(table + 16 * index, 8), image.read(table + 16 * index + 8, 8)
        if not descriptor and not callback:
            break
        if not descriptor or not callback or descriptor in descriptors:
            raise ValueError('trace vnode table missing/duplicate/partial entry')
        descriptors[descriptor] = callback
    else:
        raise ValueError('trace vnode table exceeds its bounded extent')
    wanted = dict(zip(('_vnop_open_desc', '_vnop_close_desc', '_vnop_ioctl_desc'), CHANGED[-3:]))
    for descriptor, callback in wanted.items():
        if (len(names.get(descriptor, ())) != 1 or descriptors.get(next(iter(names[descriptor]))) !=
                next(iter(names[callback]))):
            raise ValueError('private trace vnode callback is absent or substituted: ' + callback)
    counter = next(iter(names[DATA[1]]))
    if not any(s['vmaddr'] <= counter < counter + 4 <= s['vmaddr'] + s['vmsize'] and
               s['initprot'] == 3 for s in image.segs):
        raise ValueError('trace CPU counter has no bounded writable storage')
    diagnostic = {}
    if DIAG_PUBLIC[0] in names:
        address = next(iter(names[DIAG_DATA[0]]))
        lock = next(iter(names[DIAG_DATA[1]]))
        if address % 4 or not any(s['vmaddr'] <= address < address + 40 <= s['vmaddr'] + s['vmsize'] and
                                 s['initprot'] == 3 for s in image.segs) or address <= counter < address + 40:
            raise ValueError('trace diagnostic storage extent/protection/identity differs')
        diagnostic = {'diagnostic_present': True, 'diagnostic_address': hex(address),
                      'diagnostic_lock': hex(lock), 'diagnostic_bytes': 40}
    return {'success': True, 'table': hex(table), 'counter': hex(counter), **diagnostic,
            'callbacks': {d: hex(next(iter(names[n]))) for d, n in wanted.items()},
            'entries': index, 'scope': 'linked vnode dispatch and CPU storage only; enabled receiver needs separate replay'}


def default_off(codes, image, names, e, mode=1):
    if type(mode) is not int or mode not in (1,3):
        raise ValueError('launcher exclusion requires explicit mode1 or mode3')
    if PUBLIC[0] not in codes:
        return None
    # LLVM emitted the structural command-size table as immutable data, not
    # an executable helper. Pin all20 bytes rather than accepting extra names.
    sizes = next(iter(names[DATA[0]]))
    if (image.read(sizes, 20) != int.from_bytes(
            b''.join(n.to_bytes(4, 'little') for n in (72, 152, 72, 288, 16)), 'little') or
            not any(s['vmaddr'] <= sizes < sizes + 20 <= s['vmaddr'] + s['vmsize'] and
                    not s['initprot'] & 2 for s in image.segs)):
        raise ValueError('launcher structural table content/protection differs')
    # All new CPU roots were decoded by the enclosing bounded A53 loader.
    selected = {n: c for n, c in codes.items() if
                n.startswith(('_santoni_gpu_user_launch_', '_sgpu_launch_', '_launch_'))}
    records = []
    for option in (None, 0):
        for name, expected in ((PUBLIC[0], 1), (PUBLIC[1], 1), (PUBLIC[4], 0), (PUBLIC[-1], 0)):
            vm = Machine(selected, image, names, e)
            calls = []
            def external(target, state, probe=False, before=None):
                label = vm.by_address.get(target)
                if label not in ('_PE_parse_boot_argn', '_bzero', '_memset'):
                    return False
                if probe:
                    return True
                calls.append(label)
                arg = lambda i: integer(before, 'x' + str(i))
                if label == '_PE_parse_boot_argn':
                    literal = b'santonigpu_user_exec\0'
                    dest, size = arg(1), arg(2)
                    if (vm.memory.bytes(arg(0), len(literal)) != literal or size != 4 or
                            not vm.STACK <= dest < dest + size <= vm.STACK + vm.STACK_SIZE or
                            vm.memory.get(dest) != 0):
                        raise ValueError('launcher default-off option name/size/zero differs')
                    vm.memory.put(dest, 0)
                    state.put('w0', e._Value(32, int(option is not None)))
                else:
                    dest, count = arg(0), arg(1 if label == '_bzero' else 2)
                    if (not 0 < count <= 64 or not vm.STACK <= dest < dest + count <= vm.STACK + vm.STACK_SIZE or
                            label == '_memset' and arg(1) != 0):
                        raise ValueError('default-off initializer writes outside its stack')
                    vm.memory.write(dest, bytes(count))
                    state.put('x0', e._Value(64, dest))
                return True
            vm.external = external
            args = (0, 0, 0) if name == PUBLIC[-1] else (mode,) if name != PUBLIC[4] else ()
            vm.run(name, args, budget=5000)
            if integer(vm.state, 'x0') != expected or calls.count('_PE_parse_boot_argn') != 1:
                raise ValueError('default-off launcher does not return the required result')
            records.append({'symbol': name, 'option': option, 'result': expected,
                            'decoded_instruction_addresses': len(vm.visited), 'calls': calls})
    return {'success': True, 'scope': 'mode'+str(mode)+'; launcher option absent or explicitly zero',
            'boundaries': records, 'return_values': {PUBLIC[0]: 1, PUBLIC[1]: 1, PUBLIC[4]: 0, PUBLIC[-1]: 0},
            'trace_present': True, 'trace_bindings': trace_bindings(image, names),
            'PID1_hook': init_default_off(codes['_load_init_program'], image, names, e),
            'no_kernel_storage_writes_or_DT_root_allocation_mount_exec_calls': True,
            'enabled_launcher_certified': False, 'hardware_verified': False}
