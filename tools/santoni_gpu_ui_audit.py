"""Closed namespace and caller boundary for the kernel UI presentation bridge."""

CORE = tuple('_sgpu_ui_' + n for n in ('snapshot', 'fail', 'start', 'memory_valid',
    'reserved', 'image_valid', 'pixel_tables', 'tables', 'faults', 'state',
    'remap', 'submit', 'wait', 'copy', 'frame'))
ADAPTER = ('_sgpu_ui_options', '_sgpu_ui_publish', '_santoni_gpu_ui_copy', '_santoni_gpu_ui_frame')
STORAGE = ('_sgpu_ui', '_sgpu_ui_enabled', '_sgpu_ui_published', '_sgpu_ui_lock',
           '_sgpu_ui_import_pas', '_sgpu_ui_import')
DISPLAY = ('__ZN9AppleCLCD10gpuPresentEPKh', '__ZN9AppleCLCD16gpuRestoreShadowEv',
           '__ZN9AppleCLCD7presentEPKh',
           '__ZN9AppleCLCD10vsyncFiredEP8OSObjectP18IOTimerEventSource')
RENDER_CALLERS = {
    '_sgpu_ui_fail': ('_sgpu_render_abort',),
    '_sgpu_ui_start': ('_sgpu_render_live_tables', '_sgpu_render_live_state'),
    '_sgpu_ui_image_valid': ('_sgpu_render_overlap',),
    '_sgpu_ui_tables': ('_sgpu_render_overlap',),
    '_sgpu_ui_state': ('_sgpu_render_live_cp_state',),
}


def helpers(names):
    found = {n for n in names if n == '_sgpu_ui' or
             n.startswith(('_sgpu_ui_', '_santoni_gpu_ui_'))}
    if not found:
        return ()
    expected = set(CORE + ADAPTER + STORAGE)
    if found != expected or any(len(names[n]) != 1 for n in found):
        raise ValueError('UI namespace missing, ambiguous or unreviewed symbols')
    if len({next(iter(names[n])) for n in found}) != len(found):
        raise ValueError('UI function/storage identities alias')
    if any(len(names.get(n, ())) != 1 for n in DISPLAY):
        raise ValueError('UI framebuffer ABI missing or ambiguous')
    return CORE + ADAPTER + DISPLAY


def caller_boundary(codes, names):
    selected = helpers(names)
    if not selected:
        return None
    targets = {next(iter(names[n])) for n in CORE + ADAPTER}
    allowed = {
        '_sgpu_kernel_thread': ('_sgpu_ui_options',),
        '_sgpu_render_worker': ('_sgpu_ui_publish',),
        # The graphics controller reuses only the existing read/record fault
        # classifier. It cannot start, import, present or submit through UI.
        '_sgpu_graphics_hw_state': ('_sgpu_ui_faults',),
        '_sgpu_graphics_hw_faulted': ('_sgpu_ui_faults',),
        DISPLAY[0]: ('_santoni_gpu_ui_copy',),
        DISPLAY[1]: ('_santoni_gpu_ui_frame',),
        # LLVM inlines these C++ methods into their existing callers while
        # retaining the externally visible method bodies. All four changed
        # routines are loaded; admit only the same narrow adapter ABI there.
        DISPLAY[2]: ('_santoni_gpu_ui_copy', '_santoni_gpu_ui_frame'),
        DISPLAY[3]: ('_santoni_gpu_ui_frame',),
    }
    for name, code in codes.items():
        if name in CORE + ADAPTER:
            continue
        admitted = {next(iter(names[n])) for n in allowed.get(name, ())}
        if code.calls_to(targets - admitted):
            raise ValueError('UI API acquired an unreviewed caller: ' + name)
    return {'helpers': list(selected), 'kernel_only_framebuffer_ABI': True,
            'dedicated_UI_binary_certificate_required': True,
            'hardware_verified': False, 'GLES_acceleration': False}


def default_off(codes, image, names, e):
    if '_sgpu_ui_options' not in codes:
        return None
    from santoni_gpu_stock_audit import _single_return
    V = e._Value
    code = codes['_sgpu_ui_options']
    flag = V(64, next(iter(names['_sgpu_ui_enabled'])))
    parses = code.calls_to(names['_PE_parse_boot_argn'])
    if len(parses) != 1:
        raise ValueError('UI parser must parse its exact argument once')
    for mode in range(5):
        initial = e._initial(code.symbol)
        initial.put('w0', V(32, mode))
        initial.store(flag, 4, V(32, 1))
        def parse(after, before):
            addr, dest = before.get('x0'), before.get('x1')
            literal = b'santonigpu_ui\0'
            if (addr is None or not isinstance(addr.expr, int) or
                image.read(addr.expr, len(literal)) != int.from_bytes(literal, 'little') or
                before.get('x2') != V(64, 4) or before.load(dest, 4, image) != V(32, 0)):
                raise ValueError('UI parser argument/width/initializer differs')
            after.store(dest, 4, V(32, 0))
            after.put('w0', V(32, 0))
        flow = e._Flow(code, image, names, initial=initial, effects={parses[0]: parse})
        if _single_return(flow, e) != V(32, 1):
            raise ValueError('absent UI option rejects an existing mode')
        for pc, state in flow.before.items():
            # LLVM narrows this zero/one static flag to a byte. Check the
            # actual flag byte, not unallocated neighboring source padding.
            if code.ins[pc][0] == 'ret' and state.load(flag, 1, image) != V(8, 0):
                raise ValueError('absent UI option leaves the bridge enabled')
    return {'success': True, 'global': flag.expr, 'parsed_modes': list(range(5)),
            'UI_flag': 0, 'hardware_verified': False}
