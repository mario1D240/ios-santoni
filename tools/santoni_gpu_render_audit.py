"""Namespace and caller boundary for 0220's prepared, kernel-only API."""

HELPERS = tuple('_sgpu_render_' + name for name in (
    'overlap', 'memory_valid', 'tables_valid', 'lookup', 'init', 'new', 'free',
    'cpu', 'plane_valid', 'abort', 'begin', 'wait'))
LIVE_HELPERS = tuple('_sgpu_render_' + name for name in (
    'validate', 'live_fail', 'live_tables', 'live_state', 'live_link',
    'live_pattern', 'live_compare', 'live_job', 'live_start',
    'options', 'release', 'allocate', 'worker'))
CP_HELPER = '_sgpu_render_live_cp_state'
LIVE_STORAGE = tuple('_sgpu_render_' + name for name in (
    'live', 'enabled', 'allocation_attempted', 'tables_kva', 'pixels_kva',
    'allocation_retained', 'page_pas', 'owned'))


def helpers(names):
    found = {name for name in names if name.startswith('_sgpu_render_')}
    if not found:
        return ()
    selected = HELPERS + LIVE_HELPERS if found & set(LIVE_HELPERS + LIVE_STORAGE) else HELPERS
    if CP_HELPER in found:
        if selected == HELPERS:
            raise ValueError('live CP readback helper without the live worker')
        selected += (CP_HELPER,)
    expected = set(selected) | (set(LIVE_STORAGE) if selected != HELPERS else set())
    if found != expected or any(len(names[name]) != 1 for name in found):
        raise ValueError('prepared render API has missing, ambiguous or unreviewed symbols')
    if len({next(iter(names[name])) for name in found}) != len(found):
        raise ValueError('prepared render API symbols alias')
    return selected


def prepared_only(codes, names):
    selected = helpers(names)
    if not selected:
        return None
    addresses = {next(iter(names[name])) for name in selected}
    live = selected != HELPERS
    callers = {'_sgpu_kernel_thread': {'_sgpu_render_options', '_sgpu_render_worker'}} if live else {}
    from santoni_gpu_ui_audit import helpers as ui_helpers, RENDER_CALLERS
    ui = bool(ui_helpers(names))
    if ui:
        if CP_HELPER not in selected:
            raise ValueError('UI bridge requires the observed live CP helper')
        callers.update(RENDER_CALLERS)
    graphics_owned = '_sgpu_graphics_hw_begin_owned' in names or '_sgpu_graphics_hw_begin_vm' in names
    if graphics_owned:
        # 0226 moves the two legacy startup checks into the common owned
        # handoff, adding only overlap checks for its fresh private VM span.
        # Require the complete closed wide namespace before admitting that
        # specific caller; the legacy/VM wrappers receive no render API rights.
        from santoni_gpu_graphics_audit import helpers as graphics_helpers
        graphics = graphics_helpers(names)
        if '_sgpu_graphics_hw_begin_owned' not in graphics or not live or CP_HELPER not in selected:
            raise ValueError('owned graphics handoff lacks the reviewed live/wide namespace')
        if next(iter(names['_sgpu_graphics_hw_begin_owned'])) in addresses:
            raise ValueError('owned graphics handoff aliases the render API')
        callers['_sgpu_graphics_hw_begin_owned'] = (
            '_sgpu_render_overlap', '_sgpu_render_live_tables', '_sgpu_render_live_state')
    elif '_sgpu_graphics_hw_begin' in names:
        callers['_sgpu_graphics_hw_begin']=('_sgpu_render_live_tables','_sgpu_render_live_state')
    if '_sgpu_graphics_hw_state' in names:
        callers['_sgpu_graphics_hw_state']=('_sgpu_render_live_cp_state',)
    for name, code in codes.items():
        allowed = {next(iter(names[n])) for n in callers.get(name, ())}
        if name not in selected and code.calls_to(addresses - allowed):
            raise ValueError('prepared render API acquired an unreviewed runtime caller: ' + name)
    return {'helpers': list(selected), 'inspected_production_GPU_routes_do_not_call_render_API': not live,
            'live_allocator_worker_present': live, 'display_integration': ui,
            'live_allocator_worker_and_display_integration': False,
            'dedicated_live_binary_certificate_required': live}


def inspection_budget(names, launcher_present, session_present):
    """Keep prior caps; add only closed, uniquely loaded feature namespaces."""
    base = 160 if launcher_present else 128 if session_present else 96
    from santoni_gpu_ui_audit import helpers as ui_helpers
    from santoni_gpu_graphics_audit import helpers as graphics_helpers
    from santoni_gpu_dyld_startup_audit import inspection_helpers as startup_helpers
    return base + len(helpers(names)) + len(ui_helpers(names)) + len(graphics_helpers(names)) + len(startup_helpers(names))


def default_off(codes, image, names, e):
    """Execute the actual new parser with render absent/zero for all modes."""
    if '_sgpu_render_options' not in names: return None
    from santoni_gpu_stock_audit import _single_return
    code = codes['_sgpu_render_options']; V = e._Value
    flag = V(64, next(iter(names['_sgpu_render_enabled'])))
    parses = code.calls_to(names['_PE_parse_boot_argn'])
    results = []
    for mode in range(5):
        initial = e._initial(code.symbol); initial.put('w0', V(32, mode))
        initial.store(flag, 4, V(32, 0))
        def parse(after, before):
            address, dest = before.get('x0'), before.get('x1')
            literal = b'santonigpu_render\0'
            if (address is None or not isinstance(address.expr, int) or
                    image.read(address.expr, len(literal)) != int.from_bytes(literal, 'little') or
                    before.get('x2') != V(64, 4) or before.load(dest, 4, image) != V(32, 0)):
                raise ValueError('default render parser name/width/zero initializer differs')
            after.store(dest, 4, V(32, 0)); after.put('w0', V(32, 0))
        flow = e._Flow(code, image, names, initial=initial, effects={pc:parse for pc in parses})
        if _single_return(flow,e) != V(32,1): raise ValueError('absent render option rejects existing mode')
        for pc, state in flow.before.items():
            if code.ins[pc][0] == 'ret' and state.load(flag,1,image) != V(8,0):
                raise ValueError('absent render option leaves its live flag enabled')
        results.append(mode)
    return {'success':True,'global':flag.expr,'parsed_modes':results,'render_flag':0,'result':1}
