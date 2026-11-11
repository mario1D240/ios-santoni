"""Closed changed-code inventory and default-off rendering transport proof."""
GRAPHICS=tuple('_sgpu_graphics_'+n for n in ('admitted','lookup','fail','init','run','memory_valid','allocate',
    'new','info','bo_valid','cpu','retire','free','drop_snapshots','submit','wait','abort','close'))
HW=tuple('_sgpu_graphics_hw_'+n for n in ('fail','ready','reserved','tables','state','stop','resume','begin','pte',
    'change','map','unmap','fence_pa','clean','invalidate','invalidate_fence','fence','faulted','idle','publish','snapshot'))
PM4=tuple('_sgpu_pm4_'+n for n in ('parity','header','data','snapshot','rule','registers','child','draw','packet',
    'walk','inputs','run','prepare','validate'))
# Verified in the linked Xcode16.0 kernel: Darwin retains C++ internal-linkage
# mangling for these static callbacks, including inside their extern-C block.
CALLBACK_NAMES={
    'ready':'__ZL9gfx_readyPv',
    'pool_init':'__ZL13gfx_pool_initP8gfx_pooljb',
    'lease_for':'__ZL13gfx_lease_forPK20sgpu_graphics_memory',
    'allocate':'__ZL12gfx_allocatePvjbP20sgpu_graphics_memory',
    'release':'__ZL11gfx_releasePvP20sgpu_graphics_memory',
    'page_pa':'__ZL11gfx_page_paPvPK20sgpu_graphics_memoryj',
    'reserved':'__ZL12gfx_reservedPvy',
    'map':'__ZL7gfx_mapPvjPKyjyj',
    'unmap':'__ZL9gfx_unmapPvjjj',
    'pte':'__ZL7gfx_ptePvj',
    'clean':'__ZL9gfx_cleanPvPKvj',
    'invalidate':'__ZL14gfx_invalidatePvPKvj',
    'prepare':'__ZL11gfx_preparePvPK22sgpu_graphics_snapshotjPK21sgpu_graphics_commandjPK19sgpu_graphics_rangej',
    'validate':'__ZL12gfx_validatePvPKjjPK19sgpu_graphics_rangej',
    'publish':'__ZL11gfx_publishPvPK21sgpu_graphics_commandjj',
    'invalidate_fence':'__ZL20gfx_invalidate_fencePv',
    'fence':'__ZL9gfx_fencePv',
    'faulted':'__ZL11gfx_faultedPv',
    'idle':'__ZL8gfx_idlePv',
    'now':'__ZL7gfx_nowPv',
    'wait':'__ZL8gfx_waitPvj',
}
CALLBACKS=tuple(CALLBACK_NAMES.values())
WIDE_CALLBACK_NAMES={**CALLBACK_NAMES,
    'validate':'__ZL16gfx_validate_ibsPvPK22sgpu_graphics_snapshotjPK21sgpu_graphics_commandjPK19sgpu_graphics_rangej'}
WIDE_HW=tuple('_sgpu_graphics_hw_'+n for n in
    ('legacy_reserved','vm_profile','base','pages','expected_ptes','live_ptes','fence_va','begin_owned','begin_vm'))
WIDE_PM4=tuple('_sgpu_pm4_'+n for n in
    ('state_check','state_span','state_data','state4','draw_shape','packet_shape'))
VM=tuple('_gvm_'+n for n in ('fail','memory_valid','prepare','verify','propose_l2','index'))
VM_ADAPTER=tuple('_sgpu_graphics_vm_'+n for n in ('owns','page','reserved','begin'))
VM_STORAGE=tuple('_sgpu_graphics_vm_'+n for n in ('kva','attempted','retained','owned'))
IR3=tuple('_sgpu_ir3_'+n for n in ('reg','constant','full_type','src2','src3','pending','synchronize','subset'))
DESCRIPTORS=('_sgpu_sampler_subset','_sgpu_texture_subset')
RASTER=tuple('_sgpu_raster_'+n for n in ('failure','index_for','have','all_lanes','owned','finite_viewport',
    'rectangle_inside','target','vertex','constants_ready','stage_ready','config_ready','check_state',
    'check_registers','check_draw','check_packet','policy','init','batch_run','prepare_batch','validate_batch'))
ADAPTER=('_sgpu_graphics_options','_santoni_gpu_graphics_worker_ready')
STORAGE=('_sgpu_graphics_enabled','_sgpu_graphics_published','_sgpu_graphics_hw','__ZL3gfx')
GLOBAL_CTORS=('__GLOBAL__sub_I_SantoniGraphics.cpp',)
RENDERER_TASK='__ZL17gfx_renderer_taskP4task'
DYLD_FLAGS='_santoni_gpu_graphics_dyld_flags'
DYLD_POLICY='_sweet_santoni_dyld_syscall'
DYLD_TRACE=('_santoni_gpu_dyld_trace_begin','_santoni_gpu_dyld_trace_event')
DYLD_REGISTER='_sweet_amfi_policy_register'
RENDERER_CALLERS=(
    '__ZN21SantoniGraphicsClient12initWithTaskEP4taskPvj',
    '__ZN21SantoniGraphicsClient19clientMemoryForTypeEjPjPP18IOMemoryDescriptor',
    '__ZN21SantoniGraphicsClient14externalMethodEjP25IOExternalMethodArgumentsP24IOExternalMethodDispatchP8OSObjectPv')
# Include the allocation/deletion wrappers and static initialization generated
# by OSDefineMetaClassAndStructors. Exact signatures exclude unknown methods.
IOKIT_METHODS=tuple(
    '__ZN'+c+s for c in ('15SantoniGraphics','21SantoniGraphicsClient') for s in
    ('C1EPK11OSMetaClass','C2EPK11OSMetaClass','C1Ev','C2Ev','D0Ev','D1Ev','D2Ev','nwEm','dlEPvm',
     '9MetaClassC1Ev','9MetaClassC2Ev','9MetaClassD0Ev','9MetaClassD1Ev'))+tuple(
    '__ZNK'+c+s for c in ('15SantoniGraphics','21SantoniGraphicsClient') for s in
    ('12getMetaClassEv','9MetaClass5allocEv'))+(
    '__ZN15SantoniGraphics5startEP9IOService',
    '__ZN21SantoniGraphicsClient12initWithTaskEP4taskPvj',
    '__ZN21SantoniGraphicsClient4freeEv',
    '__ZN21SantoniGraphicsClient11clientCloseEv',
    '__ZN21SantoniGraphicsClient19clientMemoryForTypeEjPjPP18IOMemoryDescriptor',
    '__ZN21SantoniGraphicsClient14externalMethodEjP25IOExternalMethodArgumentsP24IOExternalMethodDispatchP8OSObjectPv',
)


def helpers(names):
    import re
    found={n for n in names if n.startswith(('_sgpu_graphics_','_sgpu_pm4_','_gfx_','_gvm_','_sgpu_ir3_',
            '_sgpu_raster_','_sgpu_sampler_','_sgpu_texture_','_sgpu_descriptor_')) or
           re.match(r'^__ZL\d+gfx(?:_|$)',n) or n.startswith('_santoni_gpu_graphics_') or
           n.startswith('_santoni_gpu_dyld_trace_') or n==DYLD_POLICY or DYLD_FLAGS in names and n==DYLD_REGISTER}
    if not found:return ()
    wide='_sgpu_graphics_hw_begin_vm' in names or any(n.startswith(('_gvm_','_sgpu_ir3_','_sgpu_raster_')) for n in found)
    callbacks=tuple(WIDE_CALLBACK_NAMES.values()) if wide else CALLBACKS
    extra=WIDE_HW+WIDE_PM4+VM+VM_ADAPTER+IR3+DESCRIPTORS+RASTER if wide else ()
    renderer=RENDERER_TASK in names
    if renderer and not wide:raise ValueError('renderer helper requires the complete wide policy')
    if renderer:extra+=(RENDERER_TASK,)
    if DYLD_FLAGS in names:
        if not renderer:raise ValueError('dyld flags require the reviewed renderer helper')
        if any(len(names.get(n,()))!=1 for n in (DYLD_FLAGS,DYLD_POLICY,DYLD_REGISTER)):
            raise ValueError('renderer dyld policy boundaries missing/ambiguous')
        extra+=(DYLD_FLAGS,DYLD_POLICY,DYLD_REGISTER)
        if any(n.startswith('_santoni_gpu_dyld_trace_') for n in names):
            if any(len(names.get(n,()))!=1 for n in DYLD_TRACE):raise ValueError('dyld trace helper missing/ambiguous')
            extra+=DYLD_TRACE
    elif DYLD_POLICY in names:raise ValueError('renderer dyld policy missing flag boundary')
    expected=set(GRAPHICS+HW+PM4+callbacks+ADAPTER+STORAGE+extra+(VM_STORAGE if wide else ()))
    if found!=expected or any(len(names[n])!=1 for n in found):
        raise ValueError('graphics namespace missing/ambiguous/unreviewed: '+str(sorted(found^expected)))
    methods={n for n in names if n.startswith(('__ZN','__ZNK')) and 'SantoniGraphics' in n and not n.endswith('E')}
    if methods!=set(IOKIT_METHODS) or any(len(names[n])!=1 for n in methods):
        raise ValueError('graphics IOKit methods missing/ambiguous/unreviewed: '+str(sorted(methods^set(IOKIT_METHODS))))
    if any(len(names.get(n,()))!=1 for n in GLOBAL_CTORS):raise ValueError('graphics static initialization identity differs')
    return GRAPHICS+HW+PM4+callbacks+ADAPTER+extra+IOKIT_METHODS+GLOBAL_CTORS


def default_off(codes,image,names,e):
    if '_sgpu_graphics_options' not in codes:return None
    from santoni_gpu_stock_audit import _single_return
    V=e._Value;code=codes['_sgpu_graphics_options'];flag=V(64,next(iter(names['_sgpu_graphics_enabled'])))
    published=V(64,next(iter(names['_sgpu_graphics_published'])))
    if sum(op=='stlr' for op,args in code.ins.values())!=1:
        raise ValueError('graphics parser must have one actual release reset')
    class PublicationResetFlow(e._Flow):
        def step(self,pc,state):
            op,args=self.code.ins[pc]
            if op=='stlr':
                if len(args)!=2:raise ValueError('graphics reset instruction geometry differs')
                address,pre=state.address(args[1])
                if pre or address!=published or not args[0].startswith('w') or state.get(args[0])!=V(32,0):
                    raise ValueError('graphics parser release store differs from exact zero reset')
                state.store(address,4,V(32,0));return state
            return super().step(pc,state)
    parses=code.calls_to(names['_PE_parse_boot_argn'])
    if len(parses)!=1:raise ValueError('graphics parser must parse one exact opt-in')
    for mode in range(5):
        initial=e._initial(code.symbol);initial.put('w0',V(32,mode));initial.store(flag,4,V(32,1));initial.store(published,4,V(32,1))
        def parse(after,before):
            pointer,dest=before.get('x0'),before.get('x1');literal=b'santonigpu_graphics\0'
            if pointer is None or not isinstance(pointer.expr,int) or image.read(pointer.expr,len(literal))!=int.from_bytes(literal,'little') or before.get('x2')!=V(64,4) or before.load(dest,4,image)!=V(32,0):
                raise ValueError('graphics opt-in name/width/default differs')
            after.store(dest,4,V(32,0));after.put('w0',V(32,0))
        flow=PublicationResetFlow(code,image,names,initial=initial,effects={parses[0]:parse})
        if _single_return(flow,e)!=V(32,1):raise ValueError('absent graphics option rejects a legacy mode')
        for pc,state in flow.before.items():
            if code.ins[pc][0]=='ret' and state.load(flag,1,image)!=V(8,0):raise ValueError('absent graphics flag remains enabled')
            if code.ins[pc][0]=='ret' and state.load(published,4,image)!=V(32,0):raise ValueError('absent graphics option leaves worker published')
    return {'success':True,'global':flag.expr,'publication_global':published.expr,
            'release_reset_checked':True,'worker_acquire_getter':worker_getter(codes,image,names,e),
            'parsed_modes':list(range(5)),'graphics_flag':0,'hardware_verified':False}


def worker_getter(codes,image,names,e):
    from santoni_gpu_launcher_replay import LauncherMachine,require
    symbol='_santoni_gpu_graphics_worker_ready';address=next(iter(names['_sgpu_graphics_published']))
    rows=[]
    for value in (0,1,2,0xffffffff):
        vm=LauncherMachine({symbol:codes[symbol]},image,names,e)
        vm.memory.map(address,4);vm.memory.put(address,value);vm.memory.readonly.append((address,address+4))
        result=vm.run(symbol,(),budget=1000)
        require(result==e._Value(32,int(value==1)),'graphics worker getter readiness differs')
        require(len(vm.atomic_events)==1 and vm.atomic_events[0]['op']=='ldar' and
            vm.atomic_events[0]['address']==hex(address) and vm.atomic_events[0]['width']==32,
            'graphics worker getter must acquire the exact publication word')
        rows.append({'value':value,'ready':int(value==1),'atomic_events':vm.atomic_events})
    return {'success':True,'cases':rows,'hardware_verified':False}


def caller_boundary(codes,names):
    if not helpers(names):return None
    wide='_sgpu_graphics_hw_begin_vm' in names
    primitives=GRAPHICS+HW+PM4+(WIDE_HW+WIDE_PM4+VM+IR3+DESCRIPTORS+RASTER+VM_ADAPTER if wide else ())
    callbacks=tuple(WIDE_CALLBACK_NAMES.values()) if wide else CALLBACKS
    private={next(iter(names[n])) for n in primitives}
    if RENDERER_TASK in names:
        target=names[RENDERER_TASK]
        for caller,code in codes.items():
            if code.calls_to(target) and caller not in RENDERER_CALLERS+(DYLD_FLAGS,):
                raise ValueError('unreviewed executable-vnode authorization caller: '+caller)
        for caller in RENDERER_CALLERS:
            if caller not in codes or not codes[caller].calls_to(target):
                raise ValueError('renderer client method lacks executable-vnode authorization: '+caller)
        if DYLD_FLAGS in names:
            if DYLD_FLAGS not in codes or not codes[DYLD_FLAGS].calls_to(target):
                raise ValueError('dyld flags lack executable-vnode authorization')
            for caller,code in codes.items():
                if code.calls_to(names[DYLD_FLAGS]) and caller!=DYLD_POLICY:
                    raise ValueError('unreviewed renderer dyld flag caller: '+caller)
            if DYLD_POLICY not in codes or not codes[DYLD_POLICY].calls_to(names[DYLD_FLAGS]):
                raise ValueError('renderer dyld callback lacks flag authorization')
    if all(n in names for n in DYLD_TRACE):
        for caller,code in codes.items():
            if code.calls_to(names[DYLD_TRACE[0]]) and caller not in (DYLD_POLICY,RENDERER_TASK):
                raise ValueError('unreviewed dyld trace reservation caller: '+caller)
            if code.calls_to(names[DYLD_TRACE[1]]) and caller not in (DYLD_TRACE[0],RENDERER_TASK):
                raise ValueError('unreviewed dyld trace event caller: '+caller)
    for n,c in codes.items():
        if wide and n in VM+IR3+DESCRIPTORS+RASTER:
            hardware={next(iter(names[target])) for target in GRAPHICS+HW+WIDE_HW+VM_ADAPTER}
            if c.calls_to(hardware):raise ValueError('portable GPU policy calls a hardware/BO producer: '+n)
        if n in GRAPHICS+HW+PM4+callbacks+IOKIT_METHODS+GLOBAL_CTORS+(WIDE_HW+WIDE_PM4+VM+IR3+DESCRIPTORS+RASTER if wide else ()):continue
        allowed=set()
        if n=='_sgpu_render_worker':
            target='_sgpu_graphics_vm_begin' if wide else '_sgpu_graphics_hw_begin'
            allowed={next(iter(names[target])),next(iter(names['_sgpu_graphics_hw_snapshot']))}
        if wide:
            roles={'_sgpu_graphics_vm_begin':('_sgpu_graphics_hw_begin_vm',),
                   '_sgpu_graphics_vm_page':('_sgpu_graphics_vm_owns',),
                   '_sgpu_graphics_vm_reserved':('_sgpu_graphics_hw_legacy_reserved',)}
            allowed.update(next(iter(names[target])) for target in roles.get(n,()))
        if c.calls_to(private-allowed):raise ValueError('unreviewed graphics API caller: '+n)
    return {'default_off_client_requires_dedicated_audit':True,
        'kernel_owned_policy_and_snapshots_require_dedicated_audit':True,
        'dedicated_graphics_binary_audit_required':True,'hardware_verified':False,'GLES_enabled':False,
        'renderer_identity_helper_present':RENDERER_TASK in names,'renderer_client_wiring_verified':False}
