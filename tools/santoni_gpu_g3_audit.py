"""G3 kernel-only wiring checks. Not a user-IB isolation or hardware certificate."""
from itertools import product

HELPERS=('_sgpu_g3_options','_sgpu_g3_prepare','_sgpu_g3_test','_sgpu_g3_wait',
         '_sgpu_g3_init','_sgpu_g3_new','_sgpu_g3_free','_sgpu_g3_begin','_sgpu_g3_complete','_sgpu_g3_abort')

def g3_options(code,image,names,e,sg):
    from santoni_gpu_stock_audit import _single_return
    V,at=e._Value,e._scm_at
    calls=code.calls_to(names['_PE_parse_boot_argn'])
    if len(calls)!=1: raise ValueError('G3 option parser missing')
    for mode,stock,pixels,g3 in product(range(5),(0,1,2),(0,1,2),(0,1,2,0xffffffff)):
        state=e._initial(code.symbol);state.put('w0',V(32,mode))
        for offset,value in ((88,stock),(96,pixels),(100,1)):state.store(at(sg,offset),4,V(32,value))
        def parse(after,before):
            literal=b'santonigpu_submit\0';address=before.get('x0');dest=before.get('x1')
            if address is None or not isinstance(address.expr,int) or before.get('x2')!=V(64,4) or (
                image.read(address.expr,len(literal))!=int.from_bytes(literal,'little')) or dest is None or (
                not isinstance(dest.expr,tuple) or dest.expr[0]!='stack'):
                raise ValueError('G3 option literal/storage/width differs')
            after.store(dest,4,V(32,g3))
        flow=e._Flow(code,image,names,initial=state,effects={calls[0]:parse})
        enabled=mode==3 and stock==pixels==g3==1
        if _single_return(flow,e)!=V(32,int(not g3 or enabled)):raise ValueError('G3 option bypass')
        for q,s in flow.before.items():
            if code.ins[q][0]=='ret' and s.load(at(sg,100),4,image)!=V(32,int(enabled)):
                raise ValueError('G3 option was not reset/exactly enabled')
    return True

def g3_fence(code,image,names,e):
    V=e._Value
    for ready,expired,prior in ((1,False,0),(4,False,0),(2001,False,0),
                              (2002,False,0),(2002,True,0),(2002,False,12)):
        state=e._initial(code.symbol);fence=V(64,('probe',0x13000))
        state.put('x1',fence);state.put('w2',V(32,7))
        state.store(V(64,('report',4)),4,V(32,prior));state.store(fence,4,V(32,0))
        flow=e._Flow(code,image,names,initial=state,stops=(code.entry,))
        pc=code.entry;reads=waits=clocks=0
        for _ in range(160000):
            op,args=code.ins[pc]
            if op=='ret':break
            target=None
            if op in ('bl','blr','br') or op=='b' and e._number(args[-1]) not in code.ins:
                target=flow.call(pc,state)
                if target not in (('callback',48),('callback',56),('callback',88)):
                    raise ValueError('unexpected G3 fence callee')
                if state.get('x0')!=V(64,('ctx',0)):raise ValueError('G3 fence callback context differs')
                if target==('callback',88):
                    if state.get('x1')!=fence or state.get('w2')!=V(32,64):raise ValueError('G3 fence line differs')
                    reads+=1
                if target==('callback',56):
                    if state.get('w1')!=V(32,100):raise ValueError('G3 fence delay differs')
                    waits+=1
            successors=code.succ[pc]
            if code.conditional(op):
                truth=state.truth(flow.predicate(pc,state))
                if truth is None:raise ValueError('unknown G3 fence condition')
                successors=(e._number(args[-1]) if truth else pc+4,)
            state=flow.step(pc,state.copy())
            if target==('callback',88):state.store(fence,4,V(32,7 if reads>=ready else 0))
            if target==('callback',48):
                state.put('x0',V(64,200000 if expired and clocks else 0));clocks+=1
            if len(successors)!=1:raise ValueError('G3 fence execution left decoded scope')
            pc=successors[0]
        else:raise ValueError('G3 fence execution budget exceeded')
        passed=ready<=2001 and not expired;want=ready if passed else 1 if expired else 2001
        if state.get('w0')!=V(32,7 if passed else 0) or reads!=want or waits!=want-1:
            raise ValueError('G3 fence sequence/time/read count differs')
        if state.load(V(64,('report',4)),4,image)!=V(32,prior if passed or prior else 11):
            raise ValueError('G3 fence timeout/prior-error contract differs')
    return 6

def audit_g3(codes,image,names,e):
    if not any(name in codes for name in HELPERS):return None
    if any(name not in codes for name in HELPERS):raise ValueError('G3 boundaries missing')
    V,at=e._Value,e._scm_at
    sites=lambda flow,targets:e._scm_sites(flow,targets)
    g3_options(codes[HELPERS[0]],image,names,e,V(64,next(iter(names['_sg']))))
    fence_cases=g3_fence(codes['_sgpu_g3_wait'],image,names,e)
    bootstrap = '_sgpu_bootstrap' if '_sgpu_bootstrap' in codes else '_sgpu_probe'
    parents={'_sgpu_g3_options':('_sgpu_kernel_thread',),'_sgpu_g3_prepare':(bootstrap,),
             '_sgpu_g3_test':(bootstrap,),'_sgpu_g3_wait':('_sgpu_g3_test',),
             '_sgpu_g3_init':('_sgpu_g3_prepare',),'_sgpu_g3_new':('_sgpu_g3_prepare',),
             '_sgpu_g3_free':('_sgpu_g3_prepare',),'_sgpu_g3_begin':('_sgpu_g3_test',),
             '_sgpu_g3_complete':('_sgpu_g3_test',),'_sgpu_g3_abort':('_sgpu_g3_test',)}
    if bootstrap == '_sgpu_bootstrap':
        for name in ('_sgpu_g3_begin', '_sgpu_g3_complete'):
            parents[name] += ('_sgpu_session_execute',)
        # AppleClang inlines session_fail at these worker-only failure sites.
        parents['_sgpu_g3_abort'] += ('_session_fail', '_session_time', '_session_check',
            '_session_poll', '_session_readiness', '_sgpu_session_prepare', '_sgpu_session_execute')
    for caller,code in codes.items():
        for callee,allowed in parents.items():
            if caller not in allowed and code.calls_to(names[callee]):
                raise ValueError('unreviewed G3 caller: ' + caller + ' -> ' + callee)
    worker=codes['_sgpu_kernel_thread'];flow=e._Flow(worker,image,names)
    hooks=sites(flow,('_sgpu_g3_options',))
    if len(hooks)!=1:raise ValueError('G3 worker hook missing')
    pc=hooks[0];sg=V(64,next(iter(names['_sg'])))
    for enabled in (0,1):
        state=flow.step(pc,flow.before[pc].copy());state.put('w0',V(32,enabled));state.store(at(sg,100),4,V(32,1))
        after=e._Flow(worker,image,names,pc+4,state)
        later=sites(after,('_sgpu_pas_cache_preflight','_sgpu_scm_capability_probe','_sgpu_zap_allocation_preflight',*e._gpu_entries(names)))
        if not enabled and (later or not sites(after,('_thread_terminate_self',))):raise ValueError('invalid G3 reaches hardware')
        if enabled:
            calls=sites(after,e._gpu_entries(names))
            if not calls or any(after.before[q].load(at(after.before[q].get('x0'),112),4,image)!=V(32,1) for q in calls):
                raise ValueError('G3 option lost before core')
    probe=codes[bootstrap];flow=e._Flow(probe,image,names)
    prepares=sites(flow,('_sgpu_g3_prepare',));pixels=sites(flow,('_sgpu_stock_pixels_test',))
    if len(prepares)!=1 or len(pixels)!=1:raise ValueError('G3 preparation/pixel prerequisite missing')
    for q in sites(flow,('_sgpu_power',)):
        if prepares[0] in probe.walk(q+4):raise ValueError('G3 mappings can change after power start')
    for passed,option in product((0,1),(0,1,2)):
        pc=pixels[0];state=flow.step(pc,flow.before[pc].copy());state.put('w0',V(32,passed))
        state.store(V(64,('ops',112)),4,V(32,option))
        after=e._Flow(probe,image,names,pc+4,state)
        if len(sites(after,('_sgpu_g3_test',)))!=int(passed==option==1):raise ValueError('G3 bypasses pixel result/opt-in')
    edges=e._controlled_calls(probe,image,names,'_sgpu_g3_prepare',forbidden=('_sgpu_power','_sgpu_smmu_start'))
    test=codes['_sgpu_g3_test'];running=e._Flow(test,image,names)
    for callee,forbidden in (('_sgpu_g3_begin',('_consume','_sgpu_g3_wait','_sgpu_g3_complete')),
            ('_consume',('_sgpu_g3_wait','_sgpu_g3_complete')),('_sgpu_g3_wait',('_sgpu_g3_complete',)),
            ('_sgpu_g3_complete',('_consume',)),('_sgpu_stock_check32',('_consume',)),('_poll',('_consume',))):
        edges+=e._controlled_calls(test,image,names,callee,false_return=True,forbidden=forbidden)
    for callee in ('_consume','_sgpu_g3_begin','_sgpu_g3_wait','_sgpu_g3_complete'):
        if len(sites(running,(callee,)))!=1:raise ValueError('G3 submit/fence loop wiring incomplete')
    if sites(running,('_sgpu_a505_halt','_sgpu_smmu_restore','_sgpu_restore_power','_sgpu_g3_free')):
        raise ValueError('G3 continuation performs cleanup')
    for q,state in running.before.items():
        if test.ins[q][0] in ('blr','br') and running.call(q,state) not in (('callback',80),('callback',88),('callback',96)):
            raise ValueError('unchecked G3 hardware callback')
    # New private roots contain no secure instructions; descendant ISA and
    # MMIO helper checks are covered by the enclosing actual-kernel audit.
    for name in HELPERS:
        if any(op in ('smc','hvc') for op,args in codes[name].ins.values()):raise ValueError('secure call in G3')
    return {'mode3_stock_pixels_G3_opt_in_checked':True,'cold_mapping_before_power':True,
            'pixel_success_prerequisite':True,'checked_failure_edges':edges,
            'bounded_sequence_fence_cases':fence_cases,'no_cleanup_calls':True,
            'scope':'fixed kernel-only caller wiring; owner/IB contracts host-tested, not user isolation',
            'hardware_submission_verified':False}
