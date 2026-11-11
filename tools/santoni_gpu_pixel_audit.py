"""Decoded wiring for the separate stock-pixel opt-in; not hardware proof."""
from itertools import product

HELPERS=('_sgpu_pixel_options','_sgpu_stock_pixels_test','_sgpu_pixel_fence')

def pixel_fence(code,image,names,e):
    """Replay decoded instructions with mocked cache/clock callbacks only.

    No branch with an unknown predicate is admitted. The actual loop must
    terminate on both its deadline and read cap; no hardware claim follows.
    """
    V=e._Value
    checks=0
    for ready,stalled,expired,prior in ((1,False,False,0),(4,False,False,0),
            (2001,True,False,0),(2002,True,False,0),(2002,False,True,0),
            (2002,True,False,12)):
        state=e._initial(code.symbol)
        base=V(64,('probe',0x10000)); fence=V(64,('probe',0x14300))
        state.store(V(64,('probe',16)),8,base)
        state.store(V(64,('report',4)),4,V(32,prior))
        state.store(fence,4,V(32,0))
        flow=e._Flow(code,image,names,initial=state,stops=(code.entry,))
        pc=code.entry; reads=waits=clocks=0
        for step in range(160000):
            op,args=code.ins[pc]
            if op=='ret': break
            target=None
            if op in ('bl','blr','br') or op=='b' and e._number(args[-1]) not in code.ins:
                target=flow.call(pc,state)
                if target not in (('callback',48),('callback',56),('callback',88),('callback',96)):
                    raise ValueError('unexpected pixel fence callee')
                if state.get('x0')!=V(64,('ctx',0)):
                    raise ValueError('pixel fence callback context differs')
                if target==('callback',88):
                    if state.get('x1')!=fence or state.get('w2')!=V(32,64):
                        raise ValueError('pixel fence invalidation is not the owned cache line')
                    reads+=1
                if target==('callback',56):
                    if state.get('w1')!=V(32,100): raise ValueError('pixel fence wait differs')
                    waits+=1
            successors=code.succ[pc]
            if code.conditional(op):
                truth=state.truth(flow.predicate(pc,state))
                if truth is None: raise ValueError('unknown pixel fence branch')
                successors=(e._number(args[-1]) if truth else pc+4,)
            state=flow.step(pc,state.copy())
            if target==('callback',88): state.store(fence,4,V(32,0xa5052d01 if reads>=ready else 0))
            if target==('callback',48):
                state.put('x0',V(64,1000+(0 if stalled else 200000 if expired and clocks else waits*100)))
                clocks+=1
            if len(successors)!=1: raise ValueError('pixel fence path has no concrete successor')
            pc=successors[0]
        else: raise ValueError('pixel fence exceeded decoded execution cap')
        passed=ready<=2001 and not expired
        want_reads=ready if passed else 1 if expired else 2001
        if state.get('w0')!=V(32,int(passed)) or reads!=want_reads or waits!=want_reads-1:
            raise ValueError('pixel fence value/deadline/read cap differs')
        if state.load(V(64,('report',4)),4,image)!=V(32,prior if passed or prior else 11):
            raise ValueError('pixel fence hides a prior error or omits timeout')
        checks+=1
    return checks

def pixel_options(entry,image,names,e,sg):
    from santoni_gpu_stock_audit import _single_return
    V,at=e._Value,e._scm_at
    calls=entry.calls_to(names['_PE_parse_boot_argn'])
    if len(calls)!=1: raise ValueError('pixel option must be independently parsed')
    pc=calls[0]
    for mode,stock,pixels in product(range(5),(0,1,2),(0,1,2,0xffffffff)):
        state=e._initial(entry.symbol); state.put('w0',V(32,mode))
        state.store(at(sg,88),4,V(32,stock)); state.store(at(sg,96),4,V(32,1))
        def parse(after,before):
            name=before.get('x0'); dest=before.get('x1'); literal=b'santonigpu_pixels\0'
            if (before.get('x2')!=V(64,4) or name is None or not isinstance(name.expr,int) or
                    image.read(name.expr,len(literal))!=int.from_bytes(literal,'little') or dest is None or
                    not isinstance(dest.expr,tuple) or dest.expr[0]!='stack'):
                raise ValueError('pixel option name/width/storage differs')
            after.store(dest,4,V(32,pixels))
        flow=e._Flow(entry,image,names,initial=state,effects={pc:parse})
        enabled=mode==3 and stock==1 and pixels==1
        if _single_return(flow,e)!=V(32,int(pixels==0 or enabled)):
            raise ValueError('pixel option exclusion differs')
        for q,s in flow.before.items():
            if entry.ins[q][0]=='ret' and s.load(at(sg,96),4,image)!=V(32,int(enabled)):
                raise ValueError('pixel option not reset/exactly enabled')
    return True

def audit_pixels(codes,image,names,e):
    if not any(name in codes for name in HELPERS): return None
    if any(name not in codes for name in (*HELPERS,'_render_test','_consume')):
        raise ValueError('pixel helper boundaries missing')
    V,at=e._Value,e._scm_at
    sites=lambda flow,symbols:e._scm_sites(flow,symbols)
    bootstrap = '_sgpu_bootstrap' if '_sgpu_bootstrap' in codes else '_sgpu_probe'
    parents={HELPERS[0]:('_sgpu_kernel_thread',),HELPERS[1]:(bootstrap,),
             HELPERS[2]:('_render_test',),
             '_render_test':(bootstrap,HELPERS[1]),'_consume':(bootstrap,'_marker_test','_render_test','_sgpu_g3_test')}
    if '_sgpu_render_live_start' in codes:
        parents['_consume'] += ('_sgpu_render_live_job',)
    if '_sgpu_ui_submit' in codes:
        parents['_consume'] += ('_sgpu_ui_submit',) # same guarded ring publication; own UI proof required
    for caller,code in codes.items():
        for callee,allowed in parents.items():
            if caller not in allowed and code.calls_to(names.get(callee,())):
                raise ValueError('unreviewed pixel-layer caller: '+caller+' -> '+callee)
    if len(names.get('_sg',()))!=1: raise ValueError('pixel adapter state identity missing')
    sg=V(64,next(iter(names['_sg'])))
    pixel_options(codes[HELPERS[0]],image,names,e,sg)
    fence_cases=pixel_fence(codes[HELPERS[2]],image,names,e)
    worker=codes['_sgpu_kernel_thread']; running=e._Flow(worker,image,names)
    hooks=sites(running,(HELPERS[0],))
    if len(hooks)!=1: raise ValueError('pixel worker hook missing')
    pc=hooks[0]
    for valid in (0,1):
        after=running.step(pc,running.before[pc].copy()); after.put('w0',V(32,valid))
        after.store(at(sg,96),4,V(32,1))
        flow=e._Flow(worker,image,names,pc+4,after)
        later=sites(flow,('_sgpu_pas_cache_preflight','_sgpu_scm_capability_probe','_sgpu_zap_allocation_preflight',*e._gpu_entries(names)))
        if not valid and (later or not sites(flow,('_thread_terminate_self',))):
            raise ValueError('invalid pixel option reaches hardware')
        if valid:
            probe_calls=sites(flow,e._gpu_entries(names))
            if not probe_calls or any(flow.before[q].load(at(flow.before[q].get('x0'),108),4,image)!=V(32,1) for q in probe_calls):
                raise ValueError('pixel option lost in worker Ops')

    probe=codes[bootstrap]; running=e._Flow(probe,image,names)
    transition=sites(running,('_sgpu_stock_transition',))
    if len(transition)!=1: raise ValueError('pixel path lacks stock transition')
    pc=transition[0]
    for transitioned,pixels in product((0,1),(0,1,2)):
        state=running.step(pc,running.before[pc].copy()); state.put('w0',V(32,transitioned))
        state.store(V(64,('ops',108)),4,V(32,pixels))
        flow=e._Flow(probe,image,names,pc+4,state)
        if len(sites(flow,(HELPERS[1],)))!=int(transitioned==1 and pixels==1):
            raise ValueError('pixel caller bypasses transition result/independent opt-in')

    pixel=codes[HELPERS[1]]
    first=e._initial(pixel.symbol); first.put('w1',V(32,3))
    wptr=V(64,('probe',0x5000)); first.put('x2',wptr); first.store(wptr,4,V(32,75))
    first.store(V(64,('probe',16)),8,V(64,0x98001000))
    first.store(V(64,('probe',24)),8,V(64,0x98000000))
    for off in range(732,741): first.store(V(64,('probe',off)),1,V(8,int(off!=735)))
    first.store(V(64,('report',0)),176,V(1408,0))
    first.store(V(64,('report',4)),4,V(32,16)); first.store(V(64,('report',8)),4,V(32,16))
    for off in (169,170,171,172): first.store(V(64,('report',off)),1,V(8,1))
    for off in (104,108): first.store(V(64,('ops',off)),4,V(32,1))
    discovered=e._Flow(pixel,image,names,initial=first)
    allowed={address for name in ('_sgpu_memory_validate','_sgpu_failure','_poll','_sgpu_stock_check32','_faults','_render_test')
             for address in names.get(name,())}
    for q,s in discovered.before.items():
        op,args=pixel.ins[q]
        if op in ('smc','hvc'): raise ValueError('unexpected secure call in pixel helper')
        if op in ('bl','blr','br') or op=='b' and e._number(args[-1]) not in pixel.ins:
            target=discovered.call(q,s)
            if target not in allowed and target not in (('callback',16),('callback',96)):
                raise ValueError('unexpected pixel helper hardware/callee')
    expected=[(4,0x2018,75),(4,0x201c,75),(4,0x20c8,0),(4,0xe0,0),
        (4,0x2000,0x1020000),(4,0x2004,0),(4,0x2008,0x08000209),
        (4,0x20e0,0x1000000),(4,0x20e4,0),(4,0x20d4,0x1010000),(4,0x20d8,0),
        (5,0x8000,0x1127),(5,0xc00,0),(5,0x1800,1),(5,0x1000,0x1f300),
        (5,0x8030,0x00802560),(5,0x8010,0x38010),(5,0x8038,0xff44),(5,0x803c,0),
        (5,0x8020,0x98000000),(5,0x8024,0x10000)]
    guards=sites(discovered,('_sgpu_stock_check32',))
    renders=sites(discovered,('_render_test',)); faults=sites(discovered,('_faults',))
    polls=sites(discovered,('_poll',))
    if len(guards)!=21 or len(renders)!=1 or len(faults)!=2 or len(polls)!=1:
        raise ValueError('pixel readiness/render/fault wiring incomplete')
    for q,want in zip(guards,expected):
        if tuple(discovered.before[q].get('w'+str(i)) for i in (1,2,3))!=tuple(V(32,v) for v in want):
            raise ValueError('pixel readiness register/value differs')
    if tuple(discovered.before[polls[0]].get('w'+str(i)) for i in range(1,6))!=(V(32,4),V(32,0x13d4),V(32,0xfffffffe),V(32,0),V(32,10000)):
        raise ValueError('pixel strict idle budget/mask differs')
    edges=e._controlled_calls(pixel,image,names,'_sgpu_stock_check32',false_return=True,
                              forbidden=('_sgpu_stock_check32','_render_test'))
    edges+=e._controlled_calls(pixel,image,names,'_poll',false_return=True,forbidden=('_render_test',))
    edges+=e._controlled_calls(pixel,image,names,'_render_test',false_return=True,forbidden=('_faults',))
    # Replay decoded gates with controlled callback/helper results. This is
    # wiring proof only; native contracts exercise the real rendering algorithm.
    def run_case(trust=0,render_ok=True,render_error=0,bad_fault=None,state=None):
        effects={}
        for q,before in discovered.before.items():
            if pixel.ins[q][0] not in ('bl','blr','br'): continue
            target=discovered.call(q,before)
            def effect(after,before,t=target,q=q):
                if t==('callback',16):
                    if (before.get('w1'),before.get('w2'))!=(V(32,4),V(32,0x3d000)):
                        raise ValueError('unexpected direct pixel MMIO read')
                    if any(before.load(V(64,('report',off)),1,image)!=V(8,1) for off in (171,173)):
                        raise ValueError('pixel held/start flags missing before post-transition access')
                    after.put('w0',V(32,trust))
                elif t in names.get('_render_test',()):
                    after.put('w0',V(32,int(render_ok)))
                    after.store(V(64,('report',24)),4,V(32,256 if render_ok else 0))
                    after.store(V(64,('report',4)),4,V(32,render_error))
                elif any(t in names.get(n,()) for n in ('_sgpu_memory_validate','_poll','_sgpu_stock_check32')):
                    after.put('w0',V(32,1))
                elif t in names.get('_faults',()) and bad_fault and q==faults[bad_fault[0]]:
                    after.store(V(64,('report',bad_fault[1])),4,V(32,bad_fault[2]))
            effects[q]=effect
        return e._Flow(pixel,image,names,initial=first if state is None else state,effects=effects)
    for trust in (0,1,0xffffffff):
        flow=run_case(trust=trust)
        if len(sites(flow,('_render_test',)))!=int(trust==0) or not flow.returns(int(trust==0)):
            raise ValueError('pixel live TRUST gate differs')
        for q,s in flow.before.items():
            if pixel.ins[q][0]=='ret':
                if s.load(V(64,('report',174)),1,image)!=V(8,int(trust==0)):
                    raise ValueError('pixel pass report is not tied to rendering success')
    for ok,error in ((False,0),(False,11),(False,12)):
        flow=run_case(render_ok=ok,render_error=error)
        if not flow.returns(0): raise ValueError('pixel failed render returned success')
        for q,s in flow.before.items():
            if pixel.ins[q][0]=='ret' and s.load(V(64,('report',4)),4,image)!=V(32,error or 13):
                raise ValueError('pixel retention hides the first render failure')
    for phase,offset,value in product((0,1),(32,36,40),(2,)):
        flow=run_case(bad_fault=(phase,offset,value))
        if not flow.returns(0) or len(sites(flow,('_render_test',)))!=phase:
            raise ValueError('pixel fault guard bypassed')
    for location,size,value in ((('ops',108),4,0),(('ops',104),4,0),
            (('report',4),4,12),(('report',64),4,1),(('report',170),1,0)):
        invalid=first.copy(); invalid.store(V(64,location),size,V(size*8,value))
        flow=run_case(state=invalid)
        if sites(flow,('_render_test','_sgpu_stock_check32','_poll')) or not flow.returns(0):
            raise ValueError('pixel private entry gate bypassed')

    consume=codes['_consume']; begin=e._initial(consume.symbol); begin.put('w1',V(32,148))
    begin.store(V(64,('report',173)),1,V(8,1))
    submitted=e._Flow(consume,image,names,initial=begin)
    writes=sites(submitted,('_checked_write32',))
    if len(writes)!=1: raise ValueError('pixel WPTR must have one checked write')
    q=writes[0]
    if tuple(submitted.before[q].get('w'+str(i)) for i in range(1,5))!=(V(32,4),V(32,0x201c),V(32,0xffffffff),V(32,148)):
        raise ValueError('pixel WPTR full echo/word count differs')
    for pc,s in submitted.before.items():
        if consume.ins[pc][0] in ('blr','br') and submitted.call(pc,s)==('callback',32):
            raise ValueError('pixel WPTR has an unchecked direct write')
    edges+=e._controlled_calls(consume,image,names,'_checked_write32',false_return=True,forbidden=('_poll',))

    render=codes['_render_test']
    edges+=e._controlled_calls(render,image,names,'_consume',false_return=True)
    edges+=e._controlled_calls(render,image,names,HELPERS[2],false_return=True)
    rf=e._Flow(render,image,names)
    if len(sites(rf,('_sgpu_blit_commands',)))!=1 or len(sites(rf,('_consume',)))!=1:
        raise ValueError('fixed pixel command/consume wiring differs')
    if len(sites(rf,(HELPERS[2],)))!=1:
        raise ValueError('bounded pixel fence wait missing')
    invalidates=[q for q,s in rf.before.items() if render.ins[q][0] in ('blr','br') and rf.call(q,s)==('callback',88)]
    if len(invalidates)!=2: raise ValueError('pixel fence/result invalidations missing')

    # The caller must retain state after an entered pixel test, including when
    # TRUST was already zero and no security write was attempted.
    running=e._Flow(probe,image,names)
    pixel_calls=sites(running,(HELPERS[1],))
    if len(pixel_calls)!=1: raise ValueError('pixel core hook missing')
    q=pixel_calls[0]; before=running.before[q]
    for attempted in (0,1):
        after=running.step(q,before.copy()); after.put('w0',V(32,0))
        after.store(V(64,('report',169)),1,V(8,attempted))
        after.store(V(64,('report',173)),1,V(8,1))
        after.store(V(64,('ops',112)),4,V(32,0)) # pixel-only role, not the separately audited G3 continuation
        after.store(at(before.get('x0'),728),4,V(32,13))
        flow=e._Flow(probe,image,names,q+4,after)
        if sites(flow,('_sgpu_a505_halt','_sgpu_a505_resume','_sgpu_smmu_restore','_sgpu_restore_power','_faults')):
            raise ValueError('pixel end path attempts hardware cleanup')
        for pc,s in flow.before.items():
            if probe.ins[pc][0] in ('blr','br') and flow.call(pc,s)!=('callback',96):
                raise ValueError('pixel end path performs further hardware callbacks')
            if probe.ins[pc][0]=='ret':
                for off,size,want in ((56,1,1),(57,1,0),(59,1,0),(60,1,0),(52,4,13)):
                    if s.load(V(64,('report',off)),size,image)!=V(size*8,want):
                        raise ValueError('pixel end path lost retention fields')
        if not flow.returns(0): raise ValueError('pixel held state claims overall clean success')
    return {'independent_mode3_stock1_pixels1':True,'readiness_checks':len(guards),
            'checked_failure_edges':edges,'live_TRUST_and_fault_guards':True,
            'checked_WPTR':hex(writes[0]),'fence_and_pixel_invalidation_sites':[hex(q) for q in invalidates],
            'bounded_fence_decoded_cases':fence_cases,
            'state_retained_without_cleanup':True,'hardware_rendering_verified':False}
