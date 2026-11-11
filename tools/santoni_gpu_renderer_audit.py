"""Replay compiled renderer identity checks with explicit XNU VFS contracts.

Inputs must contain the actual helper instruction graph and image bytes.
Platform responses are modeled. This helper-only check never authorizes an
IOKit client role, packaging or hardware rendering by itself.
"""
from santoni_gpu_binary_model import integer
from santoni_gpu_launcher_replay import LauncherMachine,require

RENDERER='__ZL17gfx_renderer_taskP4task'
EXTERNALS=('_current_proc','_current_task','_proc_task','_proc_pid','_proc_getuid',
    '_proc_getexecutablevnode','_vnode_lookup','_vnode_vtype','_vnode_getattr','_vnode_put')
TRACE_BEGIN='_santoni_gpu_dyld_trace_begin'
TRACE_EVENT='_santoni_gpu_dyld_trace_event'
ATTR_SUPPORTED=0;ATTR_ACTIVE=8;ATTR_FLAGS=16;ATTR_UID=68;ATTR_MODE=76;ATTR_SPAN=440
WANTED=(1<<7)|(1<<9)

def audit_renderer_task(codes,image,names,e):
    require(RENDERER in codes,'renderer identity helper missing')
    contexts=[n for n in ('_vfs_context_kernel','_vfs_context_current')
        if len(names.get(n,()))==1 and codes[RENDERER].calls_to(names[n])]
    require(len(contexts)==1,'renderer must use exactly one reviewed VFS context')
    context_symbol=contexts[0]
    traced=bool(codes[RENDERER].calls_to(names.get(TRACE_BEGIN,())))
    abi=(*EXTERNALS,context_symbol,*((TRACE_BEGIN,TRACE_EVENT) if traced else ()))
    require(all(len(names.get(n,()))==1 for n in (RENDERER,*abi)),
        'renderer identity helper/ABI symbols missing or ambiguous')
    task,other_task,process,exe,other_exe,context=(0x81000000,0x81000100,0x81000200,0x81000300,0x81000400,0x81000500)
    base={'owner':task,'current':task,'process':process,'process_task':task,'pid':42,'uid':501,
        'exe':exe,'context':context,'lookup':0,'expected':exe,'vtype':1,'getattr':0,
        'supported':WANTED,'file_uid':0,'mode':0o755}
    cases=[('valid',{},True),('readonly',{'mode':0o555},True),
        ('null-owner',{'owner':0},False),('other-task',{'current':other_task},False),
        ('no-process',{'process':0},False),('other-process-task',{'process_task':other_task},False),
        ('zero-pid',{'pid':0},False),('negative-pid',{'pid':-1},False),
        ('root-process',{'uid':0},False),('other-uid',{'uid':502},False),
        ('no-executable',{'exe':0},False),('no-current-context',{'context':0},False),
        ('lookup-error',{'lookup':2,'expected':0},False),('lookup-error-with-ref',{'lookup':2},False),
        ('empty-lookup',{'expected':0},False),('other-executable',{'expected':other_exe},False),
        ('directory',{'vtype':2},False),('attribute-error',{'getattr':5},False),
        ('missing-uid',{'supported':1<<9},False),('missing-mode',{'supported':1<<7},False),
        ('user-owned',{'file_uid':501},False),('group-write',{'mode':0o775},False),
        ('other-write',{'mode':0o757},False)]
    rows=[]
    for label,changes,expected in cases:
        values={**base,**changes};held={};calls=[];events=[]
        vm=LauncherMachine({RENDERER:codes[RENDERER]},image,names,e)
        def hold(vnode):held[vnode]=held.get(vnode,0)+1
        def external(address,state,probe=False,before=None):
            name=vm.by_address.get(address)
            if probe:return name in abi
            require(name in abi,'renderer calls unreviewed platform ABI: '+str(name))
            args=[before.get('x'+str(i)) for i in range(4)];calls.append(name)
            def arg(i):return integer(before,'x'+str(i))
            def result(value,width=64):state.put('x0' if width==64 else 'w0',e._Value(width,value&((1<<width)-1)))
            if name==TRACE_BEGIN:
                require(arg(0)==values['process'] and arg(1)==1 and values['uid']==501 and
                    '_proc_getexecutablevnode' not in calls,'renderer trace precedes caller checks or follows vnode acquisition')
                result(129)
            elif name==TRACE_EVENT:
                require(arg(0)==values['process'] and arg(1)==129,'renderer trace process/reservation differs')
                events.append((arg(2),arg(3)&0xffffffff));result(0xfffffff7,32)
            elif name=='_current_proc':result(values['process'])
            elif name=='_current_task':result(values['current'])
            elif name in ('_proc_task','_proc_pid','_proc_getuid','_proc_getexecutablevnode'):
                require(arg(0)==values['process'] and values['process']!=0,'renderer process argument differs')
                if name=='_proc_task':result(values['process_task'])
                elif name=='_proc_pid':result(values['pid'],32)
                elif name=='_proc_getuid':result(values['uid'],32)
                else:
                    if values['exe']:hold(values['exe'])
                    result(values['exe'])
            elif name==context_symbol:result(values['context'])
            elif name=='_vnode_lookup':
                literal=b'/usr/libexec/backboardd\0'
                require(image.read(arg(0),len(literal))==int.from_bytes(literal,'little') and arg(1)==1 and
                    arg(3)==values['context'] and values['context']!=0,'renderer lookup path/flags/context differs')
                require(vm.memory.get(arg(2),8)==0,'renderer expected-vnode output was not initialized')
                vm.memory.put(arg(2),values['expected'],8)
                if values['expected']:hold(values['expected'])
                result(values['lookup'],32)
            elif name=='_vnode_vtype':
                require(arg(0)==values['expected']==values['exe'] and held.get(arg(0),0)>0,'renderer vtype on unowned/wrong executable')
                result(values['vtype'],32)
            elif name=='_vnode_getattr':
                require(arg(0)==values['expected']==values['exe'] and arg(2)==values['context'],'renderer getattr vnode/context differs')
                attr=arg(1);region=vm.memory.locate(attr,ATTR_SPAN)
                require(region is not None and integer(before,'sp')<=attr and
                    attr+ATTR_SPAN<=vm.STACK+vm.STACK_SIZE,'renderer attribute buffer exceeds active stack span')
                require(vm.memory.get(attr+ATTR_SUPPORTED,8)==0 and vm.memory.get(attr+ATTR_ACTIVE,8)==WANTED and
                    vm.memory.get(attr+ATTR_FLAGS,4)==0,'renderer requested attributes differ')
                vm.memory.put(attr+ATTR_SUPPORTED,values['supported'],8)
                vm.memory.put(attr+ATTR_UID,values['file_uid'],4);vm.memory.put(attr+ATTR_MODE,values['mode'],2)
                result(values['getattr'],32)
            elif name=='_vnode_put':
                vnode=arg(0);require(held.get(vnode,0)>0,'renderer drops an unowned/duplicate vnode reference')
                held[vnode]-=1;result(0,32)
            return True
        vm.external=external
        output=vm.run(RENDERER,(values['owner'],),budget=10000)
        require(output==e._Value(32,int(expected)),'renderer admission differs: '+label)
        require(all(count==0 for count in held.values()),'renderer leaks executable/lookup iocount: '+label)
        if expected:
            require('_vnode_lookup' in calls and '_vnode_getattr' in calls and calls.count('_vnode_put')==2,
                'renderer acceptance skipped VFS identity or balanced releases')
        if traced:
            expected_events=[]
            if '_proc_getexecutablevnode' in calls:
                expected_events=[(10,0),(11,0 if values['exe'] else 2)]
                if values['exe']:
                    expected_events += [(12,0),(13,0 if values['context'] else 2)]
                    if '_vnode_lookup' in calls:expected_events += [(14,0),(15,values['lookup'])]
                    if '_vnode_vtype' in calls:expected_events += [(16,0),(17,values['vtype'])]
                    if '_vnode_getattr' in calls:expected_events += [(18,0),(19,values['getattr'])]
                    if values['expected'] and '_vnode_lookup' in calls:expected_events += [(20,0),(21,0)]
                    expected_events += [(22,0),(23,0),(24,int(expected))]
            require(events==expected_events,'renderer trace skips/changes a VFS boundary: '+label)
            for callee,stage in (('_proc_getexecutablevnode',10),(context_symbol,12),('_vnode_lookup',14),
                    ('_vnode_vtype',16),('_vnode_getattr',18)):
                if callee in calls:
                    index=calls.index(callee)
                    require(calls[index-1:index+2]==[TRACE_EVENT,callee,TRACE_EVENT],
                        'renderer diagnostic is not paired immediately around '+callee)
            for index,callee in enumerate(calls):
                if callee=='_vnode_put':
                    require(calls[index-1:index+2]==[TRACE_EVENT,callee,TRACE_EVENT],
                        'renderer vnode release lacks immediate paired markers')
            require(calls.count(TRACE_BEGIN)==int(bool(expected_events)),'renderer trace reservation escaped caller guard')
        rows.append({'case':label,'accepted':expected,'calls':calls,'trace_events':events,
            'instructions':len(vm.visited),'balanced_vnode_iocounts':True})
    return {'success':True,'cases':rows,'VFS_context_symbol':context_symbol,
        'attribute_offsets':{'supported':0,'active':8,'uid':68,'mode':76,'span':440},
        'paired_trace_boundaries_checked':traced,'helper_only':True,'client_role_wiring_verified':False,'VFS_responses_modeled':True,'hardware_verified':False}
