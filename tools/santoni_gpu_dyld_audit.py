"""Exact scalar dyld flag/copy contracts on supplied actual instruction graphs.

Process/VFS/boot-argument/copy responses are modeled. Registration operands/data are checked separately from runtime registration
and dyld execution. This module grants no packaging gate.
"""
from santoni_gpu_binary_model import integer
from santoni_gpu_launcher_replay import LauncherMachine,require

FLAGS='_santoni_gpu_graphics_dyld_flags'
CALLBACK='_sweet_santoni_dyld_syscall'
TRACE_BEGIN='_santoni_gpu_dyld_trace_begin'
TRACE_EVENT='_santoni_gpu_dyld_trace_event'
IDENTITY='__ZL17gfx_renderer_taskP4task'
OPTIONS={'santonigpu_graphics':1,'santonigpu':3,'santonigpu_render':1,
    'santonigpu_ui':0,'santonigpu_raster':1,'santonigpu_gles':1,'santonigpu_renderer':1}
REPLY=(1<<1)|(1<<5)
REGISTER='_sweet_amfi_policy_register'
POLICIES=('sweet_amfi','sweet_sandbox','sweet_santoni_dyld')
# Exact xnu-8796.141.3 security/mac_policy.h declarations were cross-compiled:
# conf80 bytes,335 pointer hooks,mpo_policy_syscall at pointer index117.
# https://github.com/apple-oss-distributions/xnu/blob/xnu-8796.141.3/security/mac_policy.h
CONF_BYTES=80
HOOKS=335
SYSCALL_OFFSET=936

def single(names,symbols):
    require(all(len(names.get(n,()))==1 for n in symbols),'dyld ABI missing/ambiguous')

def audit_flags(codes,image,names,e):
    abi=('_current_proc','_current_task','_PE_parse_boot_argn',IDENTITY)
    require(FLAGS in codes,'dyld flags code missing');single(names,(FLAGS,*abi))
    PROCESS,TASK=0x81000000,0x81001000
    cases=[('enabled',{},True),('null-caller',{'caller':0},False),('other-caller',{'caller':PROCESS+8},False),
        ('no-current-process',{'process':0},False),('null-task',{'task':0},False),('identity-denied',{'identity':False},False)]
    for key in OPTIONS:
        for value in (None,-1,0,1,2,3,4,0xffffffff):
            effective={**OPTIONS,key:0 if value is None else value}
            cases.append((key+':'+str(value),{'option':(key,value)},effective==OPTIONS))
    rows=[]
    for label,changes,expected in cases:
        values={'caller':PROCESS,'process':PROCESS,'task':TASK,'identity':True,**changes}
        options=dict(OPTIONS)
        if 'option' in changes:options[changes['option'][0]]=changes['option'][1]
        parsed=[];calls=[];vm=LauncherMachine({FLAGS:codes[FLAGS]},image,names,e)
        def external(address,state,probe=False,before=None):
            name=vm.by_address.get(address)
            if probe:return name in abi
            require(name in abi,'dyld flags call unreviewed ABI: '+str(name));calls.append(name)
            arg=lambda i:integer(before,'x'+str(i))
            if name=='_current_proc':state.put('x0',e._Value(64,values['process']))
            elif name=='_current_task':state.put('x0',e._Value(64,values['task']))
            elif name==IDENTITY:
                require(arg(0)==values['task'],'dyld flags authorize wrong task')
                state.put('w0',e._Value(32,int(values['identity'] and values['task']!=0)))
            else:
                key=None
                for name_ in OPTIONS:
                    text=name_.encode()+b'\0'
                    if image.read(arg(0),len(text))==int.from_bytes(text,'little'):key=name_;break
                require(key is not None and arg(2)==4,'dyld option name/width differs')
                pointer=arg(1)
                require(integer(before,'sp')<=pointer and pointer+4<=vm.STACK+vm.STACK_SIZE,
                    'dyld option output exceeds active owned stack')
                require(vm.memory.get(pointer)==0,'dyld option default is not zero');parsed.append(key)
                if options[key] is not None:vm.memory.put(pointer,options[key])
                state.put('w0',e._Value(32,int(options[key] is not None)))
            return True
        vm.external=external;result=vm.run(FLAGS,(values['caller'],),budget=10000)
        # The shared interpreter's convenience return is w0. The kernel ABI
        # returns uint64_t, so inspect the complete final x0, including high bits.
        require(vm.state.get('x0')==e._Value(64,REPLY if expected else 0),'dyld full-width flags differ: '+label)
        current=values['caller']!=0 and values['caller']==values['process']
        require(parsed==(list(OPTIONS) if current else []),'dyld option parsing bypass: '+label)
        valid_opts={k:0 if v is None else v for k,v in options.items()}==OPTIONS
        require(calls.count(IDENTITY)==int(current and valid_opts),'dyld identity/opt-in bypass: '+label)
        rows.append({'case':label,'flags':REPLY if expected else 0,'identity_calls':calls.count(IDENTITY),
            'instructions':len(vm.visited)})
    return {'success':True,'cases':rows,'scalar_contract_only':True,'platform_and_identity_responses_modeled':True,
        'policy_registration_verified':False,'runtime_dyld_verified':False,'hardware_verified':False}

def audit_callback(codes,image,names,e):
    require(CALLBACK in codes,'dyld callback code missing')
    code=codes[CALLBACK]
    bounded=bool(code.calls_to(names.get(TRACE_BEGIN,())))
    traced=bounded or bool(code.calls_to(names.get('_PE_parse_boot_argn',())))
    require(bool(code.calls_to(names.get('_printf',())))==traced,
        'dyld callback trace must pair the opt-in query and logger')
    abi=(FLAGS,'_copyin','_copyout')+((TRACE_BEGIN if bounded else '_PE_parse_boot_argn','_proc_pid','_proc_getuid','_printf') if traced else ())
    single(names,(CALLBACK,*abi))
    rows=[]
    # Preserve support for old kernels, while checking every new logger operand.
    trace_options=(0,65) if bounded else (None,-1,0,1,2) if traced else (None,)
    for label,call,flags,copyin_error,output,copyout_error,expected in [
        ('enabled',90,REPLY,0,True,0,0),('selector-zero',0,REPLY,0,True,0,103),
        ('selector89',89,REPLY,0,True,0,103),('selector91',91,REPLY,0,True,0,103),
        ('selector-negative',0xffffffff,REPLY,0,True,0,103),('flags-zero',90,0,0,True,0,103),
        ('copyin-failure',90,REPLY,5,True,0,14),('null-output',90,REPLY,0,False,0,14),
        ('copyout-failure',90,REPLY,0,True,5,5)]:
        for input_word in (0,2,4,6,0xffffffffffffffff):
            for renderer in trace_options:
                vm=LauncherMachine({CALLBACK:code},image,names,e);m=vm.memory
                PROCESS,USER,OUT=0x81000000,0x81001000,0x81002000
                m.map(USER,16);m.map(OUT,8,fill=0xa5);m.put(USER,input_word,8);m.put(USER+8,OUT if output else 0,8)
                m.readonly.append((USER,USER+16));calls=[]
                stage=1 if not flags else 2 if copyin_error else 3 if not output else 4
                def external(address,state,probe=False,before=None):
                    name=vm.by_address.get(address)
                    if probe:return name in abi
                    require(name in abi,'dyld callback calls unreviewed ABI: '+str(name));calls.append(name)
                    arg=lambda i:integer(before,'x'+str(i))
                    if name==TRACE_BEGIN:
                        require(arg(0)==PROCESS and arg(1)==0 and calls==[TRACE_BEGIN],
                            'dyld trace reservation must precede policy/VFS')
                        state.put('w0',e._Value(32,renderer))
                    elif name==FLAGS:
                        if bounded:require(calls==[TRACE_BEGIN,FLAGS],'dyld policy precedes reserved entry trace')
                        require(arg(0)==PROCESS,'dyld callback changes process pointer');state.put('x0',e._Value(64,flags))
                    elif name in ('_proc_pid','_proc_getuid'):
                        require(arg(0)==PROCESS,'dyld trace reads identity from wrong process')
                        state.put('w0',e._Value(32,42 if name=='_proc_pid' else 501))
                    elif name=='_PE_parse_boot_argn':
                        text=b'santonigpu_renderer\0'
                        require(image.read(arg(0),len(text))==int.from_bytes(text,'little') and arg(2)==4,
                            'dyld trace opt-in key/width differs')
                        require(integer(before,'sp')<=arg(1) and arg(1)+4<=vm.STACK+vm.STACK_SIZE and
                            m.get(arg(1),4)==0,'dyld trace option is outside active stack or default-on')
                        if renderer is not None:m.put(arg(1),renderer&0xffffffff,4)
                        state.put('w0',e._Value(32,int(renderer is not None)))
                    elif name=='_printf':
                        text=(b'SANTONI GPU: dyld syscall90 pid=%d uid=%u token=%u flags=%llx stage=%u error=%d\n\0' if bounded else
                            b'SANTONI GPU: dyld syscall90 pid=%d uid=%u flags=%llx stage=%u error=%d\n\0')
                        require(image.read(arg(0),len(text))==int.from_bytes(text,'little'),
                            'dyld trace format differs or exposes unreviewed data')
                        stack=integer(before,'sp')
                        # Darwin arm64 variadic args occupy stack slots; prove the
                        # actual full-width flag and completed policy/copy result.
                        require(m.get(stack,4)==42 and m.get(stack+8,4)==501 and (not bounded or m.get(stack+16,4)==renderer) and m.get(stack+(24 if bounded else 16),8)==flags and
                            m.get(stack+(32 if bounded else 24),4)==stage and m.get(stack+(40 if bounded else 32),4)==expected,
                            'dyld trace scalar operands/outcome differ')
                        require(calls.count('_copyin')==int(flags!=0) and
                            calls.count('_copyout')==int(flags!=0 and not copyin_error and output),
                            'dyld trace precedes completed copy outcome')
                        state.put('w0',e._Value(32,0xfffffff7)) # failed printk, never changes errno
                    elif name=='_copyin':
                        require(arg(0)==USER and arg(2)==16 and integer(before,'sp')<=arg(1) and
                            arg(1)+16<=vm.STACK+vm.STACK_SIZE,'dyld callback input copy exceeds active owned span')
                        if not copyin_error:m.write(arg(1),m.bytes(USER,16))
                        state.put('w0',e._Value(32,copyin_error))
                    else:
                        require(arg(1)==OUT and arg(2)==8 and integer(before,'sp')<=arg(0) and
                            arg(0)+8<=vm.STACK+vm.STACK_SIZE,'dyld callback output copy pointer/size differs')
                        require(m.get(arg(0),8)==flags,'dyld callback output flags changed')
                        if not copyout_error:m.write(OUT,m.bytes(arg(0),8))
                        state.put('w0',e._Value(32,copyout_error))
                    return True
                vm.external=external;result=vm.run(CALLBACK,(PROCESS,call,USER),budget=2000)
                require(result==e._Value(32,expected),'dyld callback return differs: '+label)
                require(calls.count(FLAGS)==int(call==90),'dyld callback selector bypass')
                require(calls.count('_copyin')==int(call==90 and flags!=0),'dyld callback flag bypass')
                require(calls.count('_copyout')==int(call==90 and flags!=0 and not copyin_error and output),
                    'dyld callback copyin/output-null bypass')
                require(calls.count(TRACE_BEGIN if bounded else '_PE_parse_boot_argn')==int(traced and call==90),
                    'dyld trace option query escaped selector90')
                require(calls.count('_printf')==int(traced and call==90 and (bool(renderer) if bounded else renderer==1)),
                    'dyld trace missing, duplicated, or enabled without exact opt-in')
                for getter in ('_proc_pid','_proc_getuid'):
                    require(calls.count(getter)==int(traced and call==90 and (bool(renderer) if bounded else renderer==1)),
                        'dyld diagnostic identity query escaped its opt-in')
                require(m.get(OUT,8)==(flags if expected==0 else 0xa5a5a5a5a5a5a5a5),'dyld callback failure exposes output')
                rows.append({'case':label,'input':input_word,'renderer_option':renderer,'result':expected,
                    'calls':calls,'instructions':len(vm.visited)})
    return {'success':True,'cases':rows,'scalar_contract_only':True,'platform_copy_responses_modeled':True,
        'trace_operands_checked':traced,'trace_reservation_before_policy_checked':bounded,'policy_registration_verified':False,
        'runtime_dyld_verified':False,'hardware_verified':False}

def audit_registration(codes,image,names,e):
    symbols=(REGISTER,'_mac_policy_register','_printf',CALLBACK,'_sweet_santoni_dyld_mac_ops',
        *('_'+policy+suffix for policy in POLICIES for suffix in ('_mac_conf','_mac_handle')))
    single(names,symbols);require(REGISTER in codes,'dyld policy registration code missing')
    one=lambda name:next(iter(names[name]))
    conf=one('_sweet_santoni_dyld_mac_conf');ops=one('_sweet_santoni_dyld_mac_ops')
    require(image.read(conf,CONF_BYTES) is not None,'dyld policy conf bytes unavailable')
    require(image.read(ops,HOOKS*8) is not None,'dyld policy hook vector bytes unavailable')
    name=image.read(conf,8);full=image.read(conf+8,8)
    require(name is not None and image.read(name,5)==int.from_bytes(b'AMFI\0','little'),'dyld policy name differs')
    title=b'SANTONI renderer dyld policy\0'
    require(full is not None and image.read(full,len(title))==int.from_bytes(title,'little'),'dyld policy full name differs')
    require(image.read(conf+32,8)==ops,'dyld policy operation vector differs')
    for offset,size in ((16,8),(24,4),(40,4),(48,8),(56,4),(64,8),(72,8)):
        require(image.read(conf+offset,size)==0,'dyld policy enables an unreviewed namespace/flag/data')
    for offset in range(0,HOOKS*8,8):
        expected=one(CALLBACK) if offset==SYSCALL_OFFSET else 0
        require(image.read(ops+offset,8)==expected,'dyld policy adds/changes a hook at '+str(offset))
    rows=[]
    for errors in ((0,0,0),(1,0,0),(0,1,0),(0,0,5),(1,2,3)):
        vm=LauncherMachine({REGISTER:codes[REGISTER]},image,names,e);calls=[];prints=[]
        def external(address,state,probe=False,before=None):
            name=vm.by_address.get(address)
            if probe:return name in ('_mac_policy_register','_printf')
            require(name in ('_mac_policy_register','_printf'),'dyld registration calls unreviewed ABI')
            if name=='_mac_policy_register':
                index=len(calls);require(index<3,'dyld registration adds an unreviewed policy')
                policy=POLICIES[index];args=[integer(before,'x'+str(i)) for i in range(3)]
                require(args==[one('_'+policy+'_mac_conf'),one('_'+policy+'_mac_handle'),0],
                    'dyld policy registration args/order differ')
                calls.append(args);state.put('w0',e._Value(32,errors[index]))
            else:
                require(len(calls)==len(prints)+1,'dyld policy logging order differs')
                prints.append(integer(before,'x0'));state.put('w0',e._Value(32,0))
            return True
        vm.external=external;vm.run(REGISTER,(),budget=10000)
        require(len(calls)==len(prints)==3,'dyld registration omits a policy after a previous failure')
        rows.append({'modeled_policy_errors':errors,'registration_calls':calls,'log_calls':len(prints),'instructions':len(vm.visited)})
    return {'success':True,'cases':rows,'conf_bytes':CONF_BYTES,'hook_count':HOOKS,'syscall_offset':SYSCALL_OFFSET,
        'policy_data_and_registration_operands_checked':True,'policy_framework_responses_modeled':True,
        'runtime_policy_registration_verified':False,'runtime_dyld_verified':False,'hardware_verified':False}


def audit_trace(codes,image,names,e):
    """Execute the reserved trace helpers; model platform atomics, never VFS."""
    roots=(TRACE_BEGIN,TRACE_EVENT)
    abi=('_current_proc','_proc_pid','_proc_getuid','_PE_parse_boot_argn','_OSAddAtomic',
        '_OSCompareAndSwap','_proc_selfname','_printf')
    single(names,(*roots,'_sweet_dyld_trace_counts',*abi))
    require(all(n in codes for n in roots),'dyld trace helper code missing')
    base=next(iter(names['_sweet_dyld_trace_counts']))
    require(len([s for s in image.segs if s.get('initprot',0)&7==3 and
        s['vmaddr']<=base and base+12<=s['vmaddr']+s['vmsize']])==1,
        'dyld trace counters require one owned RW, non-executable segment')
    initial=image.read(base,12)
    if initial is None:
        # mkpayload zeroes only the mapped segment's fileless tail. Admit a
        # whole counter span there; a hole/interior unreadable span still fails.
        tails=[s for s in image.segs if s.get('initprot',0)&7==3 and
            s['vmaddr']+s.get('filesize',s['vmsize'])<=base and
            base+12<=s['vmaddr']+s['vmsize']]
        require(len(tails)==1,'dyld trace counters are not in a proven zero-filled RW tail')
    else:require(initial==0,'dyld trace budgets must start at zero')
    process=0x81000000;rows=[]
    cases=[(uid,phase,renderer,count,True,process,process)
        for uid,phase in ((0,0),(502,0),(501,0),(501,1))
        for renderer in (None,-1,0,1,2) for count in (-1,0,1,31,32,33)]
    cases += [(501,0,1,0,False,process,process),(0,1,1,0,True,process,process),
        (501,2,1,0,True,process,process),(501,0,1,0,True,0,process),
        (501,0,1,0,True,process,0),(501,0,1,0,True,process,process+8)]
    for uid,phase,renderer,count,cas,caller,current in cases:
        vm=LauncherMachine({n:codes[n] for n in roots},image,names,e);m=vm.memory
        m.map(base,12);index=2 if phase else 1 if uid==501 else 0
        for i in range(3):m.put(base+4*i,count&0xffffffff,4)
        calls=[];prints=[];adds=[];swaps=[]
        guarded=bool(caller and caller==current and phase<=1)
        enabled=guarded and renderer==1 and (phase==0 or uid==501)
        expected=((index<<6)|(count+1)) if enabled and 0<=count<32 and cas else 0
        original=b'A%\n\x01z_.-09LongNameXXX'
        clean=bytes(c if 65<=c<=90 or 97<=c<=122 or 48<=c<=57 or c in b'_.-' else 95 for c in original[:16])
        def external(address,state,probe=False,before=None):
            name=vm.by_address.get(address)
            if probe:return name in abi
            require(name in abi,'dyld trace unreviewed ABI: '+str(name));calls.append(name)
            arg=lambda i:integer(before,'x'+str(i))
            def result(value):state.put('w0',e._Value(32,value&0xffffffff))
            if name=='_current_proc':state.put('x0',e._Value(64,current))
            elif name in ('_proc_pid','_proc_getuid'):
                require(arg(0)==process,'trace reads other process');result(42 if name=='_proc_pid' else uid)
            elif name=='_PE_parse_boot_argn':
                literal=b'santonigpu_renderer\0'
                require(image.read(arg(0),len(literal))==int.from_bytes(literal,'little') and arg(2)==4,
                    'trace opt-in name/width differs')
                require(integer(before,'sp')<=arg(1) and arg(1)+4<=vm.STACK+vm.STACK_SIZE and
                    m.get(arg(1),4)==0,'trace opt-in default/span differs')
                if renderer is not None:m.put(arg(1),renderer&0xffffffff,4)
                result(int(renderer is not None))
            elif name=='_OSAddAtomic':
                require(arg(0)==0 and arg(1)==base+4*index,'trace reads/modifies wrong counter')
                adds.append(arg(1));result(count)
            elif name=='_OSCompareAndSwap':
                require(arg(0)==count and arg(1)==count+1 and arg(2)==base+4*index and adds==[arg(2)],
                    'trace saturation/CAS target differs');swaps.append(arg(2))
                if cas:m.put(arg(2),count+1,4)
                result(int(cas))
            elif name=='_proc_selfname':
                require(prints==['boundary'] and arg(1)==17 and integer(before,'sp')<=arg(0) and
                    arg(0)+17<=vm.STACK+vm.STACK_SIZE and m.bytes(arg(0),17)==bytes(17),
                    'trace name acquisition lacks earlier marker or owned zeroed span')
                m.write(arg(0),original[:17]);result(0xfffffff7)
            else:
                literal=b'SANTONI GPU: dyld boundary pid=%d token=%u stage=%u result=%d\n\0'
                sp=integer(before,'sp')
                if image.read(arg(0),len(literal))==int.from_bytes(literal,'little'):
                    require(not prints and [m.get(sp+8*i,4) for i in range(4)]==[42,expected,0,0],
                        'trace entry scalar values/order differ');prints.append('boundary')
                else:
                    literal=b'SANTONI GPU: dyld caller pid=%d uid=%u token=%u name=%.16s\n\0'
                    require(image.read(arg(0),len(literal))==int.from_bytes(literal,'little'),'trace exposes unreviewed format')
                    require(prints==['boundary'] and [m.get(sp+8*i,4) for i in range(3)]==[42,uid,expected],
                        'trace caller scalar values/order differ')
                    ptr=m.get(sp+24,8)
                    require(m.bytes(ptr,17)==clean+b'\0','trace name is not bounded/sanitized');prints.append('caller')
                result(0xfffffff7)
            return True
        vm.external=external;result=vm.run(TRACE_BEGIN,(caller,phase),budget=5000)
        require(result==e._Value(32,expected),'trace reservation return differs')
        require(len(adds)==int(enabled) and len(swaps)==int(enabled and 0<=count<32),
            'trace retries, escapes opt-in or ignores saturation')
        require(prints==(['boundary','caller'] if expected else []) and
            calls.count('_proc_selfname')==int(bool(expected)),'trace logging escapes reservation')
        for i in range(3):require(m.get(base+4*i,4)==((count+1) if i==index and expected else count&0xffffffff),
            'trace changes unrelated counter or increments failed reservation')
        rows.append({'uid':uid,'phase':phase,'renderer':renderer,'initial_count':count,'CAS_success':cas,
            'caller':caller,'current':current,'token':expected,'calls':calls,'instructions':len(vm.visited)})
    event_rows=[]
    for caller,token,stage in ((process,129,10),(process,160,24),(0,129,10),
        (process,0,10),(process,64,10),(process,33,10),(process,161,10),(process,129,25)):
        vm=LauncherMachine({TRACE_EVENT:codes[TRACE_EVENT]},image,names,e);printed=[]
        def external(address,state,probe=False,before=None):
            name=vm.by_address.get(address)
            if probe:return name in ('_printf','_proc_pid')
            require(name in ('_printf','_proc_pid'),'trace event unreviewed ABI')
            if name=='_proc_pid':
                require(integer(before,'x0')==process,'trace event process differs');state.put('w0',e._Value(32,42))
            else:
                literal=b'SANTONI GPU: dyld boundary pid=%d token=%u stage=%u result=%d\n\0'
                require(image.read(integer(before,'x0'),len(literal))==int.from_bytes(literal,'little'),'trace event format differs')
                sp=integer(before,'sp')
                require([vm.memory.get(sp+8*i,4) for i in range(4)]==[42,token,stage,5],'trace event operands differ')
                printed.append(stage);state.put('w0',e._Value(32,0xfffffff7))
            return True
        vm.external=external;vm.run(TRACE_EVENT,(caller,token,stage,5),budget=1000)
        valid=bool(caller and 1<=(token&63)<=32 and token<=160 and stage<=24)
        require(printed==([stage] if valid else []),'trace event accepts invalid token/stage/process')
        event_rows.append({'token':token,'stage':stage,'printed':bool(printed)})
    return {'success':True,'cases':rows,'event_cases':event_rows,'independent_saturating_budgets_checked':True,
        'entry_before_name_checked':True,'bounded_sanitized_name_checked':True,'single_CAS_attempt_checked':True,
        'platform_atomic_and_logging_responses_modeled':True,'hardware_verified':False}
