"""Actual framebuffer UI instructions with explicit IOSurface/IOKit boundaries.

The member ABI below is from the existing Santoni classes, not GPU hardware
addresses. Their unchanged layout is bound to this kernel's class metadata,
getter and actual UI call arguments before any certificate can be emitted.
"""
import json
from pathlib import Path
import re
import subprocess

from check_santoni_gpu_live_kernel import LiveMachine
from santoni_gpu_binary_model import integer
from santoni_gpu_launcher_replay import require
from santoni_gpu_ui_audit import DISPLAY

CTOR = ('__ZN19IOMobileFramebuffer9MetaClassC2Ev',
        '__ZN9AppleCLCD9MetaClassC2Ev', '__ZN12SweetSurface9MetaClassC2Ev')
GETTER = '__ZN12SweetSurface13kernelAddressEv'
CONVERT = '__ZL19sweet_bgra_to_bgr24mjPKhjjj'
GLOBALS = ('santoni_ui_import', 'santoni_ui_quarantine', 'santoni_ui_shown',
           'santoni_ui_failed', 'santoni_ui_frames')
FRAME, RECORD = 0x69000000, 0x69001000
SURFACES, DESCRIPTORS, STATES, STATE_BYTES = 0x69002000, 0x69003000, 0x69004000, 0x69005000
SOURCE, OUTPUT, PANEL, SHADOW = 0x6a000000, 0x6b000000, 0x6c000000, 0x6d000000
FB = {'width':168,'height':172,'row':176,'offx':188,'offy':192,'pixels':200,
      'surface':216,'bpp':224,'stride':228,'panel':232,'quiet':280,'flip':1488}
SURFACE = {'width':16,'height':20,'stride':24,'offset':28,'format':32,
           'element':40,'elementw':42,'elementh':43,'planes':48,
           'memory':536,'state':552,'wrapped':600}


class InlineRestoreComplete(Exception):
    """A reached legacy boundary or completed last copy, not a kernel return."""


def global_name(names, suffix):
    selected=[n for n in names if n=='__ZL'+str(len(suffix))+suffix]
    require(len(selected)==1 and len(names[selected[0]])==1,'UI framebuffer global identity differs: '+suffix)
    return selected[0]


def decode(ci,image,names,e):
    roots=list(DISPLAY+CTOR+(GETTER,CONVERT))
    # LLVM may leave this existing static helper outlined instead of inlining
    # it into the new method. Admit only this exact typed helper when present.
    optional='__ZL10sweet_holdP12SweetSurfaceb'
    if optional in names:roots.append(optional)
    codes={}
    kernel=Path(ci)/'kernel/kernel.development.santoni'
    for name in roots:
        require(len(names.get(name,()))==1,'framebuffer binary ABI root missing: '+name)
        text=subprocess.check_output(['llvm-objdump','--disassemble','--disassemble-zeroes',
            '--disassemble-symbols='+name,str(kernel)],text=True)
        code=e._Code(text,name,next(iter(names[name])),noreturn=e._stack_failure_terminal(names)[0])
        words={int(a,16):int(w,16) for a,w in re.findall(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s',text,re.M)}
        require(all(image.read(pc,4)==words.get(pc) for pc in code.ins),'UI framebuffer decoded word differs')
        codes[name]=code
        # Keep this auditor's exact command output separate from the enclosing
        # common-audit disassembly of the same symbol.
        path=Path(ci)/('ui-framebuffer-'+name[1:]+'.asm')
        if not path.exists():
            with path.open('x') as stream:stream.write(text)
    target=names['__ZN11OSMetaClassC2EPKcPKS_j']
    for name,size in zip(CTOR,(136,1712,608)):
        flow=e._Flow(codes[name],image,names)
        pcs=codes[name].calls_to(target,flow.before)
        require(len(pcs)==1 and flow.before[pcs[0]].get('w3')==e._Value(32,size),
                'UI framebuffer/IOSurface class layout changed')
    require(any(op=='ldr' and any('#0x218' in arg for arg in args)
                for op,args in codes[GETTER].ins.values()),'IOSurface memory getter ABI changed')
    for n in GLOBALS:global_name(names,n)
    return codes


class FramebufferModel:
    def __init__(self,codes,image,names,e,case):
        selected={n:c for n,c in codes.items() if n in DISPLAY or n in (CONVERT,'__ZL10sweet_holdP12SweetSurfaceb')}
        self.vm=LiveMachine(selected,image,names,e)
        self.m,self.names,self.e,self.case=self.vm.memory,names,e,case
        self.globals={n:next(iter(names[global_name(names,n)])) for n in GLOBALS}
        for name,address in self.globals.items():self.m.map(address,8 if name in ('santoni_ui_frames','santoni_ui_import','santoni_ui_quarantine') else 1)
        self.m.map(next(iter(names['_sweet_console_muted'])),4)
        for addr,size in ((FRAME,1712),(RECORD,0x46c),(SURFACES,2*608),
                          (DESCRIPTORS,128),(STATES,128),(STATE_BYTES,8192),
                          (SOURCE,3932160),(OUTPUT,3932160),(PANEL,2764800),(SHADOW,3686400)):
            self.m.map(addr,size)
        for key,value in (('width',720),('height',1280),('row',2880),('bpp',3),('stride',2160)):
            self.m.put(FRAME+FB[key],value)
        self.m.put(FRAME+FB['pixels'],SHADOW,8);self.m.put(FRAME+FB['panel'],PANEL,8)
        sv=next(iter(names['__ZTV12SweetSurface']))+16
        bv=next(iter(names['__ZTV24IOBufferMemoryDescriptor']))+16
        for i in range(2):
            s=SURFACES+i*608
            self.m.put(s,sv,8)
            for key,value in (('width',720),('height',1280),('stride',3072),('format',0x42475241)):
                self.m.put(s+SURFACE[key],value)
            self.m.put(s+SURFACE['element'],4,2)
            self.m.put(s+SURFACE['elementw'],1,1);self.m.put(s+SURFACE['elementh'],1,1)
            self.m.put(s+SURFACE['memory'],DESCRIPTORS+i*64,8)
            self.m.put(s+SURFACE['state'],STATES+i*64,8)
            self.m.put(DESCRIPTORS+i*64,bv,8);self.m.put(STATES+i*64,bv,8)
        for off,value in ((0x104,1),(0x54,1),(0xc4+8,720),(0xc4+12,1280)):
            self.m.put(RECORD+off,value)
        self.m.write(SOURCE,bytes(range(256))*(3932160//256))
        self.m.write(PANEL,bytes([0x5a])*2764800)
        self.m.write(SHADOW,bytes([0xa5])*3686400)
        self.refs=[1,1];self.holds=[0,0]
        self.core_rc=1;self.core_calls=self.queries=self.barriers=0
        self.length=3932160;self.current=0
        self.inline_route=None;self.inline_rows=0;self.shadow_rows=0
        self.power_loads=[]
        self.vm.external=self.external
        self.vm.observe=self.observe

    def bytes(self,address,n):
        return b''.join(self.m.bytes(address+i,min(n-i,65536)) for i in range(0,n,65536))

    def observe(self,pc,state):
        if self.vm.by_pc[pc].ins[pc]==('dsb',('sy',)):self.barriers+=1
        op,args=self.vm.by_pc[pc].ins[pc]
        if self.inline_route=='power' and op=='ldrb' and state.address(args[1])[0]==self.e._Value(64,FRAME+1472):
            require(self.m.get(FRAME+1472,1)==1,'power route lost its enabled framebuffer flag')
            self.power_loads.append(pc)

    def external(self,target,state,probe=False,before=None):
        name=self.vm.by_address.get(target)
        inline=(DISPLAY[0],'__ZN9AppleCLCD13directPresentEPKh','_lck_mtx_lock',
                '_lck_mtx_unlock','_mach_absolute_time','__ZNK7OSArray8getCountEv')
        if self.inline_route and name in inline:
            if probe:return True
            if name=='__ZN9AppleCLCD13directPresentEPKh':
                require(self.inline_route=='present' and self.inline_rows==1280,'CPU fallback precedes completed inline shadow restore')
                raise InlineRestoreComplete()
            state.put('x0',self.e._Value(64,1 if name=='_mach_absolute_time' else 0))
            return True
        allowed=('__Z18sweet_surface_copyj',GETTER,'__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass',
                 '__ZNK18IOMemoryDescriptor9getLengthEv','__ZN24IOBufferMemoryDescriptor14getBytesNoCopyEv',
                 '__ZNK8OSObject7releaseEv','_OSAddAtomic64','_santoni_gpu_ui_copy',
                 '_santoni_gpu_ui_frame','_IOLog','_PE_parse_boot_argn','_memcpy','_memmove',CONVERT)
        if name not in allowed:return False
        if probe:return True
        a=lambda i:integer(before,'x'+str(i))
        value=0
        if name=='__Z18sweet_surface_copyj':
            require(a(0) in (1,2),'UI surface ID differs')
            self.current=a(0)-1;self.refs[self.current]+=1
            value=SURFACES+self.current*608
        elif name==GETTER:
            require(a(0)==SURFACES+self.current*608,'UI source getter uses another surface')
            value=SOURCE
        elif name=='__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass':
            require(a(0)==DESCRIPTORS+self.current*64,'UI memory cast uses another descriptor')
            meta=next(iter(self.names['__ZN24IOBufferMemoryDescriptor9metaClassE']))
            require(a(1)==self.m.image.read(meta,8),'UI memory cast uses another class')
            value=a(0)
        elif name=='__ZNK18IOMemoryDescriptor9getLengthEv':value=self.length
        elif name=='__ZN24IOBufferMemoryDescriptor14getBytesNoCopyEv':
            require(a(0) in (STATES,STATES+64),'UI hold uses another state object')
            value=STATE_BYTES+((a(0)-STATES)//64)*4096
        elif name=='__ZNK8OSObject7releaseEv':
            require(a(0) in (SURFACES,SURFACES+608),'UI release uses another surface')
            b=(a(0)-SURFACES)//608;self.refs[b]-=1
            require(self.refs[b]>=1,'UI released an unowned surface reference')
        elif name=='_OSAddAtomic64':
            require(a(1) in (STATE_BYTES+24,STATE_BYTES+4096+24),'UI in-use hold address differs')
            b=(a(1)-STATE_BYTES-24)//4096
            delta=1 if a(0)==1 else -1 if a(0)==0xffffffffffffffff else 0
            require(delta!=0,'UI in-use hold delta differs')
            self.holds[b]+=delta;require(self.holds[b]>=0,'UI hold underflow')
            self.m.put(a(1),self.holds[b],8);value=self.holds[b]
        elif name=='_santoni_gpu_ui_copy':
            require(tuple(a(i) for i in range(5))==(SOURCE,3932160,720,1280,3072) and
                    self.holds[self.current]>0,'UI copy ABI/retained in-use source differs')
            self.core_calls+=1
            if self.core_rc==1:self.m.write(OUTPUT,self.bytes(SOURCE,3932160))
            self.m.put(a(5),OUTPUT if self.core_rc==1 else 0,8)
            self.m.put(a(6),3072 if self.core_rc==1 else 0)
            value=self.core_rc&0xffffffff
        elif name=='_santoni_gpu_ui_frame':
            require(self.core_rc>=0,'framebuffer queried possibly live failed output')
            self.queries+=1;self.m.put(a(0),OUTPUT,8);self.m.put(a(1),3072);value=1
        elif name==CONVERT:
            require(tuple(a(i) for i in range(6))==(PANEL,2160,OUTPUT,3072,720,1280),
                    'UI BGRA-to-BGR24 conversion ABI/geometry differs')
            source=self.bytes(OUTPUT,3932160)
            panel=bytearray(2764800)
            for y in range(1280):
                for x in range(720):
                    panel[y*2160+x*3:y*2160+x*3+3]=source[y*3072+x*4:y*3072+x*4+3]
            self.m.write(PANEL,panel)
        elif name=='_PE_parse_boot_argn':
            require(a(2)==4,'UI console parser width differs')
            self.m.put(a(1),1);value=1
        elif name in ('_memcpy','_memmove'):
            # This CI kernel lowers the source memcpy to memmove. Both names
            # must copy exactly the next completed BGRA row into the CPU shadow;
            # framebuffer-record moves and arbitrary mapped spans are excluded.
            require(self.queries==1 and self.shadow_rows<1280 and
                    (a(0),a(1),a(2))==(SHADOW+self.shadow_rows*2880,
                                      OUTPUT+self.shadow_rows*3072,2880),
                    'UI shadow restore escapes completed output')
            self.m.write(a(0),self.m.bytes(a(1),a(2)));value=a(0)
            self.shadow_rows+=1
            if self.inline_route:
                self.inline_rows+=1
                if self.inline_route=='power' and self.inline_rows==1280:
                    raise InlineRestoreComplete()
        state.put('x0',self.e._Value(64,value));return True

    def call(self,n):
        value=self.vm.run(DISPLAY[n],(FRAME,RECORD) if n==0 else (FRAME,),budget=50000000)
        return None if value is None else value.expr

    def inline_restore(self,power=False):
        self.inline_route='power' if power else 'present'
        if power:
            self.m.put(FRAME+1472,1,1)
            client=0x69007000;lock=0x69008000
            self.m.map(client,8);self.m.map(lock,16)
            self.m.put(client,next(iter(self.names['__ZTV7OSArray']))+16,8)
            self.m.put(FRAME+264,client,8);self.m.put(FRAME+256,lock,8)
        else:
            console=next(iter(self.names['__ZZN9AppleCLCD7presentEPKhE12console_only']))
            self.m.map(console,4)
        try:
            self.vm.run(DISPLAY[3] if power else DISPLAY[2],(FRAME,0) if power else (FRAME,RECORD),budget=1000000)
        except InlineRestoreComplete:
            require(self.queries==1 and self.inline_rows==1280,'inline UI shadow copy incomplete')
            if power:require(len(self.power_loads)==1,'power inline restore did not bind the actual framebuffer flag')
        else:raise ValueError('compiled caller bypassed inline shadow restoration')
        self.inline_route=None

    def run(self):
        c=self.case
        for case,key,value,size in ((1,'format',0x52474241,4),(2,'wrapped',1,1),(3,'offset',64,4),
                                    (4,'stride',2880,4),(8,'element',2,2),(9,'elementw',2,1),(10,'planes',2,4)):
            if c==case:self.m.put(SURFACES+SURFACE[key],value,size)
        if c==5:self.m.put(RECORD+0x104,3)
        if c==6:self.m.put(RECORD+0xc4,1)
        if c==7:self.length-=1
        if c==11:self.core_rc=0
        if c==12:self.m.put(FRAME+FB['offx'],1)
        if c==13:self.m.put(FRAME+FB['bpp'],4)
        if c==14:self.m.put(RECORD+0xc4+8,719)
        if c==15:self.m.put(FRAME+FB['surface'],SURFACES,8)
        rc=self.call(0)
        if 1<=c<=15:
            require(rc==0 and self.holds==[0,0] and self.refs==[1,1] and self.barriers==0 and
                    self.core_calls==int(c==11),'unsupported UI surface did not use CPU fallback')
        else:
            require(rc==1 and self.holds==[1,0] and self.refs==[2,1] and self.barriers==1,'UI completed hold/panel barrier differs')
            panel=self.bytes(PANEL,2764800);source=self.bytes(SOURCE,3932160)
            require(all(panel[y*2160+x*3:y*2160+x*3+3]==source[y*3072+x*4:y*3072+x*4+3]
                        for y in range(1280) for x in range(720)),'UI BGR24 panel differs from imported BGRA bytes')
            if c in (16,18):
                self.m.put(RECORD+0x54,2)
                if c==18:self.core_rc=-1
                second=self.call(0)
                require(second==int(c==16),'UI completed/failed import transition differs')
                require(self.holds==([0,1] if c==16 else [1,1]),'UI previous/new import hold was released before completed handoff')
            if c in (17,19):
                if c==19:self.m.put(RECORD+0x104,3)
                self.inline_restore(power=c==17)
                shadow=self.bytes(SHADOW,3686400)
                require(all(shadow[y*2880:y*2880+2880]==source[y*3072:y*3072+2880] for y in range(1280)),
                        'GPU to CPU composition lost the completed shadow')
            if c==18:
                self.call(1)
                require(self.queries==0 and self.m.get(self.globals['santoni_ui_failed'],1)==1,
                        'UI failure read possibly live output or retried')
        return {'success':True,'case':c,'core_calls':self.core_calls,'frame_queries':self.queries,
                'holds':self.holds,'references':self.refs,'barriers':self.barriers,
                'visited_words':len(self.vm.visited),'hardware_verified':False}


def caller_routes(codes,image,names,e):
    """Bind present's success/fallback ordering and the power-off restore site."""
    code=codes[DISPLAY[2]]
    results=[]
    for gpu in (0,1):
        V=e._Value
        frame=V(64,('frame',0));record=V(64,('record',0))
        initial=e._initial(code.symbol)
        initial.put('x0',frame);initial.put('x1',record)
        console=next(iter(names['__ZZN9AppleCLCD7presentEPKhE12console_only']))
        initial.store(V(64,console),4,V(32,0))
        shown=next(iter(names[global_name(names,'santoni_ui_shown')]))
        initial.store(V(64,shown),1,V(8,1))
        initial.store(e._scm_at(frame,168),4,V(32,720))
        initial.store(e._scm_at(frame,172),4,V(32,0)) # caller ordering; full rows execute in cases17/19
        effects={}
        restore=DISPLAY[1] if code.calls_to(names[DISPLAY[1]]) else '_santoni_gpu_ui_frame'
        for callee,result in ((DISPLAY[0],gpu),(restore,1),('__ZN9AppleCLCD13directPresentEPKh',1)):
            for pc in code.calls_to(names[callee]):
                def effect(after,before,result=result,callee=callee):
                    if callee=='_santoni_gpu_ui_frame':
                        after.store(before.get('x0'),8,V(64,('pixels',0)))
                        after.store(before.get('x1'),4,V(32,3072))
                    else:
                        require(before.get('x0')==frame,'UI framebuffer caller lost its object ABI')
                        if callee!=DISPLAY[1]:require(before.get('x1')==record,'UI framebuffer caller lost the swap record')
                    after.put('w0',V(32,result))
                effects[pc]=effect
        flow=e._Flow(code,image,names,initial=initial,effects=effects)
        calls={n:code.calls_to(names[n],flow.before) for n in (DISPLAY[0],restore,'__ZN9AppleCLCD13directPresentEPKh')}
        require([len(calls[n]) for n in calls]==[1,1-gpu,1-gpu],
                'UI success did not return or fallback bypassed shadow restoration')
        if not gpu:require(calls[DISPLAY[0]][0]<calls[restore][0]<calls['__ZN9AppleCLCD13directPresentEPKh'][0],
                           'UI fallback call order differs')
        results.append({'GPU_result':gpu,'calls':{n:[hex(pc) for pc in pcs] for n,pcs in calls.items()}})
    power=codes[DISPLAY[3]]
    site=power.calls_to(names[DISPLAY[1]]) or power.calls_to(names['_santoni_gpu_ui_frame'])
    require(len(site)==1,'power-off fade lost its UI shadow restoration')
    # The actual receiver address and enabled flag are bound during concrete
    # case17, through its modeled OSArray vtable calls and full inline restore.
    loads=[pc for pc,(op,args) in power.ins.items() if op=='ldrb' and any('#0x5c0' in a for a in args)]
    require(len(loads)==1,'power-off flag load shape changed')
    return {'success':True,'present_cases':results,'power_restore_call':hex(site[0]),
            'power_flag_load':hex(loads[0]),'legacy_direct_result_modeled':True,'hardware_verified':False}
