#!/usr/bin/env python3
"""Audit actual UI import/copy instructions with modeled GPU/IOKit boundaries.

No phone boot or kernel compilation. Full native validator words are from a
private copy of the exact CI image. This certificate is software evidence only.
"""
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path

from check_santoni_gpu_live_kernel import LiveAdapter, LiveModel, INPUT, OUTPUT, TABLES, PIXELS, BYTES, GVA
from santoni_gpu_binary_model import integer
from santoni_gpu_launcher_replay import require
from santoni_gpu_scalar_certificate import load_inputs, identity_of
from santoni_gpu_ui_audit import CORE, ADAPTER, DISPLAY, default_off
from santoni_gpu_ui_native_cpu import UIPureCPU, UI_PURE, UI_BYTES

IMPORTS = (0x66000000, 0x67000000)
IMPORT_PA = (0x68000000, 0x68002000)
IMAGE, POINTER, STRIDE, SNAPSHOT = 0x68004000, 0x68005000, 0x68005008, 0x68006000
HANDOFF = ((4, 0x20c8, 3), (5, 0xc00, 0x20000), (5, 0x8000, 0x1126),
           (5, 0x8610, 1), (5, 0x87f0, 0), (5, 0x8000, 0x1127),
           (5, 0xc00, 0), (4, 0x20c8, 0))
CORE_CASES = ('normal', 'stride', 'late-pa', 'duplicate', 'table-alias', 'legacy-alias',
              'owned-alias', 'pages', 'alignment', 'bytes', 'fence', 'stop', 'tlb',
              'global-fault', 'cb-fault', 'busy', 'width', 'height', 'aperture', 'owned-change')


def packet7(op, count):
    """Independent A5xx type-7 parity oracle for circular-ring padding."""
    require(0 <= op <= 0x7f and 0 <= count <= 0x3fff, 'UI packet7 oracle input exceeds format')
    count_parity = 1
    opcode_parity = 1
    value = count
    while value:
        count_parity ^= value & 1
        value >>= 1
    value = op
    while value:
        opcode_parity ^= value & 1
        value >>= 1
    return 0x70000000 | count | (count_parity << 15) | (op << 16) | (opcode_parity << 23)


def ensure_storage(memory, address, length):
    """Add a declared adapter global, preserving any already modeled overlap."""
    if memory.locate(address,length) is not None:return
    overlap=[r for r in memory.regions if address<r[0]+len(r[1]) and r[0]<address+length]
    start=min([address]+[r[0] for r in overlap])
    end=max([address+length]+[r[0]+len(r[1]) for r in overlap])
    memory.regions=[r for r in memory.regions if all(r is not o for o in overlap)]
    memory.map(start,end-start)
    data,known,_=memory.locate(start,end-start)
    for base,old,valid in overlap:
        off=base-start;data[off:off+len(old)]=old;known[off:off+len(old)]=valid


class UIAdapter(LiveAdapter):
    """Actual adapter instructions; the separately audited UI core is a boundary."""
    def __init__(self,codes,image,names,e,native,case):
        super().__init__(codes,image,names,e,native,'success')
        self.ui_case=case
        for name in ADAPTER:
            self.vm.codes[name]=codes[name]
        self.vm.by_entry={c.entry:c for c in self.vm.codes.values()}
        self.vm.by_pc={pc:c for c in self.vm.codes.values() for pc in c.ins}
        for name,size in (('_sgpu_ui_import',40),('_sgpu_ui_import_pas',960*8),('_sgpu_ui_lock',16)):
            ensure_storage(self.m,self.address(name),size)
        self.m.map(IMPORTS[0],BYTES)
        self.m.map(POINTER,16);self.m.map(SNAPSHOT,72)
        self.options['santonigpu_ui']=0 if case==1 or 21<=case<24 else 2 if case==2 else 1
        mode=1 if case==3 else 2 if case==4 else 0 if case==24 else case-21 if 21<=case<24 else 3
        self.m.put(self.sg+84,mode)
        for off in (88,96,100,104):self.m.put(self.sg+off,1)
        self.m.put(self.address('_sgpu_render_enabled'),int(case!=6))
        if case==5:self.m.put(self.sg+88,0)
        if case==7:self.m.put(self.sg+108,1)
        self.lock_depth=self.ui_starts=self.ui_copies=self.ui_pmaps=0
        self.vm.external=self.external_ui_adapter

    def external_ui_adapter(self,target,state,probe=False,before=None):
        name=self.vm.by_address.get(target)
        handled=('_lck_mtx_lock','_lck_mtx_unlock','_sgpu_ui_start','_sgpu_ui_copy',
                 '_sgpu_ui_frame','_sgpu_ui_snapshot','_pmap_find_phys')
        if name not in handled:return super().external(target,state,probe,before)
        if probe:return True
        a=lambda i:integer(before,'x'+str(i))
        value=0
        if name in ('_lck_mtx_lock','_lck_mtx_unlock'):
            require(a(0)==self.address('_sgpu_ui_lock'),'UI lock address differs')
            if name=='_lck_mtx_lock':
                require(self.lock_depth==0,'UI lock nested');self.lock_depth=1
            else:
                require(self.lock_depth==1,'UI unlock without held lock');self.lock_depth=0
        else:
            require(self.lock_depth==1,'UI core/pmap accessed without adapter lock')
            if name=='_sgpu_ui_start':
                require(a(0)==1,'UI start lacks exact opt-in');self.ui_starts+=1;value=1
            elif name=='_pmap_find_phys':
                require(a(0)==self.m.get(self.address('_kernel_pmap'),8) and
                        a(1)==IMPORTS[0]+self.ui_pmaps*4096,'UI pmap skipped/repeated or used a foreign address')
                value=0 if self.ui_case==8 and self.ui_pmaps==959 else (0xa3000000+self.ui_pmaps*8192)>>12
                self.ui_pmaps+=1
            elif name=='_sgpu_ui_copy':
                image=self.address('_sgpu_ui_import')
                require(a(0)==image and self.ui_pmaps==960 and
                        self.m.get(image,8)==IMPORTS[0] and
                        self.m.get(image+8,8)==self.address('_sgpu_ui_import_pas') and
                        [self.m.get(image+off) for off in (16,20,24,28,32)]==[960,BYTES,720,1280,3072],
                        'UI core received incomplete/different import geometry or PA list')
                for i in range(960):
                    want=0 if self.ui_case==8 and i==959 else 0xa3000000+i*8192
                    require(self.m.get(self.address('_sgpu_ui_import_pas')+i*8,8)==want,'UI pmap result was lost/changed')
                self.ui_copies+=1
                value=0xffffffff if self.ui_case==14 else 0 if self.ui_case==8 else 1
                self.m.put(a(1),PIXELS+BYTES if value==1 else 0,8)
                self.m.put(a(2),3072 if value==1 else 0)
            elif name=='_sgpu_ui_snapshot':
                self.m.write(a(0),bytes(72))
                for off,datum in ((0,12),(4,11 if self.ui_case==14 else 0),(8,3),(12,1),(16,389)):
                    self.m.put(a(0)+off,datum)
                self.m.put(a(0)+21,int(self.ui_case==14),1)
            else:
                self.m.put(a(0),PIXELS+BYTES,8);self.m.put(a(1),3072);value=1
        state.put('x0',self.e._Value(64,value));return True

    def execute_ui(self):
        case=self.ui_case
        value=self.vm.run('_sgpu_ui_options',(self.m.get(self.sg+84),))
        invalid=2<=case<=7 or case==24
        require(value.expr==int(not invalid),'UI option/mode/foreign-role admission differs')
        if not invalid:
            self.vm.run('_sgpu_ui_publish',(int(case!=20),))
            enabled=case!=1 and case<21 and case!=20
            require(self.m.get(self.address('_sgpu_ui_published'),1)==int(enabled) and
                    self.ui_starts==int(enabled),'UI publication bypassed actual role/bootstrap')
            if case==16:self.m.put(self.address('_sgpu_ui_published'),0,1)
            if case==17:self.m.put(self.address('_page_shift'),14)
            if case==18:self.m.put(self.address('_page_size'),16384,8)
            source=IMPORTS[0]+int(case==9)
            if case==19:source=0xfffffffffffff000
            args=(source,BYTES-int(case==10),720-int(case==11),1280-int(case==12),
                  2880 if case==13 else 3072,POINTER,STRIDE)
            result=self.vm.run('_santoni_gpu_ui_copy',args)
            expected=1 if case in (0,15) else 0xffffffff if case==14 else 0
            require(result.expr==expected,'UI adapter output/error differs')
            require(self.ui_pmaps==(960 if case in (0,8,14,15) else 0),'UI imported pages not freshly/exactly queried')
            if case==14:
                require(self.m.get(self.address('_sgpu_ui_published'),1)==0,'UI failure remained published')
                require(self.vm.run('_santoni_gpu_ui_copy',args).expr==0 and self.ui_pmaps==960,'UI failure retried pmap/core')
            if case in (14,15):
                require(self.vm.run('_santoni_gpu_ui_frame',(POINTER,STRIDE)).expr==int(case==15),
                        'UI last-frame wrapper exposed failed output')
        require(self.lock_depth==0 and not self.allocations and not self.frees,'UI adapter lock/backing lifetime differs')
        return {'success':True,'case':case,'pmap_queries':self.ui_pmaps,'core_calls':self.ui_copies,
                'hardware_verified':False}


class UIModel(LiveModel):
    def fork(self):
        """Independent negative state from this same-kernel executed bootstrap."""
        result=copy.copy(self)
        result.m=copy.copy(self.m)
        result.m.regions=[(a,bytearray(data),bytearray(known)) for a,data,known in self.m.regions]
        result.m.readonly=list(self.m.readonly)
        result.vm=copy.copy(self.vm)
        result.vm.memory=result.m
        result.vm.external=result.external_ui
        result.vm.visited=set(self.vm.visited)
        result.vm.calls=[]
        for key in ('regs','ui_tlb','ui_writes','pure_calls','callbacks','published',
                    'clean_pages','invalidated_pages','old_dma','tables_dma','pixels_dma','import_dma'):
            setattr(result,key,copy.deepcopy(getattr(self,key)))
        return result

    def prepare_ui(self):
        self.ui_on = False
        self.run_live()
        self.ui = next(iter(self.names['_sgpu_ui']))
        self.m.map(self.ui, UI_BYTES)
        for n in CORE:
            self.vm.codes[n] = self.codes[n]
        self.vm.by_entry = {c.entry:c for c in self.vm.codes.values()}
        self.vm.by_pc = {pc:c for c in self.vm.codes.values() for pc in c.ins}
        for address, size in ((*((a, BYTES) for a in IMPORTS),
                               *((a, 960*8) for a in IMPORT_PA),
                               (IMAGE, 40), (POINTER, 16), (SNAPSHOT, 72))):
            self.m.map(address, size)
        self.import_dma = [bytearray(BYTES), bytearray(BYTES)]
        for b in range(2):
            for i in range(960): self.m.put(IMPORT_PA[b]+8*i, 0xa3000000+b*0x1000000+i*8192, 8)
        self.vm.external = self.external_ui
        self.ui_on = False
        require(self.call('_sgpu_ui_start', 0) == 0, 'UI bootstrap opt-in bypass')
        require(self.call('_sgpu_ui_start', 1) == 1, 'actual UI start rejected completed live bootstrap')
        require(self.call('_sgpu_ui_start', 1) == 0, 'UI start was repeated')
        require(self.m.get(next(iter(self.names['_session_core']))+136,8)==self.ui+4,
                'actual UI report is not isolated in persistent storage')
        self.ui_on = True
        self.ui_case = 'normal'
        self.ui_writes, self.ui_wraps = [], 0
        self.tlbi = self.sync = False
        self.ui_tlb = [self.m.get(TABLES+8192+8*(1+i),8) for i in range(960)]
        return self

    def call(self, symbol, *args):
        value = self.vm.run(symbol, args, budget=4000000)
        return None if value is None else value.expr

    def image(self, b=0):
        self.m.put(IMAGE, IMPORTS[b], 8); self.m.put(IMAGE+8, IMPORT_PA[b], 8)
        for off, value in ((16,960),(20,BYTES),(24,720),(28,1280),(32,3072)):
            self.m.put(IMAGE+off, value)

    def physical(self, pa):
        for b in range(2):
            offset = pa - (0xa3000000+b*0x1000000)
            if 0 <= offset < 960*8192 and offset%8192 < 4096:
                return self.import_dma[b], (offset//8192)*4096+offset%8192
        return super().physical(pa)

    def gpu(self, address, write=False):
        if self.ui_on and GVA+4096 <= address < GVA+4096+BYTES:
            require(self.regs[5,0x8000]==0x1127 and self.regs[5,0xc00]==0, 'UI GPU CB/route differs')
            pte = self.ui_tlb[(address-GVA-4096)//4096]
            require(pte&3==3 and pte&128 and not write, 'UI imported source PTE is not read-only')
            return self.physical((pte&0x0000fffffffff000)+(address&4095))
        return super().gpu(address,write)

    def external_ui(self, target, state, probe=False, before=None):
        name = self.vm.by_address.get(target)
        if name in UI_PURE:
            if probe: return True
            # All production calls use linked=true. Supply that same argument
            # even when LLVM specializes it out of the internal ABI.
            args = (1,) if name == '_sgpu_ui_tables' else (integer(before,'x0'),)
            result = self.native.run(name,self.m,args)
            state.put('w0',self.e._Value(32,result))
            self.pure_calls.append({'helper':name,'arguments':list(args),'result':result})
            return True
        if not self.ui_on:
            return super().external_live(target,state,probe,before)
        a = lambda i: integer(before,'x'+str(i))
        if name == '_sgpu_io_write32':
            if probe: return True
            write=(a(1),a(2),a(3)); index=len(self.ui_writes)%9
            expected=HANDOFF[index] if index<8 else (4,0x201c,self.m.get(self.live+4392+20))
            require(write==expected, 'UI CP/SID0/CB/TLB/submission write scope/order differs')
            self.ui_writes.append(write)
            if self.ui_case=='stop' and index==0: return True
            self.regs[write[:2]]=write[2]
            if index==0: self.regs[4,0x20c8]=15
            if index==2: self.tlbi=self.sync=False
            if index==3: self.tlbi=True
            if index==4:
                require(self.tlbi, 'UI TLBSYNC preceded ASID invalidation')
                self.sync=True
                self.ui_tlb=[int.from_bytes(self.tables_dma[8192+8*(1+i):8200+8*(1+i)],'little') for i in range(960)]
                self.regs[5,0x87f4]=int(self.ui_case=='tlb')
            if index==5: require(self.tlbi and self.sync and not self.regs[5,0x87f4], 'UI CB enabled before completed TLB handoff')
            if index==8:
                old=self.regs[4,0x2018]; end=write[2]
                if end<old:
                    remain=1024-old
                    h=int.from_bytes(self.old_dma[12288+4*old:12292+4*old],'little')
                    # Independently calculate the type-7 CP_NOP parity; payload
                    # must be zero through the exact end of the 4 KiB ring.
                    want=packet7(0x10,remain-1)
                    require(h==want and not any(self.old_dma[12292+4*old:16384]), 'circular UI ring lost vendor NOP padding')
                    self.ui_wraps+=1
                super().render(end)
                if self.ui_case=='busy': self.regs[4,0x13d4]=2
                if self.ui_case=='cb-fault': self.regs[5,0x8058]=2
                if self.ui_case=='global-fault': self.regs[5,0x48]=8
            return True
        if name == '_clean':
            if probe: return True
            address,n=a(1),a(2)
            if address in IMPORTS:
                require(n==BYTES, 'UI imported source clean extent differs')
                self.import_dma[IMPORTS.index(address)][:]=self.bytes(address,n)
            elif address==TABLES+8192:
                require(n==4*4096 and self.regs[4,0x20c8]&0xfffffff3==3 and
                        self.regs[5,0xc00]==0x20000 and self.regs[5,0x8000]==0x1126,
                        'UI PTE clean precedes CP stop/SID0 fault/CB disable')
                self.tables_dma[8192:24576]=self.bytes(address,n)
            elif address==TABLES+24576:
                require(n==64, 'UI fence clean extent differs')
                self.tables_dma[24576:24640]=self.bytes(address,n)
            else: return super().external_live(target,state,probe,before)
            return True
        if name == '_sgpu_cache_invalidate' and a(1)==TABLES+24576 and self.ui_case=='fence':
            if probe: return True
            require(a(2)==64,'UI fence invalidate extent differs')
            self.m.write(TABLES+24576,bytes(64)); return True
        return super().external_live(target,state,probe,before)

    def execute_case(self, case):
        self.ui_case=case
        self.image()
        if case in ('stride','pages','bytes','width','height'):
            off={'stride':32,'pages':16,'bytes':20,'width':24,'height':28}[case]
            self.m.put(IMAGE+off,self.m.get(IMAGE+off)-1)
        if case=='alignment':self.m.put(IMAGE,IMPORTS[0]+1,8)
        pa={ 'late-pa':0,'duplicate':0xa3000000,'table-alias':0xa0000000,
             'legacy-alias':0x98000000+23*8192,'owned-alias':0xa1000000+1919*8192,
             'aperture':0xc0000000 }.get(case)
        if pa is not None:self.m.put(IMPORT_PA[0]+959*8,pa,8)
        frames=64 if case=='normal' else 2 if case=='owned-change' else 1
        for frame in range(frames):
            b=frame%2 if case=='normal' else 0
            if case=='normal':self.image(b)
            pattern=bytes(((i*13+frame*29)&255) for i in range(256))
            self.m.write(IMPORTS[b],pattern*(BYTES//256))
            before=len(self.ui_writes)
            rc=self.call('_sgpu_ui_copy',IMAGE,POINTER,STRIDE)
            success=case=='normal' or case=='owned-change' and frame==0
            failure=case in ('fence','stop','tlb','global-fault','cb-fault','busy') or case=='owned-change' and frame==1
            require(rc==(1 if success else 0xffffffff if failure else 0), 'UI terminal return differs: '+case)
            if success:
                require(self.m.get(POINTER,8)==PIXELS+BYTES and self.m.get(STRIDE)==3072,
                        'UI output escaped the kernel-owned BO')
                cpu=self.bytes(PIXELS+BYTES,BYTES)
                require(all(cpu[y*3072:y*3072+2880]==self.bytes(IMPORTS[b]+y*3072,2880) for y in range(1280)),
                        'UI output/readback differs from independently generated imported pixels')
                require(self.call('_sgpu_ui_frame',POINTER,STRIDE)==1, 'completed UI output unavailable')
                if case=='owned-change':self.m.put(self.m.get(INPUT+16,8),0xa1001000,8)
            elif failure:
                require(self.call('_sgpu_ui_frame',POINTER,STRIDE)==0,'failure exposed possibly live UI output')
                self.call('_sgpu_ui_snapshot',SNAPSHOT)
                first=self.m.bytes(SNAPSHOT,72); writes=len(self.ui_writes)
                require(first[21]==1 and self.m.get(SNAPSHOT+4)!=0, 'UI first error/quarantine lost')
                require(self.call('_sgpu_ui_copy',IMAGE,POINTER,STRIDE)==0,'UI failure retried')
                self.call('_sgpu_ui_snapshot',SNAPSHOT)
                require(self.m.bytes(SNAPSHOT,72)==first and len(self.ui_writes)==writes,'UI first failure mutated on retry')
            else:require(len(self.ui_writes)==before,'rejected import touched GPU/SMMU')
        if case=='normal':require(self.ui_wraps>=4 and len(self.ui_writes)==64*9,'repeated UI/ring wrap inventory differs')
        return {'success':True,'case':case,'frames':frames,'wraps':self.ui_wraps,
                'visited_words':len(self.vm.visited),'register_writes':len(self.ui_writes),
                'hardware_verified':False}


def compatible_model(path):
    """Require identical execution code before consuming an earlier receipt."""
    old=Path(path).read_text();new=Path(__file__).read_text()
    def execution(source):
        tree=ast.parse(source)
        main_guard=ast.dump(ast.parse("if __name__=='__main__': pass").body[0].test)
        nodes=[n for n in tree.body if not (isinstance(n,ast.If) and ast.dump(n.test)==main_guard) and
               not (isinstance(n,ast.FunctionDef) and n.name in ('audit','compatible_model')) and
               not (isinstance(n,ast.Import) and [a.name for a in n.names]==['ast'])]
        model=ast.dump(ast.Module(body=nodes,type_ignores=[]),include_attributes=False)
        audit_node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='audit')
        calls=[ast.dump(n,include_attributes=False) for n in ast.walk(audit_node)
               if isinstance(n,ast.Call) and
               ((isinstance(n.func,ast.Attribute) and n.func.attr in ('prepare_ui','fork','execute_case','execute_ui')) or
                (isinstance(n.func,ast.Name) and n.func.id in ('UIPureCPU','UIModel','UIAdapter')))]
        loops=[ast.dump(n.iter,include_attributes=False) for n in ast.walk(audit_node)
               if isinstance(n,ast.For) and isinstance(n.target,ast.Name) and n.target.id=='case']
        return model,sorted(calls),sorted(loops)
    require(execution(old)==execution(new),'UI receipt execution code changed; run fresh components')
    return hashlib.sha256(old.encode()).hexdigest()


def audit(ci, compatible_baseline=None):
    ci=Path(ci).resolve()
    base,codes,image,names,e=load_inputs(ci)
    require(all(n in codes for n in CORE+ADAPTER+DISPLAY),'UI actual-code namespace incomplete')
    require(base.get('UI_presentation_changed_code_A53_checked') is True,'UI A53 inspection absent')
    control=default_off(codes,image,names,e)
    require(control and control['success'],'UI mode1 exclusion missing')
    raw=(ci/'kernel/kernel.development.santoni').read_bytes()
    native=UIPureCPU(codes,image,names,raw)
    from santoni_gpu_ui_framebuffer_audit import decode as decode_framebuffer, FramebufferModel, caller_routes
    frame_codes=decode_framebuffer(ci,image,names,e)
    frame_routes=caller_routes(frame_codes,image,names,e)
    common=identity_of(base)
    core_identity={**common,'tool_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   'native_CPU_sha256':hashlib.sha256(Path(__file__).with_name('santoni_gpu_ui_native_cpu.py').read_bytes()).hexdigest()}
    frame_identity={**common,'framebuffer_tool_sha256':hashlib.sha256(
        Path(__file__).with_name('santoni_gpu_ui_framebuffer_audit.py').read_bytes()).hexdigest()}
    identity={**core_identity,**frame_identity}
    compatible_hash=compatible_model(compatible_baseline) if compatible_baseline else None
    def matches(row,want):
        saved=row.get('identity',{})
        for key,value in want.items():
            if key=='tool_sha256' and compatible_hash and saved.get(key)==compatible_hash:
                continue
            if saved.get(key)!=value:return False
        return row.get('success') is True
    results=[]
    try:
        # Execute this kernel's bootstrap once. Every negative gets independent
        # copies of all runtime/CPU/DMA/TLB state, never an old kernel's result.
        folder=ci/'ui-components';folder.mkdir(exist_ok=True)
        frame_folder=ci/('ui-framebuffer-components-'+frame_identity['framebuffer_tool_sha256'][:12])
        frame_folder.mkdir(exist_ok=True)
        seed=None
        for case in CORE_CASES:
            path=folder/('core-'+case+'.json')
            if path.exists():
                row=json.loads(path.read_text())
                require(matches(row,core_identity),'UI component identity differs')
            else:
                if seed is None:
                    seed=UIModel(codes,image,names,e,native,'success')
                    seed.codes=codes
                    seed.prepare_ui()
                row={**seed.fork().execute_case(case),'identity':core_identity}
                with path.open('x') as stream:stream.write(json.dumps(row,indent=2)+'\n')
            results.append(row)
            print('Own-kernel UI core:',case,flush=True)
        adapters=[]
        for case in range(25):
            path=folder/('adapter-'+str(case)+'.json')
            if path.exists():
                row=json.loads(path.read_text())
                require(matches(row,core_identity),'UI adapter component identity differs')
            else:
                row={**UIAdapter(codes,image,names,e,native,case).execute_ui(),'identity':core_identity}
                with path.open('x') as stream:stream.write(json.dumps(row,indent=2)+'\n')
            adapters.append(row)
            print('Own-kernel UI adapter:',case,flush=True)
        frames=[]
        for case in range(20):
            path=frame_folder/('framebuffer-'+str(case)+'.json')
            if path.exists():
                row=json.loads(path.read_text())
                require(matches(row,frame_identity),'UI framebuffer component identity differs')
            else:
                row={**FramebufferModel(frame_codes,image,names,e,case).run(),'identity':frame_identity}
                with path.open('x') as stream:stream.write(json.dumps(row,indent=2)+'\n')
            frames.append(row)
            print('Own-kernel UI framebuffer:',case,flush=True)
    finally:native.close()
    record={**identity,'success':True,'hardware_verified':False,'core_results':results,'adapter_results':adapters,
             'framebuffer_results':frames,'framebuffer_routes':frame_routes,'cases':65,
             'actual_UI_core_checked':True,'full_UI_A53_words_checked':True,
             'actual_UI_adapter_checked':True,
             'actual_framebuffer_ABI_checked':True,
             'read_only_import_and_exact_owned_output_checked':True,
             'CP_SID0_CB_TLB_order_checked':True,'circular_ring_cache_fence_checked':True,
             'failure_quarantine_and_CPU_fallback_checked':True,
             'complete_UI_certificate':True,'mode1_UI_unreachable_checked':True,
             'compatible_core_receipt_tool_sha256':compatible_hash,
             'scope':'actual UI instructions and native validator words; GPU, IOKit, CPU panel converter and bootstrap boundaries modeled; no hardware/GLES proof'}
    path=ci/'ui-binary-audit.json'
    with path.open('x') as stream:stream.write(json.dumps(record,indent=2)+'\n')
    return record


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('ci',type=Path)
    parser.add_argument('--compatible-model',type=Path,
                        help='preserved completed model; reuse only with identical core/adapter execution AST')
    args=parser.parse_args()
    print(json.dumps(audit(args.ci,args.compatible_model),indent=2))
