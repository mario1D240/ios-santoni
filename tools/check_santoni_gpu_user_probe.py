#!/usr/bin/env python3
"""New linked EL0/SVC replay with explicit simulated BSD/Mach service contracts.

No kernel artifact is consumed or certified. BSD copying, credentials,
queue progress and fork/wait status are simulated contracts. A device trial
must still prove the real process, dispatcher and root launch path.
"""
import argparse
import ast
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import traceback

import check_santoni_gpu_kernel as e
from santoni_gpu_binary_model import Machine,integer
from santoni_gpu_launcher_replay import LauncherMachine
import mkinit

ROOT=Path(__file__).resolve().parents[1]
COMMANDS=tuple(0xc0804700+i for i in range(1,5))
TRACE_COMMAND=0x804047f0
SCENARIOS=('normal','mach-carry','mach-error','late-info','nonroot','transfer',
           'pid1-parent','pid1-child','open-delay','late-open','open-clock-error',
           'pid1-single-user','pid1-fork-fail','pid1-exec-fail','stopped',
           'console-open-error','console-open-overflow','console-write-error',
           'console-short-write','trace-open-error','trace-ioctl-error','getpid-error')

def _require(ok,message):
    if not ok: raise ValueError('linked EL0 probe: '+message)

def digest(data): return hashlib.sha256(data).hexdigest()


class Finished(Exception):
    def __init__(self,kind,status=0): self.kind,self.status=kind,status


def probe_inputs(folder):
    build=json.loads((folder/'build.json').read_text())
    image_bytes=(folder/'probe.macho').read_bytes()
    elf=folder/'probe.elf'
    _require(build['macho_sha256']==hashlib.sha256(image_bytes).hexdigest() and
             build['elf_sha256']==hashlib.sha256(elf.read_bytes()).hexdigest(), 'probe build inputs changed')
    sources=('tools/santoni_gpu_user_probe.c','tools/santoni_gpu_user_probe_start.S')
    _require(build['sources_sha256']=={p:digest((ROOT/p).read_bytes()) for p in sources},
             'build differs from current probe sources')
    uapi=(folder/'santoni_gpu_uapi.h').read_bytes()
    patch=(ROOT/'xnu/patches/0207-santoni-gpu-scalar-user-client.patch').read_text()
    addition=patch.split('+++ b/bsd/dev/santoni_gpu_uapi.h\n',1)[1].split('diff --git ',1)[0]
    production_uapi=''.join(line[1:]+'\n' for line in addition.splitlines() if line.startswith('+')).encode()
    _require(digest(uapi)==build['uapi_sha256'] and uapi==production_uapi,'UAPI differs from production0207')
    trace=(folder/'santoni_gpu_launch_trace.h').read_bytes()
    trace_patch=(ROOT/'xnu/patches/0211-santoni-gpu-el0-outcome-trace.patch').read_text()
    addition=trace_patch.split('+++ b/bsd/dev/santoni_gpu_launch_trace.h\n',1)[1].split('diff --git ',1)[0]
    production_trace=''.join(line[1:]+'\n' for line in addition.splitlines() if line.startswith('+')).encode()
    _require(build.get('requires_EL0_trace_kernel') is True and
             digest(trace)==build.get('trace_uapi_sha256') and trace==production_trace,
             'trace ABI differs from production0211')
    image=e._Image(image_bytes)
    _require([(s['vmaddr'],s['vmsize'],s['fileoff'],s['filesize'],s['initprot']) for s in image.segs]==[
        (0,mkinit.BASE,0,0,0),(mkinit.BASE,mkinit.SEG,0,mkinit.SEG,5),
        (mkinit.BASE+mkinit.SEG,mkinit.SEG,mkinit.SEG,len(image_bytes)-mkinit.SEG,1)],
        'static Mach-O segment layout/protections differ')
    header=struct.unpack_from('<8I',image_bytes)
    _require(header[:5]==(mkinit.MH_MAGIC_64,mkinit.CPU_TYPE_ARM64,0,mkinit.MH_EXECUTE,5) and
             header[6:]==(mkinit.MH_NOUNDEFS,0),'static Mach-O identity differs')
    offset,thread,signature=32,None,None
    for _ in range(header[4]):
        command,size=struct.unpack_from('<II',image_bytes,offset)
        _require(size>=8 and offset+size<=32+header[5],'Mach-O load command extent differs')
        if command==mkinit.LC_UNIXTHREAD:
            _require(thread is None and struct.unpack_from('<4I',image_bytes,offset)==(5,288,6,68),
                     'Mach-O thread flavor/count differs')
            thread=struct.unpack_from('<33QII',image_bytes,offset+16)
        elif command==mkinit.LC_CODE_SIGNATURE:
            _require(signature is None and size==16,'Mach-O signature command differs')
            signature=struct.unpack_from('<II',image_bytes,offset+8)
        else:_require(command==mkinit.LC_SEGMENT_64,'unexpected dynamic Mach-O command')
        offset+=size
    _require(offset==32+header[5] and thread is not None and
             all(v==0 for i,v in enumerate(thread) if i!=32),'Mach-O initial thread state differs')
    _require(signature==(mkinit.SEG,len(image_bytes)-mkinit.SEG) and
             image_bytes[mkinit.SEG:]==mkinit.code_signature(image_bytes[:mkinit.SEG],mkinit.SEG,mkinit.SEG),
             'ad-hoc code-signature page hashes/layout differ')
    symbols=(folder/'symbols.txt').read_text()
    _require(symbols==subprocess.check_output(['llvm-nm','--defined-only',str(elf)],text=True),
             'saved ELF symbols changed')
    _require(not subprocess.check_output(['llvm-nm','--undefined-only',str(elf)],text=True).strip(),
             'probe imports an external runtime')
    names=e._symbols(symbols)
    _require(all(len(names.get(n,()))==1 for n in ('__probe_code_start','__probe_code_end',
             '_start','sgpu_syscall','sgpu_user_probe_run')),'ambiguous/missing code boundary')
    start=next(iter(names['__probe_code_start']))
    end=next(iter(names['__probe_code_end']))
    _require(thread[32]==next(iter(names['_start']))==build['entry_vma'],'Mach-O/ELF launch PC differs')
    blob=(folder/'probe.bin').read_bytes()
    _require(len(blob)==build['ro_blob_bytes'] and image_bytes[mkinit.CODE_OFF:mkinit.CODE_OFF+len(blob)]==blob,
             'linked text/rodata blob differs from Mach-O')
    wanted=[name for name,addresses in names.items() if name!='__probe_code_start' and
            len(addresses)==1 and start<=next(iter(addresses))<end]
    codes,words,assembly={},{},[]
    for name in wanted:
        text=subprocess.check_output(['llvm-objdump','--disassemble','--disassemble-zeroes',
            '--disassemble-symbols='+name,str(elf)],text=True)
        code=e._Code(re.sub(r'\s+//[^\n]*','',text),name,next(iter(names[name])))
        inspected=set(code.ins)|set(code.padding)
        decoded={}
        for line in text.splitlines():
            match=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s',line)
            if match:
                pc,word=int(match[1],16),int(match[2],16)
                _require(pc in inspected and image.read(pc,4)==word,'ELF words differ from signed Mach-O')
                decoded[pc]=word
        _require(set(decoded)==inspected and not set(words)&inspected,'missing/overlapping inspected words')
        words.update(decoded);assembly.append(text)
        codes[name]=code
    _require(start==0x100000400 and end-start==build['code_bytes'] and end%4==0 and
             set(words)==set(range(start,end,4)),'linked code extent has a hole/extra word')
    _require('_start' in codes and 'sgpu_syscall' in codes and 'sgpu_user_probe_run' in codes,
             'probe entry/syscall/run boundaries missing')
    return codes,image,names,build,'\n'.join(assembly)


def audit_instructions(codes):
    entries={c.entry for c in codes.values()}
    allowed={'ret','b','bl','cbz','cbnz','tbz','tbnz','svc','wfe','adr','adrp','mov','movk',
        'sxtw','sxth','sxtb','uxtw','uxth','uxtb','ubfx','ubfiz','cmp','tst','cmn','ccmp',
        'cset','csetm','csel','csinc','csinv','csneg','cinc','add','sub','and','orr','eor','bic',
        'lsl','lsr','adds','subs','ands','bics','ldr','ldrb','ldrh','ldur','ldurb','ldurh',
        'str','strb','strh','stur','sturb','sturh','ldp','stp','nop','madd','mul','umull',
        'umaddl','umulh','udiv','neg','msub'}
    svc=[]
    for name,code in codes.items():
        for pc,(op,args) in code.ins.items():
            _require(op in allowed or op.startswith('b.'),'unreviewed ISA operation '+op)
            if op=='cinc':
                _require(len(args)==3 and args[2] in ('eq','ne') and
                         re.fullmatch(r'[wx](?:[12]?\d|30|zr)',args[0]) and
                         re.fullmatch(r'[wx](?:[12]?\d|30|zr)',args[1]) and args[0][0]==args[1][0],
                         'CINC differs from the previously proved scalar EQ/NE instruction contract')
            _require(not re.search(r'\b(?:[bhsdqv]\d+|z\d+|p\d+)\b',','.join(args)),
                     'non-general-register instruction')
            if op=='bl' or op=='b' and e._number(args[-1]) not in code.ins:
                _require(e._number(args[-1]) in entries,'external/interior linked callee')
            if op=='svc':
                _require(args==('#0x80',) and name in ('_start','sgpu_syscall'),'unreviewed trap site')
                svc.append((name,pc))
            if op=='wfe':
                _require(code.ins.get(pc+4)==('b',(hex(pc),)),'nonterminal WFE')
    _require(sorted(n for n,_ in svc)==['_start','sgpu_syscall'],'trap-site count differs')
    wrapper=codes['sgpu_syscall'];target=hex(wrapper.entry+76)
    expected=[('stp',('x19','x20','[sp, #-0x20]!')),('str',('x30','[sp, #0x10]')),
        ('mov',('x19','x7')),('mov',('x20','x0')),('mov',('x16','x0'))]
    expected += [('mov',('x'+str(i),'x'+str(i+1))) for i in range(6)]
    expected += [('svc',('#0x80',)),('cset',('w8','hs')),('str',('w8','[x19]')),
        ('cbnz',('w8',target)),('cmp',('x20','#0x2')),('b.ne',(target,)),
        ('cmp',('x1','#0x0')),('csel',('x0','xzr','x0','ne')),
        ('ldr',('x30','[sp, #0x10]')),('ldp',('x19','x20','[sp]','#0x20')),('ret',())]
    _require(list(wrapper.ins.values())==expected,'Darwin wrapper arguments/carry/fork/save ABI differs')
    entry=codes['_start']
    _require(list(entry.ins.values())==[
        ('mov',('x9','sp')),('ldr',('x0','[x9]')),('add',('x1','x9','#0x8')),
        ('and',('x9','x9','#0xfffffffffffffff0')),('mov',('sp','x9')),
        ('bl',(hex(codes['sgpu_user_probe_entry'].entry),)),('mov',('x16','#0x1')),
        ('svc',('#0x80',)),('wfe',()),('b',(hex(entry.entry+32),))],
        'launch stack/exit terminal ABI differs')
    return {'success':True,'functions':len(codes),
        'decoded_instructions':sum(len(c.ins) for c in codes.values()),
        'svc_sites':[{'function':n,'address':hex(pc)} for n,pc in svc],
        'exact_wrapper_and_entry':True,'kernel_dependency':None}


class ScalarService:
    """Independent UAPI fixture; no driver/core instructions execute here."""
    def __init__(self):
        self.owner,self.refs,self.closed,self.fd_open=None,0,False,False
        self.admitted,self.completed,self.idle,self.wave_waits=0,0,1,0
        self.values,self.info_calls,self.closes,self.fd_closes=[],0,0,0

    def open(self,uid,task):
        if uid!=0:return 13
        if self.owner is not None or self.closed:return 16
        self.owner,self.refs,self.fd_open=task,1,True
        return 0

    def close(self):self.closed=True

    def progress(self):
        self.completed=self.admitted
        if self.admitted==16:
            self.wave_waits+=1
            if self.wave_waits==3:self.idle+=1
        else:self.idle+=1

    def packet(self,command,incoming,task):
        if task!=self.owner:return 13,None
        p=list(struct.unpack('<32I',incoming))
        valid_id=1<=p[2]<=32 if command==COMMANDS[2] else p[2]==0
        allowed={0,1,2}|({4,5,6,7} if command==COMMANDS[1] else set())
        if p[0:2]!=[1,128] or not valid_id or any(v for i,v in enumerate(p) if i not in allowed):
            return 22,None
        reply=[0]*32;reply[0:3]=[1,128,p[2]]
        if command==COMMANDS[1]:
            if self.admitted-self.completed>=4:reply[3]=3
            elif self.admitted>=32:reply[3]=4
            else:
                _require(self.admitted<16 or self.wave_waits>=3,'second wave preceded newer admission-locked idle')
                _require(p[4:8]==[0xa5080000^((self.admitted+1)<<8)^i for i in range(4)],
                         'copied WRITE4 payload differs')
                self.values.append(tuple(p[4:8]));self.admitted+=1;reply[2]=self.admitted
                if self.admitted==16:self.idle+=1 # newer than preceding INFO
        elif command==COMMANDS[2]:
            if p[2]>self.completed:reply[3]=1
            else:reply[24:28]=[4,p[2]+2,170+11*p[2],4];reply[30]=1
        elif command==COMMANDS[3]:self.closes+=1;self.close()
        else:self.info_calls+=1
        reply[8:16]=[4 if self.completed==32 else 3 if self.closed else 1,
            1 if self.completed==32 else 0,self.admitted,self.admitted-self.completed,
            0,self.completed,self.completed,self.completed]
        reply[18:24]=[4*self.completed,self.completed+2,170+11*self.completed,0,0,self.idle]
        return 0,struct.pack('<32I',*reply)


class ProbeModel:
    def __init__(self,codes,image,names,scenario):
        self.k=ScalarService()
        self.scenario,self.pid,self.uid,self.task=scenario,7,0,7
        self.clock,self.forks,self.waits=1000000,0,0
        self.syscalls,self.output,self.readonly_copyouts=[],bytearray(),0
        self.trace_fd,self.trace_closes=False,0
        self.trace_records=[]
        self.console_writes,self.first_write_bytes=0,0
        # Reuse the unchanged, previously tested scalar CINC interpreter. The
        # instruction gate above admits only CINC from its extra operations;
        # no kernel artifact or launcher/VFS service model is consumed here.
        self.vm=LauncherMachine(codes,image,names,e,stack_base=0x70000000)
        self.m=self.vm.memory
        self.vm.syscall=self.syscall
        self.vm.external=lambda *args,**kwargs:False
        self.last=0x71000000; self.args=0x71000100
        self.m.map(self.last,16);self.m.put(self.last,self.clock,8)
        self.m.map(self.args,128)
        self.m.write(self.args+32,b'/dev/sgpu/sbin/launchd\0')
        self.m.write(self.args+80,b'-s\0')
        self.m.put(self.args,self.args+32,8);self.m.put(self.args+8,0,8)
        self.m.map(self.vm.STACK+self.vm.STACK_SIZE,32)
        single=scenario=='pid1-single-user'
        self.m.put(self.vm.STACK+self.vm.STACK_SIZE,2 if single else 1,8)
        self.m.put(self.vm.STACK+self.vm.STACK_SIZE+8,self.args+32,8)
        self.m.put(self.vm.STACK+self.vm.STACK_SIZE+16,self.args+80 if single else 0,8)
        self.m.put(self.vm.STACK+self.vm.STACK_SIZE+24,0,8)

    def string(self,address):
        data=bytearray()
        for offset in range(256):
            byte=self.m.get(address+offset,1)
            if not byte:return data.decode()
            data.append(byte)
        raise ValueError('unbounded syscall string')

    def worker(self):
        if self.scenario=='stopped':return
        self.k.progress()

    def syscall(self,state,before):
        nr=integer(before,'x16'); a=lambda n:integer(before,'x'+str(n))
        self.syscalls.append(nr)
        def result(value=0,error=False,second=0):
            state.put('x0',e._Value(64,value));state.put('x1',e._Value(64,second))
            state.flags=('nzcv',2 if error else 0)
            return True
        if nr==(1<<64)-89:
            self.m.put(a(0),1);self.m.put(a(0)+4,1)
            return result(5 if self.scenario=='mach-error' else 0,self.scenario=='mach-carry')
        if nr==116:
            _require(a(0)==0 and a(1)==0,'gettimeofday must request absolute-time output only')
            if self.scenario=='open-clock-error' and self.k.fd_open:return result(14,True)
            self.m.put(a(2),self.clock*1000,8);return result()
        if nr==20:return result(14,True) if self.scenario=='getpid-error' else result(self.pid)
        if nr==2:
            _require(all(a(i)==0 for i in range(6)),'fork argument contract differs')
            self.forks+=1
            if self.scenario=='pid1-fork-fail' and self.pid==1:return result(11,True)
            if self.scenario in ('nonroot','transfer'):
                self.pid=8;self.task=8
                return result(7,False,1) # deliberately not0 in x0: wrapper must normalize x1
            if self.scenario=='pid1-child' and self.pid==1:
                self.pid=2;self.task=2;return result(1,False,1)
            return result(100+self.forks,False,0)
        if nr==23:
            _require(a(0)==501,'nonroot child UID differs');self.uid=501;return result()
        if nr==7:
            _require(a(2)==1 and a(3)==0,'wait4 must be nonblocking/no rusage')
            self.m.put(a(1),0);return result(a(0)) # injected child result, not POSIX scheduler proof
        if nr==59:
            _require(self.pid==1 and self.string(a(0))=='/sbin/launchd' and a(2)==0,
                     'parent exec must preserve real launchd/environment')
            _require(self.string(self.m.get(a(1),8))=='/sbin/launchd','original init argv0 differs')
            second=self.m.get(a(1)+8,8)
            _require((self.string(second)=='-s' and self.m.get(a(1)+16,8)==0)
                     if self.scenario=='pid1-single-user' else second==0,'original init arguments differ')
            _require(self.k.owner is None and not self.k.admitted,'PID1 opened GPU before original launchd')
            if self.scenario=='pid1-exec-fail':return result(2,True)
            if self.trace_fd:self.trace_fd=False;self.trace_closes+=1 # injected O_CLOEXEC contract
            raise Finished('original-init')
        if nr==1:raise Finished('exit',a(0))
        if nr==5:
            path=self.string(a(0));_require(a(2)==0,'open mode differs')
            if path=='/dev/sgpu/sbin/launchd':
                _require(a(1)==0x01000000 and not self.trace_fd,'trace open is not readonly/CLOEXEC/one-shot')
                if self.scenario=='trace-open-error':return result(45,True)
                self.trace_fd=True;return result(8)
            _require(a(1)==2,'console/GPU open flags differ')
            if path=='/dev/console':
                if self.scenario=='console-open-error':return result(13,True)
                if self.scenario=='console-open-overflow':return result(0x80000000)
                return result(9)
            _require(path=='/dev/santonigpu','unreviewed probe file access')
            if self.scenario=='open-delay' and self.clock<1300000:return result(2,True)
            rc=self.k.open(self.uid,self.task)
            if not rc and self.scenario=='late-open':self.clock=101000000
            return result(rc if rc else 3,bool(rc))
        if nr==6:
            if a(0)==3:
                self.k.fd_open=False;self.k.fd_closes+=1;self.k.close();return result()
            if a(0)==8:
                _require(self.trace_fd,'trace close on unopened descriptor')
                self.trace_fd=False;self.trace_closes+=1;return result()
            _require(a(0)==9,'unreviewed fd close');return result()
        if nr==4:
            _require(a(0)==9 and a(2)<=512 and len(self.output)+a(2)<1024,'probe writes outside console/bound')
            self.console_writes+=1
            if self.console_writes==1:self.first_write_bytes=a(2)
            if self.scenario=='console-write-error':return result(5,True)
            if self.scenario=='console-short-write' and self.console_writes==1:
                self.output.extend(self.m.bytes(a(1),a(2)-1));return result(a(2)-1)
            self.output.extend(self.m.bytes(a(1),a(2)));return result(a(2))
        if nr==93:
            _require(all(a(i)==0 for i in range(4)),'sleep select has fd sets')
            secs,usecs=self.m.get(a(4),8),self.m.get(a(4)+8,4)
            if self.scenario=='pid1-exec-fail' and secs==1 and usecs==0:
                _require(self.k.owner is None and b'PID1 retained' in self.output,'failed exec touched GPU')
                raise Finished('retained-init')
            _require(secs==0 and usecs in (10000,100000),'unreviewed sleep interval')
            self.waits+=1
            if self.scenario!='stopped':self.clock+=secs*1000000+usecs
            self.worker();return result()
        if nr==54:
            if a(0)==8:
                _require(self.trace_fd and a(1)==TRACE_COMMAND,'unreviewed trace descriptor/command')
                _require(self.uid==0 and len(self.trace_records)<16,'trace credential/budget contract differs')
                record=list(struct.unpack('<16I',self.m.bytes(a(2),64)))
                _require(record[:2]==[1,64] and 1<=record[2]<=9 and record[3]<=2 and
                         not any(record[11:]) and record[5]<=1 and record[6]<=32 and
                         record[7]<=record[6] and record[8]<=7 and record[9]<=6,
                         'trace fixed input/header/scalars differ')
                _require(record[3]!=2 or record[2]==7,'short write status outside console-write event')
                _require((record[3:5]==[0,0] if record[2]==6 else not any(record[5:11])),
                         'trace result/ordinary event fields differ')
                self.trace_records.append({'pid':self.pid,'words':record,
                    'accepted':self.scenario!='trace-ioctl-error'})
                return result(45,True) if self.scenario=='trace-ioctl-error' else result()
            _require(a(0)==3 and self.k.fd_open,'ioctl uses a closed/unreviewed fd')
            command,pointer=a(1),a(2)
            _require(command in COMMANDS,'unreviewed scalar command')
            try:incoming=self.m.bytes(pointer,128)
            except ValueError:return result(14,True)
            rc,returned=self.k.packet(command,incoming,self.task)
            if rc:return result(rc,True)
            try:self.m.write(pointer,returned)
            except ValueError:
                self.readonly_copyouts+=1
                return result(14,True) # RO copyout fails after simulated service INFO
            if self.scenario=='late-info' and command==0xc0804701 and self.k.completed==32:
                self.clock=101000000
            return result()
        raise ValueError('unreviewed raw syscall '+str(nr))


def stopped_boundary(model):
    """Inspect the linked loop tail, then replay first/final iterations only.

    This is counter injection at the second head, not 10000 executions and not
    a guarantee that a real syscall returns or the real scheduler progresses.
    """
    code=model.vm.codes['sgpu_user_probe_run'];tails=[]
    for pc,(op,args) in code.ins.items():
        if op!='add' or len(args)!=3 or args[0]!=args[1] or args[2]!='#0x1':continue
        count=args[0];bound=code.ins.get(pc+4);branch=code.ins.get(pc+12)
        if bound and bound[0]=='mov' and bound[1][1:] == ('#0x2710',) and \
                code.ins.get(pc+8)==('cmp',(count,bound[1][0])) and branch and branch[0]=='b.ne':
            tails.append((pc,count,e._number(branch[1][0])))
    _require(len(tails)==1,'ambiguous compiled10000 attempt tail')
    tail,count,head=tails[0]
    _require(head in code.ins and head<tail and any(pc<head and ins==('mov',(count,'wzr'))
             for pc,ins in code.ins.items()),'compiled attempt initialization/head missing')
    boundary={'compiled_limit':10000,'head':hex(head),'tail':hex(tail),'counter':count,
        'head_values_before_injection':[],'injected_counter':9999,'actual_outer_iterations':0,
        'full_10000_iterations_executed':False,'scope':'linked first/final iteration and exact loop-tail pattern'}
    def observe(pc,state):
        if pc!=head:return
        value=integer(state,count);boundary['head_values_before_injection'].append(value)
        boundary['actual_outer_iterations']+=1
        _require(value==boundary['actual_outer_iterations']-1 and value in (0,1),
                 'unexpected outer head count/continued after bound')
        if value==1:state.put(count,e._Value(32,9999))
    model.vm.observe=observe
    model.loop_boundary=boundary


def replay(codes,image,names,build,scenarios,record):
    results={}
    for scenario in scenarios:
        _require(scenario in SCENARIOS,'unknown scenario '+scenario)
        model=ProbeModel(codes,image,names,scenario)
        if scenario.startswith('pid1-'):model.pid=1
        if scenario in ('nonroot','transfer'):
            _require(model.k.open(0,model.task)==0,'parent setup open')
            target='child_negative';arguments=(3,int(scenario=='nonroot'),1000000,model.last)
        else:target='_start';arguments=()
        if scenario=='stopped':stopped_boundary(model)
        try:
            model.vm.run(target,arguments,budget=20000000)
            raise ValueError('probe returned without process outcome')
        except Finished as finished:
            outcome,status=finished.kind,finished.status
            expected_kind='retained-init' if scenario=='pid1-exec-fail' else 'original-init' if scenario in (
                'pid1-parent','pid1-single-user','pid1-fork-fail') else 'exit'
            expected_status=1 if scenario in ('mach-error','late-info','stopped','late-open','open-clock-error',
                'console-open-error','console-open-overflow','getpid-error') else 0
            _require(finished.kind==expected_kind and finished.status==expected_status,
                     'linked process outcome differs '+scenario)
        success_workload=('normal','mach-carry','pid1-child','open-delay','console-write-error',
            'console-short-write','trace-open-error','trace-ioctl-error')
        if scenario in success_workload:
            if scenario not in ('console-write-error','console-short-write'):
                _require(b'RESULT pass=1' in model.output and b'sent=32 verified=32 negative=7' in model.output,
                         'linked probe did not verify complete quota/negative contract')
            _require(model.k.admitted==model.k.completed==len(model.k.values)==32 and
                     model.k.wave_waits>=3 and model.readonly_copyouts==1,'quota/idle/copied read-only contract differs')
        if scenario not in ('nonroot','transfer') and model.k.owner is not None:
            _require(model.k.closed and not model.k.fd_open and model.k.closes==1 and
                     model.k.fd_closes==1 and model.k.refs==1,'probe close/task retention differs '+scenario)
        if scenario in ('late-open','open-clock-error'):
            _require(model.k.owner is not None and not model.k.admitted,'post-open failure cleanup fixture missing')
        if scenario in ('mach-error','late-info','stopped','late-open','open-clock-error'):
            error=2 if scenario=='mach-error' else 3
            _require(b'RESULT pass=0' in model.output and (' error='+str(error)+' errno=0;').encode() in model.output,
                     'failure report reason differs '+scenario)
        if scenario in ('nonroot','transfer'):
            _require(model.k.refs==1 and not model.k.admitted and not model.k.closes and not model.k.fd_closes,
                     'child denial mutated owner/queue')
        if scenario=='stopped':
            _require(model.loop_boundary['head_values_before_injection']==[0,1] and
                     model.k.info_calls-model.readonly_copyouts==2,'stopped-clock first/final iteration differs')
        if scenario not in ('nonroot','transfer'):
            events=[r['words'][2] for r in model.trace_records]
            expected_events=[1,2,8,9] if scenario=='pid1-exec-fail' else [1,2,8] if scenario in (
                'pid1-parent','pid1-single-user','pid1-fork-fail') else [1] if scenario=='getpid-error' else \
                [1,3,4,6] if scenario in ('console-open-error','console-open-overflow') else \
                [] if scenario=='trace-open-error' else [1,3,4,5,6,7]
            _require(events==expected_events,'missing/reordered/extra EL0 observation '+scenario)
            _require(model.trace_closes==int(scenario not in ('trace-open-error','pid1-exec-fail')) and
                     model.trace_fd==bool(scenario=='pid1-exec-fail'),'trace descriptor lifetime differs '+scenario)
            reports=[r['words'] for r in model.trace_records if r['words'][2]==6]
            if scenario in success_workload and scenario!='trace-open-error':
                _require(len(reports)==1 and reports[0][5:11]==[1,32,32,7,0,0],
                         'kernel-visible EL0 outcome differs from successful workload')
            if scenario in ('console-open-error','console-open-overflow'):
                _require(model.k.owner is None and not model.k.admitted and not model.output and
                         reports[0][5:11]==[0,0,0,0,1,13 if scenario=='console-open-error' else 0xffffffff],
                         'console-open failure lost terminal observation or ran GPU')
            if scenario in ('console-write-error','console-short-write'):
                write=model.trace_records[-1]['words']
                _require(write[3:5]==([1,5] if scenario=='console-write-error' else
                    [2,model.first_write_bytes-1]),'console write outcome lost/altered GPU result')
            if scenario=='pid1-fork-fail':
                _require(model.trace_records[1]['words'][3:5]==[1,11] and model.k.owner is None,
                         'fork failure not observed before original-init fallback')
            if scenario=='pid1-exec-fail':
                _require(model.trace_records[-1]['words'][3:5]==[1,2],
                         'original exec return not observed independently of console')
        results[scenario]={'success':True,'syscalls':len(model.syscalls),'waits':model.waits,
            'output':model.output.decode(),'executed_instruction_addresses':len(model.vm.visited),
            'info_calls':model.k.info_calls,'admitted':model.k.admitted,'completed':model.k.completed,
            'close_requests':model.k.closes,'fd_closes':model.k.fd_closes,'retained_task_refs':model.k.refs,
            'outcome':outcome,'status':status,
            'trace_records':model.trace_records,'trace_fd_closes':model.trace_closes,
            'syscall_counts':{str(n):model.syscalls.count(n) for n in set(model.syscalls)},
            'kernel_dependency':None,
            'scope':'linked EL0 code/SVC with simulated BSD/Mach/fork completion/CPU queue progress',
            'hardware_or_real_dispatcher_verified':False,'probe_sha256':build['macho_sha256']}
        if scenario=='stopped':results[scenario]['loop_boundary']=model.loop_boundary
        record(scenario,results[scenario])
    return results


def completed_scope_hash(source):
    """Pin shared model/acceptance code when only the unfinished stopped case changes."""
    class Normalize(ast.NodeTransformer):
        def visit_If(self,node):
            if ast.dump(node.test)==ast.dump(ast.parse("scenario=='stopped'",mode='eval').body):
                return None
            return self.generic_visit(node)
    tree=ast.parse(source)
    wanted={'_require','digest','Finished','probe_inputs','audit_instructions','ScalarService','ProbeModel','replay'}
    nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in wanted]
    _require(len(nodes)==len(wanted),'completed model scope missing')
    nodes += [n for n in tree.body if isinstance(n,ast.Assign) and any(
        isinstance(t,ast.Name) and t.id in ('ROOT','COMMANDS','TRACE_COMMAND','SCENARIOS') for t in n.targets)]
    return digest(ast.dump(Normalize().visit(ast.Module(body=nodes,type_ignores=[]))).encode())


def stopped_scope_hash(source):
    tree=ast.parse(source)
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('stopped_boundary','replay')]
    _require(len(nodes)==2,'completed stopped-case scope missing')
    return digest(ast.dump(ast.Module(body=nodes,type_ignores=[])).encode())


def consume_completed(folder,previous):
    """Consume saved passing components; no LLVM invocation or component replay."""
    result=json.loads((previous/'result.json').read_text())
    old=(previous/'audit-source.py').read_bytes()
    _require(digest(old)==result['audit_sources_sha256']['tools/check_santoni_gpu_user_probe.py'] and
             completed_scope_hash(old)==completed_scope_hash(Path(__file__).read_bytes()),
             'completed shared model/acceptance code changed')
    if 'stopped' in result['cases']:
        _require(stopped_scope_hash(old)==stopped_scope_hash(Path(__file__).read_bytes()),
                 'completed stopped-case model/acceptance code changed')
    for p,h in result['audit_sources_sha256'].items():
        if p!='tools/check_santoni_gpu_user_probe.py':
            same=digest((ROOT/p).read_bytes())==h
            if not same and p=='tools/check_santoni_gpu_kernel.py':
                from santoni_gpu_audit_compat import kernel_auditor_compatible
                same=kernel_auditor_compatible(h)
            _require(same,'completed audit dependency changed '+p)
    build=json.loads((folder/'build.json').read_text())
    data=(folder/'probe.macho').read_bytes()
    _require(result.get('instructions',{}).get('success') and
             result.get('probe_sha256')==build['macho_sha256']==digest(data) and
             digest((folder/'probe.elf').read_bytes())==build['elf_sha256'] and
             all(digest((ROOT/p).read_bytes())==h for p,h in build['sources_sha256'].items()),
             'completed linked inputs changed')
    _require(all(n in SCENARIOS and c.get('success') and c.get('probe_sha256')==build['macho_sha256']
             for n,c in result['cases'].items()),'invalid completed case component')
    trace=(folder/'santoni_gpu_launch_trace.h').read_bytes()
    patch=(ROOT/'xnu/patches/0211-santoni-gpu-el0-outcome-trace.patch').read_text()
    addition=patch.split('+++ b/bsd/dev/santoni_gpu_launch_trace.h\n',1)[1].split('diff --git ',1)[0]
    production=''.join(line[1:]+'\n' for line in addition.splitlines() if line.startswith('+')).encode()
    _require(build.get('requires_EL0_trace_kernel') is True and
             digest(trace)==build.get('trace_uapi_sha256') and trace==production,
             'completed trace ABI differs from production0211')
    names=e._symbols((folder/'symbols.txt').read_text());image=e._Image(data)
    start,end=(next(iter(names[n])) for n in ('__probe_code_start','__probe_code_end'))
    assembly=(previous/'linked.asm').read_text()
    codes={n:e._Code(re.sub(r'\s+//[^\n]*','',assembly),n,next(iter(a))) for n,a in names.items()
           if n!='__probe_code_start' and len(a)==1 and start<=next(iter(a))<end}
    # Saved LLVM words still refer to this exact immutable image.
    for line in assembly.splitlines():
        m=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s',line)
        if m:_require(image.read(int(m[1],16),4)==int(m[2],16),'saved decoded word changed')
    return codes,image,names,build,assembly,result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('probe',type=Path)
    parser.add_argument('--scenarios',nargs='+',default=list(SCENARIOS))
    parser.add_argument('--resume',type=Path,help='consume unchanged passing components from this replay directory')
    args=parser.parse_args()
    out=args.probe/('replay-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));out.mkdir()
    result={'success':False,'cases':{},'kernel_dependency':None,'kernel_certified':False,'hardware_verified':False}
    (out/'audit-source.py').write_bytes(Path(__file__).read_bytes())
    def record(name,case):
        result['cases'][name]=case
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    try:
        if args.resume:
            codes,image,names,build,assembly,previous=consume_completed(args.probe,args.resume)
            result['instructions']=previous['instructions']
            result['cases']=previous['cases']
            result['consumed_components']={'evidence':str(args.resume),'cases':list(previous['cases']),
                'audit_sources_sha256':previous['audit_sources_sha256']}
        else:codes,image,names,build,assembly=probe_inputs(args.probe)
        result['probe_sha256']=build['macho_sha256']
        result['audit_sources_sha256']={p:digest((ROOT/p).read_bytes()) for p in
            ('tools/check_santoni_gpu_user_probe.py','tools/santoni_gpu_binary_model.py',
             'tools/check_santoni_gpu_kernel.py','tools/mkinit.py','tools/santoni_gpu_launcher_replay.py')}
        (out/'linked.asm').write_text(assembly)
        if not args.resume:result['instructions']=audit_instructions(codes)
        remaining=[n for n in args.scenarios if n not in result['cases']]
        result['executed_this_attempt']=remaining
        replay(codes,image,names,build,remaining,record)
        result['success']=True
        result['complete_scenario_scope']=set(result['cases'])==set(SCENARIOS)
    except Exception as error:
        result['error']=str(error);(out/'traceback.txt').write_text(traceback.format_exc())
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'evidence':str(out),'success':result['success'],
                      'completed_cases':len(result['cases']),'error':result.get('error')},indent=2))
    return 0 if result['success'] else 1


if __name__=='__main__':raise SystemExit(main())
