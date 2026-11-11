#!/usr/bin/env python3
"""Screen actual iOS graphics code words and declare (not assume) dependencies.

This is a CPU ISA/metadata check, never GPU/raster/runtime or hardware proof.
LLVM uses an explicitly restricted ARMv8-A/A53 profile. Unknown instructions,
decoder holes and bytes that differ from the input image fail closed. Optional
crypto/CRC and newer instructions are refused even if LLVM decodes an alias.
"""
import argparse
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

CPU_ATTRIBUTES='-crypto,-crc,-fullfp16,-dotprod,-pauth,-bti,-lse,-rcpc,-sve,-sve2'
MAX_BINARY=128*1024*1024
MAX_DISASSEMBLY=768*1024*1024

def uleb(data,position):
    value=0
    for shift in range(0,64,7):
        if position>=len(data):raise ValueError('truncated function-start ULEB')
        byte=data[position];position+=1;value|=(byte&127)<<shift
        if not byte&128:
            if value>0xffffffffffffffff:raise ValueError('oversized function-start ULEB')
            return value,position
    raise ValueError('oversized function-start ULEB')

def metadata(data):
    if len(data)<32 or len(data)>MAX_BINARY:raise ValueError('library size outside bound')
    header=struct.unpack_from('<8I',data)
    if header[:4]!=(0xfeedfacf,0x100000c,0,6):raise ValueError('not a plain-arm64 Mach-O dylib')
    if header[4]>128 or header[5]>len(data)-32:raise ValueError('load-command bound')
    position=32;limit=position+header[5];sections=[];all_sections=[];dylibs=[];starts=None;symtab=None;indirect=None;deployment=False
    for _ in range(header[4]):
        if position+8>limit:raise ValueError('truncated load command')
        command,size=struct.unpack_from('<II',data,position)
        if size<8 or size%8 or position+size>limit:raise ValueError('load-command extent')
        if command==0x19:
            if size<72:raise ValueError('segment header extent')
            name,address,length,offset,bytes_,maxprot,initprot,count=struct.unpack_from('<16s4Q3I',data,position+8)
            if count>128 or size!=72+count*80 or offset>len(data) or bytes_>len(data)-offset:
                raise ValueError('segment extent')
            for i in range(count):
                section,segment,va,span,off=struct.unpack_from('<16s16sQQI',data,position+72+i*80)
                flags=struct.unpack_from('<I',data,position+72+i*80+64)[0]
                reserved1,reserved2=struct.unpack_from('<II',data,position+72+i*80+68)
                all_sections.append({'address':va,'bytes':span,'offset':off,'flags':flags,
                    'reserved1':reserved1,'reserved2':reserved2})
                if flags&0x80000400:
                    if not initprot&4 or va<address or span>length or va-address>length-span or off>len(data) or span>len(data)-off:
                        raise ValueError('instruction section extent/permissions')
                    if (va|span|off)&3:raise ValueError('unaligned instruction section')
                    sections.append({'segment':segment.rstrip(b'\0').decode('ascii'),
                        'name':section.rstrip(b'\0').decode('ascii'),'address':va,'bytes':span,'offset':off})
        elif command in (0xc,0x80000018,0x8000001f,0x80000023):
            if size<24:raise ValueError('dylib command extent')
            off=struct.unpack_from('<I',data,position+8)[0]
            if off<24 or off>=size:raise ValueError('dylib name extent')
            name=data[position+off:position+size]
            if b'\0' not in name:raise ValueError('unterminated dylib name')
            dylibs.append({'name':name.split(b'\0',1)[0].decode('utf-8'), 'weak':command==0x80000018})
        elif command==0x26:
            if size!=16 or starts is not None:raise ValueError('function-start command')
            off,span=struct.unpack_from('<II',data,position+8)
            if off>len(data) or span>len(data)-off:raise ValueError('function-start extent')
            starts=data[off:off+span]
        elif command==2:
            if size!=24 or symtab is not None:raise ValueError('symbol-table command')
            symtab=struct.unpack_from('<4I',data,position+8)
        elif command==0xb:
            if size!=80 or indirect is not None:raise ValueError('dynamic-symbol command')
            indirect=struct.unpack_from('<II',data,position+56)
        elif command==0x32:
            if size<24:raise ValueError('build-version extent')
            platform,minos=struct.unpack_from('<II',data,position+8)
            if platform!=2 or minos!=0x100000:raise ValueError('not the iOS16 deployment target')
            deployment=True
        position+=size
    if position!=limit or not deployment or not sections or starts is None or symtab is None:
        raise ValueError('incomplete Mach-O metadata')
    sections.sort(key=lambda s:s['address'])
    for i,s in enumerate(sections):
        for previous in sections[:i]:
            if s['address']<previous['address']+previous['bytes'] or (
                s['offset']<previous['offset']+previous['bytes'] and previous['offset']<s['offset']+s['bytes']):
                raise ValueError('overlapping instruction sections')
    functions=[];at=0;address=0;terminated=False
    while at<len(starts):
        delta,at=uleb(starts,at)
        if not delta:
            if any(starts[at:]):raise ValueError('nonzero function-start tail')
            terminated=True;break
        address+=delta
        if address>0xffffffffffffffff or address&3 or not any(s['address']<=address<s['address']+s['bytes'] for s in sections):
            raise ValueError('function root outside instruction sections')
        functions.append(address)
        if len(functions)>262144:raise ValueError('function-root count')
    if not terminated or not functions:raise ValueError('missing function-start terminator/roots')
    symoff,count,stroff,strbytes=symtab
    if count>1048576 or symoff>len(data) or count*16>len(data)-symoff or stroff>len(data) or strbytes>len(data)-stroff:
        raise ValueError('symbol-table extent')
    imports=[];names={}
    for i in range(count):
        string,type_,section,desc,value=struct.unpack_from('<IBBHQ',data,symoff+i*16)
        if type_&0xe0 or type_&0xe or not type_&1:continue
        if string>=strbytes or value:raise ValueError('undefined-symbol framing')
        tail=data[stroff+string:stroff+strbytes]
        end=tail.find(b'\0')
        if end<0 or end>8192:raise ValueError('undefined-symbol name')
        ordinal=desc>>8
        if not 1<=ordinal<=len(dylibs):raise ValueError('unsupported flat/self/lookup import ordinal')
        item={'name':tail[:end].decode('utf-8'),'dylib':dylibs[ordinal-1]['name'],'weak':bool(desc&0x40)}
        imports.append(item);names[i]=item
    noreturn={}
    if indirect is not None:
        off,number=indirect
        if off>len(data) or number>1048576 or number*4>len(data)-off:raise ValueError('indirect-symbol extent')
        def symbol(index):
            if index>=number:raise ValueError('indirect-symbol index')
            return struct.unpack_from('<I',data,off+index*4)[0]
        # Public platform ABI specifies these routines never return. Bind BL
        # targets through actual stub words AND the matching GOT symbol index;
        # never infer a callee from LLVM's nearest-symbol annotation.
        abi={'_abort':'/usr/lib/libSystem.B.dylib','_longjmp':'/usr/lib/libSystem.B.dylib',
             '_exit':'/usr/lib/libSystem.B.dylib','___stack_chk_fail':'/usr/lib/libSystem.B.dylib',
             '___cxa_throw':'/usr/lib/libc++.1.dylib'}
        for s in all_sections:
            if s['flags']&255!=8:continue
            if s['reserved2']!=12 or s['bytes']%12:raise ValueError('unexpected plain-arm64 stub shape')
            for i in range(s['bytes']//12):
                si=symbol(s['reserved1']+i);imported=names.get(si)
                if not imported or imported['weak'] or abi.get(imported['name'])!=imported['dylib']:continue
                address=s['address']+i*12;pos=s['offset']+i*12
                a,b,c=struct.unpack_from('<3I',data,pos)
                if a&0x9f00001f!=0x90000010 or b&0xffc003ff!=0xf9400210 or c!=0xd61f0200:
                    raise ValueError('noreturn stub instruction mismatch')
                immediate=((a>>5)&0x7ffff)*4+((a>>29)&3)
                if immediate&0x100000:immediate-=0x200000
                pointer=(address&~4095)+(immediate<<12)+((b>>10)&4095)*8
                got=[p for p in all_sections if p['flags']&255 in (6,7) and p['address']<=pointer<p['address']+p['bytes']]
                if len(got)!=1 or (pointer-got[0]['address'])%8 or symbol(got[0]['reserved1']+(pointer-got[0]['address'])//8)!=si:
                    raise ValueError('noreturn stub/GOT identity mismatch')
                noreturn[address]=imported
    return {'sections':sections,'function_starts':functions,'dylibs':dylibs,'imports':imports,'noreturn_stubs':noreturn}

def forbidden(op,body,word):
    # PAC/BTI decode as legacy HINT when those extensions are disabled. Reject
    # these aliases explicitly; do not mistake decoder acceptance for proof.
    if word&0xfffff01f==0xd503201f and ((word>>5)&127)>5:return True
    mnemonic=op.split('.',1)[0] # Mach-O LLVM spells vector width on the opcode.
    return bool(re.fullmatch(r'(?:cas|swp|(?:ld|st)(?:add|clr|eor|set|smax|smin|umax|umin)|'
        r'ldapr|ldapur|stlur|pac|aut|xpac|braa|brab|blraa|blrab|retaa|retab|eretaa|eretab|'
        r'ldraa|ldrab|ld64b|st64b|aes|sha|crc32|pmull)[a-z0-9]*|'
        r'bti|sb|ssbb|pssbb|dgh|cfinv|rmif|setf8|setf16|sdot|udot|sqrdmlah|sqrdmlsh',mnemonic) or
        re.search(r'\b(?:z\d+|p\d+)\b',body))

# Bounded whole-function no-normal-return proof; no source-name trust.

MAX_TERMINAL_FUNCTION_WORDS=128

def signed(value,bits):return value-(1<<bits) if value&(1<<(bits-1)) else value

def terminal_body(data,section,start,end,rows,stubs,forbidden):
    if any(type(value) is not int for value in (start,end,section.get('address'),section.get('offset'),section.get('bytes'))):return None
    if not 0<end-start<=4*MAX_TERMINAL_FUNCTION_WORDS or start%4 or (end-start)%4:return None
    if section['address']<0 or section['offset']<0 or section['bytes']<0 or \
            start<section['address'] or end>section['address']+section['bytes']:return None
    offset=section['offset']+start-section['address']
    if offset<0 or offset>len(data) or end-start>len(data)-offset:return None
    if [row[0] for row in rows]!=list(range(start,end,4)):return None
    code={}
    for pc,word,op,body in rows:
        offset=section['offset']+pc-section['address']
        if word!=struct.unpack_from('<I',data,offset)[0] or forbidden(op,body,word):return None
        code[pc]=(word,op,body)
    visiting=set();completed={};reachable=set();exits={}
    def visit(pc):
        if pc in completed:return completed[pc]
        if pc in visiting or pc not in code:return False
        visiting.add(pc);reachable.add(pc)
        word,op,body=code[pc]
        successors=None;terminal=None
        # Branch directions/targets are decoded from the actual word, then
        # cross-checked with LLVM text. No assumption about branch conditions.
        if word&0xfc000000 in (0x14000000,0x94000000):
            expected='bl' if word&0xfc000000==0x94000000 else 'b'
            target=pc+signed(word&0x3ffffff,26)*4
            if op!=expected:return False
            if target in stubs:terminal=target
            elif op=='bl':successors=[pc+4] # ordinary callees may return
            else:successors=[target]
        elif word&0xff000010==0x54000000:
            if not op.startswith('b.'):return False
            target=pc+signed((word>>5)&0x7ffff,19)*4;successors=[pc+4,target]
        elif word&0x7e000000 in (0x34000000,0x36000000):
            test=word&0x7e000000==0x36000000
            if op not in (('tbz','tbnz') if test else ('cbz','cbnz')):return False
            bits=14 if test else 19
            target=pc+signed((word>>5)&((1<<bits)-1),bits)*4;successors=[pc+4,target]
        elif op in ('ret','br','blr','eret','drps','svc','hvc','smc','brk','hlt','udf','unknown') or \
            word&0xffff0000==0 or word&0xff000000==0xd4000000 or \
            word&0xfe000000==0xd6000000:return False
        elif op in ('b','bl','cbz','cbnz','tbz','tbnz') or op.startswith('b.'):return False
        else:successors=[pc+4]
        if terminal is not None or len(successors or [])==2 or op in ('b','bl'):
            try:decoded=int(body.split(',')[-1].strip().split()[0].removeprefix('#'),0)
            except (ValueError,IndexError):return False
            if decoded!=target:return False
        if terminal is not None:
            exits[terminal]=stubs[terminal];answer=True
        else:answer=all(visit(next_pc) for next_pc in successors)
        visiting.remove(pc);completed[pc]=answer
        return answer
    if not visit(start) or not exits:return None
    offset=section['offset']+start-section['address']
    return {'start':start,'end':end,'code_sha256':hashlib.sha256(data[offset:offset+end-start]).hexdigest(),
        'reachable_words':len(reachable),'terminal_ABI_stubs':{hex(pc):name for pc,name in exits.items()},
        'conditions_overapproximated':True,'source_names_trusted':False,'hardware_verified':False}

def terminal_functions(data,info,lines,forbidden):
    roots=sorted(info['function_starts']);ranges={}
    for index,start in enumerate(roots):
        sections=[s for s in info['sections'] if s['address']<=start<s['address']+s['bytes']]
        if len(sections)!=1:raise ValueError('terminal-proof root section differs')
        section=sections[0];end=min(roots[index+1] if index+1<len(roots) else section['address']+section['bytes'],section['address']+section['bytes'])
        if 0<end-start<=4*MAX_TERMINAL_FUNCTION_WORDS:ranges[start]=(end,section)
    current=None;rows=[];proven={}
    def finish():
        if current is None:return
        end,section=ranges[current]
        proof=terminal_body(data,section,current,end,rows,info.get('noreturn_stubs',{}),forbidden)
        if proof:proven[current]=proof
    for line in lines:
        if not re.match(r'^\s*[0-9a-fA-F]+:',line):continue
        decoded=re.fullmatch(r'\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{8})\s+([A-Za-z][A-Za-z0-9_.]*)\s*(.*?)\s*',line)
        if not decoded:raise ValueError('terminal-proof decoder framing')
        pc=int(decoded[1],16);index=bisect_right(roots,pc)-1
        candidate=roots[index] if index>=0 and roots[index] in ranges and pc<ranges[roots[index]][0] else None
        if candidate!=current:finish();current=candidate;rows=[]
        if current is not None:rows.append((pc,int(decoded[2],16),decoded[3].lower(),decoded[4].split(';',1)[0].strip()))
    finish()
    return proven

def screen(data,info,lines):
    terminal_targets=set(info.get('noreturn_stubs',{}))|set(info.get('noreturn_functions',{}))
    sections=info['sections'];starts=set(info['function_starts']);index=-1;next_pc=None;seen=set();count=0
    raw_traps={section['address']+4*i for section in sections
        for i,(word,) in enumerate(struct.iter_unpack('<I',data[section['offset']:section['offset']+section['bytes']]))
        if word&0xffe0001f==0xd4200000}
    trap_edges={};indirect_functions=set();function_root=None
    opcounts={};branch_targets=set();padding=set();zero_run=[];previous=None;unreachable_traps=set();function_indirect=False
    def finish_zero(next_address):
        if not zero_run:return
        # A64 BR is an unconditional tail branch, like B/RET it has no
        # architectural fall-through. The next function root/alignment and
        # absence of direct targets are still required for every zero word.
        terminal=previous is not None and (previous[1] in ('b','br','ret') or
            previous[1]=='bl' and previous[2] in terminal_targets or previous[0] in unreachable_traps)
        if len(zero_run)>3 or not terminal or next_address%16 or next_address not in starts:
            raise ValueError('unproven zero alignment padding at '+hex(zero_run[0]))
        padding.update(zero_run);zero_run.clear()
    for line in lines:
        heading=re.fullmatch(r'Disassembly of section ([^,]+),([^:]+):\s*',line.strip())
        if heading:
            if index>=0 and next_pc!=sections[index]['address']+sections[index]['bytes']:raise ValueError('decoder section hole')
            finish_zero(next_pc or 0)
            name=(heading[1],heading[2]);matches=[i for i,s in enumerate(sections) if (s['segment'],s['name'])==name]
            if len(matches)!=1 or matches[0] in seen:raise ValueError('unknown/duplicate instruction section')
            index=matches[0];seen.add(index);next_pc=sections[index]['address'];previous=None;function_indirect=False;function_root=None;continue
        if not re.match(r'^\s*[0-9a-fA-F]+:',line):continue
        if index<0:raise ValueError('instruction without a declared section')
        decoded=re.fullmatch(r'\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{8})\s+([A-Za-z][A-Za-z0-9_.]*)\s*(.*?)\s*',line)
        if not decoded:raise ValueError('unknown/malformed decoder output: '+line.strip()[:160])
        pc=int(decoded[1],16);word=int(decoded[2],16);op=decoded[3].lower();body=decoded[4].split(';',1)[0].strip()
        s=sections[index]
        if pc!=next_pc or pc+4>s['address']+s['bytes']:raise ValueError('decoder address hole/extent: expected '+hex(next_pc)+', got '+hex(pc))
        if word!=struct.unpack_from('<I',data,s['offset']+pc-s['address'])[0]:raise ValueError('decoded word differs from input image')
        before_previous=previous
        if pc in starts:function_indirect=False;function_root=pc
        if op=='unknown' or forbidden(op,body,word):raise ValueError('unsupported A53 instruction at '+hex(pc)+': '+op+' '+body)
        if op=='udf':
            if word:raise ValueError('nonzero undefined instruction')
            if pc in starts:raise ValueError('undefined instruction at a declared function root')
            zero_run.append(pc)
            if len(zero_run)>3:raise ValueError('interior/oversized zero run')
        else:
            finish_zero(pc)
            # Clang can emit one defensive BRK after a bound noreturn call.
            # The trap is a decoded instruction, NOT padding. Only this exact
            # no-fallthrough predecessor makes it unreachable, and any direct
            # target/function root at the trap invalidates that proof below.
            known_terminal=previous is not None and (previous[1]=='bl' and previous[2] in terminal_targets or
                previous[1] in ('b','ret') and not function_indirect)
            if op=='brk' and pc not in starts and known_terminal:
                unreachable_traps.add(pc)
            previous=(pc,op,None,word)
        if op=='br':
            function_indirect=True;indirect_functions.add((index,function_root))
        if op=='b' or op.startswith('b.') or op in ('cbz','cbnz','tbz','tbnz','bl'):
            target=body.split(',')[-1].strip().split()[0]
            try:target=int(target.removeprefix('#'),0);branch_targets.add(target)
            except ValueError:raise ValueError('unresolved decoded direct branch')
            if target in raw_traps:trap_edges.setdefault(target,[]).append((pc,op,word,before_previous,(index,function_root)))
            if op=='bl':previous=(pc,op,target,word)
        opcounts[op]=opcounts.get(op,0)+1;count+=1;next_pc=pc+4
    if index<0 or next_pc!=sections[index]['address']+sections[index]['bytes']:raise ValueError('incomplete final instruction section')
    finish_zero(next_pc)
    if seen!=set(range(len(sections))) or count!=sum(s['bytes']//4 for s in sections):raise ValueError('incomplete executable section coverage')
    if padding&branch_targets:raise ValueError('direct branch targets zero padding')
    dead_edges=[]
    for trap in sorted(unreachable_traps&branch_targets):
        # Clang may branch to its defensive BRK after calling other proved
        # terminal helpers. Admit only an untargeted B immediately after BL
        # to an actual nonreturning target, with no indirect branch anywhere
        # in its complete containing function. Reachable targets still fail.
        for pc,op,word,prior,scope in trap_edges.get(trap,[]):
            if (op!='b' or word&0xfc000000!=0x14000000 or
                pc+signed(word&0x3ffffff,26)*4!=trap or
                pc in starts or pc in branch_targets or scope[1] is None or scope in indirect_functions or
                prior is None or prior[0]!=pc-4 or prior[1]!='bl' or prior[2] not in terminal_targets or
                prior[3]&0xfc000000!=0x94000000 or
                prior[0]+signed(prior[3]&0x3ffffff,26)*4!=prior[2]):
                raise ValueError('direct branch targets presumed unreachable noreturn trap at '+hex(trap))
            dead_edges.append({'trap':hex(trap),'branch':hex(pc),'branch_word':hex(word),
                'call':hex(prior[0]),'call_word':hex(prior[3]),'terminal_callee':hex(prior[2]),
                'function_root':hex(scope[1]),'source_untargeted':True,'function_has_no_indirect_branch':True})
        if not trap_edges.get(trap):raise ValueError('missing incoming trap-edge proof')
    return {'instructions':count,'opcodes':opcounts,'admitted_padding_words':len(padding),
        'all_instruction_words_bound_to_image':True,'LLVM_feature_profile':CPU_ATTRIBUTES,
        'padding_noreturn_ABI_stubs':{hex(k):v for k,v in info.get('noreturn_stubs',{}).items()},
        'noreturn_defensive_traps':len(unreachable_traps),
        'dead_branch_edges_to_noreturn_traps':dead_edges,
        'padding_noreturn_function_proofs':{hex(pc):proof for pc,proof in info.get('noreturn_functions',{}).items()},
        'CPU_ISA_screened':True,'runtime_dependencies_verified':False,'hardware_verified':False}

def audit(binary,output):
    binary=Path(binary).resolve();output=Path(output).resolve()
    if binary.stat().st_size>MAX_BINARY:raise ValueError('library exceeds bound')
    data=binary.read_bytes();info=metadata(data);output.mkdir(exist_ok=False)
    report={'library':str(binary),'library_sha256':hashlib.sha256(data).hexdigest(),'library_bytes':len(data),
        'CPU_ISA_screened':False,'runtime_dependencies_verified':False,'hardware_verified':False,
        'dependencies':info['dylibs'],'imports':info['imports']}
    command=['llvm-objdump','-d','--disassemble-zeroes','--mcpu=cortex-a53','--mattr='+CPU_ATTRIBUTES,'--no-symbolic-operands',str(binary)]
    try:
        with (output/'disassembly.txt').open('x') as stdout,(output/'decoder-stderr.txt').open('x') as stderr:
            run=subprocess.run(command,stdout=stdout,stderr=stderr,timeout=120)
        if run.returncode:raise ValueError('LLVM disassembly failed')
        if (output/'disassembly.txt').stat().st_size>MAX_DISASSEMBLY:raise ValueError('disassembly exceeds bound')
        with (output/'disassembly.txt').open() as lines:
            info['noreturn_functions']=terminal_functions(data,info,lines,forbidden)
        report['padding_noreturn_function_proofs']={hex(pc):proof for pc,proof in info['noreturn_functions'].items()}
        with (output/'disassembly.txt').open() as lines:report.update(screen(data,info,lines))
        report['success']=True
    except Exception as error:
        report.update({'success':False,'failure':str(error)})
    report['command']=command;report['tool_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    with (output/'report.json').open('x') as stream:json.dump(report,stream,indent=2)
    if not report['success']:raise ValueError(report['failure'])
    return report

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('library',type=Path)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    print(json.dumps(audit(args.library,args.output),indent=2))
