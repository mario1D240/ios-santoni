"""Test-only resolution of compiler objects to explicit modeled ABI addresses.

Not a kernel linker or delivery certificate. Only the checked relocation forms
from these host fixtures are admitted; unknown forms fail closed.
"""
import struct
from pathlib import Path

def resolved_object(path):
    original=Path(path).read_bytes();data=bytearray(original)
    off=32;sections=[];symtab=None
    for _ in range(struct.unpack_from('<I',data,16)[0]):
        command,size=struct.unpack_from('<II',data,off)
        if command==0x19:
            for i in range(struct.unpack_from('<I',data,off+64)[0]):
                name,segment,va,span,fileoff,align,reloc,number,flags=struct.unpack_from('<16s16sQQ5I',data,off+72+i*80)
                assert reloc+number*8<=len(data)
                assert flags&255==1 or fileoff+span<=len(data)
                sections.append({'name':name.rstrip(b'\0').decode(),'va':va,'span':span,
                    'offset':fileoff,'reloc':reloc,'number':number,'flags':flags})
        elif command==2:symtab=struct.unpack_from('<4I',data,off+8)
        off+=size
    symoff,count,stroff,strbytes=symtab;symbols=[];names={}
    for i in range(count):
        string,kind,section,desc,value=struct.unpack_from('<IBBHQ',data,symoff+16*i)
        assert string<strbytes
        name=data[stroff+string:stroff+strbytes].split(b'\0',1)[0].decode()
        symbol={'name':name,'type':kind,'section':section,'value':value};symbols.append(symbol)
        if section:names.setdefault(name,set()).add(value)
    data_symbols={'_kernel_pmap','_kernel_task','___stack_chk_guard'}
    externals={symbol['name'] for symbol in symbols if not symbol['section']}
    addresses={name:(0x200000+index*8 if name in data_symbols else 0x400000+index*0x100)
        for index,name in enumerate(sorted(externals))}
    names.update({name:{value} for name,value in addresses.items()})
    got={};rows=[]
    for section in sections:
        pending=None
        for i in range(section['number']):
            local,info=struct.unpack_from('<iI',data,section['reloc']+8*i)
            index,kind,external,length=info&0xffffff,info>>28,info>>27&1,info>>25&3
            assert 0<=local<=section['span']-(1<<length)
            if kind==10:
                assert pending is None and not external and length==2
                pending=(local,index-(1<<24) if index&(1<<23) else index)
                continue
            assert external and index<len(symbols),(section['name'],kind,index,external,length)
            addend=0
            if pending is not None:
                assert pending[0]==local and kind in (3,4)
                addend=pending[1];pending=None
            symbol=symbols[index];name=symbol['name']
            target=(symbol['value'] if symbol['section'] else addresses[name])+addend
            pc=section['va']+local;position=section['offset']+local
            assert section['flags']&255!=1
            if kind==0:
                assert length==3
                old=struct.unpack_from('<Q',data,position)[0]
                value=target+old;struct.pack_into('<Q',data,position,value)
            else:
                assert length==2
                old=struct.unpack_from('<I',data,position)[0]
                if kind in (5,6):
                    assert not addend
                    if name not in got:got[name]=0x100000+8*len(got)
                    target=got[name]
                if kind==2:
                    assert old&0x7c000000==0x14000000 and not (target-pc)&3
                    assert -(1<<27)<=target-pc<(1<<27)
                    value=(old&0xfc000000)|(((target-pc)//4)&0x3ffffff)
                elif kind in (3,5):
                    assert old&0x9f000000==0x90000000
                    delta=(target>>12)-(pc>>12);assert -(1<<20)<=delta<(1<<20);delta&=0x1fffff
                    value=(old&~0x60ffffe0)|((delta&3)<<29)|((delta>>2)<<5)
                elif kind in (4,6):
                    if old&0x7f000000==0x11000000:
                        assert not old&(1<<22);scale=1
                    else:
                        assert old&0x3b000000==0x39000000
                        scale=16 if old&(1<<26) and old&(1<<23) else 1<<((old>>30)&3)
                    assert (target&4095)%scale==0
                    value=(old&~(4095<<10))|(((target&4095)//scale)<<10)
                else:raise ValueError('unreviewed object relocation '+str(kind))
                struct.pack_into('<I',data,position,value)
            rows.append({'section':section['name'],'pc':pc,'kind':kind,'symbol':name,
                'addend':addend,'target':target,'original':old,'resolved':value})
        assert pending is None
    class Image:
        segs=tuple({'vmaddr':s['va'],'vmsize':s['span'],'initprot':3 if s['flags']&255==1 else 5}
            for s in sections)
        def read(self,address,size):
            for section in sections:
                if section['va']<=address and address+size<=section['va']+section['span']:
                    if section['flags']&255==1:return 0
                    at=section['offset']+address-section['va']
                    return int.from_bytes(data[at:at+size],'little')
            for name,pointer in got.items():
                if address==pointer and size==8:return addresses[name]
            return None
    return original,data,names,Image(),rows
