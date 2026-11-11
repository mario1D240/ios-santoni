#!/usr/bin/env python3
"""Bounded structural inventory of captured Mesa PM4, not a GPU admission gate.

Walk owned IB references and draw-state payloads only. Other packet payloads,
register values, shader/texture semantics and execution are explicitly unproven.
No captured VA is a physical address and no command is sent to a device.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import re
import xml.etree.ElementTree as ET

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.parse_santoni_graphics_capture import parse

def header(word):
    parity=lambda value:1^(value.bit_count()&1)
    kind=word>>28
    if kind==4:
        count=word&127;op=(word>>8)&0x3ffff
        valid=count and word==(0x40000000|count|(parity(count)<<7)|(op<<8)|(parity(op)<<27))
    elif kind==7:
        count=word&0x3fff;op=(word>>16)&127
        valid=word==(0x70000000|count|(parity(count)<<15)|(op<<16)|(parity(op)<<23))
    else:raise ValueError('not an A5xx type4/type7 packet')
    if not valid:raise ValueError('invalid A5xx packet parity/count/reserved bits')
    return kind,op,count

def symbols(mesa):
    """Names from the supplied Mesa XML; names themselves confer no admission."""
    namespace={'r':'http://nouveau.freedesktop.org/'}
    paths=[Path(mesa)/'src/freedreno/registers/adreno'/name for name in ('adreno_pm4.xml','a5xx.xml')]
    lock=json.loads((Path(__file__).resolve().parent/'santoni-graphics/mesa-reference.json').read_text())
    inputs={str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    for path in paths:
        if inputs[str(path)]!=lock['source_sha256'][str(path.relative_to(mesa))]:
            raise ValueError('symbol XML differs from pinned Mesa')
    packets={};registers={}
    pm4=ET.parse(paths[0])
    for node in pm4.findall('.//r:enum',namespace):
        if node.get('name')=='adreno_pm4_type3_packets':
            for value in node.findall('r:value',namespace):
                variants=value.get('variants')
                if variants:
                    interval=re.fullmatch(r'A([2-7])XX(?:-(?:A([2-7])XX)?)?',variants)
                    if not interval:raise ValueError('unknown chip variants in packet XML')
                    low=int(interval[1]);high=int(interval[2]) if interval[2] else (7 if '-' in variants else low)
                    if not low<=5<=high:continue
                packets.setdefault(int(value.get('value'),0),[]).append(value.get('name'))
    def walk(node,base=0,prefix=''):
        for child in node:
            tag=child.tag.rsplit('}',1)[-1]
            if tag=='array':
                for index in range(int(child.get('length'),0)):
                    walk(child,base+int(child.get('offset'),0)+index*int(child.get('stride'),0),
                        prefix+child.get('name')+'['+str(index)+']_')
            elif tag in ('reg32','reg64'):
                offset=base+int(child.get('offset'),0);name='A5XX_'+prefix+child.get('name')
                registers.setdefault(offset,[]).append(name)
                if tag=='reg64':registers.setdefault(offset+1,[]).append(name+'_HI')
    for domain in ET.parse(paths[1]).findall('r:domain',namespace):
        if domain.get('name')=='A5XX':walk(domain)
    return packets,registers,inputs

def inspect(capture,packet_names=None,register_names=None):
    packet_names=packet_names or {};register_names=register_names or {}
    nodes=[];active=[];total_words=0;registers=[];opcodes={}
    def resolve(va,size):
        if not size or (va|size)&3 or va<0 or va+size>1<<32:raise ValueError('invalid IB address/span')
        for handle,obj in capture['buffers'].items():
            offset=va-obj['gpu_va']
            if 0<=offset<=obj['bytes'] and size<=obj['bytes']-offset:return handle,obj,offset
        raise ValueError('IB outside captured owned BOs')
    def walk(va,size,parent=None,reference='root'):
        nonlocal total_words
        handle,obj,offset=resolve(va,size)
        if len(active)>=8 or len(nodes)>=512 or total_words+size//4>131072:
            raise ValueError('IB depth/node/word bound exceeded')
        if any(va<old_va+old_size and old_va<va+size for old_va,old_size in active):
            raise ValueError('active IB cycle/overlap')
        active.append((va,size));total_words+=size//4
        index=len(nodes);node={'handle':handle,'offset':offset,'bytes':size,'parent':parent,'reference':reference,'packets':[]}
        nodes.append(node)
        words=struct.unpack_from('<'+str(size//4)+'I',obj['payload'],offset)
        position=0
        while position<len(words):
            kind,op,count=header(words[position])
            if count>len(words)-position-1:raise ValueError('packet exceeds IB')
            values=words[position+1:position+1+count]
            packet={'word':position,'type':kind,'op':op,'payload':list(values)}
            if kind==4:
                packet['names']=register_names.get(op,[])
                for i,value in enumerate(values):
                    registers.append({'node':index,'word':position+1+i,'reg':op+i,'value':value,'names':register_names.get(op+i,[])})
            else:
                packet['names']=packet_names.get(op,[]);opcodes[op]=opcodes.get(op,0)+1
                # Mesa adreno_pm4.xml and the production SGPU parser: both
                # INDIRECT_BUFFER forms have low/high address + dword count.
                if op in (0x37,0x3f):
                    if count!=3 or values[1] or not values[2]:raise ValueError('invalid indirect-buffer payload')
                    walk(values[0],values[2]*4,index,'indirect-buffer')
                elif op==0x43:
                    if not count or count%3:raise ValueError('invalid draw-state triplets')
                    for i in range(0,count,3):
                        control,low,high=values[i:i+3];length=control&0xffff
                        if control&~0x1f0fffff:raise ValueError('unsupported draw-state control')
                        if control&(3<<17) or not length:
                            if length or low or high:raise ValueError('disabled draw-state carries a pointer')
                        else:
                            if high:raise ValueError('draw-state high address outside modeled window')
                            walk(low,length*4,index,'potential-draw-state')
            node['packets'].append(packet);position+=count+1
        active.pop()
    for root in capture['roots']:
        obj=capture['buffers'][root['handle']]
        walk(obj['gpu_va']+root['offset'],root['bytes'])
    return {'nodes':nodes,'register_writes':registers,'opcodes':{str(op):count for op,count in sorted(opcodes.items())},
        'words':total_words,'hardware_verified':False,'GPU_accessed':False,'admission_verified':False,
        'execution_semantics_verified':False,'shader_descriptor_values_validated':False}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture',type=Path);parser.add_argument('--mesa',type=Path);parser.add_argument('--output',type=Path)
    args=parser.parse_args();data=args.capture.read_bytes()
    packets,registers,inputs=symbols(args.mesa) if args.mesa else ({},{},{})
    record=inspect(parse(data),packets,registers)
    record.update({'capture_sha256':hashlib.sha256(data).hexdigest(),'symbol_inputs_sha256':inputs})
    if args.output:
        with args.output.open('x') as stream:json.dump(record,stream,indent=2)
    else:print(json.dumps(record,indent=2))

if __name__=='__main__':main()
