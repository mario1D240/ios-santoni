#!/usr/bin/env python3
"""Validate host-only Mesa capture framing/BO ownership and expose raw packets."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

MAX_BYTES=128*1024*1024
def parse(data):
    if not 32<=len(data)<=MAX_BYTES:raise ValueError('capture size outside bound')
    magic,version,buffers,roots,fence,reserved,gpu,flags=struct.unpack_from('<8I',data)
    if magic!=0x50434753 or version!=1 or not 1<=buffers<=64 or not 1<=roots<=8 or not fence or reserved or flags or gpu!=505:
        raise ValueError('invalid host capture header')
    position=32;commands=[]
    for _ in range(roots):
        handle,offset,size=struct.unpack_from('<3I',data,position);position+=12
        if not handle or not size or (offset|size)&3:raise ValueError('invalid root geometry')
        commands.append({'handle':handle,'offset':offset,'bytes':size})
    objects={}
    for _ in range(buffers):
        if position+16>len(data):raise ValueError('truncated BO header')
        handle,va,size,permissions=struct.unpack_from('<4I',data,position);position+=16
        if not handle or handle in objects or not va or va&4095 or not size or permissions not in (1,2) or position+size>len(data):
            raise ValueError('invalid BO identity/span')
        rounded=(size+4095)&~4095
        if va+rounded+4096>1<<32:raise ValueError('BO/guard wraps GVA')
        for old in objects.values():
            if va<old['gpu_va']+((old['bytes']+4095)&~4095)+4096 and old['gpu_va']<va+rounded+4096:
                raise ValueError('overlapping BO/guard spans')
        payload=data[position:position+size];position+=size
        objects[handle]={'gpu_va':va,'bytes':size,'permissions':permissions,'sha256':hashlib.sha256(payload).hexdigest(),'payload':payload}
    if position!=len(data):raise ValueError('trailing capture bytes')
    for root in commands:
        obj=objects.get(root['handle'])
        if not obj or root['offset']>obj['bytes'] or root['bytes']>obj['bytes']-root['offset']:
            raise ValueError('root outside listed BO')
    return {'roots':commands,'buffers':objects,'modeled_fence':fence,'GPU_accessed':False,'hardware_verified':False}
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('capture',type=Path);args=parser.parse_args()
    result=parse(args.capture.read_bytes())
    for obj in result['buffers'].values():obj.pop('payload')
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
