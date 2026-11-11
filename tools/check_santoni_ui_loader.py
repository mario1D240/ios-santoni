#!/usr/bin/env python3
"""Bind readonly loader declarations to the exact audited EAGL image.

This checks image/config/CPU-report identity. It does not prove dyld execution,
which remains a separate installed-root and hardware requirement.
"""
import argparse,hashlib,json,struct,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.build_santoni_graphics_gles import ui_artifact_path
from tools.check_santoni_graphics_library import metadata

def digest(data):return hashlib.sha256(data).hexdigest()

def readonly_strings(data):
    metadata(data) # Validate Mach-O bounds, architecture, deployment and roots.
    ncmd,size=struct.unpack_from('<II',data,16);position=32;strings=[]
    for _ in range(ncmd):
        command,length=struct.unpack_from('<II',data,position)
        if command==0x19:
            va,extent,fileoff,filesize=struct.unpack_from('<4Q',data,position+24)
            initprot,count=struct.unpack_from('<II',data,position+60)
            for i in range(count):
                section=position+72+i*80
                name,segment,address,span,offset=struct.unpack_from('<16s16sQQI',data,section)
                flags=struct.unpack_from('<I',data,section+64)[0]
                if name.rstrip(b'\0')==b'__cstring':
                    if not initprot&1 or initprot&2 or flags&255!=2 or flags&0x80000400 or \
                        address<va or span>extent or address-va>extent-span or offset<fileoff or \
                        span>filesize or offset-fileoff>filesize-span or offset>len(data) or span>len(data)-offset:
                        raise ValueError('loader string section is writable or malformed')
                    strings.append(data[offset:offset+span])
        position+=length
    if position!=32+size or not strings:raise ValueError('loader readonly string section missing')
    return strings

def check(eagl,loader,eagl_cpu,loader_cpu,build):
    eagl,loader=Path(eagl),Path(loader);main=eagl.read_bytes();data=loader.read_bytes()
    main_sha,loader_sha=digest(main),digest(data)
    metadata(main);strings=readonly_strings(data)
    for path,sha in ((eagl_cpu,main_sha),(loader_cpu,loader_sha)):
        report=json.loads(Path(path).read_text())
        if report.get('success') is not True or report.get('CPU_ISA_screened') is not True or \
            report.get('all_instruction_words_bound_to_image') is not True or report.get('library_sha256')!=sha:
            raise ValueError('CPU report does not prove this exact image')
    record=json.loads(Path(build).read_text());binding=record.get('ui_loader',{})
    expected=ui_artifact_path(main_sha,'libsantoni-eagl.dylib')
    if record.get('success') is not True or record.get('eagl_library',{}).get('sha256')!=main_sha or \
        record.get('eagl_library',{}).get('bytes')!=len(main) or binding.get('bytes')!=len(data) or \
        binding.get('sha256')!=loader_sha or binding.get('eagl_sha256')!=main_sha or binding.get('eagl_path')!=expected or \
        binding.get('loader_path')!=ui_artifact_path(loader_sha,'libsantoni-ui-loader.dylib'):
        raise ValueError('build manifest loader/library identity mismatch')
    for text in (expected,'sgfx_eagl_install','/System/Library/Frameworks/OpenGLES.framework/OpenGLES'):
        needle=text.encode()+b'\0'
        if sum(block.count(needle) for block in strings)!=1:raise ValueError('loader readonly declaration missing/ambiguous: '+text)
    return {'success':True,'eagl_sha256':main_sha,'loader_sha256':loader_sha,'eagl_path':expected,
        'readonly_declarations_verified':True,'CPU_reports_bound_to_images':True,
        'runtime_dyld_verified':False,'installed_root_verified':False,'hardware_verified':False}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('eagl','loader','eagl_cpu','loader_cpu','build'):parser.add_argument('--'+name.replace('_','-'),required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path);a=parser.parse_args()
    result=check(a.eagl,a.loader,a.eagl_cpu,a.loader_cpu,a.build)
    with a.output.open('x') as out:json.dump(result,out,indent=2)
    print(json.dumps(result,indent=2))
