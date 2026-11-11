#!/usr/bin/env python3
"""Build the staged iOS msm/command adapter; install nothing or enable no GLES."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def build(mesa,output):
    from tests.reconstruct_santoni_touch import reconstruct
    mesa=Path(mesa).resolve();output=Path(output).resolve()
    if output.exists():raise ValueError('refusing to overwrite Mesa adapter output')
    if platform.system()!='Darwin':raise ValueError('iOS adapter requires macOS/Xcode')
    lock=json.loads((ROOT/'tools/santoni-graphics/mesa-reference.json').read_text())
    for name in ('include/drm-uapi/msm_drm.h','include/drm-uapi/drm.h'):
        if hashlib.sha256((mesa/name).read_bytes()).hexdigest()!=lock['source_sha256'][name]:
            raise ValueError('Mesa UAPI differs from the pinned dependency: '+name)
    output.mkdir(parents=True);source=output/'uapi-source'
    receipt=reconstruct(source,targets=('bsd/dev/santoni_gpu_graphics_uapi.h',))
    files=tuple('tools/santoni-graphics/'+name for name in ('client.c','client.h','commands.c','commands.h','msm.c','msm.h','mesa-reference.json'))
    inputs={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in files}
    commands=[];objects=[]
    with (output/'build.log').open('x') as log:
        for name in ('client','commands','msm'):
            obj=output/(name+'.o');command=['xcrun','--sdk','iphoneos','clang','--target=arm64-apple-ios16.0',
                '-mcpu=cortex-a53','-std=c11','-O2','-Wall','-Wextra','-Werror','-I',str(source/'bsd/dev'),
                '-I',str(mesa/'include/drm-uapi'),'-c',str(ROOT/'tools/santoni-graphics'/(name+'.c')),'-o',str(obj)]
            subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True);commands.append(command);objects.append(obj)
        library=output/'libsantoni_graphics_msm.a'
        subprocess.run(['xcrun','ar','rcs',str(library),*[str(p) for p in objects]],stdout=log,stderr=subprocess.STDOUT,check=True)
    if inputs!={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in files}:
        raise ValueError('Mesa adapter source changed during build')
    record={'success':True,'commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'mesa':lock,'uapi_source':receipt,'inputs_sha256':inputs,'commands':commands,
        'library_sha256':hashlib.sha256(library.read_bytes()).hexdigest(),
        'objects_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in objects},
        'GLES_enabled':False,'full_Gallium_linked':False,'hardware_verified':False}
    (output/'build.json').write_text(json.dumps(record,indent=2)+'\n');return record


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--mesa',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(json.dumps(build(a.mesa,a.output),indent=2))
