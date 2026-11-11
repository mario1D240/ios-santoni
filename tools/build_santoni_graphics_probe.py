#!/usr/bin/env python3
"""Build a separately staged iOS BO/IB client with the production UAPI.

This builds userspace only, writes a new output directory, and installs nothing.
Kernel, exact-binary audit and hardware acceptance remain separate gates.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def build(output):
    from tests.reconstruct_santoni_touch import reconstruct
    output=Path(output).resolve()
    if output.exists():raise ValueError('refusing to overwrite graphics-client output')
    if platform.system()!='Darwin':raise ValueError('iOS client needs macOS/Xcode; no kernel is compiled locally')
    output.mkdir(parents=True)
    source=output/'uapi-source';receipt=reconstruct(source,targets=('bsd/dev/santoni_gpu_graphics_uapi.h',))
    inputs=('tools/santoni-graphics/client.h','tools/santoni-graphics/client.c','tools/santoni-graphics/probe.c')
    before={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in inputs}
    binary=output/'santoni-graphics-probe'
    command=['xcrun','--sdk','iphoneos','clang','--target=arm64-apple-ios16.0','-mcpu=cortex-a53',
        '-O2','-Wall','-Wextra','-Werror','-I',str(source/'bsd/dev'),'-framework','IOKit',
        str(ROOT/inputs[1]),str(ROOT/inputs[2]),'-o',str(binary)]
    with (output/'build.log').open('x') as log:
        subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True)
        subprocess.run(['codesign','--sign','-',str(binary)],stdout=log,stderr=subprocess.STDOUT,check=True)
    if before!={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in inputs}:
        raise ValueError('client source changed during build')
    record={'success':True,'commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'inputs_sha256':before,'uapi_source':receipt,'command':command,'binary':str(binary),
        'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
        'kernel_binary_verified':False,'hardware_verified':False,'GLES_enabled':False}
    (output/'build.json').write_text(json.dumps(record,indent=2)+'\n');return record


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    print(json.dumps(build(parser.parse_args().output),indent=2))
