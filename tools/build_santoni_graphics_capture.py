#!/usr/bin/env python3
"""Run actual Mesa on a memory-only host transport and retain emitted packets.

This is not a kernel/iOS/hardware rendering build. No GPU/device is opened and
no completion/pixel/hardware gate may be derived from the modeled responses.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.build_santoni_graphics_gles import LIBRARIES,MESA_OPTIONS,prepare_source
from tests.reconstruct_santoni_touch import reconstruct

def capture_dimensions(width,height):
    if type(width) is not int or type(height) is not int or not 1<=width<=4096 or not 1<=height<=4096:
        raise ValueError('capture dimensions outside bound')

def run_capture(executable,output,width=64,height=64,ui_profile=False):
    """Keep the primary run immutable even if diagnostic re-execution fails."""
    capture_dimensions(width,height)
    if type(ui_profile) is not bool:raise ValueError('UI-like capture opt-in must be boolean')
    destination=output/'packets';destination.mkdir(exist_ok=False)
    environment=os.environ.copy();environment['SANTONI_CAPTURE_DIR']=str(destination)
    environment['SANTONI_CAPTURE_WIDTH']=str(width);environment['SANTONI_CAPTURE_HEIGHT']=str(height)
    environment['SANTONI_CAPTURE_UI']='1' if ui_profile else '0'
    record={'run_exit_code':None,'run_timed_out':False,'debugger_exit_code':None,'debugger_timed_out':False,'width':width,'height':height,'ui_like_profile':ui_profile}
    with (output/'run.log').open('x') as log:
        try:
            result=subprocess.run([str(executable)],env=environment,stdout=log,stderr=subprocess.STDOUT,timeout=120)
            record['run_exit_code']=result.returncode
        except subprocess.TimeoutExpired:
            record['run_timed_out']=True
            log.write('\nCAPTURE primary run exceeded 120-second bound\n')
    if record['run_exit_code']!=0:
        # LLDB runs the program again. It must not overwrite primary packets,
        # and its modeled submissions must never be counted as primary output.
        diagnostic=output/'diagnostic-packets';diagnostic.mkdir(exist_ok=False)
        environment['SANTONI_CAPTURE_DIR']=str(diagnostic)
        with (output/'backtrace.log').open('x') as log:
            try:
                result=subprocess.run(['lldb','--batch','-o','run','-o','thread backtrace all','-o','quit','--',str(executable)],
                    env=environment,stdout=log,stderr=subprocess.STDOUT,timeout=45)
                record['debugger_exit_code']=result.returncode
            except subprocess.TimeoutExpired:
                record['debugger_timed_out']=True
                log.write('\nCAPTURE diagnostic run exceeded 45-second bound\n')
            except OSError as error:
                log.write('CAPTURE debugger unavailable: '+str(error)+'\n')
    record['success']=record['run_exit_code']==0 and not record['run_timed_out']
    return destination,record

def build(mesa,output,width=64,height=64,ui_profile=False):
    capture_dimensions(width,height)
    if type(ui_profile) is not bool:raise ValueError('UI-like capture opt-in must be boolean')
    if platform.system()!='Darwin':raise ValueError('native capture build requires the macOS CI host')
    output=Path(output).resolve();source,source_record=prepare_source(mesa,output)
    receipt=reconstruct(output/'uapi-source',targets=('bsd/dev/santoni_gpu_graphics_uapi.h',
        'bsd/dev/santoni_gpu_core.h','bsd/dev/santoni_gpu_graphics.h'))
    own=ROOT/'tools/santoni-graphics'
    sources=('client.c','msm.c','drm.c','gles.c','ui_surface.c','ui_gl.c',
        'capture/transport.c','capture/submit.c','capture/main.c')
    inputs={str((own/name).relative_to(ROOT)):hashlib.sha256((own/name).read_bytes()).hexdigest() for name in sources}
    cc=subprocess.check_output(['xcrun','--sdk','macosx','--find','clang'],text=True).strip()
    cxx=subprocess.check_output(['xcrun','--sdk','macosx','--find','clang++'],text=True).strip()
    ar=subprocess.check_output(['xcrun','--sdk','macosx','--find','ar'],text=True).strip()
    sdk=subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip()
    flags=['-isysroot',sdk,'-DSANTONI_GFX_MESA=1','-I'+str(own),'-I'+str(own/'include'),
        '-I'+str(output/'uapi-source/bsd/dev')]
    # A native host executable is necessary to run the real state tracker and
    # IR3 compiler. Its CPU ISA is not offered as iOS/A53 verification.
    configuration=output/'native.ini'
    array=lambda values:'['+', '.join(repr(v) for v in values)+']'
    configuration.write_text('[binaries]\nc = '+array([cc,'-isysroot',sdk])+'\ncpp = '+array([cxx,'-isysroot',sdk])+
        '\nar = '+repr(ar)+"\npkg-config = 'false'\n[built-in options]\nc_args = "+array(flags[2:])+
        '\ncpp_args = '+array(flags[2:])+'\n')
    directory=output/'mesa-build';commands=[]
    with (output/'build.log').open('x') as log:
        command=['meson','setup',str(directory),str(source),'--native-file',str(configuration),
            '--buildtype=release','--wrap-mode=nofallback',*MESA_OPTIONS]
        subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True);commands.append(command)
        command=['ninja','-C',str(directory),*LIBRARIES]
        subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True);commands.append(command)
        inventory=json.loads((directory/'compile_commands.json').read_text())
        tracker=next(row for row in inventory if row['file'].endswith('state_tracker/st_manager.c'))
        defines=[v for v in (tracker.get('arguments') or shlex.split(tracker['command'])) if v.startswith('-D')]
        includes=[source/'include',source/'include/drm-uapi',source/'src',source/'src/mesa',source/'src/mapi',
            source/'src/gallium/include',source/'src/gallium/auxiliary',source/'src/gallium/drivers',
            source/'src/gallium/winsys',source/'src/freedreno',directory/'src',directory/'src/mesa',
            directory/'src/mapi',directory/'src/util']
        objects=[]
        for name in sources:
            obj=output/(name.replace('/','-')+'.o')
            command=[cc,*flags,*defines,*['-I'+str(p) for p in includes],'-std=c11','-O2','-g','-Wall','-Wextra','-Werror',
                '-c',str(own/name),'-o',str(obj)]
            subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True);commands.append(command);objects.append(obj)
        executable=output/'capture-mesa'
        command=[cxx,'-isysroot',sdk,'-Wl,-dead_strip','-o',str(executable),*[str(p) for p in objects],
            *[str(directory/name) for name in LIBRARIES],'-lz']
        subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True);commands.append(command)
        destination,execution=run_capture(executable,output,width,height,ui_profile)
    captures=sorted(destination.glob('submit-*.bin'))
    record={**execution,'host':platform.machine(),
        'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'mesa_source':source_record,'uapi':receipt,'inputs_sha256':inputs,'commands':commands,
        'captures_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in captures},
        'kernel_built':False,'GPU_accessed':False,'hardware_verified':False,'completion_responses_modeled':True,
        'production_command_packager_linked':False}
    with (output/'capture.json').open('x') as stream:json.dump(record,stream,indent=2)
    if not record['success']:raise RuntimeError('actual Mesa command-generation run failed; see run.log')
    return record
if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--mesa',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--width',type=int,default=64);parser.add_argument('--height',type=int,default=64)
    parser.add_argument('--ui-profile',action='store_true',help='also capture an interpolated, linear-filtered premultiplied quad; host model only');args=parser.parse_args()
    print(json.dumps(build(args.mesa,args.output,args.width,args.height,args.ui_profile),indent=2))
