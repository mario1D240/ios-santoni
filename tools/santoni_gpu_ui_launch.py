#!/usr/bin/env python3
"""Stage audited UI images and launch plists in a new offline overlay directory.

This does not mount or change an installed root, package a boot image, or certify
dyld execution. Keep the original plist bytes in the generated restore directory.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path,PurePosixPath
import plistlib
import re
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from tools.build_santoni_graphics_gles import ui_artifact_path
from tools.check_santoni_graphics_library import metadata
from tools.check_santoni_ui_loader import check

AGGREGATE='/System/Library/xpc/launchd.plist'
INDIVIDUAL='/System/Library/LaunchDaemons/com.apple.backboardd.plist'
EXECUTABLE='/usr/libexec/backboardd'

def sha(data):return hashlib.sha256(data).hexdigest()

def patch_job(job,loader_path):
    if not isinstance(job,dict) or job.get('Label')!='com.apple.backboardd' or \
        job.get('Program') not in (None,EXECUTABLE) or job.get('ProgramArguments')!=[EXECUTABLE] or \
        job.get('UserName')!='mobile' or job.get('GroupName') not in (None,'mobile'):
        raise ValueError('backboardd executable/user contract differs')
    environment=job.get('EnvironmentVariables',{})
    if not isinstance(environment,dict) or any(not isinstance(k,str) or not isinstance(v,str)
        for k,v in environment.items()):raise ValueError('launch environment is malformed')
    if any(k.startswith('DYLD_') for k in environment):
        raise ValueError('existing dyld overrides must be reviewed before UI staging')
    result=copy.deepcopy(job)
    result['EnvironmentVariables']={**environment,'DYLD_INSERT_LIBRARIES':loader_path}
    return result

def patch_plists(aggregate,individual,loader_path):
    if re.fullmatch(r'/usr/local/lib/santoni-gpu-ui/[0-9a-f]{64}/libsantoni-ui-loader\.dylib',loader_path) is None:
        raise ValueError('loader path does not bind an exact image SHA')
    combined=plistlib.loads(aggregate);single=plistlib.loads(individual)
    if not isinstance(combined,dict) or not isinstance(combined.get('LaunchDaemons'),dict):
        raise ValueError('aggregate launchd jobs missing')
    jobs=combined['LaunchDaemons']
    matches=[key for key,job in jobs.items() if isinstance(job,dict) and job.get('Label')=='com.apple.backboardd']
    if matches!=[INDIVIDUAL]:raise ValueError('aggregate renderer job missing, moved or ambiguous')
    result=copy.deepcopy(combined)
    result['LaunchDaemons'][INDIVIDUAL]=patch_job(jobs[INDIVIDUAL],loader_path)
    single_result=patch_job(single,loader_path)
    # Preserve all other job semantics and every renderer field except the
    # intended environment insertion, even though binary plist offsets change.
    return (plistlib.dumps(result,fmt=plistlib.FMT_BINARY,sort_keys=False),
        plistlib.dumps(single_result,fmt=plistlib.FMT_BINARY,sort_keys=False))

def absolute_dependencies(data):
    dependencies=metadata(data)['dylibs']
    for dependency in dependencies:
        name=dependency['name'];path=PurePosixPath(name)
        if not name.startswith(('/usr/lib/','/System/Library/')) or ':' in name or '\\' in name or \
            '..' in path.parts or str(path)!=name:
            raise ValueError('UI policy requires absolute system dependency paths: '+name)
    return dependencies

def stage(eagl,loader,eagl_cpu,loader_cpu,build,aggregate,individual,output):
    paths=[Path(p) for p in (eagl,loader,eagl_cpu,loader_cpu,build,aggregate,individual)]
    original=[p.read_bytes() for p in paths]
    binding=check(*paths[:5])
    dependencies=[absolute_dependencies(data) for data in original[:2]]
    eagl_path=ui_artifact_path(binding['eagl_sha256'],'libsantoni-eagl.dylib')
    loader_path=ui_artifact_path(binding['loader_sha256'],'libsantoni-ui-loader.dylib')
    combined,single=patch_plists(original[5],original[6],loader_path)
    if any(p.read_bytes()!=data for p,data in zip(paths,original)):
        raise ValueError('UI staging input changed during validation')
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    records=[]
    for prefix,path,data,mode in (
        ('root-overlay',eagl_path,original[0],0o755),('root-overlay',loader_path,original[1],0o755),
        ('root-overlay',AGGREGATE,combined,0o644),('root-overlay',INDIVIDUAL,single,0o644),
        ('restore',AGGREGATE,original[5],None),('restore',INDIVIDUAL,original[6],None)):
        destination=output/prefix/path.lstrip('/')
        destination.parent.mkdir(parents=True,exist_ok=True)
        with destination.open('xb') as stream:stream.write(data)
        records.append({'role':prefix,'path':path,'bytes':len(data),'sha256':sha(data),
            'install_uid':0 if mode is not None else None,'install_gid':0 if mode is not None else None,
            'install_mode':mode,'installed_metadata_verified':False})
    record={'success':True,'binding':binding,'files':records,
        'inputs':[{'path':str(p),'sha256':sha(data)} for p,data in zip(paths,original)],
        'dependencies':dependencies,'renderer_job_count':1,'renderer_uid':501,
        'required_kernel_options':{'santonigpu':3,'santonigpu_graphics':1,'santonigpu_render':1,
            'santonigpu_ui':0,'santonigpu_raster':1,'santonigpu_gles':1,'santonigpu_renderer':1},
        'kernel_dyld_policy_verified':False,'installed_root_verified':False,'runtime_dyld_verified':False,
        'boot_image_packaged':False,'hardware_verified':False}
    with (output/'launch-overlay.json').open('x') as stream:json.dump(record,stream,indent=2)
    return record

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('eagl','loader','eagl_cpu','loader_cpu','build','aggregate','individual','output'):
        parser.add_argument('--'+name.replace('_','-'),type=Path,required=True)
    arguments=parser.parse_args()
    print(json.dumps(stage(**vars(arguments)),indent=2))
