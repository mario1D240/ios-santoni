#!/usr/bin/env python3
"""Consume exact graphics/PM4 native contracts; never certify phone rendering."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def verify_bridge(record):
    from tools.verify_santoni_gpu_raster_evidence import verify
    return verify(record,'bridge')


def verify_publish(record):
    from tests.test_santoni_gpu_graphics_publish import FILES,INPUTS,CASES,VARIANTS
    from tests.native_santoni_gpu_core import reconstruct
    if record.get('success') is not True or record.get('hardware_verified') is not False:
        raise ValueError('graphics publication evidence scope differs')
    if record.get('inputs_sha256')!={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in INPUTS}:
        raise ValueError('graphics publication harness changed')
    with tempfile.TemporaryDirectory(prefix='graphics-publication-intake-') as t:
        result=reconstruct(Path(t)/'source',targets=FILES)
    if record.get('source_sha256')!={**result['sha256'],**result['dependencies'],**result['native_link_dependencies']}:
        raise ValueError('graphics publication reconstructed bytes differ')
    rows=record.get('rows',[])
    if len(rows)!=len(VARIANTS) or {r.get('label') for r in rows}!={v[0] for v in VARIANTS}:
        raise ValueError('graphics publication variants incomplete')
    for row in rows:
        runs=row.get('runs',[])
        if row.get('compile_exit')!=0 or [r.get('case') for r in runs]!=list(range(CASES)) or any(r.get('exit_code')!=0 for r in runs):
            raise ValueError('graphics publication contract failed/incomplete')
        if 'wraps=3' not in runs[2].get('stdout',''):
            raise ValueError('graphics publication circular ring was not exercised')
    return {'success':True,'kind':'publish','positive_executions':CASES*len(VARIANTS),
            'hardware_verified':False,'shader_rendering_verified':False,'test_executions':0}


def verify_publish_mutants(record):
    from tests.test_santoni_gpu_graphics_publish_mutants import INPUTS,MUTANTS
    from tests.test_santoni_gpu_graphics_publish import FILES
    from tests.native_santoni_gpu_core import reconstruct
    from tests.test_santoni_gpu_prepare import source_function
    if record.get('success') is not True or record.get('hardware_verified') is not False:
        raise ValueError('graphics publication mutation scope differs')
    if record.get('inputs_sha256')!={p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in INPUTS}:
        raise ValueError('graphics publication mutation harness changed')
    with tempfile.TemporaryDirectory(prefix='graphics-publish-mutant-intake-') as t:
        result=reconstruct(Path(t)/'source',targets=FILES)
        actual=(Path(t)/'source/bsd/dev/santoni_gpu_core.c').read_text()
    if record.get('source_sha256')!={**result['sha256'],**result['dependencies'],**result['native_link_dependencies']}:
        raise ValueError('graphics publication mutation source differs')
    rows=record.get('rows',[])
    if len(rows)!=len(MUTANTS) or {r.get('label') for r in rows}!={m[0] for m in MUTANTS}:
        raise ValueError('graphics publication mutation inventory incomplete')
    function=source_function(actual,'sgpu_graphics_hw_publish')
    for row in rows:
        label,case,old,new=next(m for m in MUTANTS if m[0]==row['label'])
        if function.count(old)!=1:raise ValueError('graphics publication mutation became ambiguous')
        mutated=actual.replace(function,function.replace(old,new),1)
        if row.get('mutant_sha256')!=hashlib.sha256(mutated.encode()).hexdigest() or row.get('case')!=case or row.get('compile_exit')!=0 or type(row.get('exit_code')) is not int or row['exit_code']==0:
            raise ValueError('graphics publication mutation did not compile and fail its actual harness')
    return {'success':True,'kind':'publish-mutants','compiled_rejected_mutants':len(MUTANTS),
            'hardware_verified':False,'shader_rendering_verified':False,'test_executions':0}


def verify(record,kind):
    if kind=='bridge':return verify_bridge(record)
    if kind=='publish':return verify_publish(record)
    if kind=='publish-mutants':return verify_publish_mutants(record)
    from tests.reconstruct_santoni_touch import reconstruct
    if kind=='graphics':
        from tests.test_santoni_gpu_graphics import FILES,MUTANTS
        cases=45;module='santoni_gpu_graphics.c'
    elif kind=='pm4':
        from tests.test_santoni_gpu_pm4 import FILES,MUTANTS
        cases=46;module='santoni_gpu_pm4.c'
    else:raise ValueError('unknown graphics receipt kind')
    expected={str(p):hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in
        ('tests/test_santoni_gpu_'+kind+'.c','tests/test_santoni_gpu_'+kind+'.py','tests/reconstruct_santoni_touch.py')}
    if record.get('inputs_sha256')!=expected:raise ValueError('graphics native harness/intake bytes changed')
    with tempfile.TemporaryDirectory(prefix='graphics-intake-') as temporary:
        result=reconstruct(Path(temporary)/'source',targets=FILES)
    if record.get('source_sha256')!=result['sha256']:raise ValueError('graphics native source bytes changed')
    labels={'O0','O2','ubsan'}|{m[0]+'-'+v for m in MUTANTS for v in ('O0','O2','ubsan')}
    rows=record.get('rows',[])
    if len(rows)!=len(labels) or {r.get('label') for r in rows}!=labels:raise ValueError('graphics execution inventory incomplete')
    for row in rows:
        if row.get('compile_exit')!=0:raise ValueError('noncompiling graphics mutant is not evidence')
        runs=row.get('runs',[]);mutant=row['label'] not in ('O0','O2','ubsan')
        if row.get('mutant') is not mutant:raise ValueError('graphics variant classification differs')
        if not mutant:
            if [r.get('case') for r in runs]!=list(range(cases)) or any(r.get('exit_code')!=0 for r in runs):raise ValueError('graphics positive contract did not pass')
            if row.get('source_sha256')!=result['sha256']['bsd/dev/'+module]:raise ValueError('compiled graphics source differs')
        elif not runs or [r.get('case') for r in runs]!=list(range(len(runs))) or runs[-1].get('exit_code') in (0,None) or any(r.get('exit_code')!=0 for r in runs[:-1]):
            raise ValueError('graphics mutant did not compile and fail its harness')
    if record.get('success') is not True or record.get('hardware_verified') is not False:raise ValueError('graphics evidence scope differs')
    return {'success':True,'kind':kind,'positive_executions':3*cases,'compiled_rejected_mutants':3*len(MUTANTS),
            'test_executions':0,'hardware_verified':False,'shader_rendering_verified':False}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('kind',choices=('graphics','pm4','bridge','publish','publish-mutants'));p.add_argument('record',type=Path)
    a=p.parse_args();print(json.dumps(verify(json.loads(a.record.read_text()),a.kind),indent=2))
