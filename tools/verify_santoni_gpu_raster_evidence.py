#!/usr/bin/env python3
"""Bind reconstructed restricted raster contracts; never certify GPU pixels."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

def digest(data):return hashlib.sha256(data).hexdigest()

def contract(kind):
    from tests.reconstruct_santoni_touch import reconstruct
    if kind not in ('ir3','raster','bridge'):raise ValueError('unknown raster evidence kind')
    name='graphics_bridge' if kind=='bridge' else kind
    module=__import__('tests.test_santoni_gpu_'+name,fromlist=['FILES'])
    with tempfile.TemporaryDirectory(prefix='raster-evidence-intake-') as temporary:
        source=Path(temporary)/'source'
        result=reconstruct(source,targets=module.FILES)
        texts={name:(source/name).read_text() for name in module.FILES if name.endswith('.c')}
    return module,result['sha256'],texts

def compile_row(row,flags):
    command=row.get('command')
    if type(row.get('compile_exit')) is not int or row['compile_exit']!=0:
        raise ValueError('raster variant did not compile')
    if not isinstance(command,list) or not command or any(not isinstance(a,str) for a in command):
        raise ValueError('raster compile command framing')
    required=['-std=c11','-Wall','-Wextra','-Werror','-DARM64_BOARD_CONFIG_SANTONI',*flags]
    if any(flag not in command for flag in required):raise ValueError('raster compile policy differs')
    if any(a.startswith('-O') and a not in flags for a in command):raise ValueError('raster optimization override')
    if any(a=='-w' or a.startswith(('-Wno-error','-fno-sanitize=')) for a in command):
        raise ValueError('raster checking override')

def verify(record,kind):
    if not isinstance(record,dict) or record.get('success') is not True or record.get('hardware_verified') is not False:
        raise ValueError('raster receipt scope differs')
    module,source,texts=contract(kind)
    inputs={name:digest((ROOT/name).read_bytes()) for name in module.INPUTS}
    if record.get('inputs_sha256')!=inputs:raise ValueError('raster harness bytes differ')
    if record.get('source_sha256')!=source:raise ValueError('raster reconstructed bytes differ')
    rows=record.get('rows')
    if not isinstance(rows,list) or any(not isinstance(row,dict) for row in rows):
        raise ValueError('raster variant framing')
    if any(not isinstance(row.get('name'),str) for row in rows):
        raise ValueError('raster variant name framing')
    if kind=='bridge':
        if record.get('allocator_VM_begin_modeled') is not True:raise ValueError('bridge allocator uncertainty missing')
        cases={'hardware':[[str(i)] for i in range(17)],'iokit':[[str(i)] for i in module.IOKIT_CASES],
            'iokit-wide':[[str(i)] for i in module.WIDE_IOKIT_CASES],'pipeline':[[]],'worker':[[str(i)] for i in range(8)]}
        expected={name+'-'+label:args for name,args in cases.items() for label,_ in module.VARIANTS}
        if len(rows)!=len(expected) or {row.get('name') for row in rows}!=set(expected):
            raise ValueError('bridge variants incomplete')
        for row in rows:
            runs=row.get('runs')
            if type(row.get('compile_exit')) is not int or row['compile_exit']!=0 or not isinstance(runs,list):
                raise ValueError('bridge compile/run framing')
            if any(not isinstance(run,dict) for run in runs) or [run.get('args') for run in runs]!=expected[row['name']]:
                raise ValueError('bridge case inventory differs')
            if any(type(run.get('exit_code')) is not int or run['exit_code']!=0 for run in runs):
                raise ValueError('bridge contract failed')
        return {'success':True,'kind':kind,'positive_executions':sum(len(args) for args in expected.values()),
            'compiled_rejected_mutants':0,'hardware_verified':False,'shader_rendering_verified':False,'test_executions':0}

    expected={}
    if kind=='ir3':
        path='bsd/dev/santoni_gpu_ir3.c'
        positive=[(0,k) for k in range(5)]+[(case,4) for case in range(1,86)]
        for label,flags in module.VARIANTS:expected[label]=(False,positive,source[path],flags)
        for name,old,new,case in module.MUTANTS:
            for token in ('reg','constant'):
                old=old.replace(token+'(','sgpu_ir3_'+token+'(')
                new=new.replace(token+'(','sgpu_ir3_'+token+'(')
            if texts[path].count(old)!=1:raise ValueError('IR3 mutation target differs')
            mutated=digest(texts[path].replace(old,new,1).encode())
            for label,flags in module.VARIANTS:expected[name+'-'+label]=(True,[(case,4)],mutated,flags)
    else:
        if record.get('transport_refused_after_validation') is not True:raise ValueError('raster transport uncertainty missing')
        source_map={name:inputs[name] for name in ('tests/test_santoni_gpu_raster.c',
            'tools/santoni-graphics/client.c','tools/santoni-graphics/commands.c')}
        source_map.update({'bsd/dev/'+name+'.c':source['bsd/dev/'+name+'.c'] for name in module.MODULES})
        for label,flags in module.VARIANTS:expected[label]=(False,list(range(51)),source_map,flags)
        for name,target,old,new,case in module.MUTANTS:
            path='bsd/dev/'+target+'.c'
            if texts[path].count(old)!=1:raise ValueError('raster mutation target differs')
            mutated={**source_map,path:digest(texts[path].replace(old,new,1).encode())}
            for label,flags in module.VARIANTS:expected[name+'-'+label]=(True,[case],mutated,flags)
    if len(rows)!=len(expected) or {row.get('name') for row in rows}!=set(expected):
        raise ValueError('raster mutation/variant inventory incomplete')
    for row in rows:
        mutant,cases,compiled,flags=expected[row['name']]
        compile_row(row,flags)
        if row.get('mutant') is not mutant or row.get('source_sha256')!=compiled:
            raise ValueError('raster compiled variant bytes differ')
        runs=row.get('runs')
        if not isinstance(runs,list) or any(not isinstance(run,dict) for run in runs):
            raise ValueError('raster run framing')
        if any(type(run.get('case')) is not int or (kind=='ir3' and type(run.get('kind')) is not int) for run in runs):
            raise ValueError('raster case/index framing')
        actual=[(run.get('case'),run.get('kind')) if kind=='ir3' else run.get('case') for run in runs]
        if actual!=cases or any(type(run.get('exit')) is not int or (run['exit']!=0)!=mutant for run in runs):
            raise ValueError('raster positive/refusal contract differs')
    positives=sum(len(cases) for mutant,cases,_,_ in expected.values() if not mutant)
    negatives=sum(1 for mutant,_,_,_ in expected.values() if mutant)
    if type(record.get('native_executions')) is not int or type(record.get('compiled_rejected_mutants')) is not int or \
        record['native_executions']!=positives or record['compiled_rejected_mutants']!=negatives:
        raise ValueError('raster receipt counters differ from exact rows')
    return {'success':True,'kind':kind,'positive_executions':positives,'compiled_rejected_mutants':negatives,
        'hardware_verified':False,'shader_rendering_verified':False,'test_executions':0}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind',choices=('ir3','raster','bridge'))
    parser.add_argument('record',type=Path)
    args=parser.parse_args()
    print(json.dumps(verify(json.loads(args.record.read_text()),args.kind),indent=2))
