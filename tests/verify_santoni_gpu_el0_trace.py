#!/usr/bin/env python3
"""Run only new CPU/VFS trace and changed probe entry contracts.

Extract exact reconstructed functions. Kernel/VFS/syscall services and the
unchanged GPU workload report are explicit injected contracts; no old tests,
MMIO, hardware, kernel build, image packaging or device access is performed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

import verify_santoni_gpu_launcher as extract

ROOT=Path(__file__).resolve().parents[1]
RECEIVER_CASES=('normal','result','failure-result','quota','reserved','non-result-fields',
    'diag-open-flags','diag-open-access','diag-ioctl-abi','diag-ioctl-wrong-mount','diag-silent',
    'diag-saturation','diag-first-wins','diag-late','diag-concurrent',
    'forged-pass','open-write','close-cloexec','null-args','off','mode1','mode2','wrong-flags',
    'no-suffix','wrong-suffix','preparing','failed','unmounted','wrong-backing','wrong-eof',
    'wrong-span','null-vnode','directory','null-node','wrong-node','wrong-mount','null-mount',
    'null-mount-data','pager-failed','wrong-command','wide-command','kernel-context',
    'null-context','null-process','foreign-process','pid0','nonroot','missing-executable',
    'other-executable','null-record','write-descriptor','version','size','event','status',
    'bounds','verification','negative','error')
PROBE_CASES=('normal','console-error','console-overflow','write-error','short-write',
    'first-write-error','pid1-parent','pid1-fork-error','pid1-child','pid1-exec-error',
    'trace-open-error','trace-ioctl-error','gpu-failure','getpid-error')
MUTANTS=(
    ('receiver','kernel-context','if (!ctx || vfs_context_iskernel(ctx)) return EACCES;',
        'if (!ctx) return EACCES;','kernel-context'),
    ('receiver','process-identity','p!=current_proc()','false','foreign-process'),
    ('receiver','executable-identity','bool same=textvp==vp;','(void)vp; bool same=true;','other-executable'),
    ('receiver','command-width','ap->a_command!=SGPU_LAUNCH_TRACE_IOCTL',
        '(uint32_t)ap->a_command!=(uint32_t)SGPU_LAUNCH_TRACE_IOCTL','wide-command'),
    ('receiver','reserved-record','if (r->reserved[i])\n        return mockfs_santoni_diag_refuse(false,4,EINVAL);',
        'if (false && r->reserved[i])\n        return mockfs_santoni_diag_refuse(false,4,EINVAL);','reserved'),
    ('receiver','event-budget','mockfs_santoni_trace_events>=SGPU_LAUNCH_TRACE_LIMIT',
        'false','quota'),
    ('receiver','mode3-role','launch_options(mode)==SG_LAUNCH_ON','true','mode1'),
    ('receiver','diag-first-overwrite','if (!*first) *first=stage;',
        '*first=stage;','diag-first-wins'),
    ('receiver','diag-wrap','if (*field!=UINT32_MAX) ++*field;',
        '++*field;','diag-saturation'),
    ('receiver','diag-unlocked','lck_mtx_lock(&mockfs_santoni_diag_lock);\n    uint32_t *seen=',
        'uint32_t *seen=','diag-first-wins'),
    ('receiver','diag-empty-copy','*out=mockfs_santoni_trace_diag;',
        'memset(out,0,sizeof(*out));','diag-late'),
    ('probe','console-failure-outcome','trace_event(trace_fd,SG_LTRACE_RESULT,0,0,&failure);',
        '(void)failure;','console-error'),
    ('probe','console-first-failure','if (!status->status && (error || rc!=bytes))',
        'if (0 && (error || rc!=bytes))','first-write-error'),
    ('probe','cloexec-descriptor','0x01000000,0,0,0,&open_error','0,0,0,0,&open_error','normal'),
)

def amalgamations(source):
    launch=(source/'bsd/dev/santoni_gpu_launch.c').read_text()
    vnops=(source/'bsd/miscfs/mockfs/mockfs_vnops.c').read_text()
    state=launch[launch.index('enum { LAUNCH_NEW'):launch.index('static enum sgpu_launch_role launch_options')]
    counter=re.search(r'^static uint32_t mockfs_santoni_trace_events;',vnops,re.M)
    if not counter:raise ValueError('missing actual saturating trace counter')
    diag=re.search(r'^static struct sgpu_launch_trace_diag mockfs_santoni_trace_diag;',vnops,re.M)
    if not diag:raise ValueError('missing actual trace diagnostic record')
    locks=re.findall(r'^static LCK_(?:GRP|MTX)_DECLARE\([^\n]+;',vnops,re.M)
    if len(locks)!=2:raise ValueError('missing actual diagnostic lock declarations')
    receiver=['#include "santoni_gpu_el0_trace_stubs.h"',state,
        extract.function(launch,'launch_options'),
        extract.function(launch,'santoni_gpu_user_launch_trace_ready'),counter.group(),*locks,diag.group()]
    receiver += [extract.function(vnops,n) for n in ('mockfs_santoni_diag_inc',
        'mockfs_santoni_diag_note',
        'mockfs_santoni_diag_refuse','santoni_gpu_user_launch_trace_snapshot',
        'mockfs_santoni_trace_mount','mockfs_santoni_trace_access','mockfs_santoni_open',
        'mockfs_santoni_close','mockfs_santoni_ioctl')]
    receiver += ['#include "test_santoni_gpu_el0_trace.c"']
    probe=(ROOT/'tools/santoni_gpu_user_probe.c').read_text()
    entry=[probe[:probe.index('void *memset')],
        'int sgpu_user_probe_run(struct sgpu_probe_report *);']
    entry += [extract.function(probe,n) for n in ('call','errno_value','trace_event','trace_close',
        'sleep_us','text_length','write_bytes','write_text','write_number','report',
        'original_init','sgpu_user_probe_entry')]
    entry += ['#include "test_santoni_gpu_el0_trace_probe.c"']
    return {'receiver':'\n\n'.join(receiver),'probe':'\n\n'.join(entry)}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--suite',choices=('receiver','probe','both'),default='both')
    p.add_argument('--variants',nargs='+',choices=('O0','O2','UBSan'),default=['O0','O2','UBSan'])
    p.add_argument('--cases',nargs='+')
    p.add_argument('--mutants',action='store_true')
    args=p.parse_args()
    if args.output.exists():p.error('refusing existing evidence output')
    args.output.mkdir(parents=True)
    code=amalgamations(args.source)
    suites=('receiver','probe') if args.suite=='both' else (args.suite,)
    hashes=lambda paths:{str(n):hashlib.sha256(n.read_bytes()).hexdigest() for n in paths}
    record={'success':False,'scope':__doc__,'hardware_verified':False,'kernel_certified':False,
        'sources_sha256':hashes([args.source/n for n in ('bsd/dev/santoni_gpu_launch.c',
            'bsd/dev/santoni_gpu_launch.h','bsd/dev/santoni_gpu_launch_trace.h',
            'bsd/dev/santoni_gpu_launch_core.c','bsd/miscfs/mockfs/mockfs_vnops.c')]+
            [ROOT/n for n in ('tools/santoni_gpu_user_probe.c','tests/verify_santoni_gpu_el0_trace.py',
                'tests/santoni_gpu_el0_trace_stubs.h','tests/test_santoni_gpu_el0_trace.c',
                'tests/test_santoni_gpu_el0_trace_probe.c')]),'cases':{},'mutants':{}}
    def save(): (args.output/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
    cc=shlex.split(os.environ.get('HOST_CC','clang'))
    with tempfile.TemporaryDirectory(prefix='sgpu-el0-trace-',dir=preferred if preferred.is_dir() else None) as tmp:
        def compile_source(suite,text,name,flags):
            path=args.output/(name+'.c'); path.write_text(text)
            binary=Path(tmp)/name
            cmd=[*cc,'-std=gnu11','-Wall','-Wextra','-Werror','-Wno-unused-function',*flags,
                '-pthread','-I',str(ROOT/'tests'),'-I',str(args.source/'bsd/dev'),str(path)]
            if suite=='receiver':cmd.append(str(args.source/'bsd/dev/santoni_gpu_launch_core.c'))
            cmd += ['-o',str(binary)]
            r=subprocess.run(cmd,capture_output=True,text=True,timeout=60)
            (args.output/(name+'-compile.txt')).write_text(r.stdout+r.stderr)
            if r.returncode:raise ValueError('compile failed: '+name+'; see saved log')
            return binary
        try:
            for suite in suites:
                cases=args.cases or (RECEIVER_CASES if suite=='receiver' else PROBE_CASES)
                allowed=RECEIVER_CASES if suite=='receiver' else PROBE_CASES
                if not set(cases)<=set(allowed):raise ValueError('unknown selected cases')
                for variant in args.variants:
                    flags=['-O0'] if variant=='O0' else ['-O2']
                    if variant=='UBSan':flags += ['-fsanitize=undefined','-fno-sanitize-recover=all']
                    binary=compile_source(suite,code[suite],suite+'-'+variant,flags)
                    completed=record['cases'].setdefault(suite,{}).setdefault(variant,{})
                    for case in cases:
                        r=subprocess.run([str(binary),case],capture_output=True,text=True,timeout=15)
                        completed[case]={'exit_code':r.returncode,'output':r.stdout+r.stderr}; save()
                        if r.returncode:raise ValueError(suite+' '+variant+' '+case+' failed')
                    print(suite+' '+variant+': '+str(len(completed))+' new cases passed',flush=True)
            if args.mutants:
                for suite,name,old,new,case in MUTANTS:
                    if suite not in suites:continue
                    if code[suite].count(old)!=1:raise ValueError('ambiguous mutant '+name)
                    binary=compile_source(suite,code[suite].replace(old,new,1),'mutant-'+name,['-O2'])
                    r=subprocess.run([str(binary),case],capture_output=True,text=True,timeout=15)
                    record['mutants'][name]={'compiled':True,'rejected':r.returncode!=0,
                        'exit_code':r.returncode,'case':case,'output':r.stdout+r.stderr}; save()
                    if not r.returncode:raise ValueError('compiling mutant survived '+name)
                print(str(len(record['mutants']))+' compiling mutants rejected',flush=True)
            record['success']=True
        except (OSError,ValueError,subprocess.SubprocessError) as error:record['error']=str(error)
        save()
    print(json.dumps({'success':record['success'],'evidence':str(args.output/'result.json'),
        'error':record.get('error')}))
    return 0 if record['success'] else 1

if __name__=='__main__':raise SystemExit(main())
