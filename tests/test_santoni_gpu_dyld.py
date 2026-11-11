"""Run reconstructed dyld policy bodies; VFS identity/copies/parsing modeled."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from tests.reconstruct_santoni_touch import reconstruct
from tests.test_santoni_gpu_prepare import source_function

ROOT=Path(__file__).resolve().parents[1]
FILES=('bsd/kern/sweet_amfi.c','iokit/Kernel/arm/SantoniGraphics.cpp')
INPUTS=('tests/test_santoni_gpu_dyld.py','tests/test_santoni_gpu_dyld.cpp',
    'tests/santoni_gpu_dyld_stubs.h','tests/reconstruct_santoni_touch.py',
    'tests/test_santoni_gpu_prepare.py')

class DyldPolicy(unittest.TestCase):
    def test_actual_opt_ins_selector_copy_geometry_and_errors(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='santoni-dyld-',dir=preferred if preferred.is_dir() else None) as temporary:
            work=Path(temporary)
            source=reconstruct(work/'source',targets=FILES)
            cpp=(work/'source'/FILES[1]).read_text()
            policy_source=(work/'source'/FILES[0]).read_text()
            flags=source_function(cpp,'santoni_gpu_graphics_dyld_flags')
            policy=source_function(policy_source,'sweet_santoni_dyld_syscall')
            helpers=policy_source[policy_source.index('/* Three independent, saturating boot budgets:'):policy_source.index('static int __attribute__((noinline))\nsweet_santoni_dyld_syscall')]
            rows=[]
            def execute(label,options,flag_body=flags,policy_body=policy,helper_body=helpers,reject=False):
                folder=work/label;folder.mkdir()
                header='#include "santoni_gpu_dyld_stubs.h"\n'
                (folder/'flags.cpp').write_text(header+'extern "C" {\n'+flag_body+'\n}\n')
                (folder/'policy.c').write_text(header+helper_body+policy_body+
                    '\nint fixture_policy(proc_t p,int call,user_addr_t arg){return sweet_santoni_dyld_syscall(p,call,arg);}'
                    '\nvoid fixture_reset_trace(void){for(unsigned i=0;i<3;i++)sweet_dyld_trace_counts[i]=0;}\n')
                commands=[['clang','-std=c11',*options,'-Wall','-Wextra','-Werror','-I',str(ROOT/'tests'),
                    '-Dprintf=fixture_dyld_printf','-c',str(folder/'policy.c'),'-o',str(folder/'policy.o')],
                    ['clang++','-std=c++17',*options,'-Wall','-Wextra','-Werror','-I',str(ROOT/'tests'),
                    str(folder/'flags.cpp'),str(ROOT/'tests/test_santoni_gpu_dyld.cpp'),str(folder/'policy.o'),'-o',str(folder/'test')]]
                row={'label':label,'commands':commands,'compile_results':[],'reject_expected':reject};rows.append(row)
                for command in commands:
                    result=subprocess.run(command,capture_output=True,text=True,timeout=60)
                    row['compile_results'].append({'exit':result.returncode,'stderr':result.stderr})
                    self.assertEqual(result.returncode,0,label+'\n'+result.stderr)
                result=subprocess.run([str(folder/'test')],capture_output=True,text=True,timeout=15)
                row['run']={'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
                if reject:self.assertNotEqual(result.returncode,0,label+' survived')
                else:
                    self.assertEqual(result.returncode,0,label+'\n'+result.stderr)
                    self.assertEqual(result.stdout,'passed 65 dyld policy contract cases; bounded trace checks passed\n')
            for label,options in [('O0',['-O0']),('O2',['-O2']),
                ('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:execute(label,options)
            changes=[('process-owner','process!=current_proc()','false'),
                *[(name,term+' ||','') for name,term in (
                    ('graphics','graphics!=1'),('mode','mode!=3'),('render','render!=1'),('ui','ui!=0'),
                    ('raster','raster!=1'),('gles','gles!=1'),('renderer','renderer!=1'))],
                ('identity','!gfx_renderer_task(current_task())','false'),
                ('widen-policy','(1ull<<1)|(1ull<<5)','0x7bull')]
            for label,old,new in changes:
                self.assertEqual(flags.count(old),1,label)
                execute(label,['-O2'],flag_body=flags.replace(old,new),reject=True)
            for label,old,new in [('copyin','copyin(arg,args,sizeof(args))!=0','copyin(arg,args,sizeof(args))<0'),
                ('output-null','else if(!args[1])','else if(!args[1] && 0)'),('selector','call!=90','call==89'),
                ('trace-missing','if(token)','if(token && 0)'),
                ('trace-flags','(unsigned long long)flags','(unsigned long long)(flags!=0)'),
                ('trace-error','flags,stage,error);','flags,stage,0);'),
                ('trace-stage','flags,stage,error);','flags,stage+1,error);'),
                ('logging-return','return error;','return 0;')]:
                self.assertEqual(policy.count(old),1,label)
                execute(label,['-O2'],policy_body=policy.replace(old,new),reject=True)
            for label,old,new in [('trace-default','renderer!=1','renderer==2'),
                ('trace-cap','count>=32','count>32'),('trace-phase','phase>1','phase>2'),
                ('trace-name-sanitize',"name[i]='_'",'(void)c'),
                ('trace-entry-missing','santoni_gpu_dyld_trace_event(process,token,0,0);',';')]:
                self.assertEqual(helpers.count(old),1,label)
                execute(label,['-O2'],helper_body=helpers.replace(old,new),reject=True)
            record_path=os.environ.get('SANTONI_GPU_DYLD_RECORD')
            if record_path:
                record={'success':True,'rows':rows,'source_sha256':source['sha256'],
                    'inputs_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in INPUTS},
                    'positive_native_executions':3,'positive_contract_cases':195,'compiled_rejected_mutants':len(rows)-3,
                    'platform_copy_parse_responses_modeled':True,'identity_helper_response_modeled':True,
                    'actual_linked_kernel_wiring_verified':False,'hardware_verified':False}
                with Path(record_path).open('x') as stream:json.dump(record,stream,indent=2)

    def test_registration_retains_signature_policy_and_santoni_scope(self):
        with tempfile.TemporaryDirectory(prefix='santoni-dyld-registration-') as temporary:
            reconstruct(Path(temporary)/'source',targets=FILES)
            source=(Path(temporary)/'source'/FILES[0]).read_text()
            registration=source_function(source,'sweet_amfi_policy_register')
            for policy in ('sweet_amfi','sweet_sandbox','sweet_santoni_dyld'):
                self.assertIn('mac_policy_register(&'+policy+'_mac_conf, &'+policy+'_mac_handle, NULL)',registration)
            self.assertIn('#if defined(ARM64_BOARD_CONFIG_SANTONI)\n    error = mac_policy_register(&sweet_santoni_dyld_mac_conf',registration)
            self.assertIn('.mpc_name = "AMFI"',source)
            self.assertIn('.mpo_policy_syscall = sweet_santoni_dyld_syscall',source)
            self.assertIn('.mpc_name = "SWEET AMFI"',source)

if __name__=='__main__':unittest.main()
