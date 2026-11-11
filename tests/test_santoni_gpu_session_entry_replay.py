"""Exact 3587443 decoded worker; mutations edit instructions, not native binaries."""
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import check_santoni_gpu_kernel as e
import santoni_gpu_launcher_audit as launcher
import santoni_gpu_session_replay as replay



class ActualEntry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        folder=ROOT/'out/ci-3587443'
        kernel=folder/'kernel/kernel.development.santoni'
        certificate=folder/'gpu-binary-audit.json'
        if not kernel.is_file() or not certificate.is_file():
            raise unittest.SkipTest('exact downloaded and audited3587443 kernel required')
        data=kernel.read_bytes();digest=hashlib.sha256(data).hexdigest()
        if digest!='0a4a9aab367dac92b8aa1d3b657f655b37dbfc0e188b14b8e19c54952a052fa3':
            raise ValueError('3587443 entry fixture kernel hash differs')
        report=json.loads(certificate.read_text());run=json.loads((folder/'run.json').read_text())
        if report.get('kernel_sha256')!=digest or report.get('commit')!=run.get('headSha') or \
                report.get('audit_scope')!='full' or run.get('status')!='completed' or \
                run.get('conclusion')!='success' or run.get('repository_private') is not True:
            raise ValueError('3587443 entry fixture audit identity differs')
        cls.names=e._symbols((folder/'kernel.symbols.txt').read_text());cls.image=e._Image(data)
        roots={'_sgpu_kernel_thread','_sgpu_user_options','_sgpu_user_test_options',
               '_sgpu_render_options','_sgpu_ui_options','_sgpu_graphics_options',
               '_santoni_gpu_graphics_worker_ready','_load_init_program'}
        roots.update(n for n in report['inspected_functions'] if
                     n.startswith(('_santoni_gpu_user_launch_','_sgpu_launch_','_launch_')))
        noreturn=e._stack_failure_terminal(cls.names)[0]|cls.names.get('_panic',set())|cls.names.get('_Assert',set())
        cls.codes={}
        for name in sorted(roots):
            if len(cls.names.get(name,()))!=1:raise ValueError('entry fixture root missing/ambiguous: '+name)
            text=(folder/(name.removeprefix('_')+'.asm')).read_text()
            code=e._Code(text,name,next(iter(cls.names[name])),noreturn=noreturn)
            bound=set()
            for line in text.splitlines():
                match=re.match(r'\s*([0-9a-f]+):\s+([0-9a-f]{8})\s',line)
                if match and int(match[1],16) in code.ins:
                    pc=int(match[1],16)
                    if cls.image.read(pc,4)!=int(match[2],16):raise ValueError('entry fixture decoded bytes differ')
                    bound.add(pc)
            if bound!=set(code.ins):raise ValueError('entry fixture has unbound decoded instructions')
            cls.codes[name]=code

    def check(self,codes):
        return replay.audit_entry(codes,self.image,self.names,e)

    def test_exact_worker_enters_only_successful_session_and_refuses_other_roles(self):
        cases=self.check(self.codes)
        self.assertEqual([c['return_paths'] for c in cases],[24,1,24,24])

    def test_deleted_validators_or_wrong_mode_cannot_borrow_disabled_results(self):
        for name in ('_santoni_gpu_user_launch_options_ok','_santoni_gpu_user_launch_worker_ready',
                     '_sgpu_user_options','_sgpu_user_test_options','_sgpu_render_options',
                     '_sgpu_ui_options','_sgpu_graphics_options'):
            for mutation in ('delete','wrong-mode'):
                with self.subTest(name=name,mutation=mutation):
                    codes=copy.deepcopy(self.codes);worker=codes['_sgpu_kernel_thread']
                    pc=worker.calls_to(self.names[name])[0]
                    if mutation=='delete':worker.ins[pc]=('nop',())
                    else:
                        before=max(address for address,(op,args) in worker.ins.items()
                                   if address<pc and args and args[0]=='w0' and op in ('ldr','mov'))
                        worker.ins[before]=('mov',('w0','#1'))
                    with self.assertRaises(ValueError):self.check(codes)

    def test_actual_graphics_release_reset_and_exact_startup_delay_cannot_be_removed(self):
        codes=copy.deepcopy(self.codes)
        parser=codes['_sgpu_graphics_options']
        pc=next(pc for pc,(op,args) in parser.ins.items() if op=='stlr')
        parser.ins[pc]=('nop',())
        with self.assertRaises(ValueError):self.check(codes)
        codes=copy.deepcopy(self.codes);worker=codes['_sgpu_kernel_thread']
        # Xcode inlines the40-second sleep into the worker. Mutate its real
        # clock interval, rather than assuming a retained direct wait call.
        wait=worker.calls_to(self.names['_clock_interval_to_deadline'])[0]
        before=max(pc for pc,(op,args) in worker.ins.items()
                   if pc<wait and args and args[0]=='w0' and op in ('mov','movk'))
        worker.ins[before]=('mov',('w0','#1'))
        with self.assertRaisesRegex(ValueError,'startup delay'):self.check(codes)

    def test_a_known_parser_name_cannot_approve_a_different_GPU_callee(self):
        codes=copy.deepcopy(self.codes);worker=codes['_sgpu_kernel_thread']
        pc=worker.calls_to(self.names['_sgpu_graphics_options'])[0]
        worker.ins[pc]=('bl',(hex(next(iter(self.names['_sgpu_graphics_new']))),))
        with self.assertRaisesRegex(ValueError,'unreviewed session worker callee'):self.check(codes)

    def test_launcher_exclusion_mode_scope_is_explicit_and_keeps_both_real_modes(self):
        for mode in (1,3):
            proof=launcher.default_off(self.codes,self.image,self.names,e,mode=mode)
            self.assertEqual(proof['scope'],f'mode{mode}; launcher option absent or explicitly zero')
            self.assertTrue(proof['no_kernel_storage_writes_or_DT_root_allocation_mount_exec_calls'])
            self.assertFalse(proof['enabled_launcher_certified'])
        for mode in (None,False,True,0,2,4,'3',3.0):
            with self.subTest(mode=mode),self.assertRaises(ValueError):
                launcher.default_off(self.codes,self.image,self.names,e,mode=mode)


if __name__=='__main__':unittest.main()
