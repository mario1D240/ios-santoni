"""Session certificates require every component, including launcher exclusion."""
from contextlib import ExitStack
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import check_santoni_gpu_kernel as decoder
import santoni_gpu_control_audit as control
import santoni_gpu_session_audit as session
from tests.test_santoni_gpu_pixel_audit import decoded


class SessionComposition(unittest.TestCase):
    def components(self, stack):
        stack.enter_context(patch.object(session,'session_identity',return_value={'present':True}))
        for name in ('session_start_storage','session_bootstrap_storage','session_lock_wiring'):
            stack.enter_context(patch.object(session,name,return_value={'component':name}))
        for name in ('audit_queue','audit_core','audit_worker','audit_producer','audit_entry','audit_clock','audit_cold_arena'):
            stack.enter_context(patch('santoni_gpu_session_replay.'+name,return_value={'component':name}))
        return {n:object() for n in ('_sgpu_session_start','_sgpu_session_loop','_sgpu_session_producer')}

    def test_exact_launcher_component_is_forwarded_into_control_isolation(self):
        launcher={'success':True,'scope':'mode1; launcher option absent or explicitly zero',
                  'return_values':{'_santoni_gpu_user_launch_options_ok':1,
                                   '_santoni_gpu_user_launch_worker_ready':1}}
        with ExitStack() as stack:
            codes=self.components(stack)
            def check(codes_,image,names,e,launcher=None):
                self.assertIs(launcher,proof)
                return {'launcher_default_off':launcher}
            proof=launcher
            checked=stack.enter_context(patch.object(control,'audit_control',side_effect=check))
            result=session.audit_session(codes,object(),{},decoder,launcher=launcher)
            checked.assert_called_once()
            self.assertIs(result['control_isolation']['launcher_default_off'],launcher)
            self.assertFalse(result['hardware_or_scheduler_verified'])

    def test_control_component_failure_cannot_be_ignored_or_replaced(self):
        with ExitStack() as stack:
            codes=self.components(stack)
            stack.enter_context(patch.object(control,'audit_control',side_effect=ValueError('launcher exclusion refused')))
            with self.assertRaisesRegex(ValueError,'launcher exclusion refused'):
                session.audit_session(codes,object(),{},decoder,launcher=None)

    def test_old_non_session_kernel_does_not_gain_a_certificate(self):
        with patch.object(session,'session_identity',return_value=None),patch.object(control,'audit_control') as checked:
            self.assertIsNone(session.audit_session({},object(),{},decoder,launcher={'success':True}))
            checked.assert_not_called()

    def test_actual_worker_guard_still_refuses_missing_or_invalid_launcher_proofs(self):
        class Image:
            def read(self,address,size):return None
        names={n:{0x2000+i*0x100} for i,n in enumerate(('_sg','_sgpu_probe','_sgpu_stock_options',
               '_sgpu_pixel_options','_sgpu_g3_options','_sgpu_session_options',
               '_santoni_gpu_user_launch_options_ok','_santoni_gpu_user_launch_worker_ready'))}
        code=decoded(['ret'],'_sgpu_kernel_thread')
        for proof in (None,{}, {'success':False}, {'success':True,'scope':'mode3'},
                      {'success':True,'scope':'mode1; launcher option absent or explicitly zero',
                       'return_values':{'_santoni_gpu_user_launch_options_ok':1,
                                        '_santoni_gpu_user_launch_worker_ready':0}}):
            with self.subTest(proof=proof),self.assertRaisesRegex(ValueError,'launcher exclusion component'):
                control.worker_control(code,Image(),names,decoder,launcher=proof)


if __name__=='__main__':unittest.main()
