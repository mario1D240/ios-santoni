"""Session delivery remains closed without new exact-kernel binary evidence."""
import json
import sys
import unittest
from unittest.mock import patch
from tests import test_santoni_gpu_boot_gates as fixture
from tools import check_santoni_gpu_kernel as checker
import santoni_gpu_boot as boot
SHA,RUN,KERNEL_SHA,RECIPE=fixture.SHA,fixture.RUN,fixture.KERNEL_SHA,fixture.RECIPE

class SessionGates(unittest.TestCase):
    def setUp(self):fixture.BootGates.setUp(self)
    def test_session_role_exact_options(self):
        for mode in range(4):
            for enabled in (False,True,0,1,None,'1'):
                good=type(enabled)is bool and (not enabled or mode==3)
                if good:boot.validate_probe_options(mode,False,False,session=enabled)
                else:
                    with self.assertRaises(ValueError):boot.validate_probe_options(mode,False,False,session=enabled)
        for key in ('zap_preflight','zap_scm_probe','zap_cache_preflight','stock_unsecure','stock_pixels','g3'):
            opts={name:False for name in ('zap_preflight','zap_scm_probe')};opts[key]=True
            with self.assertRaises(ValueError):boot.validate_probe_options(3,**opts,session=True)
        with patch.object(boot.subprocess,'check_output',return_value=RECIPE):
            power=boot.command_args(boot.command_line(SHA,1,visible_console=True))
            session=boot.command_args(boot.command_line(SHA,3,visible_console=True,session=True))
            self.assertEqual(session,{**power,'santonigpu':'3','santonigpu_stock':'1','santonigpu_pixels':'1',
                                     'santonigpu_submit':'1','santonigpu_session':'1'})
        for other in ('--g3-submit','--stock-pixels','--zap-scm-probe'):
            with patch.object(sys,'argv',['boot',SHA,'--mode','3','--g3-session',other]),patch('sys.stderr'):
                with self.assertRaises(SystemExit):boot.main()
    def test_old_binary_gate_never_authorizes_session(self):
        path=self.ci/'gpu-binary-audit.json';original=json.loads(path.read_text())
        previous={**original,boot.STOCK_BINARY_GATE:True,boot.PIXEL_BINARY_GATE:True,boot.G3_BINARY_GATE:True}
        for value in (None,False,1):
            path.write_text(json.dumps({**previous,boot.SESSION_BINARY_GATE:value}))
            with self.assertRaises(ValueError):boot.require_binary_audit(path,SHA,RUN,KERNEL_SHA,session=True)
        # Synthetic gate plumbing only; this is not a decoded session proof.
        path.write_text(json.dumps({**previous,boot.SESSION_BINARY_GATE:True}))
        boot.require_binary_audit(path,SHA,RUN,KERNEL_SHA,session=True)
        for commit,run,kernel in ((SHA,RUN+1,KERNEL_SHA),('b'*40,RUN,KERNEL_SHA),(SHA,RUN,'b'*64)):
            with self.assertRaises(ValueError):boot.require_binary_audit(path,commit,run,kernel,session=True)
    def test_actual_checker_fails_closed_for_new_session_symbols(self):
        self.assertIsNone(checker.audit_session({}, None,
            {'_sgpu_probe':{1},'_sgpu_g3_test':{2}}, checker))
        for name in ('_sgpu_session_start','_sgpu_session_execute','_sgpu_bootstrap'):
            with self.assertRaisesRegex(ValueError,'boundaries'):
                checker.audit_session({}, None, {name:{1}}, checker)
if __name__=='__main__':unittest.main()
