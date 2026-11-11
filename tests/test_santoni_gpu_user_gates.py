"""New scalar-role plumbing; synthetic gates are not binary or hardware proof."""
import json
import subprocess
import sys
import unittest
from unittest.mock import patch
from tests import test_santoni_gpu_boot_gates as fixture
import santoni_gpu_boot as boot
from tools import check_santoni_gpu_kernel as checker

SHA,RUN,KERNEL_SHA,RECIPE=fixture.SHA,fixture.RUN,fixture.KERNEL_SHA,fixture.RECIPE
ROLES=('user','user_preflight')


class UserGates(unittest.TestCase):
    def setUp(self): fixture.BootGates.setUp(self)

    def report(self):
        return {'commit':SHA,'ci_run':RUN,'kernel_sha256':KERNEL_SHA,
                **{key:True for key in fixture.KEYS},
                **{key:True for key in (boot.STOCK_BINARY_GATE,boot.PIXEL_BINARY_GATE,
                    boot.G3_BINARY_GATE,boot.SESSION_BINARY_GATE,boot.USER_BINARY_GATE,
                    boot.USER_PREFLIGHT_BINARY_GATE)}}

    def write_report(self,report):
        path=self.ci/'gpu-binary-audit.json';path.write_text(json.dumps(report));return path

    def test_scalar_roles_require_boolean_mode3_and_are_exclusive(self):
        for role in ROLES:
            for mode in range(4):
                for enabled in (False,True,0,1,None,'1'):
                    if type(enabled)is bool and (not enabled or mode==3):
                        boot.validate_probe_options(mode,False,False,**{role:enabled})
                    else:
                        with self.assertRaises(ValueError):
                            boot.validate_probe_options(mode,False,False,**{role:enabled})
            for other in ('zap_preflight','zap_scm_probe','zap_cache_preflight',
                          'stock_unsecure','stock_pixels','g3','session',*ROLES):
                if other==role:continue
                args={'zap_preflight':False,'zap_scm_probe':False,role:True,other:True}
                with self.assertRaises(ValueError):boot.validate_probe_options(3,**args)

    def test_exact_dependencies_and_no_silent_automatic_preflight(self):
        with patch.object(boot.subprocess,'check_output',return_value=RECIPE):
            session=boot.command_args(boot.command_line(SHA,3,visible_console=True,session=True))
            manual=boot.command_args(boot.command_line(SHA,3,visible_console=True,user=True))
            automatic=boot.command_args(boot.command_line(SHA,3,visible_console=True,user_preflight=True))
        self.assertEqual(manual,{**session,'santonigpu_user':'1'})
        self.assertEqual(automatic,{**manual,'santonigpu_user_test':'1'})
        self.assertNotIn('santonigpu_zap',automatic)
        for role in ROLES:
            recipe=RECIPE.replace('CMDLINE="','CMDLINE="santonigpu_user_test=1 ')
            with patch.object(boot.subprocess,'check_output',return_value=recipe):
                with self.assertRaises(ValueError):boot.command_line(SHA,3,**{role:True})

    def test_old_session_certificate_and_partial_user_gates_reject(self):
        original=self.report()
        for role in ROLES:
            needed=(boot.USER_BINARY_GATE,boot.USER_PREFLIGHT_BINARY_GATE) if role=='user_preflight' else (boot.USER_BINARY_GATE,)
            for key in (*needed,boot.STOCK_BINARY_GATE,boot.PIXEL_BINARY_GATE,boot.G3_BINARY_GATE,boot.SESSION_BINARY_GATE):
                for value in (None,False,1):
                    path=self.write_report({**original,key:value})
                    with self.assertRaises(ValueError):
                        boot.require_binary_audit(path,SHA,RUN,KERNEL_SHA,mode=3,**{role:True})
            path=self.write_report(original)
            boot.require_binary_audit(path,SHA,RUN,KERNEL_SHA,mode=3,**{role:True})
            for identity in ((SHA,RUN+1,KERNEL_SHA),('b'*40,RUN,KERNEL_SHA),(SHA,RUN,'b'*64)):
                with self.assertRaises(ValueError):
                    boot.require_binary_audit(path,*identity,mode=3,**{role:True})
        path=self.write_report({**original,'scalar_user_client_present':True,boot.USER_BINARY_GATE:False})
        with self.assertRaises(ValueError):boot.require_binary_audit(path,SHA,RUN,KERNEL_SHA,mode=3)

    def test_mode1_control_needs_new_inactive_role_proof(self):
        control={**self.report(),'audit_scope':'mode1-control','permitted_modes':[1],
                 boot.CONTROL_BINARY_GATE:True,'scalar_user_client_present':True}
        for value in (None,False,1):
            path=self.write_report({**control,boot.USER_CONTROL_BINARY_GATE:value})
            with self.assertRaises(ValueError):boot.require_binary_audit(path,SHA,RUN,KERNEL_SHA,mode=1)
        path=self.write_report({**control,boot.USER_CONTROL_BINARY_GATE:True})
        boot.require_binary_audit(path,SHA,RUN,KERNEL_SHA,mode=1)
        for role in ROLES:
            with self.assertRaises(ValueError):
                boot.require_binary_audit(path,SHA,RUN,KERNEL_SHA,mode=1,**{role:True})

    def test_package_rejects_before_firmware_or_output_without_own_gates(self):
        with patch.object(boot,'ROOT',self.root),patch.object(boot,'BASE',self.base),\
             patch.object(boot.subprocess,'check_output',return_value=RECIPE),\
             patch.object(boot,'firmware_blob',side_effect=AssertionError('firmware reached')):
            for role in ROLES:
                report=self.report();report.pop(boot.USER_BINARY_GATE)
                self.write_report(report)
                with self.assertRaises(ValueError):boot.package(SHA,3,self.root/'absent-firmware',**{role:True})
                self.write_report(self.report())
                with self.assertRaisesRegex(ValueError,'mode-1 hardware'):
                    boot.package(SHA,3,self.root/'absent-firmware',**{role:True})
                name='user-client' if role=='user' else 'user-preflight'
                self.assertFalse((self.ci/('gpu-'+name+'-4core')).exists())

    def test_new_roles_fit_existing_recipe_and_reject_shim_truncation(self):
        existing=subprocess.check_output(['git','rev-parse','HEAD'],cwd=boot.ROOT,text=True).strip()
        for role in ROLES:
            # Check the committed current recipe, including in a shallow CI checkout.
            # This constructs arguments only; it does not package or accept a kernel.
            line=boot.command_line(existing,3,visible_console=True,**{role:True})
            self.assertLess(len(line.encode()),608)
        with patch.object(boot.subprocess,'check_output',return_value=RECIPE):
            count=len(boot.command_line(SHA,3,user_preflight=True))
        for length in (607,608):
            padding='pad='+'x'*(length-count-5)+' '
            recipe=RECIPE.replace('CMDLINE="','CMDLINE="'+padding)
            with patch.object(boot.subprocess,'check_output',return_value=recipe):
                if length==607:
                    self.assertEqual(len(boot.command_line(SHA,3,user_preflight=True)),607)
                else:
                    with self.assertRaisesRegex(ValueError,'truncated'):
                        boot.command_line(SHA,3,user_preflight=True)

    def test_cli_does_not_combine_manual_automatic_or_prior_roles(self):
        for role in ('--user-client','--user-preflight'):
            for other in ('--g3-session','--zap-scm-probe','--user-client','--user-preflight'):
                if other==role:continue
                with patch.object(sys,'argv',['boot',SHA,'--mode','3',role,other]),patch('sys.stderr'):
                    with self.assertRaises(SystemExit):boot.main()

    def test_auditor_closes_all_direct_and_cdevsw_boundaries(self):
        self.assertEqual(checker._scalar_user_helpers({'_sgpu_probe':{1}}),())
        required=(*checker.SCALAR_USER_HELPERS,*checker.SCALAR_USER_STORAGE)
        names={name:{100+index*16} for index,name in enumerate(required)}
        self.assertEqual(checker._scalar_user_helpers(names),checker.SCALAR_USER_HELPERS)
        for missing in required:
            reduced={name:address for name,address in names.items() if name!=missing}
            with self.assertRaisesRegex(ValueError,'boundaries'):checker._scalar_user_helpers(reduced)
        with self.assertRaisesRegex(ValueError,'boundaries'):
            checker._scalar_user_helpers({**names,'_sgpu_user_unknown':{9999}})
        with self.assertRaisesRegex(ValueError,'boundaries'):
            checker._scalar_user_helpers({**names,required[0]:{100,200}})
        with self.assertRaisesRegex(ValueError,'alias'):
            checker._scalar_user_helpers({**names,required[1]:names[required[0]]})


if __name__=='__main__':unittest.main()
