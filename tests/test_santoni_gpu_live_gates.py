"""No full-buffer role or foreign-kernel receipt can bypass the packager."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import santoni_gpu_boot as boot
from santoni_gpu_live_gate import CHECKS, CP_CHECKS, require_audit
from tests.test_santoni_gpu_boot_gates import RECIPE


class LiveGates(unittest.TestCase):
    def test_role_requires_mode3_and_excludes_all_other_diagnostics(self):
        args = (False, False, False, False, False, False, False, False, False, False)
        for mode in (0, 1, 2):
            with self.assertRaises(ValueError): boot.validate_probe_options(mode, *args, render_test=True)
        boot.validate_probe_options(3, *args, render_test=True)
        for name in ('zap_preflight','zap_scm_probe','zap_cache_preflight','stock_unsecure',
                     'stock_pixels','g3','session','user','user_preflight','user_exec'):
            values = dict(zip(('zap_preflight','zap_scm_probe','zap_cache_preflight','stock_unsecure',
                               'stock_pixels','g3','session','user','user_preflight','user_exec'), args))
            values[name] = True
            with self.assertRaises(ValueError): boot.validate_probe_options(3, **values, render_test=True)

    def test_render_recipe_preserves_fallback_and_disables_scalar_launcher(self):
        with patch.object(boot.subprocess, 'check_output', return_value=RECIPE):
            line = boot.command_line('a'*40, 3, render_test=True, remoted_platform=True)
        args = boot.command_args(line)
        self.assertEqual({n: args.get(n) for n in ('cpus','sweethidtest','santonigpu_render',
            'santonigpu_stock','santonigpu_pixels','santonigpu_submit','santonigpu_session')},
            {'cpus':'4','sweethidtest':'0','santonigpu_render':'1','santonigpu_stock':'1',
             'santonigpu_pixels':'1','santonigpu_submit':'1','santonigpu_session':'1'})
        for name in ('santonigpu_user','santonigpu_user_exec','santonigpu_zap','santonigpu_scm'):
            self.assertNotIn(name, args)

    def test_missing_foreign_or_incomplete_actual_kernel_proof_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(ValueError): require_audit(root, 'a'*40, 7, 'b'*64, True, True)
            record = {'success':True,'hardware_verified':False,'commit':'a'*40,'ci_run':7,
                      'kernel_sha256':'b'*64,'cases':23,**{name:True for name in CHECKS}}
            path = root / 'live-binary-audit.json'; path.write_text(json.dumps(record))
            require_audit(root, 'a'*40, 7, 'b'*64, True, True)
            for change in ({'kernel_sha256':'c'*64},{'cases':22},{'hardware_verified':True},
                           {CHECKS[0]:False}):
                path.write_text(json.dumps({**record,**change}))
                with self.assertRaises(ValueError): require_audit(root, 'a'*40, 7, 'b'*64, True, True)

    def test_new_CP_helper_requires_all_37_cases_and_exact_response_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path=root/'live-binary-audit.json'
            record={'success':True,'hardware_verified':False,'commit':'a'*40,'ci_run':7,
                    'kernel_sha256':'b'*64,'cases':37,**{name:True for name in (*CHECKS,*CP_CHECKS)},
                    'CP_readback_mask':'0xfffffff3','CP_response_bits':'0x0000000c'}
            path.write_text(json.dumps(record))
            require_audit(root,'a'*40,7,'b'*64,True,True,cp_readback_v2=True)
            for change in ({'cases':23},{'CP_readback_mask':'0x00000003'},
                           {'CP_response_bits':'0x000000fc'},*({name:False} for name in CP_CHECKS)):
                path.write_text(json.dumps({**record,**change}))
                with self.assertRaises(ValueError): require_audit(root,'a'*40,7,'b'*64,True,True,cp_readback_v2=True)


if __name__ == '__main__': unittest.main()
