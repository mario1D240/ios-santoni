"""Explicit exclusion scopes cannot silently become enabled-client evidence."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from santoni_gpu_launcher_audit import default_off
from santoni_gpu_user_audit import scalar_option_wiring


class ExclusionScopes(unittest.TestCase):
    def test_launcher_mode_scope_rejects_implicit_or_unreviewed_modes(self):
        for mode in (None,False,True,0,2,4,'3',3.0):
            with self.subTest(mode=mode),self.assertRaises(ValueError):
                default_off({},None,{},None,mode=mode)

    def test_scalar_scope_requires_a_boolean(self):
        for scope in (None,0,1,'true',[],{}):
            with self.subTest(scope=scope),self.assertRaises(ValueError):
                scalar_option_wiring(None,None,{},None,None,disabled_only=scope)


if __name__=='__main__':unittest.main()
