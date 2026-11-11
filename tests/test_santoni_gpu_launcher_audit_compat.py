"""New evidence-reuse contract; changed shared decoder code must fail closed."""
import hashlib
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import santoni_gpu_audit_compat as compat


class AuditCompatibility(unittest.TestCase):
    def test_only_orchestration_can_change(self):
        source = 'import x\nLIMIT=1\nclass Decoder:\n def decode(self): return LIMIT\ndef audit(): return 0\n'
        original = compat.shared_ast(source)
        self.assertEqual(original, compat.shared_ast(source.replace('audit(): return 0', 'audit(): return 1')))
        for changed in (source.replace('LIMIT=1', 'LIMIT=2'), source.replace('return LIMIT', 'return 0'),
                        source.replace('import x', 'import y'), source + '\ndef helper(): return 0\n'):
            self.assertNotEqual(original, compat.shared_ast(changed))
        with self.assertRaises(ValueError):
            compat.shared_ast(source + '\ndef audit(): return 2\n')

    def test_exact_retained_decoder_dependency(self):
        old = subprocess.check_output(['git', 'show', compat.PRE_LAUNCHER + ':' + compat.KERNEL_AUDITOR], cwd=ROOT)
        self.assertTrue(compat.kernel_auditor_compatible(hashlib.sha256(old).hexdigest()))
        self.assertFalse(compat.kernel_auditor_compatible('0' * 64))


if __name__ == '__main__':
    unittest.main()
