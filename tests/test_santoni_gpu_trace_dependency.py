"""New traced-probe dependency bridge; completed linked scenarios never replay."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import santoni_gpu_audit_compat as compat


def source(audit_value, decoder_value=53):
    return (f'class Decoder:\n    def run(self):\n        return {decoder_value}\n\n'
            f'def audit(commit):\n    return {audit_value}\n').encode()


class TraceDependency(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.current = self.root / compat.KERNEL_AUDITOR
        self.current.parent.mkdir()
        self.current.write_bytes(source(2))
        self.origins = {compat.PRE_LAUNCHER: source(0), compat.TRACE_PROBE: source(1)}
        self.root_patch = patch.object(compat, 'ROOT', self.root)
        self.root_patch.start(); self.addCleanup(self.root_patch.stop)
        def git_show(command, cwd):
            self.assertEqual(cwd, self.root)
            self.assertEqual(command[:2], ['git', 'show'])
            revision, path = command[2].split(':', 1)
            self.assertEqual(path, compat.KERNEL_AUDITOR)
            self.assertIn(revision, self.origins, 'unreviewed source revisions cannot become origins')
            return self.origins[revision]
        self.git_patch = patch.object(compat.subprocess, 'check_output', side_effect=git_show)
        self.git = self.git_patch.start(); self.addCleanup(self.git_patch.stop)

    def test_exact_trace_origin_accepts_only_orchestration_changes(self):
        previous = hashlib.sha256(self.origins[compat.TRACE_PROBE]).hexdigest()
        self.assertIs(compat.kernel_auditor_compatible(previous), True)

    def test_decoder_change_rejects_even_with_the_correct_trace_origin_hash(self):
        previous = hashlib.sha256(self.origins[compat.TRACE_PROBE]).hexdigest()
        self.current.write_bytes(source(2, 54))
        self.assertIs(compat.kernel_auditor_compatible(previous), False)

    def test_unknown_same_ast_source_hash_is_not_an_admitted_origin(self):
        previous = hashlib.sha256(source(3)).hexdigest()
        self.assertIs(compat.kernel_auditor_compatible(previous), False)
        self.assertEqual(self.git.call_count, 2)

    def test_modified_committed_origin_bytes_cannot_satisfy_the_recorded_hash(self):
        previous = hashlib.sha256(self.origins[compat.TRACE_PROBE]).hexdigest()
        self.origins[compat.TRACE_PROBE] += b'\n'
        self.assertIs(compat.kernel_auditor_compatible(previous), False)

    def test_ambiguous_or_missing_audit_scope_rejects(self):
        previous = hashlib.sha256(self.origins[compat.TRACE_PROBE]).hexdigest()
        for contents in (b'class Decoder: pass\n', source(2) + b'def audit(commit): return 3\n'):
            self.current.write_bytes(contents)
            with self.assertRaises(ValueError): compat.kernel_auditor_compatible(previous)


if __name__ == '__main__':
    unittest.main()
