"""New audit startup/cache contracts; synthetic services never certify a kernel."""
import ast
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from types import FunctionType
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import check_santoni_gpu_kernel as auditor


class ReachedImageConsumer(Exception):
    pass


class KernelImageOrder(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sgpu-audit-image-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.commit = 'a' * 40
        self.folder = self.root / 'out' / ('ci-' + self.commit[:7])
        kernel = self.folder / 'kernel' / 'kernel.development.santoni'
        kernel.parent.mkdir(parents=True)
        self.payload = b'synthetic startup fixture; not a Mach-O kernel'
        self.digest = hashlib.sha256(self.payload).hexdigest()
        kernel.write_bytes(self.payload)
        (kernel.parent / 'SHA256SUMS').write_text(self.digest + '  ' + kernel.name + '\n')
        (self.folder / 'run.json').write_text(json.dumps({'headSha': self.commit,
            'status': 'completed', 'conclusion': 'success', 'repository_private': True, 'databaseId': 7}))
        for name in ('santoni_gpu_mockfs_vfs_audit.py', 'santoni_gpu_binary_model.py'):
            target = self.root / 'tools' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / 'tools' / name).read_bytes())
        tree = ast.parse(Path(auditor.__file__).read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'audit')
        required = next(n.value for n in function.body if isinstance(n, ast.Assign) and
            any(isinstance(t, ast.Name) and t.id == 'required' for t in n.targets))
        self.names = {name: {0x1000 + 16 * i} for i, name in
            enumerate((*ast.literal_eval(required), '_IOKitBSDInit'))}
        self.images = []
        self.provider_calls = []

    def image(self, data):
        self.assertEqual(data, self.payload)
        instance = SimpleNamespace(data=data)
        self.images.append(instance)
        return instance

    def provider(self, folder, image, names, engine, **kwargs):
        self.assertIs(image, self.images[-1])
        self.assertEqual(folder, self.folder)
        self.assertIs(names, self.names)
        self.assertEqual(kwargs, {})  # provider must decode/bind its own VFS roots
        self.provider_calls.append(image)
        return {'success': True, 'enabled_LP64_mount_dispatch_checked': True,
                'kernel_sha256': self.digest, 'registration': {'vfs_flags': '0x104'},
                'hardware_verified': False, 'cases': [{'case': name} for name in (
                    'linked64', 'linked32', 'ready64', 'callee-error', 'wrong-bit',
                    'missing-callback', 'dead-mount')]}

    def invoke(self, launcher=True, function=None):
        def consume(worker, image, names, local_names):
            self.assertIs(image, self.images[-1])
            raise ReachedImageConsumer
        with ExitStack() as stack:
            changes = {'ROOT': self.root, '_Image': self.image,
                '_symbols': lambda *args, **kwargs: self.names,
                '_stack_failure_terminal': lambda names: (set(), None, None),
                '_Code': lambda *args, **kwargs: object(), '_scalar_user_helpers': lambda names: (),
                '_scm_smc_scope': lambda codes: None, '_ops_wiring': consume,
                '_SCM_HELPERS': (), 'CACHE_HELPERS': (), 'STOCK_HELPERS': (),
                'PIXEL_HELPERS': (), 'G3_HELPERS': ()}
            for name, value in changes.items():
                stack.enter_context(patch.object(auditor, name, value))
            stack.enter_context(patch.object(auditor.subprocess, 'check_output', return_value=''))
            stack.enter_context(patch('santoni_gpu_launcher_audit.load_launcher', return_value=launcher))
            stack.enter_context(patch('santoni_gpu_mockfs_vfs_audit.audit', side_effect=self.provider))
            (function or auditor.audit)(self.commit, mode1_control=True)

    def test_launcher_provider_receives_one_checked_image_and_decodes_its_own_roots(self):
        with self.assertRaises(ReachedImageConsumer): self.invoke()
        self.assertEqual(len(self.images), 1)
        self.assertEqual(len(self.provider_calls), 1)
        self.assertEqual(len(list(self.folder.glob('launcher-mount-provider-*.json'))), 1)

    def test_absent_launcher_still_initializes_the_image_before_ops_wiring(self):
        with self.assertRaises(ReachedImageConsumer): self.invoke(launcher=False)
        self.assertEqual(len(self.images), 1)
        self.assertEqual(self.provider_calls, [])

    def test_bad_checksum_refuses_before_constructing_image_or_provider(self):
        (self.folder / 'kernel' / 'SHA256SUMS').write_text('0' * 64 + '  kernel.development.santoni\n')
        with self.assertRaisesRegex(ValueError, 'checksum'): self.invoke()
        self.assertEqual(self.images, [])
        self.assertEqual(self.provider_calls, [])

    def test_completed_provider_is_consumed_and_untyped_gate_refuses_without_replay(self):
        with self.assertRaises(ReachedImageConsumer): self.invoke()
        with self.assertRaises(ReachedImageConsumer): self.invoke()
        self.assertEqual(len(self.provider_calls), 1)
        record = next(self.folder.glob('launcher-mount-provider-*.json'))
        saved = json.loads(record.read_text())
        saved['result']['enabled_LP64_mount_dispatch_checked'] = 1
        record.write_text(json.dumps(saved))
        with self.assertRaisesRegex(ValueError, 'component differs'): self.invoke()
        self.assertEqual(len(self.provider_calls), 1)

    def test_compiling_late_image_mutant_is_rejected_before_provider(self):
        tree = ast.parse(Path(auditor.__file__).read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'audit')
        assignment = next(n for n in function.body if isinstance(n, ast.Assign) and
            any(isinstance(t, ast.Name) and t.id == 'image' for t in n.targets))
        function.body.remove(assignment)
        function.body.append(assignment)
        module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
        namespace = dict(auditor.__dict__)
        exec(compile(module, '<late-image-mutant>', 'exec'), namespace)
        compiled = namespace['audit']
        # Use the real auditor globals so invoke() injects the same services.
        mutant = FunctionType(compiled.__code__, auditor.__dict__, compiled.__name__, compiled.__defaults__)
        with self.assertRaises(UnboundLocalError): self.invoke(function=mutant)
        self.assertEqual(self.images, [])
        self.assertEqual(self.provider_calls, [])


if __name__ == '__main__':
    unittest.main()
