"""Actual root setup against an isolated filesystem; no mounted image is edited."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / 'tools/sweet-root-tweaks.py'
SPEC = importlib.util.spec_from_file_location('sweet_root_tweaks', SOURCE)
tweaks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tweaks)


class ExtensionSetup(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        # The host fixture performs real reads/writes/chmod. Ownership calls are
        # captured because Termux cannot chown to the iOS root/mobile accounts.
        ownership = mock.patch.object(tweaks.os, 'chown')
        self.chown = ownership.start()
        self.addCleanup(ownership.stop)
        self.output = io.StringIO()
        self.redirect = contextlib.redirect_stdout(self.output)
        self.redirect.__enter__()
        self.addCleanup(self.redirect.__exit__, None, None, None)
        self.pref = self.root / 'private/var/mobile/Library/Preferences/com.apple.migration.plist'
        self.flag = self.root / 'private/var/preferences/FeatureFlags/Domain/ExtensionKit.plist'
        self.sentinel = self.root / 'private/var/datamigrator/migrate'

    def write(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(plistlib.dumps(value, fmt=plistlib.FMT_BINARY))

    def test_first_boot_has_real_extension_policy_and_mobile_migration_request(self):
        tweaks.feature_flags(str(self.root))
        tweaks.migration(str(self.root))
        self.assertEqual(plistlib.loads(self.flag.read_bytes()), {
            'enforce_xpc_cache_code_signing': {'Enabled': False}})
        self.assertTrue(self.flag.read_bytes().startswith(b'<?xml'))
        self.assertEqual(self.sentinel.read_bytes(), b'')
        self.assertFalse(self.pref.exists())
        for path, uid in ((self.flag, 0), (self.sentinel, 501)):
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
            self.chown.assert_any_call(str(path), uid, uid)

    def test_old_synthetic_completion_is_removed_without_losing_other_data_or_inode(self):
        self.write(self.pref, {'LastSystemVersion': tweaks.BUILD,
            'DMUserDataDisposition': {'SyntheticDidUpgrade': False, 'buildVersion': tweaks.BUILD},
            'UserOwnedState': {'keep': [1, 2, 3]}})
        os.chmod(self.pref, 0o640)
        before = self.pref.stat()
        # A descriptor opened before the edit must still see the updated data;
        # this rejects unlink/replace implementations on hosts that cannot make
        # hard links, without claiming an HFS hard-link execution here.
        with self.pref.open('rb') as backing:
            tweaks.migration(str(self.root))
            self.assertEqual(plistlib.loads(backing.read()), {'UserOwnedState': {'keep': [1, 2, 3]}})
        self.assertEqual(self.pref.stat().st_ino, before.st_ino)
        self.assertEqual(self.pref.stat().st_mode & 0o777, 0o640)
        self.chown.assert_any_call(str(self.pref), before.st_uid, before.st_gid)
        self.assertTrue(self.sentinel.exists())

    def test_genuine_or_foreign_migration_state_is_left_byte_identical(self):
        for state in (
                {'LastSystemVersion': tweaks.BUILD, 'CompletedSteps': ['extensions']},
                {'LastSystemVersion': 'other-build', 'DMUserDataDisposition': {
                    'SyntheticDidUpgrade': False, 'buildVersion': 'other-build'}},
                {'LastSystemVersion': tweaks.BUILD, 'DMUserDataDisposition': {
                    'SyntheticDidUpgrade': True, 'buildVersion': tweaks.BUILD}},
                {'LastSystemVersion': tweaks.BUILD, 'DMUserDataDisposition': {
                    'SyntheticDidUpgrade': 0, 'buildVersion': tweaks.BUILD}},
                {'LastSystemVersion': tweaks.BUILD, 'DMUserDataDisposition': {
                    'SyntheticDidUpgrade': 0.0, 'buildVersion': tweaks.BUILD}},
                {'LastSystemVersion': tweaks.BUILD, 'DMUserDataDisposition': {
                    'SyntheticDidUpgrade': False, 'buildVersion': tweaks.BUILD, 'RealState': True}}):
            with self.subTest(state=state):
                self.write(self.pref, state)
                before = self.pref.read_bytes()
                tweaks.migration(str(self.root))
                self.assertEqual(self.pref.read_bytes(), before)
                self.assertFalse(self.sentinel.exists())

    def test_repeated_setup_preserves_existing_request_and_other_feature_fields(self):
        self.write(self.flag, {'OtherFeature': {'Enabled': True},
            'enforce_xpc_cache_code_signing': {'Enabled': True, 'ExtraSetting': 'keep'}})
        self.sentinel.parent.mkdir(parents=True)
        self.sentinel.write_bytes(b'preserved marker')
        os.chmod(self.sentinel, 0o600)
        before = self.sentinel.stat()
        for _ in range(2):
            tweaks.feature_flags(str(self.root))
            tweaks.migration(str(self.root))
        self.assertEqual(plistlib.loads(self.flag.read_bytes()), {'OtherFeature': {'Enabled': True},
            'enforce_xpc_cache_code_signing': {'Enabled': False, 'ExtraSetting': 'keep'}})
        self.assertEqual(self.sentinel.read_bytes(), b'preserved marker')
        self.assertEqual(self.sentinel.stat().st_ino, before.st_ino)
        self.assertEqual(self.sentinel.stat().st_mode & 0o777, 0o600)

    def test_malformed_existing_state_fails_before_rewriting_it(self):
        for path, value, action in ((self.flag, [], tweaks.feature_flags),
                (self.flag, {'enforce_xpc_cache_code_signing': True}, tweaks.feature_flags),
                (self.pref, [], tweaks.migration)):
            with self.subTest(path=path, value=value):
                self.write(path, value)
                before = path.read_bytes()
                with self.assertRaises(ValueError):
                    action(str(self.root))
                self.assertEqual(path.read_bytes(), before)

    def test_actual_main_preserves_migration_and_does_not_request_it_by_default(self):
        self.write(self.pref, {'LastSystemVersion': tweaks.BUILD,
            'DMUserDataDisposition': {'SyntheticDidUpgrade': False, 'buildVersion': tweaks.BUILD}})
        before = self.pref.read_bytes()
        (self.root / 'System/Library/xpc').mkdir(parents=True)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(tweaks.sys, 'argv', ['sweet-root-tweaks.py', str(self.root)]))
            for name in ('launchd', 'containers', 'activation', 'audio', 'merge_pref'):
                stack.enter_context(mock.patch.object(tweaks, name))
            tweaks.main()
        self.assertFalse(self.sentinel.exists())
        self.assertTrue(self.flag.exists())
        self.assertEqual(self.pref.read_bytes(), before)

    def test_actual_main_migration_requires_explicit_option(self):
        (self.root / 'System/Library/xpc').mkdir(parents=True)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(tweaks.sys, 'argv',
                ['sweet-root-tweaks.py', str(self.root), '--migrate-extensions']))
            for name in ('launchd', 'containers', 'activation', 'audio', 'merge_pref'):
                stack.enter_context(mock.patch.object(tweaks, name))
            tweaks.main()
        self.assertTrue(self.sentinel.exists())
        self.assertFalse(self.pref.exists())


if __name__ == '__main__':
    unittest.main()
