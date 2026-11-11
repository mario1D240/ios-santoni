"""Exercise the uploader with fake curl; never upload host files to GoFile."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools/gofile-upload.sh'
FAKE_CURL = r'''
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['CURL_CALLS'], 'a') as log:
    log.write(json.dumps(args) + '\n')
servers = args[-1] == 'https://api.gofile.io/servers'
kind = 'SERVERS' if servers else 'UPLOAD'
sys.stdout.write(os.environ[kind + '_JSON'])
raise SystemExit(int(os.environ.get(kind + '_EXIT', '0')))
'''


class GoFileUploadTests(unittest.TestCase):
    def setUp(self):
        preferred = Path('/data/data/com.termux/files/usr/tmp/opencode')
        self.temp = tempfile.TemporaryDirectory(prefix='gofile-test-',
            dir=preferred if preferred.is_dir() else None)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        curl = self.root / 'curl'
        curl.write_text('#!' + sys.executable + '\n' + FAKE_CURL)
        curl.chmod(0o700)
        self.artifact = self.root / 'kernel with spaces.tgz'
        self.artifact.write_bytes(b'fake CI artifact, no kernel or device data\n')
        self.calls = self.root / 'calls.jsonl'
        self.summary, self.output = self.root / 'summary.md', self.root / 'outputs'
        self.env = {**os.environ, 'PATH': str(self.root) + os.pathsep + os.environ['PATH'],
            'CURL_CALLS': str(self.calls),
            'SERVERS_JSON': json.dumps({'status': 'ok', 'data': {'servers': [{'name': 'store1'}]}}),
            'UPLOAD_JSON': json.dumps({'status': 'ok', 'data': {
                'downloadPage': 'https://gofile.io/d/abc123', 'guestToken': 'DO-NOT-PRINT'}}),
            'GITHUB_STEP_SUMMARY': str(self.summary), 'GITHUB_OUTPUT': str(self.output),
            'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2'}

    def run_upload(self, args=None, **env):
        return subprocess.run(['bash', str(SCRIPT), *(args if args is not None else [str(self.artifact)])],
            env={**self.env, **env}, capture_output=True, text=True, timeout=15)

    def test_success_records_link_hash_and_exact_run_without_guest_token(self):
        result = self.run_upload()
        self.assertEqual(result.returncode, 0, result.stderr)
        digest = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self.assertIn('https://gofile.io/d/abc123', result.stdout)
        self.assertIn(digest, result.stdout)
        self.assertEqual(self.output.read_text(), f'url=https://gofile.io/d/abc123\nsha256={digest}\n')
        self.assertIn('Commit: `' + 'a' * 40 + '` · Run: `123` · Attempt: `2`', self.summary.read_text())
        self.assertNotIn('DO-NOT-PRINT', result.stdout + result.stderr + self.summary.read_text())
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1][-1], 'https://store1.gofile.io/uploadFile')
        self.assertEqual(calls[1][calls[1].index('--form') + 1], f'file=@"{self.artifact}"')
        for call in calls:
            self.assertIn('--fail', call)
            self.assertIn('--max-time', call)
            self.assertIn('--connect-timeout', call)
        self.assertNotIn('--retry', calls[1])  # avoid duplicate anonymous uploads

    def test_file_argument_is_required_and_checked_before_network(self):
        empty = self.root / 'empty'; empty.touch()
        for args in ([], ['missing'], [str(empty)], [str(self.root)], [str(self.artifact), 'extra']):
            with self.subTest(args=args):
                self.assertNotEqual(self.run_upload(args).returncode, 0)
                self.assertFalse(self.calls.exists())

    def test_malformed_failed_or_untrusted_server_reply_stops_before_upload(self):
        replies = ('not json', '{}', '{"status":"error"}',
            json.dumps({'status': 'ok', 'data': {'servers': []}}),
            *(json.dumps({'status': 'ok', 'data': {'servers': [{'name': server}]}})
              for server in (None, '', 'store1.evil.example', '../other', 'store1/path')))
        for reply in replies:
            with self.subTest(reply=reply):
                if self.calls.exists(): self.calls.unlink()
                result = self.run_upload(SERVERS_JSON=reply)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(self.calls.read_text().splitlines()), 1)
                self.assertFalse(self.summary.exists())
                self.assertFalse(self.output.exists())

    def test_transport_and_upload_service_errors_never_publish_success(self):
        cases = [{'SERVERS_EXIT': '22'}, {'UPLOAD_EXIT': '22'}, {'UPLOAD_EXIT': '28'},
                 {'UPLOAD_JSON': 'not json'}, {'UPLOAD_JSON': '{"status":"error"}'},
                 {'UPLOAD_JSON': '{"status":"ok","data":{}}'}]
        cases += [{'UPLOAD_JSON': json.dumps({'status': 'ok', 'data': {'downloadPage': link}})}
                  for link in (None, 'null', 'http://gofile.io/d/id', 'https://evil.example/d/id')]
        for changes in cases:
            with self.subTest(changes=changes):
                result = self.run_upload(**changes)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.summary.exists())
                self.assertFalse(self.output.exists())
                self.assertNotIn('SHA256:', result.stdout)

    def test_quotes_and_backslashes_are_escaped_for_curl_multipart(self):
        artifact = self.root / 'space "quoted" \\ semicolon;.tgz'
        artifact.write_bytes(b'test')
        result = self.run_upload([str(artifact)])
        self.assertEqual(result.returncode, 0, result.stderr)
        args = json.loads(self.calls.read_text().splitlines()[1])
        escaped = str(artifact).replace('\\', '\\\\').replace('"', '\\"')
        self.assertEqual(args[args.index('--form') + 1], f'file=@"{escaped}"')


if __name__ == '__main__':
    unittest.main()
