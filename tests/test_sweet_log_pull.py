#!/usr/bin/env python3
"""Run log extraction against a fake read-only ADB, never a connected device."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ADB = '''#!/usr/bin/env python3
import os,sys,struct,json
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['ADB_CALLS'], 'a') as log:
    log.write(json.dumps(args) + '\\n')
partition = os.environ['ADB_PARTITION']
if args[0] == 'shell':
    if len(args) > 1 and args[1] == 'blockdev':
        print(2000 * 4096)
    else:
        print(partition)
elif args[0] == 'exec-out':
    assert args[1].startswith('dd if=') and ' of=' not in args[1]
    text = b'LOG-PULL-TEST\\n'
    if partition.endswith('/system'):
        assert 'bs=512 count=8193' in args[1] and 'skip=' not in args[1]
        header = struct.pack('<12sIIQQ', b'SANTONILOG1', 1, 4 << 20, len(text), 1)
        page = 512
    else:
        assert partition.endswith('/userdata')
        assert 'bs=4096 skip=975 count=1025' in args[1]
        header = struct.pack('<8sIIQQ', b'SWEETLOG', 1, 4 << 20, len(text), 1)
        page = 4096
    blob = header.ljust(page, b'\\0') + text.ljust(4 << 20, b'\\0')
    if os.environ.get('ADB_SHORT') == '1': blob = blob[:page + 10]
    sys.stdout.buffer.write(blob)
else: raise SystemExit(2)
'''


def main():
    preferred = Path('/data/data/com.termux/files/usr/tmp/opencode')
    with tempfile.TemporaryDirectory(prefix='log-pull-host-',
                                     dir=preferred if preferred.is_dir() else None) as tmp:
        work = Path(tmp)
        fake = work / 'adb'
        fake.write_text(ADB)
        fake.chmod(0o700)
        cases = [('system', False), ('userdata', False),
                 ('system', True), ('userdata', True), ('', False)]
        checks = 0
        for prefix in ('/dev/block/bootdevice/by-name/', '/dev/block/by-name/'):
            for name, short in cases:
                partition = prefix + name if name else ''
                output = work / f'log-{checks}.txt'
                calls = work / f'calls-{checks}.jsonl'
                env = dict(os.environ, PATH=str(work) + os.pathsep + os.environ['PATH'],
                           ADB_PARTITION=partition, ADB_SHORT=str(int(short)), ADB_CALLS=str(calls))
                result = subprocess.run(['sh', str(ROOT / 'tools/sweet-log-pull.sh'), str(output)],
                                        env=env, capture_output=True, text=True, timeout=30)
                success = bool(name) and not short
                if bool(result.returncode == 0) != success:
                    raise AssertionError(f'{partition} short={short}: {result.stderr}')
                if success:
                    assert output.read_text() == 'LOG-PULL-TEST\n'
                else:
                    assert not output.exists(), 'failed read was decoded as a complete log'
                commands = [json.loads(line) for line in calls.read_text().splitlines()]
                assert all(not any(re.search(r'(^|\s)(flash|erase|of=)', part) for part in cmd)
                           for cmd in commands), 'non-read-only device command'
                checks += 1
        print(f'Persistent log extraction: {checks}/{checks} host checks passed (fake ADB only)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
