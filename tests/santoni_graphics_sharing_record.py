"""Optional raw native receipts for the shared-context contracts."""
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def write_sharing_record(name, record):
    directory = os.environ.get('SANTONI_GRAPHICS_SHARING_RECORD_DIR')
    if not directory:
        return
    paths = [p for p in (ROOT / 'tools/santoni-graphics').rglob('*') if p.is_file()]
    paths += [p for p in (ROOT / 'tests').glob('*santoni_graphics*') if p.is_file()]
    paths += [p for p in (ROOT / 'tests/ui_eagl_stubs').rglob('*') if p.is_file()]
    record = {**record, 'source_promoted': True, 'hardware_verified': False,
              'inputs_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in sorted(paths)}}
    with (Path(directory) / (name + '.json')).open('x') as output:
        json.dump(record, output, indent=2)
