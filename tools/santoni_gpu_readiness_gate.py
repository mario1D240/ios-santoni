"""Require the exact-kernel trace-pause proof when the new helper is present."""
import hashlib
import json
from pathlib import Path

SYMBOL = b'_sgpu_trace_pause_required\0'
CHECKS = ('actual_trace_and_getters_checked', 'stack_only_writes_checked',
          'printf_and_wait_ABI_checked', 'exact_EL0_role_checked', 'acyclic_A53_checked')


def require_audit(ci, commit, run, kernel_sha, present):
    if type(present) is not bool:
        raise ValueError('explicit readiness policy presence required')
    if not present: return None
    path = Path(ci) / 'readiness-binary-audit.json'
    if not path.is_file():
        raise ValueError('run check_santoni_gpu_readiness_kernel.py before packaging this kernel')
    record = json.loads(path.read_text())
    tool = Path(__file__).with_name('check_santoni_gpu_readiness_kernel.py')
    if (record.get('success') is not True or record.get('hardware_verified') is not False or
            (record.get('commit'), record.get('ci_run'), record.get('kernel_sha256')) != (commit, run, kernel_sha) or
            type(record.get('cases')) is not int or record['cases'] != 40 or
            any(record.get(k) is not True for k in CHECKS) or
            record.get('tool_sha256') != hashlib.sha256(tool.read_bytes()).hexdigest()):
        raise ValueError('readiness requires complete proof for this exact kernel/tool')
    return record
