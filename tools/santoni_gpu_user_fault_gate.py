"""Require the new diagnostic's actual-kernel proof before controlled packaging."""
import hashlib
import json
from pathlib import Path

MARKER = b'SANTONI GPU: USER FAULT pc='
DETAIL_MARKER = b'SANTONI GPU: USER FAULT esr='
CHECKS = ('actual_helper_and_getters_checked', 'mode1_fault_observation_unreachable_checked',
          'immutable_frame_and_bounded_weak_CAS_checked', 'three_terminal_routes_linked_checked',
          'actual_printf_tuple_checked', 'changed_code_A53_checked', 'bounded_executable_section_checked',
          'actual_terminal_route_arguments_checked')


def require_audit(ci, commit, run, kernel_sha, present):
    if type(present) is not bool:
        raise ValueError('explicit user-fault diagnostic presence required')
    if not present:
        return None
    path = Path(ci) / 'user-fault-binary-audit.json'
    if not path.is_file():
        raise ValueError('run check_santoni_gpu_user_fault_kernel.py before packaging this kernel')
    record = json.loads(path.read_text())
    tool = Path(__file__).with_name('check_santoni_gpu_user_fault_kernel.py')
    if (record.get('success') is not True or record.get('hardware_verified') is not False or
            (record.get('commit'), record.get('ci_run'), record.get('kernel_sha256')) != (commit, run, kernel_sha) or
            type(record.get('cases')) is not int or record['cases'] != 22 or
                type(record.get('terminal_route_cases')) is not int or record['terminal_route_cases'] != 3 or
            any(record.get(k) is not True for k in CHECKS) or
            record.get('tool_sha256') != hashlib.sha256(tool.read_bytes()).hexdigest()):
        raise ValueError('user-fault observation requires a complete proof for this exact kernel/tool')
    return record
