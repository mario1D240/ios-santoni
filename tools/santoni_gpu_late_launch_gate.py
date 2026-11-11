"""Consume the exact-kernel late CPU observation proof before delivery."""
import json
from pathlib import Path

MARKER = b'SANTONI GPU: USER LAUNCH LATE mode='
DIAG_MARKER = b'SANTONI GPU: USER TRACE DIAG open='
DIAG_CHECKS = ('diagnostic_getter_linkage_and_scalars_checked',
               'diagnostic_mutex_and_printf_arguments_checked', 'diagnostic_reads_mutex_checked')
CHECKS = ('changed_code_A53_checked', 'mode3_publication_scope_checked',
          'actual_getter_linkage_and_scalars_checked', 'publication_and_mutex_order_checked',
          'immutable_CPU_state_checked')


def require_audit(ci, commit, run, kernel_sha, present, diagnostics=False):
    if type(present) is not bool: raise ValueError('explicit late-observation presence required')
    if type(diagnostics) is not bool or diagnostics and not present:
        raise ValueError('explicit diagnostic presence requires the late publication snapshot')
    if not present: return None
    path = Path(ci) / 'late-launch-binary-audit.json'
    if not path.is_file(): raise ValueError('run the separate late-launch actual-binary audit before packaging')
    record = json.loads(path.read_text())
    if (not isinstance(record, dict) or record.get('success') is not True or
            (record.get('commit'), record.get('ci_run'), record.get('kernel_sha256')) != (commit, run, kernel_sha) or
            record.get('hardware_verified') is not False or type(record.get('cases')) is not int or
            record['cases'] != 33 or any(record.get(name) is not True for name in
                                       (*CHECKS, *(DIAG_CHECKS if diagnostics else ())))):
        raise ValueError('late-launch observation requires its exact-kernel complete CPU proof')
    return record
