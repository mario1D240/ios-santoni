"""Admission for the separately opted-in, hardware-unproven EAGL renderer trial."""
import hashlib
import json
from pathlib import Path

CHECKS = ('renderer_admission_checked', 'service_flags_and_vtable_checked',
          'owned_pool_claim_caller_checked', 'descriptor_mapping_checked',
          'all_client_selectors_checked', 'close_owner_retention_checked',
          'dyld_policy_checked')
COMPONENTS = ('claim', 'overlap', 'pool_failure', 'denials', 'observer',
              'info_submit', 'mapping', 'remaining', 'service_close', 'dyld')


def validate(mode, render_test, ui_copy, enabled, skip_mode1=False):
    if type(enabled) is not bool:
        raise ValueError('renderer opt-in must be boolean')
    if type(skip_mode1) is not bool or (skip_mode1 and mode != 3):
        raise ValueError('skip-mode1 requires explicit mode3 and a boolean opt-in')
    # The packager retains every software audit and requires the hardware pass
    # by default. Its explicit --skip-mode1 records an unverified hardware trial.
    if enabled and (mode != 3 or not render_test or ui_copy):
        raise ValueError('renderer requires mode3/render-test and UI-copy off')


def require_audit(ci, commit, run, kernel_sha):
    path = Path(ci) / 'renderer-client-binary-audit.json'
    if not path.is_file():
        raise ValueError('complete own-kernel renderer client audit required')
    report = json.loads(path.read_text())
    if (report.get('success') is not True or report.get('hardware_verified') is not False or
            (report.get('commit'), report.get('ci_run'), report.get('kernel_sha256')) !=
            (commit, run, kernel_sha) or any(report.get(k) is not True for k in CHECKS)):
        raise ValueError('renderer client evidence is incomplete or belongs to another kernel')
    parts = report.get('components')
    if (not isinstance(parts, list) or len(parts) != len(COMPONENTS) or
            {r.get('name') for r in parts} != set(COMPONENTS) or
            len({r.get('path') for r in parts}) != len(COMPONENTS)):
        raise ValueError('renderer component inventory incomplete')
    project = Path(__file__).resolve().parents[1]
    for row in parts:
        source = (project / row['path']).resolve()
        if (not source.is_relative_to(project / 'out') or
                hashlib.sha256(source.read_bytes()).hexdigest() != row['sha256']):
            raise ValueError('renderer component provenance differs')
        data = json.loads(source.read_text())
        if (data.get('success') is not True or data.get('hardware_verified') is not False or
                (data.get('commit'), data.get('ci_run'), data.get('kernel_sha256')) !=
                (commit, run, kernel_sha)):
            raise ValueError('renderer component is failed or from another kernel')
    return report
