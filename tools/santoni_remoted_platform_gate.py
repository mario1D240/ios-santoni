"""Consume the separate exact-kernel0212 proof; never grant hardware success."""
import json
from pathlib import Path

MARKER = b'SANTONI PLATFORM: remoted pid='
CHECKS = ('Cortex_A53_changed_code_checked', 'default_off_checked',
          'exact_root_exec_checked', 'signing_state_preserved_checked',
          'exec_success_callsite_checked', 'tunable_storage_binding_checked')


def validate(mode, user_exec, enabled, render_test=False):
    if type(mode) is not int or mode not in range(4) or type(user_exec) is not bool or type(enabled) is not bool:
        raise ValueError('remoted workaround requires explicit integer mode and boolean roles')
    if type(render_test) is not bool or render_test and mode != 3:
        raise ValueError('render workaround role requires explicit mode3')
    if enabled and not ((mode == 1 and not user_exec) or (mode == 3 and (user_exec or render_test))):
        raise ValueError('remoted workaround is limited to mode1 or the mode3 EL0 trace role')


def require_audit(ci, commit, run, kernel_sha, present, enabled):
    if type(present) is not bool or type(enabled) is not bool:
        raise ValueError('explicit remoted presence/opt-in required')
    if not present:
        if enabled:
            raise ValueError('remoted workaround is not in this kernel')
        return None
    path = Path(ci) / 'remoted-platform-binary-audit.json'
    if not path.is_file():
        raise ValueError('run the separate remoted platform binary audit before packaging')
    record = json.loads(path.read_text())
    if (not isinstance(record, dict) or record.get('success') is not True or
            (record.get('commit'), record.get('ci_run'), record.get('kernel_sha256')) != (commit, run, kernel_sha) or
            record.get('hardware_verified') is not False or
            any(record.get(name) is not True for name in CHECKS)):
        raise ValueError('remoted workaround needs its own exact-kernel binary proof')
    return record
