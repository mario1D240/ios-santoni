"""Own-kernel admission for the explicitly enabled UI presentation-copy role."""
import json
import hashlib
from pathlib import Path

MARKER = b'_santoni_gpu_ui_copy'
CHECKS = ('actual_UI_core_checked', 'actual_UI_adapter_checked',
          'actual_framebuffer_ABI_checked', 'full_UI_A53_words_checked',
          'read_only_import_and_exact_owned_output_checked',
          'CP_SID0_CB_TLB_order_checked', 'circular_ring_cache_fence_checked',
          'failure_quarantine_and_CPU_fallback_checked', 'mode1_UI_unreachable_checked')


def validate(mode, render_test, enabled, ui_hz=30):
    if type(enabled) is not bool or type(render_test) is not bool:
        raise ValueError('UI presentation requires explicit boolean options')
    if enabled and (type(mode) is not int or mode != 3 or not render_test):
        raise ValueError('UI presentation requires mode3 and the separate full-buffer render role')
    if type(ui_hz) is not int or ui_hz not in (30, 60) or (ui_hz != 30 and not enabled):
        raise ValueError('UI refresh must be 30 or an explicitly enabled UI-copy 60 Hz candidate')


def require_audit(ci, commit, run, kernel_sha, present, enabled):
    if type(present) is not bool or type(enabled) is not bool:
        raise ValueError('explicit UI presence and opt-in required')
    if not present:
        if enabled:
            raise ValueError('UI presentation bridge absent from this kernel')
        return None
    path = Path(ci) / 'ui-binary-audit.json'
    if not path.is_file():
        raise ValueError('run the own-kernel UI presentation audit before packaging')
    record = json.loads(path.read_text())
    if ((record.get('commit'), record.get('ci_run'), record.get('kernel_sha256')) !=
        (commit, run, kernel_sha) or record.get('success') is not True or
        record.get('hardware_verified') is not False or
        any(record.get(k) is not True for k in CHECKS)):
        raise ValueError('UI presentation needs complete proofs for this exact CI/kernel')
    from check_santoni_gpu_ui_kernel import CORE_CASES
    for key,expected in (('core_results',list(CORE_CASES)),
                         ('adapter_results',list(range(25))),('framebuffer_results',list(range(20)))):
        rows=record.get(key,[])
        if [r.get('case') for r in rows]!=expected or any(r.get('success') is not True or
            (r.get('identity',{}).get('commit'),r.get('identity',{}).get('ci_run'),
             r.get('identity',{}).get('kernel_sha256'))!=(commit,run,kernel_sha) for r in rows):
            raise ValueError('UI own-kernel component inventory incomplete or mismatched')
    if record.get('cases')!=65 or record.get('complete_UI_certificate') is not True:
        raise ValueError('UI certificate lacks all65 required instruction cases')
    for key,file in (('tool_sha256','check_santoni_gpu_ui_kernel.py'),
                     ('framebuffer_tool_sha256','santoni_gpu_ui_framebuffer_audit.py'),
                     ('native_CPU_sha256','santoni_gpu_ui_native_cpu.py')):
        if record.get(key)!=hashlib.sha256(Path(__file__).with_name(file).read_bytes()).hexdigest():
            raise ValueError('UI binary proof belongs to another auditor/model revision')
    return record
