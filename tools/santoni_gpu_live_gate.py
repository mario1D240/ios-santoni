"""Bind the new full-buffer role to its complete exact-kernel model proof."""
import json
from pathlib import Path

MARKER = b'_sgpu_render_live_start'
CP_MARKER = b'_sgpu_render_live_cp_state'
CP_CHECKS = ('A505_CP_observed_response_bits_and_bounded_requests_checked',
             'A505_CP_unknown_bits_missing_requests_and_busy_stop_rejected')
CHECKS = ('actual_live_core_checked', 'full_native_A53_helper_words_checked',
          'retained_TTBR_legacy_mapping_and_SID0_fault_routing_checked',
          'two_full_BGRA_jobs_cache_fence_readback_quarantine_checked',
          'actual_allocator_role_and_dispatch_checked')


def require_audit(ci, commit, run, kernel_sha, present, enabled, cp_readback_v2=False):
    if type(present) is not bool or type(enabled) is not bool:
        raise ValueError('explicit live render presence/opt-in required')
    if type(cp_readback_v2) is not bool or cp_readback_v2 and not present:
        raise ValueError('explicit CP readback helper identity required')
    if not present:
        if enabled: raise ValueError('live render worker is absent from this kernel')
        return None
    path = Path(ci) / 'live-binary-audit.json'
    if not path.is_file(): raise ValueError('run the own-kernel live render audit before packaging')
    record = json.loads(path.read_text())
    expected_cases = 37 if cp_readback_v2 else 23
    if (record.get('success') is not True or record.get('hardware_verified') is not False or
            (record.get('commit'), record.get('ci_run'), record.get('kernel_sha256')) != (commit, run, kernel_sha) or
            record.get('cases') != expected_cases or any(record.get(name) is not True for name in CHECKS)):
        raise ValueError('live render requires all %s exact-kernel core/allocator/role cases' % expected_cases)
    if cp_readback_v2 and (any(record.get(name) is not True for name in CP_CHECKS) or
                          record.get('CP_readback_mask') != '0xfffffff3' or
                          record.get('CP_response_bits') != '0x0000000c'):
        raise ValueError('new CP helper requires exact observed-response, request, unknown-bit and busy-stop proofs')
    return record
