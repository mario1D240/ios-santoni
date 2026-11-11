"""Delivery gates for the new boot-only launcher; never issue a certificate.

Recorded linked probe components may be consumed without executing them again.
They do not certify the kernel's exec, mount, pager, ownership or GPU worker.
"""
import json
from pathlib import Path

PRESENT = 'EL0_launcher_present'
ISA_GATE = 'EL0_launcher_changed_code_A53_checked'
CONTROL_GATE = 'mode1_control_EL0_launcher_unreachable_checked'
LAUNCH_GATE = 'EL0_launcher_wiring_checked'
PROPERTY = 'santoni-gpu-el0-probe'
MARKER = b'SANTONI GPU: USER LAUNCH '


def require_kernel_gates(report, mode, enabled=False, present=False):
    if type(enabled) is not bool or type(present) is not bool:
        raise ValueError('launcher gates require explicit boolean roles')
    if enabled and mode != 3:
        raise ValueError('EL0 launcher requires mode3')
    declared = report.get(PRESENT, False)
    if type(declared) is not bool or (present and declared is not True):
        raise ValueError('binary audit has not recorded the new EL0 launcher')
    if not (declared or present or enabled):
        return
    if declared is not True or report.get(ISA_GATE) is not True:
        raise ValueError('EL0 launcher requires its own exact-kernel A53 inspection')
    if type(mode) is not int or mode not in range(4):
        raise ValueError('launcher certificate requires an explicit integer mode')
    gate = CONTROL_GATE if mode == 1 else LAUNCH_GATE
    if report.get(gate) is not True:
        raise ValueError('EL0 launcher binary gate is missing: ' + gate)
    if enabled and report.get('EL0_launcher_mount_registry_checked') is not True:
        raise ValueError('EL0 launcher requires the linked LP64 mockfs registration/provider gate')
    if enabled and (report.get('EL0_launcher_trace_present') is not True or
                    report.get('EL0_launcher_trace_wiring_checked') is not True):
        raise ValueError('EL0 diagnostic probe requires its exact-kernel vnode trace receiver gate')
    if enabled and report.get('EL0_launcher_trace_dispatch_checked') is not True:
        raise ValueError('EL0 diagnostic probe requires its exact-kernel common vnode dispatch gate')


def consume_probe(folder, evidence):
    """Consume the completed linked record; zero new replay cases."""
    import check_santoni_gpu_user_probe as probe
    folder, evidence = Path(folder), Path(evidence)
    result = json.loads((evidence / 'result.json').read_text())
    if (result.get('success') is not True or result.get('complete_scenario_scope') is not True or
            set(result.get('cases', ())) != set(probe.SCENARIOS) or
            result.get('kernel_dependency') is not None or
            result.get('kernel_certified') is not False or result.get('hardware_verified') is not False):
        raise ValueError('complete independent linked-probe evidence required')
    _, _, _, build, _, consumed = probe.consume_completed(folder, evidence)
    data = (folder / 'probe.macho').read_bytes()
    if (len(data) != 16635 or consumed.get('probe_sha256') != build['macho_sha256'] or
            build.get('requires_EL0_trace_kernel') is not True):
        raise ValueError('probe differs from the bounded launcher input')
    return data, {'probe_sha256': build['macho_sha256'], 'probe_bytes': len(data),
                  'linked_evidence': str(evidence), 'consumed_linked_cases': len(result['cases']),
                  'executed_linked_cases': 0, 'kernel_certified': False, 'hardware_verified': False}
