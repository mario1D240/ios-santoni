"""New receiver consumption/refusal gates; no completed native or linked replay."""
import ast
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import santoni_gpu_el0_trace_audit as trace
import santoni_gpu_trace_dispatch_audit as dispatch
from tests.test_santoni_gpu_trace_dispatch_binary import dispatch_fixture
import santoni_gpu_launcher_replay as launcher
import santoni_gpu_scalar_certificate as certificate
from santoni_gpu_binary_model import Memory, state_type
import check_santoni_gpu_kernel as kernel
# Import a fixture module, never its TestCase classes into test discovery.
from tests import test_santoni_gpu_launcher_certificate as launcher_fixtures


class TraceCertificate(unittest.TestCase):
    def test_cpu_diagnostic_reads_and_copies_keep_the_mutex_guard(self):
        class EmptyImage:
            def read(self, address, size): return None
        m = SimpleNamespace(diag=0x9000, diag_locked=False, vm=SimpleNamespace(State=state_type(kernel)))
        trace.guard_diagnostic_loads(m)
        memory = Memory(EmptyImage()); memory.map(m.diag, 40)
        state = m.vm.State(memory)
        address = kernel._Value(64, m.diag)
        for current in (state, state.copy()):
            for read in (current.load, current.load_copy):
                with self.assertRaises(ValueError): read(address, 4, EmptyImage())
        m.diag_locked = True
        self.assertEqual(state.load(address, 4, EmptyImage()).expr, 0)
        with self.assertRaises(ValueError): state.load(kernel._Value(64, m.diag+36), 8, EmptyImage())

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.folder = Path(self.directory.name)
        self.source = (ROOT / 'tools/santoni_gpu_el0_trace_audit.py').read_bytes()
        (self.folder / 'trace-source.py').write_bytes(self.source)
        self.source_sha = hashlib.sha256(self.source).hexdigest()
        self.identity = {'commit': 'a' * 40, 'ci_run': 123, 'kernel_sha256': 'b' * 64}
        self.probe_sha, self.graph_sha, self.counter = 'c' * 64, 'd' * 64, '0x7000'

    def receiver(self):
        records = {}
        for name, spec in trace.SCENARIOS.items():
            outputs = [0] * 16 + [16] * 2 if spec['kind'] == 'quota' else [spec['expected']]
            admitted = outputs.count(0) if spec['kind'] in ('ioctl', 'quota') else 0
            before = spec['settings'].get('counter', 0)
            pid, words = spec['settings'].get('pid', 2), spec['record']
            printed = [{'format': trace.RESULT_FORMAT if words[2] == 6 else trace.TRACE_FORMAT,
                'values': [words[5], pid, *words[6:11]] if words[2] == 6 else
                [words[2], pid, words[3], words[4], before + index + 1]} for index in range(admitted)]
            result = {'case': name, 'success': True, 'outputs': outputs, 'counter_before': before,
                'counter_after': before + admitted, 'print_count': admitted, 'printed_records': printed,
                'locked_counter_writes': [{'address': self.counter, 'bytes': 4, 'locked': True}] * admitted,
                'record_immutable': True, 'other_CPU_storage_immutable': True,
                'iocounts_released': True, 'mutex_balanced': True, 'hardware_verified': False,
                'service_calls': ['_printf'] if admitted else [], 'decoded_instruction_addresses': 1}
            result.update(diagnostic_snapshot=trace.expected_diagnostics(spec),
                          diagnostic_getter_checked=True, diagnostic_mutex_checked=True,
                          diagnostic_address='0x9000', diagnostic_writes=[])
            records[name] = {**self.identity, 'success': True, 'probe_sha256': self.probe_sha,
                'decoded_graph_sha256': self.graph_sha, 'spec_sha256': trace.digest(spec),
                'source_record': 'trace-source.py', 'tool_sha256': self.source_sha, 'result': result}
        return {**trace.assemble(records, self.identity, self.probe_sha, trace.TRACE_UAPI_SHA256),
            'tool_sha256': self.source_sha, 'synthetic': True,
            'independent_probe': {'probe_sha256': self.probe_sha, 'probe_bytes': 16635,
                'consumed_linked_cases': 22, 'executed_linked_cases': 0,
                'kernel_certified': False, 'hardware_verified': False}}

    def arguments(self):
        base = {**self.identity, **dict.fromkeys(certificate.LEGACY_GATES, True),
            'audit_scope': 'mode1-control', 'EL0_launcher_present': True,
            'EL0_launcher_changed_code_A53_checked': True, 'EL0_launcher_mount_registry_checked': True,
            'mode1_control_EL0_launcher_unreachable_checked': True,
            'inspected_functions': [*trace.ROOTS, *dispatch.ROOTS], 'EL0_launcher_trace_dispatch_checked': True, 'hardware_verified': False,
            'wiring_evidence': {'mode1_control': {'synthetic': True}, 'EL0_launcher_default_off': {
                'trace_present': True, 'trace_bindings': {'success': True, 'counter': self.counter,
                    'diagnostic_present': True, 'diagnostic_address': '0x9000', 'diagnostic_bytes': 40}}}}
        base['wiring_evidence']['EL0_launcher_trace_dispatch'] = dispatch_fixture(self.identity,
            base['wiring_evidence']['EL0_launcher_default_off']['trace_bindings'])
        groups = [{name: {**self.identity, 'success': True, 'synthetic': True} for name in keys}
                  for keys in (certificate.SESSION_COMPONENTS, certificate.SCALAR_COMPONENTS,
                               certificate.PREFLIGHT_COMPONENTS)]
        records = launcher_fixtures.linked_fixture(self.identity, self.probe_sha)
        extra_ast = ast.dump(ast.parse(textwrap.dedent(inspect.getsource(launcher.LauncherMachine.extra_step))))
        records['interpreter'] = {**self.identity, 'success': True, 'synthetic': True,
            'tested_operations': ['rev', 'mvn', 'cinc', 'ldar', 'stlr'],
            'shared_run_sha256': launcher.BASE_RUN_SHA256,
            'extra_step_ast_sha256': hashlib.sha256(extra_ast.encode()).hexdigest(),
            'worker_paths_ast_sha256': hashlib.sha256(ast.dump(launcher._paths_tree).encode()).hexdigest(),
            'shared_model_sha256': hashlib.sha256((ROOT / 'tools/santoni_gpu_binary_model.py').read_bytes()).hexdigest(),
            'new_contract_checks_passed': True, 'completed_kernel_components_consumed_without_replay': True,
            'hardware_verified': False}
        return base, *groups, records

    def validate(self, record):
        return trace.validate_component(record, self.identity, self.probe_sha, self.counter, self.folder)

    def test_receiver_cannot_replace_missing_or_other_kernel_common_dispatch(self):
        for mutation in ('missing', 'other-kernel', 'not-inspected', 'false-gate'):
            args = self.arguments(); base = args[0]
            if mutation == 'missing': base['wiring_evidence'].pop('EL0_launcher_trace_dispatch')
            elif mutation == 'other-kernel': base['wiring_evidence']['EL0_launcher_trace_dispatch']['kernel_sha256'] = 'f' * 64
            elif mutation == 'not-inspected': base['inspected_functions'].remove('_vn_ioctl')
            else: base['EL0_launcher_trace_dispatch_checked'] = False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                certificate.assemble(*args, trace=self.receiver(), evidence_folder=self.folder)

    def test_complete_receiver_emits_both_trace_gates_without_replay_or_changing_control(self):
        args, record = self.arguments(), self.receiver()
        before = deepcopy(args[0])
        with patch.object(trace, 'run_case', side_effect=AssertionError('completed receiver replayed')):
            report = certificate.assemble(*args, trace=record, evidence_folder=self.folder)
        self.assertIs(report['EL0_launcher_trace_present'], True)
        self.assertIs(report['EL0_launcher_trace_wiring_checked'], True)
        self.assertIs(report['hardware_verified'], False)
        self.assertEqual(args[0], before)
        self.assertIs(report['wiring_evidence']['EL0_launcher_trace']['source_evidence_checked'], True)

    def test_complete_other_components_cannot_replace_missing_receiver_evidence(self):
        for record in (None, {}, {'success': True, **self.identity}):
            with self.assertRaises(ValueError):
                certificate.assemble(*self.arguments(), trace=record, evidence_folder=self.folder)

    def test_wrong_kernel_probe_abi_and_unproved_receiver_scope_reject(self):
        changes = (('commit', 'e' * 40), ('ci_run', 124), ('kernel_sha256', 'e' * 64),
                   ('probe_sha256', 'f' * 64), ('trace_uapi_sha256', 'f' * 64),
                   ('record_limit', 17), ('record_bytes', 65), ('ioctl_command', trace.COMMAND + (1 << 32)),
                   ('enabled_receiver_complete', 1), ('case_count', len(trace.SCENARIOS) - 1),
                   ('hardware_verified', True), ('roots', list(trace.ROOTS[:-1])))
        for key, value in changes:
            record = self.receiver(); record[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.validate(record)

    def test_every_missing_case_and_changed_graph_or_case_contract_rejects(self):
        original = self.receiver()
        for name in trace.SCENARIOS:
            record = deepcopy(original); del record['cases'][name]
            with self.subTest(case=name), self.assertRaises(ValueError): self.validate(record)
        for key, value in (('success', 1), ('spec_sha256', 'e' * 64), ('decoded_graph_sha256', 'e' * 64)):
            record = deepcopy(original); record['cases']['result_pass'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.validate(record)

    def test_quota_and_locked_counter_proof_cannot_be_summarized_as_success(self):
        changes = (('counter_after', 17), ('print_count', 15), ('outputs', [0] * 18),
                   ('locked_counter_writes', [{'address': self.counter, 'bytes': 4, 'locked': True}] * 15))
        for key, value in changes:
            record = self.receiver(); record['cases']['quota_16_then_two_denials']['result'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.validate(record)
        for key, value in (('locked', 1), ('bytes', 8), ('address', '0x8000')):
            record = self.receiver()
            record['cases']['event_1']['result']['locked_counter_writes'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.validate(record)

    def test_current_pid_final_prefix_payload_and_foreign_services_are_checked(self):
        for mutation in ('pid', 'prefix', 'payload', 'service'):
            record = self.receiver(); result = record['cases']['result_pass']['result']
            if mutation == 'pid': result['printed_records'][0]['values'][1] = 999
            elif mutation == 'prefix': result['printed_records'][0]['format'] = trace.TRACE_FORMAT
            elif mutation == 'payload': result['record_immutable'] = 1
            else: result['service_calls'].append('_sgpu_probe')
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.validate(record)

    def test_changed_executed_source_rejects_even_after_rehashing_its_file(self):
        record = self.receiver()
        changed = self.source.replace(b'class TraceModel:', b'class TraceModel:\n    unreviewed = 1')
        (self.folder / 'trace-source.py').write_bytes(changed)
        for case in record['cases'].values(): case['tool_sha256'] = hashlib.sha256(changed).hexdigest()
        with self.assertRaisesRegex(ValueError, 'executed source'): self.validate(record)

    def test_missing_stale_escaping_or_aliased_source_evidence_rejects(self):
        for relative in ('missing.py', '../outside.py', '/outside.py'):
            record = self.receiver(); record['cases']['result_pass']['source_record'] = relative
            with self.subTest(relative=relative), self.assertRaises((ValueError, FileNotFoundError)):
                self.validate(record)
        record = self.receiver(); record['cases']['result_pass']['tool_sha256'] = 'f' * 64
        with self.assertRaises(ValueError): self.validate(record)

    def test_independent_probe_cannot_be_old_incomplete_or_replayed(self):
        for key, value in (('probe_sha256', 'f' * 64), ('consumed_linked_cases', 15),
                           ('executed_linked_cases', 22), ('kernel_certified', True), ('hardware_verified', True)):
            record = self.receiver(); record['independent_probe'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.validate(record)

    def test_receiver_requires_this_control_counter_and_all_inspected_roots(self):
        args = self.arguments(); args[0]['wiring_evidence']['EL0_launcher_default_off']['trace_bindings']['counter'] = '0x8000'
        with self.assertRaises(ValueError):
            certificate.assemble(*args, trace=self.receiver(), evidence_folder=self.folder)
        args = self.arguments(); args[0]['inspected_functions'] = list(trace.ROOTS[:-1])
        with self.assertRaises(ValueError):
            certificate.assemble(*args, trace=self.receiver(), evidence_folder=self.folder)

    def test_kernel_without_receiver_cannot_accept_an_attached_trace_component(self):
        args = self.arguments(); args[0]['wiring_evidence']['EL0_launcher_default_off']['trace_present'] = False
        with self.assertRaises(ValueError):
            certificate.assemble(*args, trace=self.receiver(), evidence_folder=self.folder)

    def test_diagnostic_control_binding_must_match_the_enabled_receiver(self):
        for key, value in (('diagnostic_present', False), ('diagnostic_address', '0xa000'),
                           ('diagnostic_bytes', 39)):
            args = self.arguments()
            args[0]['wiring_evidence']['EL0_launcher_default_off']['trace_bindings'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                certificate.assemble(*args, trace=self.receiver(), evidence_folder=self.folder)

    def test_trace_reuse_plan_cannot_alias_another_component_or_escape(self):
        for relative in ('launcher.json', '../outside.json'):
            (self.folder / 'scalar-proof-inputs.json').write_text(json.dumps({
                'scalar': {}, 'preflight': {}, 'launcher': {'image': 'launcher.json'}, 'trace': relative}))
            with self.assertRaises(ValueError): certificate.prior_trace_proof(self.folder, self.identity)

    def test_write_contract_refuses_unlocked_wrong_width_and_non_counter_storage(self):
        model = object.__new__(trace.TraceModel)
        model.vm = SimpleNamespace(STACK=0x1000, STACK_SIZE=0x100)
        model.counter, model.diag, model.locked, model.writes, model.diag_writes = 0x7000, 0x9000, True, [], []
        model.diag_locked = False
        model.write_guard(0x7000, 4)
        for address, size in ((0x7000, 8), (0x7004, 4), (0x8000, 4)):
            with self.assertRaises(ValueError): model.write_guard(address, size)
        model.locked = False
        with self.assertRaises(ValueError): model.write_guard(0x7000, 4)
        # Diagnostic stores require their own mutex and an aligned word.
        with self.assertRaises(ValueError): model.write_guard(model.diag + 8, 4)
        model.diag_locked = True
        model.write_guard(model.diag + 8, 4)
        for address, size in ((model.diag + 1, 4), (model.diag + 36, 8), (model.diag + 40, 4)):
            with self.assertRaises(ValueError): model.write_guard(address, size)
        self.assertEqual(len(model.writes), 1)
        self.assertEqual(len(model.diag_writes), 1)

    def test_diagnostics_cannot_be_missing_swapped_unlocked_or_written_elsewhere(self):
        for mutation in ('missing', 'swapped', 'getter', 'mutex', 'unlocked', 'outside', 'unaligned'):
            record = self.receiver(); result = record['cases']['event_1']['result']
            if mutation == 'missing': del result['diagnostic_snapshot']
            elif mutation == 'swapped': result['diagnostic_snapshot'][3:5] = [0, 1]
            elif mutation == 'getter': result['diagnostic_getter_checked'] = 1
            elif mutation == 'mutex': result['diagnostic_mutex_checked'] = False
            else:
                result['diagnostic_writes'] = [{'address': '0x9000', 'bytes': 4, 'locked': True}]
                if mutation == 'unlocked': result['diagnostic_writes'][0]['locked'] = False
                elif mutation == 'outside': result['diagnostic_writes'][0]['address'] = '0xa000'
                else: result['diagnostic_writes'][0]['address'] = '0x9001'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.validate(record)


if __name__ == '__main__':
    unittest.main()
