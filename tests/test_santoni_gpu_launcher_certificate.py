"""New launcher certificate/cache and service refusal contracts only."""
import ast
from contextlib import ExitStack, redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import check_santoni_gpu_kernel as e
import santoni_gpu_launcher_replay as r
import santoni_gpu_scalar_certificate as c
from santoni_gpu_user_integration_audit import audit_worker_entry
from tests import test_santoni_gpu_launcher_replay as _instruction_tests
from tests import test_santoni_gpu_scalar_certificate as _scalar_tests
Image = _instruction_tests.Image


def linked_fixture(identity, probe_sha='c' * 64):
    records = {name: {**identity, 'success': True, 'hardware_verified': False, 'synthetic': True,
        'cases': [{'case': label} for label in sorted(r.CASE_NAMES[name])],
        'probe_sha256': probe_sha, 'record_path': 'launcher-components/' + name + '.json',
        'record_sha256': f'{index + 1:064x}'} for index, name in enumerate(r.COMPONENTS)}
    workers = {case['case']: case for case in records['worker']['cases']}
    workers['off'].update(mode=3, options_ok=1, worker_ready=1)
    for name in ('reject-before-delay', 'reject-after-delay'):
        workers[name]['refusal_paths'] = {'return_paths': 1}
    records['attributes']['cases'][0].update(mode=0o500, uid=0, gid=0,
        uid_gid_mode_supported=True, attribute_bytes=440)
    return records


class LauncherAggregateTests(unittest.TestCase):
    identity = {'commit': 'a' * 40, 'ci_run': 123, 'kernel_sha256': 'b' * 64}

    def test_missing_failed_duplicate_and_unreviewed_scope_reject(self):
        for name in r.COMPONENTS:
            for mutation in ('missing', 'failed', 'unknown-case', 'duplicate-case'):
                records = linked_fixture(self.identity)
                if mutation == 'missing': del records[name]
                elif mutation == 'failed': records[name]['success'] = False
                elif mutation == 'unknown-case': records[name]['cases'][0]['case'] = 'unreviewed'
                else: records[name]['cases'].append(copy.deepcopy(records[name]['cases'][0]))
                with self.subTest(name=name, mutation=mutation), self.assertRaises(ValueError):
                    r.assemble_components(records, self.identity)

    def test_different_identity_probe_alias_and_unsupported_attributes_reject(self):
        changes = (('image', 'ci_run', 124), ('image', 'probe_sha256', 'd' * 64),
                   ('image', 'record_path', 'launcher-components/options.json'),
                   ('image', 'record_sha256', f'{1:064x}'))
        for name, key, value in changes:
            records = linked_fixture(self.identity); records[name][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.assemble_components(records, self.identity)
        records = linked_fixture(self.identity)
        records['attributes']['cases'][0]['uid_gid_mode_supported'] = False
        with self.assertRaises(ValueError): r.assemble_components(records, self.identity)

    def test_all_linked_components_still_do_not_issue_a_delivery_certificate(self):
        result = r.assemble_components(linked_fixture(self.identity), self.identity)
        self.assertTrue(result['linked_components_complete'])
        self.assertFalse(result['launcher_certificate_complete'])
        self.assertFalse(result['hardware_verified'])

    def test_cli_cached_aggregation_never_calls_a_replay_function(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary); probe = folder / 'probe'; probe.mkdir()
            data = b'fixture'; digest = hashlib.sha256(data).hexdigest()
            (probe / 'probe.macho').write_bytes(data)
            (probe / 'build.json').write_text(json.dumps({'macho_sha256': digest, 'macho_bytes': len(data)}))
            cache = folder / 'launcher-components'; cache.mkdir()
            for name, record in linked_fixture(self.identity, digest).items():
                (cache / (name + '.json')).write_text(json.dumps(record))
            with ExitStack() as stack:
                load = stack.enter_context(patch.object(c, 'load_inputs', return_value=(self.identity, None, None, None, e)))
                actions = [stack.enter_context(patch.object(r, 'audit_' + name,
                    side_effect=AssertionError('cached pass replayed'))) for name in r.COMPONENTS]
                stack.enter_context(patch.object(sys, 'argv', ['launcher', str(folder), '--probe-dir', str(probe), '--aggregate']))
                stack.enter_context(redirect_stdout(io.StringIO()))
                r.main()
                load.assert_called_once_with(folder, decode=False)
                for action in actions: action.assert_not_called()


class LauncherCertificateTests(unittest.TestCase):
    def fixture(self):
        base, session, scalar, preflight = _scalar_tests.ScalarCertificate().fixture()
        base.update(EL0_launcher_present=True, EL0_launcher_changed_code_A53_checked=True,
                    mode1_control_EL0_launcher_unreachable_checked=True, EL0_launcher_wiring_checked=False)
        return base, session, scalar, preflight

    def test_present_launcher_cannot_be_certified_without_its_components(self):
        args = self.fixture()
        with self.assertRaises(ValueError): c.assemble(*args)
        for launcher in ({}, {'interpreter': {**c.identity_of(args[0]), 'success': True}},
                         {'default_off': args[0]}):
            with self.assertRaises(ValueError): c.assemble(*args, launcher)
        self.assertFalse(args[0]['EL0_launcher_wiring_checked'])

    def test_missing_interpreter_and_host_only_or_stale_evidence_reject(self):
        args = self.fixture(); identity = c.identity_of(args[0])
        linked = linked_fixture(identity)
        with self.assertRaises(ValueError): c.assemble(*args, linked)
        linked['interpreter'] = {**identity, 'success': True, 'hardware_verified': False,
                                 'new_contract_checks_passed': True}
        with self.assertRaises(ValueError): c.assemble(*args, linked)
        linked['interpreter']['kernel_sha256'] = 'e' * 64
        with self.assertRaises(ValueError): c.assemble(*args, linked)

    def test_scalar_bridge_requires_proved_launcher_off_and_refusal_results(self):
        names = {r.PUBLIC[0]: {0x9000}}
        for record in (None, {'success': True, 'cases': []}, {'success': True, 'cases': [
                {'case': 'off', 'mode': 3, 'options_ok': 0, 'worker_ready': 1}]}):
            with self.assertRaises(ValueError): audit_worker_entry({}, Image(), names, e, record)


class LauncherExtensionBoundaryTests(unittest.TestCase):
    machine = _instruction_tests.LauncherInstructionTests.machine

    def test_acquire_release_reject_misaligned_access_before_memory_changes(self):
        for prefix, size in (('w', 4), ('x', 8)):
            for op in ('ldar', 'stlr'):
                vm = self.machine([f'{op} {prefix}0, [x1]', 'ret'])
                vm.memory.map(0x8000, 16, fill=0xa5)
                with self.assertRaisesRegex(ValueError, 'unaligned'):
                    vm.run('_extension', (7, 0x8001))
                self.assertEqual(vm.memory.bytes(0x8000, 16), b'\xa5' * 16)
                self.assertEqual(vm.atomic_events, [])

    def test_worker_terminal_extension_preserves_all_other_walker_ast(self):
        tree = copy.deepcopy(r._paths_tree); tree.body[0].name = '_paths'
        terminals = [node for node in ast.walk(tree) if isinstance(node, ast.If) and
            ast.dump(node.test) == ast.dump(ast.parse('not successors', mode='eval').body)]
        self.assertEqual(len(terminals), 1)
        self.assertIsInstance(terminals[0].body[0], ast.If)
        del terminals[0].body[0]
        self.assertEqual(ast.dump(tree), ast.dump(ast.parse(r._paths_source)))

    def model(self, symbol):
        model = object.__new__(r.LauncherModel); model.e = e
        model.vm = r.LauncherMachine({}, Image(), {symbol: {0x9000}}, e)
        model.m, model.calls, model.events = model.vm.memory, [], []
        model.launch = 0x8200; model.m.map(model.launch, 88)
        model.locked, model.allocated, model.cleaned, model.released = True, 1, 1, 0
        model.pagers, model.pager_error, model.user_copyouts, model.copyout_error_at = 0, 0, 0, 0
        return model

    def invoke(self, model, values):
        before, after = model.vm.State(model.m), model.vm.State(model.m)
        for index, value in enumerate(values): before.put('x' + str(index), e._Value(64, value))
        model.external(0x9000, after, before=before)
        return after

    def test_pager_refuses_physical_address_eof_and_unclean_or_released_backing(self):
        for mutation in ('pa', 'eof', 'unclean', 'released'):
            model = self.model('_pager_map_to_phys_contiguous')
            values = [model.UBC, 0, model.KVA, model.SPAN]
            if mutation == 'pa': values[2] = model.PA
            if mutation == 'eof': values[3] = model.FILE
            if mutation == 'unclean': model.cleaned = 0
            if mutation == 'released': model.released = 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.invoke(model, values)
            self.assertEqual(model.pagers, 0)

    def test_release_refuses_potentially_exposed_cpu_backing(self):
        model = self.model('_kmem_free_guard'); model.m.put(model.launch + 40, 1, 1)
        with self.assertRaises(ValueError): self.invoke(model, (model.MAP, model.KVA, model.SPAN, 0, 0))
        self.assertEqual(model.released, 0)

    def test_pid1_copyout_refuses_outside_owned_user_scratch(self):
        model = self.model('_copyout'); model.m.map(model.USER_SCRATCH, 4096, fill=0xa5)
        model.m.map(0x8400, 16); model.m.write(0x8400, b'0123456789abcdef')
        with self.assertRaises(ValueError):
            self.invoke(model, (0x8400, model.USER_SCRATCH + 4090, 16))
        self.assertEqual(model.user_copyouts, 0)
        self.assertEqual(model.m.bytes(model.USER_SCRATCH, 4096), b'\xa5' * 4096)


if __name__ == '__main__':
    unittest.main()
