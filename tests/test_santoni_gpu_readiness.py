import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import santoni_gpu_readiness_gate as gate
import check_santoni_gpu_readiness_kernel as audit
import verify_santoni_gpu_readiness_evidence as evidence
import check_santoni_gpu_kernel as decoder


class ReadinessTests(unittest.TestCase):
    def model(self):
        class EmptyImage:
            segs = ()
            def read(self, address, size): return None
        names = {name: {0x1000+index*16} for index, name in enumerate(audit.FUNCTIONS)}
        names.update(_sg={0x2000}, _launch={0x3000}, _printf={0x4000}, _clock_interval_to_deadline={0x4010})
        codes = {n: SimpleNamespace(entry=next(iter(names[n])), ins={next(iter(names[n])): ('ret', ())})
                 for n in audit.FUNCTIONS}
        return audit.TraceModel(codes, EmptyImage(), names, decoder, 'normal', True)

    def test_model_maps_readonly_launcher_and_rejects_foreign_stores(self):
        model = self.model()
        self.assertEqual(model.m.get(model.sg+84, 4), 3)
        self.assertEqual(model.m.get(0x3000+64, 4), 2)
        with self.assertRaises(ValueError): model.m.put(model.sg+84, 0, 4)
        with self.assertRaises(ValueError): model.write(model.MESSAGE, 1)
        model.write(model.vm.STACK, 8)

    def test_model_rejects_swapped_printf_values_and_shortened_wait(self):
        model = self.model(); m = model.m; sp = model.vm.STACK
        m.write_hook = None
        fmt = b'SANTONI GPU: %s [%08x %08x %08x]\n\0'
        m.map(0x6000, len(fmt)); m.write(0x6000, fmt)
        m.put(sp, model.MESSAGE, 8)
        for offset, value in ((8, 0x80000001), (16, 0xffffffff), (24, 0x76543210)): m.put(sp+offset, value, 4)
        m.write_hook = model.write
        before = decoder._State({'x0': decoder._Value(64, 0x6000), 'sp': decoder._Value(64, sp)})
        self.assertTrue(model.external(0x4000, before.copy(), before=before))
        m.put(sp+8, 0xffffffff, 4)
        with self.assertRaises(ValueError): model.external(0x4000, before.copy(), before=before)
        bad_wait = decoder._State({'x0': decoder._Value(64, 1000000),
            'x1': decoder._Value(64, 1000), 'x2': decoder._Value(64, sp+32)})
        with self.assertRaises(ValueError): model.external(0x4010, bad_wait.copy(), before=bad_wait)

    def test_gate_requires_this_kernel_tool_and_complete_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(gate.require_audit(tmp, 'a'*40, 1, 'b'*64, False))
            with self.assertRaises(ValueError): gate.require_audit(tmp, 'a'*40, 1, 'b'*64, True)
            good = {'success': True, 'hardware_verified': False, 'commit': 'a'*40,
                'ci_run': 1, 'kernel_sha256': 'b'*64, 'cases': 40,
                'tool_sha256': hashlib.sha256(Path(audit.__file__).read_bytes()).hexdigest(),
                **{key: True for key in gate.CHECKS}}
            path = Path(tmp) / 'readiness-binary-audit.json'; path.write_text(json.dumps(good))
            self.assertEqual(gate.require_audit(tmp, 'a'*40, 1, 'b'*64, True), good)
            for key, value in [('commit', 'c'*40), ('ci_run', 2), ('kernel_sha256', '0'*64),
                ('cases', 39), ('hardware_verified', True), ('tool_sha256', '0'*64), *[(k, False) for k in gate.CHECKS]]:
                bad = {**good, key: value}; path.write_text(json.dumps(bad))
                with self.assertRaises(ValueError): gate.require_audit(tmp, 'a'*40, 1, 'b'*64, True)

    def test_intake_refuses_changed_inputs_partial_or_uncompiled_evidence(self):
        record = json.loads((Path(__file__).with_name('santoni_gpu_readiness_host_evidence.json')).read_text())
        self.assertEqual(evidence.verify(record)['consumed_native_cases'], 246)
        for mutation in ('compile', 'run', 'scope', 'hash', 'inventory', 'baseline'):
            bad = copy.deepcopy(record)
            if mutation == 'compile': bad['runs'][-1]['compile_exit'] = 1
            if mutation == 'run': bad['runs'][-1]['run_exit'] = 0
            if mutation == 'scope': bad['hardware_verified'] = True
            if mutation == 'hash': bad['inputs_sha256'][evidence.INPUTS[0]] = '0'*64
            if mutation == 'inventory': bad['runs'].pop()
            if mutation == 'baseline': bad['baseline_inputs_sha256'] = {}
            with self.assertRaises(ValueError): evidence.verify(bad)


if __name__ == '__main__': unittest.main()
