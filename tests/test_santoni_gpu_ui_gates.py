"""Reject incomplete/different-kernel UI proofs and unauthorized runtime callers."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import santoni_gpu_boot as boot
import santoni_gpu_ui_gate as gate
import santoni_gpu_ui_audit as boundary
from santoni_gpu_render_audit import HELPERS, LIVE_HELPERS, LIVE_STORAGE, CP_HELPER, prepared_only, inspection_budget
from tests.test_santoni_gpu_boot_gates import RECIPE


class Code:
    def __init__(self, targets=()): self.targets = targets
    def calls_to(self, addresses): return set(self.targets) & set(addresses)


class UIGates(unittest.TestCase):
    def test_completed_UI_receipts_require_identical_execution_code(self):
        from check_santoni_gpu_ui_kernel import compatible_model
        source=(ROOT/'tools/check_santoni_gpu_ui_kernel.py').read_text()
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'completed.py'
            harmless=source+'\n# preserved completion metadata\n'
            path.write_text(harmless)
            self.assertEqual(compatible_model(path),hashlib.sha256(harmless.encode()).hexdigest())
            for old,new in (('self.ui_case=case','self.ui_case=case+1'),
                            ('seed.prepare_ui()','seed.prepare_ui(1)'),
                            ('for case in range(25):','for case in range(24):')):
                self.assertIn(old,source)
                path.write_text(source.replace(old,new,1))
                with self.assertRaises(ValueError):compatible_model(path)

    def test_shadow_copy_model_rejects_uncompleted_and_misdirected_rows(self):
        import check_santoni_gpu_kernel as e
        from santoni_gpu_binary_model import Memory
        from santoni_gpu_ui_framebuffer_audit import FramebufferModel,SHADOW,OUTPUT
        def attempt(name,args,queries=1,rows=0):
            model=FramebufferModel.__new__(FramebufferModel)
            model.vm=SimpleNamespace(by_address={1:name})
            model.m=Memory(SimpleNamespace(read=lambda *_:0))
            model.m.map(SHADOW,4096);model.m.map(OUTPUT,4096,fill=0x5a)
            model.e=e;model.inline_route=None;model.queries=queries
            model.shadow_rows=rows;model.inline_rows=0
            before=SimpleNamespace(get=lambda reg:e._Value(64,args[int(reg[1:])]))
            state=SimpleNamespace(put=lambda *_:None)
            model.external(1,state,before=before)
            self.assertEqual(model.m.bytes(SHADOW,2880),bytes([0x5a])*2880)
        for name in ('_memcpy','_memmove'):
            attempt(name,(SHADOW,OUTPUT,2880))
            for args,queries,rows in (((SHADOW,OUTPUT,2880),0,0),
                    ((SHADOW+4,OUTPUT,2880),1,0),((SHADOW,OUTPUT+4,2880),1,0),
                    ((SHADOW,OUTPUT,2879),1,0),((SHADOW,OUTPUT,2880),1,1280)):
                with self.assertRaises(ValueError):attempt(name,args,queries,rows)

    def names(self):
        all_names = (*HELPERS, *LIVE_HELPERS, *LIVE_STORAGE, CP_HELPER,
                     *boundary.CORE, *boundary.ADAPTER, *boundary.STORAGE, *boundary.DISPLAY)
        return {n: {0x1000 + i * 32} for i, n in enumerate(all_names)}

    def test_closed_namespace_and_exact_display_ABI(self):
        self.assertEqual(boundary.helpers({}), ())
        names = self.names()
        self.assertEqual(boundary.helpers(names), boundary.CORE + boundary.ADAPTER + boundary.DISPLAY)
        for wrong in ({n:v for n,v in names.items() if n != '_sgpu_ui_wait'},
                      {**names, '_sgpu_ui_shader': {0x9000}},
                      {**names, '_sgpu_ui': names['_sgpu_ui_start']},
                      {**names, boundary.DISPLAY[0]: {0x9000, 0x9010}}):
            with self.assertRaises(ValueError): boundary.helpers(wrong)
        self.assertEqual(inspection_budget(names, True, True),
                         160 + len(HELPERS) + len(LIVE_HELPERS) + 1 + len(boundary.helpers(names)))

    def test_exact_runtime_callers_and_render_scope(self):
        names = self.names()
        addr = lambda n: next(iter(names[n]))
        codes = {boundary.DISPLAY[0]: Code([addr('_santoni_gpu_ui_copy')]),
                 boundary.DISPLAY[1]: Code([addr('_santoni_gpu_ui_frame')]),
                 '_sgpu_ui_state': Code([addr(CP_HELPER)])}
        boundary.caller_boundary(codes, names)
        for caller in ('_sgpu_graphics_hw_state','_sgpu_graphics_hw_faulted'):
            boundary.caller_boundary({**codes,caller:Code([addr('_sgpu_ui_faults')])},names)
            for forbidden in ('_sgpu_ui_start','_sgpu_ui_copy','_santoni_gpu_ui_frame'):
                with self.assertRaises(ValueError):
                    boundary.caller_boundary({**codes,caller:Code([addr(forbidden)])},names)
        prepared_only(codes, names)
        for n, target in (('_sgpu_kernel_thread', '_sgpu_ui_copy'),
                          ('_sgpu_user_ioctl', '_santoni_gpu_ui_copy'),
                          (boundary.DISPLAY[0], '_sgpu_ui_copy')):
            with self.assertRaises(ValueError):
                boundary.caller_boundary({**codes, n: Code([addr(target)])}, names)
        with self.assertRaises(ValueError):
            prepared_only({**codes, '_sgpu_ui_wait': Code([addr('_sgpu_render_new')])}, names)

    def test_UI_cmdline_requires_explicit_mode3_render(self):
        for mode in range(4):
            gate.validate(mode, False, False)
            with self.assertRaises(ValueError): gate.validate(mode, False, True)
        for mode in (0, 1, 2, True):
            with self.assertRaises(ValueError): gate.validate(mode, True, True)
        for enabled in (1, None, 'yes'):
            with self.assertRaises(ValueError): gate.validate(3, True, enabled)
        with patch.object(boot.subprocess, 'check_output', return_value=RECIPE):
            for mode in range(4):
                self.assertNotIn('santonigpu_ui', boot.command_line('a'*40, mode))
            line = boot.command_line('a'*40, 3, render_test=True, ui_presentation=True)
            args = boot.command_args(line)
            for key in ('santonigpu_render', 'santonigpu_ui', 'santonigpu_stock',
                        'santonigpu_pixels', 'santonigpu_submit', 'santonigpu_session'):
                self.assertEqual(args[key], '1')
            self.assertEqual(args['cpus'], '4')
            self.assertNotIn('santonigpu_user', args)
            self.assertEqual(args['sweetfb_hz'], '30')
            sixty = boot.command_line('a'*40, 3, render_test=True, ui_presentation=True, ui_hz=60)
            self.assertEqual(boot.command_args(sixty), {**args, 'sweetfb_hz':'60'})
            self.assertLess(len(sixty.encode()), 608)
            for bad in (0, 31, 120, True, '60', None):
                with self.assertRaises(ValueError):
                    boot.command_line('a'*40, 3, render_test=True, ui_presentation=True, ui_hz=bad)
            for mode in range(4):
                with self.assertRaises(ValueError): boot.command_line('a'*40, mode, ui_hz=60)
        with patch.object(boot.subprocess, 'check_output', return_value=RECIPE.replace('cpus=8', 'cpus=8 santonigpu_ui=1')):
            with self.assertRaises(ValueError): boot.command_line('a'*40, 1)

    def test_UI_certificate_required_even_for_disabled_bridge(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            self.assertIsNone(gate.require_audit(folder, 'a'*40, 12, 'b'*64, False, False))
            with self.assertRaises(ValueError): gate.require_audit(folder, 'a'*40, 12, 'b'*64, False, True)
            for enabled in (False, True):
                with self.assertRaises(ValueError): gate.require_audit(folder, 'a'*40, 12, 'b'*64, True, enabled)
            record = dict(commit='a'*40, ci_run=12, kernel_sha256='b'*64,
                          success=True, hardware_verified=False, **{k:True for k in gate.CHECKS})
            from check_santoni_gpu_ui_kernel import CORE_CASES
            identity={k:record[k] for k in ('commit','ci_run','kernel_sha256')}
            for key,cases in (('core_results',CORE_CASES),('adapter_results',range(25)),('framebuffer_results',range(20))):
                record[key]=[{'case':c,'success':True,'identity':identity} for c in cases]
            record.update(cases=65,complete_UI_certificate=True)
            for key,file in (('tool_sha256','check_santoni_gpu_ui_kernel.py'),
                             ('framebuffer_tool_sha256','santoni_gpu_ui_framebuffer_audit.py'),
                             ('native_CPU_sha256','santoni_gpu_ui_native_cpu.py')):
                record[key]=hashlib.sha256((ROOT/'tools'/file).read_bytes()).hexdigest()
            path = folder / 'ui-binary-audit.json'
            path.write_text(json.dumps(record))
            gate.require_audit(folder, 'a'*40, 12, 'b'*64, True, True)
            wrong = [{**record, k: False} for k in gate.CHECKS]
            wrong += [{**record, 'commit':'c'*40}, {**record, 'ci_run':13},
                      {**record, 'kernel_sha256':'c'*64}, {**record, 'hardware_verified':True},
                      {**record, 'core_results':record['core_results'][:-1]},
                      {**record, 'tool_sha256':'c'*64}, {**record, 'cases':64},
                      {**record, 'complete_UI_certificate':False}]
            for r in wrong:
                path.write_text(json.dumps(r))
                with self.assertRaises(ValueError): gate.require_audit(folder, 'a'*40, 12, 'b'*64, True, True)


class UIEvidence(unittest.TestCase):
    def test_current_receipt_and_rejection_of_missing_mutant_or_changed_source(self):
        import verify_santoni_gpu_ui_evidence as intake
        record = json.loads((ROOT / 'tests/santoni_gpu_ui_host_evidence.json').read_text())
        result = intake.verify(record)
        self.assertEqual(result['positive_executions'], 195)
        self.assertEqual(result['compiled_rejected_mutants'], 12)
        self.assertIs(result['hardware_verified'], False)
        manifest = {'sha256': result['source_sha256']}
        variants = []
        r = copy.deepcopy(record); r['rows'].pop(); variants.append(r)
        r = copy.deepcopy(record); r['rows'][-1]['compile_exit'] = 1; variants.append(r)
        r = copy.deepcopy(record); r['rows'][-1]['runs'][0]['exit'] = 0; variants.append(r)
        r = copy.deepcopy(record); r['rows'][0]['runs'].pop(); variants.append(r)
        r = copy.deepcopy(record); r['identity']['core_sha256'] = 'c'*64; variants.append(r)
        r = copy.deepcopy(record); r['inputs'][intake.INPUTS[0]] = 'c'*64; variants.append(r)
        with patch('tests.reconstruct_santoni_touch.reconstruct', return_value=manifest):
            for r in variants:
                with self.assertRaises(ValueError): intake.verify(r)


if __name__ == '__main__': unittest.main()
