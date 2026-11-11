"""Closed graphics namespace/caller and exact recorded-evidence rejection gates."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import santoni_gpu_graphics_audit as audit
import verify_santoni_gpu_graphics_evidence as intake
import check_santoni_gpu_kernel as decoder

class Code:
    def __init__(self,targets=()):self.targets=set(targets)
    def calls_to(self,targets):return self.targets&set(targets)

class GraphicsGates(unittest.TestCase):
    def names(self):
        names={n:{0x1000+i*32} for i,n in enumerate(audit.GRAPHICS+audit.HW+audit.PM4+audit.CALLBACKS+audit.ADAPTER+audit.STORAGE)}
        names.update({n:{0x8000+i*32} for i,n in enumerate(audit.IOKIT_METHODS+audit.GLOBAL_CTORS)})
        return names

    def test_namespace_refuses_missing_ambiguous_and_new_helpers(self):
        names=self.names();self.assertTrue(audit.helpers(names));self.assertEqual(audit.helpers({}),())
        for changed in [{**names,'_sgpu_graphics_bypass':{0x7000}},
                        {**names,audit.CALLBACK_NAMES['map']:{0x8000,0x9000}},
                        {k:v for k,v in names.items() if k!='_sgpu_pm4_prepare'},
                        {**names,'__ZN21SantoniGraphicsClient12bypassPolicyEv':{0x8000}}]:
            with self.assertRaises(ValueError):audit.helpers(changed)

    def test_only_reviewed_kernel_callers_reach_graphics(self):
        names=self.names();address=lambda n:next(iter(names[n]))
        audit.caller_boundary({'_sgpu_render_worker':Code([address('_sgpu_graphics_hw_begin')])},names)
        for caller in ('_sgpu_user_ioctl','_sgpu_kernel_thread','_unreviewed_worker','_unreviewed_SantoniGraphics_worker'):
            with self.assertRaises(ValueError):audit.caller_boundary({caller:Code([address('_sgpu_graphics_hw_begin')])},names)
        with self.assertRaises(ValueError):audit.caller_boundary({'_sgpu_render_worker':Code([address('_sgpu_graphics_submit')])},names)

    def wide_names(self):
        names=self.names();names.pop(audit.CALLBACK_NAMES['validate'])
        names[audit.WIDE_CALLBACK_NAMES['validate']]={0x9000}
        extra=audit.WIDE_HW+audit.WIDE_PM4+audit.VM+audit.VM_ADAPTER+audit.VM_STORAGE+audit.IR3+audit.DESCRIPTORS+audit.RASTER
        names.update({n:{0xa000+i*32} for i,n in enumerate(extra)})
        return names

    def test_wide_raster_namespace_is_complete_and_closed(self):
        names=self.wide_names();functions=audit.helpers(names);self.assertTrue(functions)
        for storage in audit.STORAGE+audit.VM_STORAGE:self.assertNotIn(storage,functions)
        for function in audit.IR3+audit.DESCRIPTORS+audit.RASTER:self.assertIn(function,functions)
        for absent in ('_gvm_memory_valid','_sgpu_ir3_reg','_sgpu_raster_check_state','_sgpu_graphics_hw_fence_va',
                       audit.WIDE_CALLBACK_NAMES['validate']):
            with self.subTest(absent=absent),self.assertRaises(ValueError):
                audit.helpers({k:v for k,v in names.items() if k!=absent})
        for unknown in ('_gvm_bypass','_sgpu_ir3_bypass','_sgpu_raster_bypass','_sgpu_descriptor_bypass'):
            with self.subTest(unknown=unknown),self.assertRaises(ValueError):
                audit.helpers({**names,unknown:{0x20000}})
        with self.assertRaises(ValueError):audit.helpers({**names,'_sgpu_ir3_reg':{0x20000,0x30000}})
        with self.assertRaises(ValueError):audit.helpers({**names,audit.CALLBACK_NAMES['validate']:{0x20000}})

    def test_renderer_helper_namespace_and_caller_scope(self):
        names={**self.wide_names(),audit.RENDERER_TASK:{0x24000}}
        self.assertIn(audit.RENDERER_TASK,audit.helpers(names))
        codes={caller:Code(names[audit.RENDERER_TASK]) for caller in audit.RENDERER_CALLERS}
        result=audit.caller_boundary(codes,names)
        self.assertTrue(result['renderer_identity_helper_present'])
        self.assertFalse(result['renderer_client_wiring_verified'])
        for missing in audit.RENDERER_CALLERS:
            with self.subTest(missing=missing),self.assertRaises(ValueError):
                audit.caller_boundary({k:v for k,v in codes.items() if k!=missing},names)
        with self.assertRaises(ValueError):audit.caller_boundary({**codes,'_unreviewed':Code({0x24000})},names)
        with self.assertRaises(ValueError):audit.helpers({**self.names(),audit.RENDERER_TASK:{0x24000}})
        with self.assertRaises(ValueError):audit.helpers({**names,audit.RENDERER_TASK:{0x24000,0x25000}})
        with self.assertRaises(ValueError):audit.helpers({**names,'__ZL21gfx_renderer_bypassPv':{0x25000}})

    def test_wide_vm_role_boundary_is_specific(self):
        names=self.wide_names();address=lambda n:next(iter(names[n]))
        audit.caller_boundary({'_sgpu_render_worker':Code([address('_sgpu_graphics_vm_begin')]),
            '_sgpu_graphics_vm_begin':Code([address('_sgpu_graphics_hw_begin_vm')]),
            '_sgpu_graphics_vm_page':Code([address('_sgpu_graphics_vm_owns')]),
            '_sgpu_graphics_vm_reserved':Code([address('_sgpu_graphics_hw_legacy_reserved')])},names)
        for caller,target in (('_sgpu_render_worker','_sgpu_graphics_hw_begin_vm'),
                ('_sgpu_render_worker','_sgpu_graphics_submit'),('_sgpu_graphics_vm_begin','_sgpu_graphics_submit'),
                ('_unreviewed_worker','_sgpu_graphics_vm_begin'),('_unreviewed_worker','_sgpu_raster_prepare_batch'),
                ('_sgpu_user_ioctl','_gvm_prepare'),('_sgpu_raster_check_state','_sgpu_graphics_hw_publish'),
                ('_sgpu_ir3_reg','_sgpu_graphics_new'),('_gvm_verify','_sgpu_graphics_vm_begin')):
            with self.subTest(caller=caller,target=target),self.assertRaises(ValueError):
                audit.caller_boundary({caller:Code([address(target)])},names)

    def test_dyld_boundaries_require_renderer_identity_and_closed_callers(self):
        names={**self.wide_names(),audit.RENDERER_TASK:{0x24000},audit.DYLD_FLAGS:{0x24100},
            audit.DYLD_POLICY:{0x24200},audit.DYLD_REGISTER:{0x24300}}
        functions=audit.helpers(names)
        for symbol in (audit.DYLD_FLAGS,audit.DYLD_POLICY,audit.DYLD_REGISTER):self.assertIn(symbol,functions)
        codes={caller:Code(names[audit.RENDERER_TASK]) for caller in audit.RENDERER_CALLERS+(audit.DYLD_FLAGS,)}
        codes[audit.DYLD_POLICY]=Code(names[audit.DYLD_FLAGS])
        audit.caller_boundary(codes,names)
        for missing in (audit.RENDERER_TASK,audit.DYLD_FLAGS,audit.DYLD_POLICY,audit.DYLD_REGISTER):
            with self.subTest(missing=missing),self.assertRaises(ValueError):audit.helpers({k:v for k,v in names.items() if k!=missing})
        with self.assertRaises(ValueError):audit.helpers({**names,'_santoni_gpu_graphics_bypass':{0x25000}})
        with self.assertRaises(ValueError):audit.helpers({**names,audit.DYLD_POLICY:{0x24200,0x24400}})
        for symbol in (audit.DYLD_FLAGS,audit.DYLD_POLICY):
            with self.subTest(symbol=symbol),self.assertRaises(ValueError):audit.caller_boundary({**codes,symbol:Code()},names)
        with self.assertRaises(ValueError):audit.caller_boundary({**codes,'_unreviewed':Code(names[audit.DYLD_FLAGS])},names)
        traced={**names,**{n:{0x25000+16*i} for i,n in enumerate(audit.DYLD_TRACE)}}
        self.assertTrue(set(audit.DYLD_TRACE)<=set(audit.helpers(traced)))
        for missing in audit.DYLD_TRACE:
            with self.subTest(missing=missing),self.assertRaises(ValueError):
                audit.helpers({k:v for k,v in traced.items() if k!=missing})
        with self.assertRaises(ValueError):audit.helpers({**traced,'_santoni_gpu_dyld_trace_bypass':{0x26000}})
        for target in audit.DYLD_TRACE:
            with self.subTest(target=target),self.assertRaises(ValueError):
                audit.caller_boundary({**codes,'_unreviewed':Code(traced[target])},traced)

    def test_worker_getter_executes_acquire_and_rejects_wrong_word_or_plain_load(self):
        class Image:
            segs=()
            def read(self,address,size):return None
        symbol='_santoni_gpu_graphics_worker_ready'
        names={symbol:{0x1000},'_sgpu_graphics_published':{0x3000}}
        def code(load='ldar',address=0x3000,compare=1):
            text=f'''0000000000001000 <{symbol}>:
 1000: d2800008 mov x8, #{address}
 1004: 88dffd08 {load} w8, [x8]
 1008: 7100051f cmp w8, #{compare}
 100c: 1a9f17e0 cset w0, eq
 1010: d65f03c0 ret
'''
            return decoder._Code(text,symbol,0x1000)
        good=audit.worker_getter({symbol:code()},Image(),names,decoder)
        self.assertEqual(len(good['cases']),4)
        for bad in (code(load='ldr'),code(address=0x3004),code(compare=0)):
            with self.assertRaises(ValueError):audit.worker_getter({symbol:bad},Image(),names,decoder)

    def test_native_receipts_bind_input_inventory_and_actual_source(self):
        for kind,cases in [('graphics',45),('pm4',46)]:
            record=json.loads((ROOT/'tests'/('santoni_gpu_'+kind+'_host_evidence.json')).read_text())
            module=__import__('tests.test_santoni_gpu_'+kind,fromlist=['FILES'])
            with patch('tests.reconstruct_santoni_touch.reconstruct',return_value={'sha256':record['source_sha256']}):
                self.assertEqual(intake.verify(record,kind)['positive_executions'],cases*3)
                bad=[]
                r=copy.deepcopy(record);r['rows'].pop();bad.append(r)
                r=copy.deepcopy(record);r['rows'][0]['runs'].pop();bad.append(r)
                r=copy.deepcopy(record);r['rows'][-1]['compile_exit']=1;bad.append(r)
                r=copy.deepcopy(record);r['rows'][-1]['runs'][-1]['exit_code']=0;bad.append(r)
                r=copy.deepcopy(record);r['source_sha256'][module.FILES[-1]]='f'*64;bad.append(r)
                r=copy.deepcopy(record);r['hardware_verified']=True;bad.append(r)
                for r in bad:
                    with self.assertRaises(ValueError):intake.verify(r,kind)

if __name__=='__main__':unittest.main()
