"""The new API cannot silently gain a runtime caller or bypass ISA loading."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from santoni_gpu_render_audit import HELPERS, LIVE_HELPERS, LIVE_STORAGE, CP_HELPER, helpers, prepared_only, inspection_budget


class Code:
    def __init__(self, calls=()):
        self.calls = calls

    def calls_to(self, addresses):
        return [target for target in self.calls if target in addresses]


class RenderAuditTests(unittest.TestCase):
    def names(self):
        return {name: {0x1000 + i * 16} for i, name in enumerate(HELPERS)}

    def test_old_kernel_and_complete_prepared_namespace(self):
        self.assertEqual(helpers({}), ())
        self.assertEqual(helpers(self.names()), HELPERS)
        self.assertIsNone(prepared_only({}, {}))

    def test_missing_added_aliased_and_ambiguous_symbols_fail(self):
        original = self.names()
        for names in ({n: v for n, v in original.items() if n != HELPERS[0]},
                      {**original, '_sgpu_render_publish': {0x3000}},
                      {**original, HELPERS[0]: {0x1000, 0x2000}},
                      {**original, HELPERS[0]: original[HELPERS[1]]}):
            with self.assertRaises(ValueError):
                helpers(names)

    def test_existing_worker_cannot_start_rendering_without_new_wave(self):
        names = self.names(); target = next(iter(names['_sgpu_render_begin']))
        with self.assertRaisesRegex(ValueError, 'runtime caller'):
            prepared_only({'_sgpu_kernel_thread': Code([target])}, names)
        result = prepared_only({'_sgpu_render_begin': Code([target]), '_sgpu_kernel_thread': Code()}, names)
        self.assertIs(result['live_allocator_worker_and_display_integration'], False)

    def test_inspection_cap_expands_only_for_exact_new_roots(self):
        for launcher, session, old in ((True, True, 160), (False, True, 128), (False, False, 96)):
            self.assertEqual(inspection_budget({}, launcher, session), old)
            self.assertEqual(inspection_budget(self.names(), launcher, session), old + 12)
        with self.assertRaises(ValueError):
            inspection_budget({'_sgpu_render_unknown': {0x1234}}, True, True)

    def test_live_namespace_admits_only_the_worker_dispatch_boundary(self):
        names = {name: {0x1000 + i * 16} for i, name in enumerate((*HELPERS, *LIVE_HELPERS, *LIVE_STORAGE))}
        self.assertEqual(helpers(names), HELPERS + LIVE_HELPERS)
        target = next(iter(names['_sgpu_render_worker']))
        record = prepared_only({'_sgpu_kernel_thread': Code([target])}, names)
        self.assertIs(record['live_allocator_worker_present'], True)
        self.assertIs(record['display_integration'], False)
        self.assertIs(record['dedicated_live_binary_certificate_required'], True)
        bad = next(iter(names['_sgpu_render_begin']))
        with self.assertRaises(ValueError):
            prepared_only({'_sgpu_kernel_thread': Code([bad])}, names)

    def test_CP_helper_expands_only_the_live_namespace_and_cannot_gain_another_caller(self):
        names = {name: {0x1000+i*16} for i,name in enumerate((*HELPERS,*LIVE_HELPERS,*LIVE_STORAGE,CP_HELPER))}
        self.assertEqual(helpers(names), HELPERS+LIVE_HELPERS+(CP_HELPER,))
        self.assertEqual(inspection_budget(names,True,True),160+len(HELPERS)+len(LIVE_HELPERS)+1)
        target=next(iter(names[CP_HELPER]))
        prepared_only({'_sgpu_render_live_state':Code([target])},names)
        with self.assertRaises(ValueError): prepared_only({'_sgpu_kernel_thread':Code([target])},names)
        with self.assertRaises(ValueError): helpers({**self.names(),CP_HELPER:{0x8000}})

    def owned_names(self):
        from tests.test_santoni_gpu_graphics_gates import GraphicsGates
        names=GraphicsGates().wide_names()
        names.update({name:{0x50000+i*32} for i,name in
                      enumerate((*HELPERS,*LIVE_HELPERS,*LIVE_STORAGE,CP_HELPER))})
        return names

    def test_owned_graphics_handoff_has_only_three_exact_render_rights(self):
        names=self.owned_names();address=lambda name:next(iter(names[name]))
        permitted=('_sgpu_render_overlap','_sgpu_render_live_tables','_sgpu_render_live_state')
        prepared_only({'_sgpu_graphics_hw_begin_owned':Code([address(n) for n in permitted]),
                       '_sgpu_graphics_hw_state':Code([address(CP_HELPER)])},names)
        for caller in ('_sgpu_graphics_hw_begin','_sgpu_graphics_hw_begin_vm',
                       '_sgpu_graphics_vm_begin','_sgpu_kernel_thread','_sgpu_user_ioctl','_unreviewed_worker'):
            for target in permitted:
                with self.subTest(caller=caller,target=target),self.assertRaises(ValueError):
                    prepared_only({caller:Code([address(target)])},names)
        for target in ('_sgpu_render_begin','_sgpu_render_live_job','_sgpu_render_new',
                       '_sgpu_render_abort','_sgpu_render_worker',CP_HELPER):
            with self.subTest(target=target),self.assertRaises(ValueError):
                prepared_only({'_sgpu_graphics_hw_begin_owned':Code([address(target)])},names)

    def test_owned_graphics_rights_require_complete_nonaliased_wide_and_live_names(self):
        names=self.owned_names()
        target=next(iter(names['_sgpu_render_overlap']))
        graphs={'_sgpu_graphics_hw_begin_owned':Code([target])}
        missing=('_sgpu_graphics_hw_begin_owned','_sgpu_graphics_hw_begin_vm','_gvm_prepare',
                 '_sgpu_ir3_reg','_sgpu_raster_check_state',CP_HELPER)
        for name in missing:
            with self.subTest(missing=name),self.assertRaises(ValueError):
                prepared_only(graphs,{n:v for n,v in names.items() if n!=name})
        for changed in ({**names,'_sgpu_graphics_bypass':{0x80000}},
                        {**names,'_sgpu_graphics_hw_begin_owned':{0x80000,0x90000}},
                        {**names,'_sgpu_graphics_hw_begin_owned':names['_sgpu_render_begin']}):
            with self.assertRaises(ValueError):prepared_only(graphs,changed)


if __name__ == '__main__':
    unittest.main()
