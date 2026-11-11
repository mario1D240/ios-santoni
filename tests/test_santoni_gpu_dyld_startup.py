"""Synthetic graph regression tests; actual-word evidence is separate."""
import copy,re,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools')]
import check_santoni_gpu_kernel as e
from santoni_gpu_dyld_startup_audit import audit_startup,inspection_helpers,BOOT,BSD,REGISTER,VFS,USER,FLAGS,COLD

class StartupGraph(unittest.TestCase):
    def test_exact_startup_inspection_inventory(self):
        names={FLAGS:{0x8000},BOOT:{0x1000},BSD:{0x4000},
            **{n:{0x9000+i*32} for i,n in enumerate(COLD)}}
        self.assertEqual(inspection_helpers(names),(BOOT,BSD,*COLD))
        self.assertEqual(inspection_helpers({}),())
        for symbol in (BOOT,BSD,*COLD):
            with self.subTest(ambiguous=symbol),self.assertRaises(ValueError):
                inspection_helpers({**names,symbol:{0x10000,0x10020}})
        for symbol in (BOOT,BSD):
            with self.subTest(missing=symbol),self.assertRaises(ValueError):
                inspection_helpers({k:v for k,v in names.items() if k!=symbol})
        for unknown in ('_bsd_init.cold.0','_bsd_init.cold.6','_bsd_init.cold.99','_bsd_init.cold.bad'):
            with self.subTest(unknown=unknown),self.assertRaises(ValueError):
                inspection_helpers({**names,unknown:{0x10000}})
        with self.assertRaises(ValueError):inspection_helpers({**names,COLD[0]:names[BSD]})
        self.assertEqual(inspection_helpers({FLAGS:{0x8000},BOOT:{0x1000},BSD:{0x4000}}),(BOOT,BSD))

    def test_inspection_budget_counts_only_reviewed_dyld_startup_roots(self):
        from tests.test_santoni_gpu_graphics_gates import GraphicsGates
        from santoni_gpu_graphics_audit import RENDERER_TASK,DYLD_POLICY,DYLD_REGISTER,helpers
        from santoni_gpu_render_audit import inspection_budget
        names={**GraphicsGates().wide_names(),RENDERER_TASK:{0x24000},FLAGS:{0x24100},
            DYLD_POLICY:{0x24200},DYLD_REGISTER:{0x24300},BOOT:{0x24400},BSD:{0x24500},
            **{n:{0x24600+i*32} for i,n in enumerate(COLD)}}
        self.assertEqual(inspection_budget(names,True,True),160+len(helpers(names))+7)
        with self.assertRaises(ValueError):inspection_budget({**names,'_bsd_init.cold.6':{0x25000}},True,True)

    def decoded(self,lines,symbol,base):
        labels={};pc=base
        for line in lines:
            if line.endswith(':'):labels[line[:-1]]=pc
            else:pc+=4
        output=[f'{base:x} <{symbol}>:'];pc=base
        for line in lines:
            if line.endswith(':'):continue
            line=re.sub(r'@(\w+)',lambda match:hex(labels[match[1]]),line)
            output.append(f'{pc:x}: d503201f {line}');pc+=4
        return e._Code('\n'.join(output),symbol,base)

    def fixture(self,bsd=None,boot=None):
        names={BOOT:{0x1000},BSD:{0x4000},VFS:{0x5000},REGISTER:{0x6000},USER:{0x7000}}
        first=self.decoded(boot or ['bl 0x4000','ret'],BOOT,0x1000)
        second=self.decoded(bsd or ['bl 0x5000','bl 0x6000','bl 0x7000','ret'],BSD,0x4000)
        return {BOOT:first,BSD:second},names

    def test_order_and_failure_branch_reachability(self):
        codes,names=self.fixture();result=audit_startup(codes,names)
        self.assertTrue(result['registration_dominates_initial_user_bootstrap'])
        self.assertFalse(result['hardware_verified'])
        codes,names=self.fixture(['cbz w0, @fail','bl 0x5000','bl 0x6000','bl 0x7000','ret','fail:','ret'])
        self.assertTrue(audit_startup(codes,names)['success'])

    def test_missing_duplicate_reordered_and_conditional_calls_refused(self):
        cases=[['bl 0x5000','bl 0x7000','ret'],
            ['bl 0x5000','bl 0x6000','bl 0x6000','bl 0x7000','ret'],
            ['bl 0x6000','bl 0x5000','bl 0x7000','ret'],
            ['bl 0x5000','bl 0x7000','bl 0x6000','ret'],
            ['bl 0x5000','cbnz w0, @user','bl 0x6000','user:','bl 0x7000','ret'],
            ['cbnz w0, @register','bl 0x5000','register:','bl 0x6000','bl 0x7000','ret']]
        for body in cases:
            with self.subTest(body=body),self.assertRaises(ValueError):audit_startup(*self.fixture(body))
        for body in (['ret'],['bl 0x4000','bl 0x4000','ret'],['bl 0x4000','bl 0x7000','ret']):
            with self.subTest(boot=body),self.assertRaises(ValueError):audit_startup(*self.fixture(boot=body))

    def test_symbol_and_complete_root_requirements(self):
        codes,names=self.fixture()
        for symbol in names:
            changed={k:v for k,v in names.items() if k!=symbol}
            with self.subTest(missing=symbol),self.assertRaises(ValueError):audit_startup(codes,changed)
            changed={**names,symbol:{0x4000,0x8000}}
            with self.subTest(ambiguous=symbol),self.assertRaises(ValueError):audit_startup(codes,changed)
        for symbol in (BOOT,BSD):
            with self.subTest(root=symbol),self.assertRaises(ValueError):audit_startup({k:v for k,v in codes.items() if k!=symbol},names)
            changed={**codes,symbol:copy.copy(codes[symbol])};changed[symbol].entry+=4
            with self.subTest(wrong_entry=symbol),self.assertRaises(ValueError):audit_startup(changed,names)
            changed={**codes,symbol:copy.copy(codes[symbol])};changed[symbol].symbol='_other'
            with self.subTest(wrong_symbol=symbol),self.assertRaises(ValueError):audit_startup(changed,names)

if __name__=='__main__':unittest.main()
