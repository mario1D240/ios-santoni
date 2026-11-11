"""Synthetic decoded negative oracles; never a certificate for a real kernel."""
import sys
from pathlib import Path
import hashlib
import re
import subprocess
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import check_santoni_gpu_kernel as e
import santoni_gpu_stock_audit as stock


class EmptyImage:
    def read(self, address, size):
        return None


def code(instructions, name='_sgpu_stock_write_allowed'):
    text = '1000 <' + name + '>:\n' + '\n'.join(
        f'{0x1000 + i*4:x}: d503201f {op}' for i, op in enumerate(instructions))
    return e._Code(text, name, 0x1000)


class StockAuditTests(unittest.TestCase):
    def test_actual_14f03ac_stock_wiring_and_decoded_mutants_when_available(self):
        kernel=Path(__file__).resolve().parents[1]/'out/ci-14f03ac/kernel/kernel.development.santoni'
        if not kernel.is_file(): self.skipTest('optional exact CI kernel absent')
        self.assertEqual(hashlib.sha256(kernel.read_bytes()).hexdigest(),
                         '3870acd756119af56e6e913e440965f07c8fbfe56e2f312d5a5939796dbecf4b')
        names=e._symbols(subprocess.check_output(['llvm-nm','--defined-only',str(kernel)],text=True))
        image=e._Image(kernel.read_bytes())
        targets=(*stock.HELPERS,'_checked_write32','_sgpu_io_write32',
                 '_sgpu_kernel_thread','_sgpu_probe','_faults')
        assembly={name:subprocess.check_output(['llvm-objdump','--disassemble','--disassemble-zeroes',
                  '--disassemble-symbols='+name,str(kernel)],text=True) for name in targets}
        def decode(texts):
            return {name:e._Code(text,name,next(iter(names[name])),
                                noreturn=names.get('___stack_chk_fail',())) for name,text in texts.items()}
        codes=decode(assembly)
        result=stock.audit_stock(codes,image,names,e)
        self.assertTrue(result['no_post_attempt_MMIO_or_cleanup'])
        self.assertTrue(result['fault_status_rejection_checked'])
        self.assertEqual(len(result['fresh_guard_failure_edges']),11)
        self.assertFalse(result['hardware_permission_or_safety_verified'])
        # Decode deliberate instruction mutations, never modify the real kernel.
        transition=codes['_sgpu_stock_transition']
        guarded=transition.calls_to(names['_sgpu_stock_check32'])[0]+4
        fresh_value=next(pc for pc,(op,args) in transition.ins.items()
                         if op=='mov' and args==('w3','#0x4b'))
        for pc in (guarded,fresh_value):
            altered=dict(assembly)
            altered[transition.symbol],count=re.subn(r'(?m)^(\s*'+f'{pc:x}'+r':)\s+.*$',
                r'\1 d503201f nop',altered[transition.symbol])
            self.assertEqual(count,1)
            with self.subTest(instruction=hex(pc)), self.assertRaises(ValueError):
                stock.audit_stock(decode(altered),image,names,e)

    def test_call_site_listing_is_address_ordered_not_set_iteration_order(self):
        fixture=code(['bl 0x2000','nop','bl 0x2000','ret'])
        fixture.reachable=list(reversed(sorted(fixture.reachable)))
        self.assertEqual(fixture.calls_to({0x2000}),[0x1000,0x1008])
        self.assertEqual(fixture.calls_to({0x2000},{0x1008:None,0x1000:None}),[0x1000,0x1008])

    def permission_code(self):
        ins = []
        for reg, value in (('w0',3),('w1',1),('w2',4),('w3',0x3d000),('w4',0)):
            ins += [f'cmp {reg}, #{value}', 'b.ne 0x1030']
        return ins + ['mov w0, #1', 'ret', 'mov w0, #0', 'ret']

    def test_decoded_permission_truth_table_and_each_missing_guard(self):
        original = self.permission_code()
        self.assertEqual(stock.permission_cases(code(original), EmptyImage(), {}, e), 864)
        for i in range(5):
            mutated = original.copy(); mutated[2*i+1] = 'nop'
            with self.subTest(guard=i), self.assertRaisesRegex(ValueError, 'permission'):
                stock.permission_cases(code(mutated), EmptyImage(), {}, e)
        for i in range(5):
            mutated = original.copy(); mutated[2*i] = original[2*i].replace('#', '#1', 1)
            with self.subTest(wrong_value=i), self.assertRaises(ValueError):
                stock.permission_cases(code(mutated), EmptyImage(), {}, e)

    def test_stock_audit_does_not_accept_partial_boundary_sets(self):
        self.assertIsNone(stock.audit_stock({}, EmptyImage(), {}, e))
        for name in stock.HELPERS:
            with self.subTest(name=name), self.assertRaises(ValueError):
                stock.audit_stock({name: code(['ret'], name)}, EmptyImage(), {name:{0x1000}}, e)

    def test_indexed_addresses_preserve_width_and_reject_unknown_forms(self):
        s = e._State({'x1':e._Value(64,0x1000), 'x2':e._Value(64,0xffffffff00000003)})
        self.assertEqual(s.address('[x1, w2, uxtw #3]')[0], e._Value(64,0x1018))
        s.put('x2',e._Value(64,4))
        self.assertEqual(s.address('[x1, x2, lsl #2]')[0],e._Value(64,0x1010))
        for text in ('[x1, w2, sxtw #3]', '[x1, w2]', '[x1, x2, uxtw #3]', '[x1, x9, lsl #3]'):
            self.assertIsNone(s.address(text)[0])

    def test_unresolved_return_cannot_pass(self):
        flow=e._Flow(code(['ret']),EmptyImage(),{})
        with self.assertRaises(ValueError):
            stock._single_return(flow,e)

    def test_extended_address_arithmetic_is_zero_extended_not_signed(self):
        fixture=code(['add x0, x1, w2, uxtw', 'ret'])
        state=e._initial(fixture.symbol)
        state.put('x1',e._Value(64,0x1000)); state.put('x2',e._Value(64,0xffffffff80000003))
        flow=e._Flow(fixture,EmptyImage(),{},initial=state)
        self.assertEqual(flow.before[0x1004].get('x0'), e._Value(64,0x80001003))

    def test_fresh_read_helper_rejects_wrong_mask_and_constant_success(self):
        ins=['mov x19, x0','mov w20, w3','ldr x8, [x19]','ldr x9, [x8, #16]',
             'ldr x0, [x8]','blr x9','cmp w0, w20','cset w0, eq','ret']
        self.assertEqual(stock.check32_cases(code(ins,'_sgpu_stock_check32'),EmptyImage(),{},e),1)
        for change in ('mov w0, #1','cset w0, ne'):
            mutant=ins.copy(); mutant[7]=change
            with self.assertRaises(ValueError):
                stock.check32_cases(code(mutant,'_sgpu_stock_check32'),EmptyImage(),{},e)

    def test_last_pre_store_read_must_still_be_one(self):
        ins=['mov x19, x0','ldr x8, [x19]','ldr x9, [x8, #16]',
             'ldr x0, [x8]','blr x9','cmp w0, #1','b.ne FAIL',
             'ldr x8, [x19]','ldr x9, [x8, #32]','ldr x0, [x8]',
             'mov w3, #0','blr x9','ldr x8, [x19]','ldr x9, [x8, #16]',
             'ldr x0, [x8]','blr x9','mov w0, #1','ret','mov w0, #0','ret']
        ins[6]=f'b.ne {0x1000+18*4:#x}'
        result=stock.write_precondition_cases(code(ins,'_checked_write32'),EmptyImage(),{},e)
        self.assertTrue(result['old_must_equal_one'])
        for index,replacement in ((5,'cmp w0, #2'),(6,'nop'),(18,'mov w0, #1')):
            mutant=ins.copy(); mutant[index]=replacement
            with self.assertRaises(ValueError):
                stock.write_precondition_cases(code(mutant,'_checked_write32'),EmptyImage(),{},e)


if __name__ == '__main__':
    unittest.main()
