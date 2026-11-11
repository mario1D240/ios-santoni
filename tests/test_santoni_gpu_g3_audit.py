"""Synthetic decoded G3 gate negatives; not a new CI or hardware result."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import check_santoni_gpu_kernel as e
import santoni_gpu_g3_audit as g
from tests import test_santoni_gpu_pixel_audit as fixture
class Image:
    def read(self,address,size):
        literal=b'santonigpu_submit\0'
        return int.from_bytes(literal,'little') if (address,size)==(0x3000,len(literal)) else None
class G3AuditTests(unittest.TestCase):
    def options(self):
        lines=[x.replace('#96','#100') for x in fixture.PixelAuditTests().options()]
        i=lines.index('cmp w8, #1')
        return lines[:i]+['ldr w9, [x20, #96]','cmp w9, #1','b.ne @bad']+lines[i:]
    def test_exact_g3_options_and_negatives(self):
        names={'_PE_parse_boot_argn':{0x4000}}
        self.assertTrue(g.g3_options(fixture.decoded(self.options(),'_sgpu_g3_options'),Image(),names,e,e._Value(64,0x2000)))
        for old,new in (('cmp w19, #3','cmp w19, #2'),('cmp w8, #1','cmp w8, #2'),
                ('ldr w9, [x20, #96]','mov w9, #1'),('str wzr, [x20, #100]','nop')):
            with self.subTest(change=old),self.assertRaises(ValueError):
                g.g3_options(fixture.decoded([new if x==old else x for x in self.options()],
                             '_sgpu_g3_options'),Image(),names,e,e._Value(64,0x2000))
    def fence(self):
        lines=fixture.PixelAuditTests().fence()
        start=lines.index('ldr x0, [x20]')
        lines=['mov x19, x0','ldr x20, [x19]','mov x21, x1','mov w24, w2']+lines[start:]
        return [x.replace('mov w0, #1','mov w0, w24') for x in lines
                if x not in ('mov w24, #0x2d01','movk w24, #0xa505, lsl #16')]
    def test_sequence_deadline_and_stopped_clock_bound(self):
        self.assertEqual(g.g3_fence(fixture.decoded(self.fence(),'_sgpu_g3_wait'),Image(),{},e),6)
        for old,new in (('cmp w23, #2000','cmp w23, #1999'),('b.hs @bad','nop'),
                ('mov w0, w24','mov w0, #1'),('mov w2, #64','mov w2, #32')):
            with self.subTest(change=old),self.assertRaises(ValueError):
                g.g3_fence(fixture.decoded([new if x==old else x for x in self.fence()],
                           '_sgpu_g3_wait'),Image(),{},e)
    def test_partial_or_absent_helpers(self):
        self.assertIsNone(g.audit_g3({},Image(),{},e))
        for name in g.HELPERS:
            with self.assertRaises(ValueError):g.audit_g3({name:fixture.decoded(['ret'],name)},Image(),{},e)
if __name__=='__main__':unittest.main()
