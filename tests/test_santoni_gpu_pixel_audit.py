"""Decoded pixel-option negatives, not hardware evidence or a kernel image."""
import re
import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import check_santoni_gpu_kernel as e
import santoni_gpu_pixel_audit as p

class Image:
    def read(self,address,size):
        literal=b'santonigpu_pixels\0'
        return int.from_bytes(literal,'little') if (address,size)==(0x3000,len(literal)) else None

def decoded(lines,symbol='_sgpu_pixel_options'):
    labels={}; pc=0x1000
    for line in lines:
        if line.endswith(':'): labels[line[:-1]]=pc
        else: pc+=4
    output=[f'1000 <{symbol}>:']; pc=0x1000
    for line in lines:
        if line.endswith(':'): continue
        line=re.sub(r'@(\w+)',lambda m:hex(labels[m[1]]),line)
        output.append(f'{pc:x}: d503201f {line}'); pc+=4
    return e._Code('\n'.join(output),symbol,0x1000)

class PixelAuditTests(unittest.TestCase):
    def options(self):
        return ['mov w19, w0','mov x20, #0x2000','str wzr, [x20, #96]',
                'sub sp, sp, #16','str wzr, [sp]','mov x0, #0x3000','mov x1, sp',
                'mov w2, #4','bl 0x4000','ldr w8, [sp]','cbz w8, @good',
                'cmp w19, #3','b.ne @bad','ldr w9, [x20, #88]','cmp w9, #1','b.ne @bad',
                'cmp w8, #1','b.ne @bad','mov w8, #1','str w8, [x20, #96]',
                'good:','mov w0, #1','add sp, sp, #16','ret',
                'bad:','mov w0, #0','add sp, sp, #16','ret']

    def test_independent_pixel_option_and_rejections(self):
        names={'_PE_parse_boot_argn':{0x4000}}
        self.assertTrue(p.pixel_options(decoded(self.options()),Image(),names,e,e._Value(64,0x2000)))
        changes=(('str wzr, [x20, #96]','nop'),('cmp w19, #3','cmp w19, #2'),
                 ('cmp w9, #1','cmp w9, #0'),('cmp w8, #1','cmp w8, #2'),
                 ('mov x0, #0x3000','mov x0, #0x3004'),('mov w2, #4','mov w2, #8'),
                 ('str w8, [x20, #96]','nop'))
        for old,new in changes:
            lines=[new if line==old else line for line in self.options()]
            with self.subTest(change=old),self.assertRaises(ValueError):
                p.pixel_options(decoded(lines),Image(),names,e,e._Value(64,0x2000))

    def test_no_or_partial_pixel_helpers_fail_closed(self):
        self.assertIsNone(p.audit_pixels({},Image(),{},e))
        for name in p.HELPERS:
            with self.assertRaises(ValueError):
                p.audit_pixels({name:decoded(['ret'],name)},Image(),{name:{0x1000}},e)

    def fence(self):
        return ['mov x19, x0','ldr x20, [x19]','ldr x21, [x19, #16]',
                'add x21, x21, #0x4000','add x21, x21, #768',
                'ldr x0, [x20]','ldr x8, [x20, #48]','blr x8','mov x22, x0',
                'mov w23, #0','mov w24, #0x2d01','movk w24, #0xa505, lsl #16',
                'loop:','ldr x0, [x20]','mov x1, x21','mov w2, #64',
                'ldr x8, [x20, #88]','blr x8','ldr w8, [x21]',
                'cmp w8, w24','b.eq @good',
                'ldr x0, [x20]','ldr x8, [x20, #48]','blr x8','sub x8, x0, x22',
                'mov x9, #0x0d40','movk x9, #3, lsl #16','cmp x8, x9','b.hs @bad',
                'cmp w23, #2000','b.eq @bad',
                'ldr x0, [x20]','mov w1, #100','ldr x8, [x20, #56]','blr x8',
                'add w23, w23, #1','b @loop',
                'good:','mov w0, #1','ret',
                'bad:','ldr x9, [x19, #8]','ldr w8, [x9, #4]','cbnz w8, @done',
                'mov w8, #11','str w8, [x9, #4]',
                'done:','mov w0, #0','ret']

    def test_decoded_fence_deadline_cap_cache_and_error(self):
        self.assertEqual(p.pixel_fence(decoded(self.fence(),'_sgpu_pixel_fence'),Image(),{},e),6)
        for old,new in (('cmp w23, #2000','cmp w23, #1999'),
                        ('mov w24, #0x2d01','mov w24, #0x2d02'),
                        ('mov w2, #64','mov w2, #32'),
                        ('b.hs @bad','nop'),('mov w8, #11','mov w8, #16'),
                        ('cbnz w8, @done','nop')):
            with self.subTest(change=old),self.assertRaises(ValueError):
                p.pixel_fence(decoded([new if line==old else line for line in self.fence()],
                                     '_sgpu_pixel_fence'),Image(),{},e)

if __name__=='__main__': unittest.main()
