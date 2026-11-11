"""Actual library screen: unknown bytes/ISA aliases/holes must refuse."""
import struct
import re
import shutil
import subprocess
from pathlib import Path
import tempfile
import unittest
from tools.check_santoni_graphics_library import metadata,screen,forbidden,uleb

def fixture():
    # A minimal plain-arm64/iOS16 dylib, two functions and one ordinary stub.
    section=lambda name,address,bytes_,offset,flags:struct.pack('<16s16sQQ8I',name,b'__TEXT',address,bytes_,offset,2,0,0,flags,0,0,0)
    segment=struct.pack('<II16s4Q4I',0x19,232,b'__TEXT',0,0x8000,0,0x4070,5,5,2,0)
    segment+=section(b'__text',0x4000,32,0x4000,0x80000400)+section(b'__stubs',0x4020,12,0x4020,0x80000408)
    name=b'/usr/lib/libSystem.B.dylib\0';length=(24+len(name)+7)&~7
    dylib=struct.pack('<6I',0xc,length,24,0,0,0)+name+b'\0'*(length-24-len(name))
    symtab=struct.pack('<6I',2,24,0x4030,1,0x4040,8)
    starts=struct.pack('<4I',0x26,16,0x4060,8)
    version=struct.pack('<6I',0x32,24,2,0x100000,0x120000,0)
    commands=segment+dylib+symtab+starts+version
    data=bytearray(0x4070);data[:32]=struct.pack('<8I',0xfeedfacf,0x100000c,0,6,5,len(commands),0,0)
    data[32:32+len(commands)]=commands
    words=[0xd65f03c0,0,0,0,0xd65f03c0,0xd503201f,0xd503201f,0xd503201f,
           0x90000010,0xf9400210,0xd61f0200]
    for i,word in enumerate(words):struct.pack_into('<I',data,0x4000+i*4,word)
    data[0x4030:0x4040]=struct.pack('<IBBHQ',1,1,0,1<<8,0)
    data[0x4040:0x4048]=b'\0_abort\0'
    data[0x4060:0x4068]=b'\x80\x80\x01\x10\0\0\0\0'
    descriptions=[('ret',''),('udf','#0'),('udf','#0'),('udf','#0'),('ret',''),('nop',''),('nop',''),('nop',''),
                  ('adrp','x16, 0x0'),('ldr','x16, [x16]'),('br','x16')]
    lines=['Disassembly of section __TEXT,__text:\n']
    for i,(op,body) in enumerate(descriptions):
        if i==8:lines.append('Disassembly of section __TEXT,__stubs:\n')
        lines.append(f'{0x4000+i*4:x}: {words[i]:08x} {op} {body}\n')
    return data,lines

def noreturn_fixture():
    data,lines=fixture();commands=bytes(data[32:32+struct.unpack_from('<I',data,20)[0]])
    dynamic=[0xb,80]+[0]*18;dynamic[14]=0x4050;dynamic[15]=2
    got=struct.pack('<II16s4Q4I',0x19,152,b'__DATA_CONST',0x5000,0x1000,0x4070,8,3,3,1,0)
    got+=struct.pack('<16s16sQQ8I',b'__got',b'__DATA_CONST',0x5000,8,0x4070,3,0,0,6,1,0,0)
    commands+=struct.pack('<20I',*dynamic)+got
    data.extend(b'\0'*8);struct.pack_into('<II',data,16,7,len(commands));data[32:32+len(commands)]=commands
    struct.pack_into('<Q',data,32+32,0x5000) # TEXT VM extent ends before DATA_CONST.
    struct.pack_into('<I',data,32+72+80+72,12) # actual stub width.
    struct.pack_into('<2I',data,0x4050,0,0)
    struct.pack_into('<3I',data,0x4020,0xb0000010,0xf9400210,0xd61f0200)
    lines[10]='4020: b0000010 adrp x16, 0x5000\n'
    lines[11]='4024: f9400210 ldr x16, [x16]\n'
    return data,lines

class LibraryScreen(unittest.TestCase):
    def test_actual_word_coverage_and_dependencies(self):
        data,lines=fixture();info=metadata(data);result=screen(data,info,lines)
        self.assertEqual(result['instructions'],11);self.assertEqual(result['admitted_padding_words'],3)
        self.assertFalse(result['runtime_dependencies_verified']);self.assertFalse(result['hardware_verified'])
        self.assertEqual(info['function_starts'],[0x4000,0x4010])
        self.assertEqual(info['imports'],[{'name':'_abort','dylib':'/usr/lib/libSystem.B.dylib','weak':False}])

    def test_decoder_and_alignment_negatives(self):
        for case in ('hole','unknown','wrong-word','interior-zero','target-padding','missing-root','missing-section',
                     'duplicate-section','last-hole','unaligned-next','function-root-zero','nonzero-udf','PAC-hint'):
            with self.subTest(case=case):
                data,lines=fixture();info=metadata(data)
                if case=='hole':del lines[2]
                elif case=='unknown':lines[1]='4000: d65f03c0 <unknown>\n'
                elif case=='wrong-word':lines[1]='4000: d503201f nop\n'
                elif case=='interior-zero':
                    struct.pack_into('<I',data,0x4000,0x8b010000);lines[1]='4000: 8b010000 add x0, x0, x1\n'
                elif case=='target-padding':
                    struct.pack_into('<I',data,0x4000,0x14000002);lines[1]='4000: 14000002 b 0x4008\n'
                elif case=='missing-root':info['function_starts']=[0x4000]
                elif case=='missing-section':lines=lines[:9]
                elif case=='duplicate-section':lines+=lines[9:]
                elif case=='last-hole':lines=lines[:-1]
                elif case=='unaligned-next':info['function_starts']=[0x4000,0x400c]
                elif case=='function-root-zero':info['function_starts'].append(0x4008)
                elif case=='nonzero-udf':
                    struct.pack_into('<I',data,0x4004,1);lines[2]='4004: 00000001 udf #1\n'
                elif case=='PAC-hint':
                    struct.pack_into('<I',data,0x4014,0xd503233f);lines[6]='4014: d503233f hint #25\n'
                with self.assertRaises(ValueError):screen(data,info,lines)

    def test_optional_or_new_ISA_refused(self):
        for op,body,word in [('cas','x0, x1, [x2]',0xc8a07c41),('aese','v0.16b, v1.16b',0x4e284820),
            ('pmull','v0.1q, v1.1d, v2.1d',0),('crc32w','w0, w1, w2',0),('bti','c',0xd503245f),
            ('sdot','v0.4s, v1.16b, v2.16b',0),('fadd','z0, z1, z2',0),('ldapr','x0, [x1]',0)]:
            self.assertTrue(forbidden(op,body,word),(op,body))
        self.assertFalse(forbidden('fcvt','h0, s1',0x1e23c020))
        self.assertFalse(forbidden('fadd','s0, s1, s2',0x1e222820))
        self.assertFalse(forbidden('nop','',0xd503201f))
        self.assertTrue(forbidden('aese.16b','v0, v1',0x4e284820))
        self.assertTrue(forbidden('sdot.4s','v0, v1, v2',0x4e829420))

    @unittest.skipUnless(shutil.which('llvm-mc') and shutil.which('llvm-objdump'),'LLVM assembler/decoder unavailable')
    def test_actual_compiled_ISA_cases_and_aliases(self):
        instructions=[('add x0, x1, x2',True),('fadd s0, s1, s2',True),('fcvt h0, s1',True),
            ('cas x0, x1, [x2]',False),('fadd h0, h1, h2',False),('sdot v0.4s, v1.16b, v2.16b',False),
            ('paciasp',False),('bti c',False),('aese v0.16b, v1.16b',False),('crc32w w0, w1, w2',False)]
        with tempfile.TemporaryDirectory(prefix='graphics-ISA-corpus-') as temporary:
            for index,(instruction,valid) in enumerate(instructions):
                with self.subTest(instruction=instruction):
                    built=subprocess.run(['llvm-mc','-triple','aarch64','-mattr=+lse,+fullfp16,+dotprod,+pauth,+bti,+crypto,+crc',
                        '--show-encoding'],input=instruction+'\n',capture_output=True,text=True,timeout=15)
                    self.assertEqual(built.returncode,0,built.stderr)
                    encodings=re.findall(r'encoding: \[([^\]]+)\]',built.stdout);self.assertEqual(len(encodings),1)
                    encoded=bytes(int(byte.strip(),0) for byte in encodings[0].split(','));self.assertEqual(len(encoded),4)
                    decoded=subprocess.run(['llvm-mc','-triple','aarch64','--disassemble','--mcpu=cortex-a53',
                        '--mattr=-crypto,-crc,-fullfp16,-dotprod,-pauth,-bti,-lse,-rcpc,-sve,-sve2'],
                        input=' '.join(hex(byte) for byte in encoded)+'\n',capture_output=True,text=True,timeout=15)
                    self.assertEqual(decoded.returncode,0,decoded.stderr)
                    # Put the compiled test instruction in the second function,
                    # leaving the fixture's first RET/padding contract intact.
                    data,lines=fixture();data[0x4014:0x4018]=encoded
                    word=int.from_bytes(encoded,'little')
                    decoded_instructions=[line.strip() for line in decoded.stdout.splitlines() if line.strip() and not line.strip().startswith('.')]
                    if valid:self.assertEqual(len(decoded_instructions),1,decoded.stdout+decoded.stderr)
                    body=decoded_instructions[0] if len(decoded_instructions)==1 else '<unknown>'
                    lines[6]=f'4014: {word:08x} '+body+'\n'
                    if valid:self.assertEqual(screen(data,metadata(data),lines)['instructions'],11)
                    else:
                        with self.assertRaises(ValueError):screen(data,metadata(data),lines)

    def test_machine_tail_branch_has_no_fallthrough(self):
        data,lines=fixture();struct.pack_into('<I',data,0x4000,0xd61f0040)
        lines[1]='4000: d61f0040 br x2\n'
        self.assertEqual(screen(data,metadata(data),lines)['admitted_padding_words'],3)

    def test_noreturn_defensive_trap_is_not_generic_trap_approval(self):
        for case in ('bound','unbound','trap-root','trap-target'):
            with self.subTest(case=case):
                data,lines=fixture();info=metadata(data)
                struct.pack_into('<II',data,0x4000,0x94000008,0xd4200020)
                lines[1]='4000: 94000008 bl 0x4020\n';lines[2]='4004: d4200020 brk #1\n'
                if case!='unbound':info['noreturn_stubs']={0x4020:{'name':'_abort'}}
                if case=='trap-root':info['function_starts'].append(0x4004)
                if case=='trap-target':
                    struct.pack_into('<I',data,0x4014,0x17fffffc);lines[6]='4014: 17fffffc b 0x4004\n'
                if case=='bound':self.assertEqual(screen(data,info,lines)['noreturn_defensive_traps'],1)
                else:
                    with self.assertRaises(ValueError):screen(data,info,lines)

    def test_noreturn_stub_bound_by_machine_words_and_GOT_index(self):
        data,lines=noreturn_fixture();info=metadata(data)
        self.assertEqual(info['noreturn_stubs'],{0x4020:{'name':'_abort','dylib':'/usr/lib/libSystem.B.dylib','weak':False}})
        for case in ('different-GOT','bad-ADRP','bad-LDR','bad-BR','table-index','table-size','weak','wrong-ABI'):
            with self.subTest(case=case):
                data,_=noreturn_fixture()
                if case=='different-GOT':struct.pack_into('<I',data,0x4024,0xf9400610)
                elif case=='bad-ADRP':struct.pack_into('<I',data,0x4020,0xb0000011)
                elif case=='bad-LDR':struct.pack_into('<I',data,0x4024,0xf9400211)
                elif case=='bad-BR':struct.pack_into('<I',data,0x4028,0xd61f0220)
                elif case=='table-index':struct.pack_into('<I',data,0x4054,0x80000000)
                elif case=='table-size':
                    # The original command area ends immediately before DYSYMTAB.
                    offset=32+232+56+24+16+24;struct.pack_into('<I',data,offset+60,0x100001)
                elif case=='weak':struct.pack_into('<H',data,0x4036,0x140)
                elif case=='wrong-ABI':data[0x4041:0x4047]=b'_other'
                if case in ('weak','wrong-ABI'):self.assertFalse(metadata(data)['noreturn_stubs'])
                else:
                    with self.assertRaises(ValueError):metadata(data)

    def test_dead_trap_after_return_requires_no_unknown_indirect_entry(self):
        for indirect in (False,True):
            with self.subTest(indirect=indirect):
                data,lines=fixture();info=metadata(data)
                words=[0xd61f0040 if indirect else 0xd503201f,0xd65f03c0,0xd4200020,0]
                ops=['br x2' if indirect else 'nop','ret','brk #1','udf #0']
                for i in range(4):
                    struct.pack_into('<I',data,0x4000+i*4,words[i]);lines[i+1]=f'{0x4000+i*4:x}: {words[i]:08x} {ops[i]}\n'
                if indirect:
                    with self.assertRaises(ValueError):screen(data,info,lines)
                else:self.assertEqual(screen(data,info,lines)['noreturn_defensive_traps'],1)

    def test_malformed_MachO_metadata(self):
        for case in ('cpu','subtype','filetype','oversize-command','unaligned-command','invalid-import','missing-terminator',
                     'nonzero-tail','function-outside-code','string-no-nul','bad-string-offset','overlapping-sections'):
            with self.subTest(case=case):
                data,_=fixture()
                if case=='cpu':struct.pack_into('<I',data,4,0)
                elif case=='subtype':struct.pack_into('<I',data,8,2)
                elif case=='filetype':struct.pack_into('<I',data,12,2)
                elif case=='oversize-command':struct.pack_into('<I',data,36,len(data))
                elif case=='unaligned-command':struct.pack_into('<I',data,36,231)
                elif case=='invalid-import':struct.pack_into('<H',data,0x4036,0xfe00)
                elif case=='missing-terminator':data[0x4060:0x4068]=b'\x80'*8
                elif case=='nonzero-tail':data[0x4067]=1
                elif case=='function-outside-code':data[0x4060:0x4068]=b'\x80\x90\x01\x10\0\0\0\0'
                elif case=='string-no-nul':data[0x4040:0x4048]=b'12345678'
                elif case=='bad-string-offset':struct.pack_into('<I',data,0x4030,8)
                elif case=='overlapping-sections':struct.pack_into('<Q',data,32+72+80+32,0x4010)
                with self.assertRaises(ValueError):metadata(data)

    def test_uleb_bounds(self):
        self.assertEqual(uleb(b'\x80\x80\x01',0),(0x4000,3))
        for data in (b'',b'\x80',b'\xff'*10,b'\xff'*9+b'\x7f'):
            with self.assertRaises(ValueError):uleb(data,0)

if __name__=='__main__':unittest.main()
