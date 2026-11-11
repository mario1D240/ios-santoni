"""All old ISA gates plus whole-function no-return machine-word challenges."""
import hashlib
from pathlib import Path
import struct
import unittest
from tools import check_santoni_graphics_library as draft
from tests.test_santoni_graphics_library import noreturn_fixture

def body_fixture():
    words=[0x34000060,0x940003ff,0xd503201f,0x94000401,*([0xd503201f]*4)]
    data=bytearray(struct.pack('<8I',*words))
    ops=[('cbz','w0, 0x100c'),('bl','0x2000'),('nop',''),('bl','0x2010'),*([('nop','')]*4)]
    rows=[(0x1000+4*i,word,*op) for i,(word,op) in enumerate(zip(words,ops))]
    section={'address':0x1000,'offset':0,'bytes':32}
    stubs={0x2000:{'name':'_abort'},0x2010:{'name':'_longjmp'}}
    return data,section,rows,stubs

class TerminalProof(unittest.TestCase):
    def prove(self,data,section,rows,stubs,end=0x1020):
        return draft.terminal_body(data,section,0x1000,end,rows,stubs,draft.forbidden)

    def test_all_conditions_and_actual_word_targets_are_proved(self):
        data,section,rows,stubs=body_fixture();proof=self.prove(data,section,rows,stubs)
        self.assertEqual(proof['reachable_words'],3)
        self.assertEqual(set(proof['terminal_ABI_stubs']),{'0x2000','0x2010'})
        self.assertEqual(proof['code_sha256'],hashlib.sha256(data).hexdigest())
        self.assertTrue(proof['conditions_overapproximated']);self.assertFalse(proof['source_names_trusted'])

    def test_returns_unknown_edges_loops_words_and_holes_refused(self):
        cases=('return-left','return-right','loop','conditional-loop','outside','indirect','indirect-call',
            'trap','udf','PAC','hole','duplicate','word-mismatch','target-mismatch','missing-ABI','too-large')
        for case in cases:
            with self.subTest(case=case):
                data,section,rows,stubs=body_fixture();end=0x1020
                def change(index,word,op,body=''):
                    struct.pack_into('<I',data,index*4,word);rows[index]=(0x1000+4*index,word,op,body)
                if case=='return-left':change(1,0xd65f03c0,'ret')
                elif case=='return-right':change(3,0xd65f03c0,'ret')
                elif case=='loop':change(0,0x14000000,'b','0x1000')
                elif case=='conditional-loop':change(0,0x34000000,'cbz','w0, 0x1000')
                elif case=='outside':change(0,0x14000800,'b','0x3000')
                elif case=='indirect':change(0,0xd61f0040,'br','x2')
                elif case=='indirect-call':change(0,0xd63f0040,'blr','x2')
                elif case=='trap':change(0,0xd4200020,'brk','#1')
                elif case=='udf':change(0,0,'udf','#0')
                elif case=='PAC':change(0,0xd503233f,'hint','#25')
                elif case=='hole':rows.pop(1)
                elif case=='duplicate':rows.insert(1,rows[0])
                elif case=='word-mismatch':rows[0]=(0x1000,0xd503201f,'nop','')
                elif case=='target-mismatch':rows[0]=(0x1000,rows[0][1],'cbz','w0, 0x1004')
                elif case=='missing-ABI':stubs.pop(0x2010)
                elif case=='too-large':end=0x1000+4*(draft.MAX_TERMINAL_FUNCTION_WORDS+1)
                self.assertIsNone(self.prove(data,section,rows,stubs,end))

    def test_section_bounds_and_types_cannot_bind_another_image_span(self):
        for changes in ({'offset':-32},{'offset':32},{'offset':True},{'address':0x1004},
                        {'address':-1},{'bytes':28},{'bytes':False}):
            with self.subTest(changes=changes):
                data,section,rows,stubs=body_fixture()
                self.assertIsNone(self.prove(data,{**section,**changes},rows,stubs))
        data,section,rows,stubs=body_fixture()
        self.assertIsNone(self.prove(data[:-1],section,rows,stubs))

    def test_raw_control_words_are_refused_even_if_text_claims_fallthrough(self):
        for word in (0,1,0xd4200020,0xd4000001,0xd4000002,0xd4000003,
                     0xd65f03c0,0xd61f0040,0xd63f0040,0xd69f03e0,0xd6bf03e0):
            with self.subTest(word=hex(word)):
                data,section,rows,stubs=body_fixture()
                struct.pack_into('<I',data,0,word)
                rows[0]=(0x1000,word,'nop','')
                self.assertIsNone(self.prove(data,section,rows,stubs))

    def internal_fixture(self):
        data,lines=noreturn_fixture()
        struct.pack_into('<II',data,0x4000,0x94000004,0)
        struct.pack_into('<I',data,0x4010,0x94000004)
        lines[1]='4000: 94000004 bl 0x4010\n'
        lines[5]='4010: 94000004 bl 0x4020\n'
        return data,lines

    def test_internal_call_padding_requires_whole_actual_callee_proof(self):
        data,lines=self.internal_fixture();info=draft.metadata(data)
        with self.assertRaises(ValueError):draft.screen(data,info,lines)
        info['noreturn_functions']=draft.terminal_functions(data,info,lines,draft.forbidden)
        self.assertEqual(set(info['noreturn_functions']),{0x4010})
        result=draft.screen(data,info,lines);self.assertEqual(result['admitted_padding_words'],3)
        for case in ('return','ABI','hole','byte-mismatch','padding-target'):
            with self.subTest(case=case):
                data,lines=self.internal_fixture();info=draft.metadata(data)
                if case=='return':struct.pack_into('<I',data,0x4010,0xd65f03c0);lines[5]='4010: d65f03c0 ret\n'
                elif case=='ABI':info['noreturn_stubs']={}
                elif case=='hole':lines.pop(5)
                elif case=='byte-mismatch':lines[5]='4010: d65f03c0 ret\n'
                elif case=='padding-target':struct.pack_into('<I',data,0x4014,0x17fffffc);lines[6]='4014: 17fffffc b 0x4004\n'
                info['noreturn_functions']=draft.terminal_functions(data,info,lines,draft.forbidden)
                with self.assertRaises(ValueError):draft.screen(data,info,lines)

    def test_longjmp_requires_real_stub_GOT_ordinal_and_nonweak_ABI(self):
        for case in ('bound','weak','wrong-library'):
            with self.subTest(case=case):
                data,_=noreturn_fixture();position=32
                while struct.unpack_from('<I',data,position)[0]!=2:position+=struct.unpack_from('<I',data,position+4)[0]
                names=b'\0_longjmp\0';stroff=len(data);data.extend(names)
                struct.pack_into('<II',data,position+16,stroff,len(names))
                if case=='weak':struct.pack_into('<H',data,0x4036,0x140)
                elif case=='wrong-library':
                    at=data.index(b'/usr/lib/libSystem.B.dylib');data[at+9]=ord('x')
                stubs=draft.metadata(data)['noreturn_stubs']
                if case=='bound':self.assertEqual(stubs[0x4020]['name'],'_longjmp')
                else:self.assertFalse(stubs)

class DeadTrapEdges(unittest.TestCase):
    def fixture(self):
        data, lines = noreturn_fixture()
        words = [0x94000008, 0xd4200020, 0, 0,
                 0x94000004, 0x17fffffc, 0x94000002, 0x17fffffa]
        ops = [('bl', '0x4020'), ('brk', '#1'), ('udf', '#0'), ('udf', '#0'),
               ('bl', '0x4020'), ('b', '0x4004'), ('bl', '0x4020'), ('b', '0x4004')]
        for i, (word, (op, body)) in enumerate(zip(words, ops)):
            struct.pack_into('<I', data, 0x4000 + i*4, word)
            lines[i+1] = f'{0x4000+i*4:x}: {word:08x} {op} {body}\n'
        return data, lines

    def test_only_proved_dead_edges_may_target_a_defensive_trap(self):
        data, lines = self.fixture()
        result = draft.screen(data, draft.metadata(data), lines)
        self.assertEqual(result['admitted_padding_words'], 2)
        self.assertEqual(result['noreturn_defensive_traps'], 1)
        proofs = result['dead_branch_edges_to_noreturn_traps']
        self.assertEqual([r['branch'] for r in proofs], ['0x4014', '0x401c'])
        self.assertTrue(all(r['trap'] == '0x4004' and r['source_untargeted'] and
                            r['function_has_no_indirect_branch'] for r in proofs))

    def test_unproved_reachable_indirect_and_falsely_decoded_edges_refuse(self):
        for case in ('ordinary-left', 'ordinary-right', 'source-root', 'source-target',
                     'later-indirect', 'conditional-source', 'raw-call-text', 'raw-branch-text',
                     'no-main-terminator', 'trap-root'):
            with self.subTest(case=case):
                data, lines = self.fixture()
                info = draft.metadata(data)
                def change(pc, word, op, body=''):
                    struct.pack_into('<I', data, pc, word)
                    lines[1+(pc-0x4000)//4] = f'{pc:x}: {word:08x} {op} {body}\n'
                if case == 'ordinary-left': change(0x4010, 0x94000005, 'bl', '0x4024')
                elif case == 'ordinary-right': change(0x4018, 0x94000003, 'bl', '0x4024')
                elif case == 'source-root': info['function_starts'].append(0x4014)
                elif case == 'source-target':
                    change(0x4018, 0x17ffffff, 'b', '0x4014')
                    change(0x401c, 0xd503201f, 'nop')
                elif case == 'later-indirect':
                    change(0x4018, 0xd61f0040, 'br', 'x2')
                    change(0x401c, 0xd503201f, 'nop')
                elif case == 'conditional-source': change(0x4014, 0x54ffff80, 'b.eq', '0x4004')
                elif case == 'raw-call-text': change(0x4010, 0xd503201f, 'bl', '0x4020')
                elif case == 'raw-branch-text': change(0x4014, 0xd503201f, 'b', '0x4004')
                elif case == 'no-main-terminator': change(0x4000, 0x94000009, 'bl', '0x4024')
                elif case == 'trap-root': info['function_starts'].append(0x4004)
                with self.assertRaises(ValueError):
                    draft.screen(data, info, lines)

if __name__=='__main__':unittest.main()
