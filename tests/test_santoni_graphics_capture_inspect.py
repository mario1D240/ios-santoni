"""Structural captured-PM4 inventory, malformed owned references and limits."""
import struct
import unittest
from tests.test_santoni_graphics_msm import MESA
from tools.parse_santoni_graphics_capture import parse
from tools.inspect_santoni_graphics_capture import header,inspect,symbols

def packet(op,*words,kind=7):
    count=len(words);parity=lambda value:1^(value.bit_count()&1)
    value=(0x70000000|count|(parity(count)<<15)|(op<<16)|(parity(op)<<23)) if kind==7 else (
        0x40000000|count|(parity(count)<<7)|(op<<8)|(parity(op)<<27))
    return [value,*words]

def capture(streams,root=0):
    data=struct.pack('<8I',0x50434753,1,len(streams),1,1,0,505,0)
    data+=struct.pack('<3I',root+1,0,len(streams[root])*4)
    for index,words in enumerate(streams):
        payload=struct.pack('<'+str(len(words))+'I',*words)
        data+=struct.pack('<4I',index+1,0x01201000+index*0x2000,len(payload),1)+payload
    return parse(data)

class CaptureInventoryTests(unittest.TestCase):
    def test_headers_and_exact_parity(self):
        self.assertEqual(header(0x70108000),(7,0x10,0))
        self.assertEqual(header(0x70268000),(7,0x26,0))
        word=packet(0xe5ac,0x01203000,0,kind=4)[0]
        self.assertEqual(header(word),(4,0xe5ac,2))
        for bad in (0,0xffffffff,0x70100000,word^(1<<27),word^(1<<7),0x48000080):
            with self.assertRaises(ValueError):header(bad)

    def test_nested_inventory_and_xml_names(self):
        opcodes,registers,inputs=symbols(MESA)
        self.assertIn('CP_LOAD_STATE4',opcodes[0x30])
        self.assertEqual(registers[0xe5ac],['A5XX_SP_VS_OBJ_START_LO'])
        self.assertEqual(registers[0xe40a],['A5XX_VFD_FETCH[0]_BASE_LO'])
        self.assertEqual(len(inputs),2)
        root=packet(0x3f,0x01203000,0,3)+packet(0x13)
        child=packet(0xe5ac,0x01205000,0,kind=4)
        record=inspect(capture([root,child]),opcodes,registers)
        self.assertEqual(len(record['nodes']),2)
        self.assertEqual(record['register_writes'][0]['value'],0x01205000)
        self.assertEqual(record['opcodes'],{'19':1,'63':1})
        self.assertFalse(record['admission_verified'])
        self.assertFalse(record['shader_descriptor_values_validated'])
        self.assertFalse(record['hardware_verified'])

    def test_repeated_children_are_not_deduplicated(self):
        root=packet(0x37,0x01203000,0,1)*2
        result=inspect(capture([root,packet(0x10)]))
        self.assertEqual(len(result['nodes']),3)
        self.assertEqual(result['opcodes']['16'],2)

    def test_draw_states_are_potential_not_execution_proof(self):
        root=packet(0x43,(3<<24)|1,0x01203000,0,1<<17,0,0)
        result=inspect(capture([root,packet(0x10)]))
        self.assertEqual(result['nodes'][1]['reference'],'potential-draw-state')
        self.assertFalse(result['execution_semantics_verified'])

    def test_invalid_child_payloads(self):
        for words in ((0x01203000,1,1),(0x01203000,0,0),(0x01203000,0),(0x01203002,0,1),
            (0x01204000,0,1),(0x01203000,0,2)):
            with self.subTest(words=words),self.assertRaises(ValueError):
                inspect(capture([packet(0x3f,*words),packet(0x10)]))

    def test_draw_state_malformed_triplets(self):
        for words in ((),(1,0),((1<<20)|1,0x01203000,0),(1,0x01203000,1),
            ((1<<17)|1,0x01203000,0),(0,0x01203000,0)):
            with self.subTest(words=words),self.assertRaises(ValueError):
                inspect(capture([packet(0x43,*words),packet(0x10)]))

    def test_cycles_and_active_partial_overlap(self):
        for va,length in ((0x01201000,4),(0x01201004,3)):
            with self.assertRaises(ValueError):inspect(capture([packet(0x3f,va,0,length)]))

    def test_truncated_packet_and_data_not_treated_as_commands(self):
        with self.assertRaises(ValueError):inspect(capture([[packet(0x10,7)[0]]]))
        result=inspect(capture([packet(0x10,0xffffffff,0x01201000)]))
        self.assertEqual(len(result['nodes']),1)
        self.assertEqual(result['register_writes'],[])

    def test_depth_bound(self):
        streams=[packet(0x3f,0x01201000+(i+1)*0x2000,0,4 if i<6 else 1) for i in range(7)]
        streams.append(packet(0x10));self.assertEqual(len(inspect(capture(streams))['nodes']),8)
        streams[-1]=packet(0x3f,0x01211000,0,1);streams[-2][-1]=4;streams.append(packet(0x10))
        with self.assertRaises(ValueError):inspect(capture(streams))

    def test_node_bound(self):
        with self.assertRaises(ValueError):inspect(capture([packet(0x37,0x01203000,0,1)*512,packet(0x10)]))

    def test_word_bound(self):
        # Use a standalone object so its large span does not overlap guards.
        words=packet(0x10,*([0]*16383))*9
        with self.assertRaisesRegex(ValueError,'word bound'):inspect(capture([words]))

if __name__=='__main__':unittest.main()
