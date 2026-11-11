"""Live-only CMEQ immediate-zero semantics; shared interpreter stays unchanged."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import check_santoni_gpu_kernel as e
from check_santoni_gpu_live_kernel import live_vector_step


class VectorZero(unittest.TestCase):
    def test_unzip_preserves_even_lanes_from_both_inputs(self):
        for op,bits,lanes in (('uzp1.8h',16,8),('uzp1.4s',32,4)):
            state=e._State()
            for reg,start in (('q1',1),('q2',11)):
                state.put(reg,e._Value(128,sum((start+i)<<(bits*i) for i in range(lanes))))
            self.assertTrue(live_vector_step(op,['v0','v1','v2'],state,None,e))
            values=[1+i for i in range(0,lanes,2)]+[11+i for i in range(0,lanes,2)]
            self.assertEqual(state.get('q0').expr,sum(value<<(bits*i) for i,value in enumerate(values)))
    def test_each_lane_compares_to_zero(self):
        for lanes in (2,4):
            for values in ((0,)*lanes,tuple(range(lanes)),(0xffffffff,)*lanes,
                           tuple(0 if i%2 else 0x80000000 for i in range(lanes))):
                state=e._State();state.put('q1',e._Value(128,sum(value<<(32*i) for i,value in enumerate(values))))
                self.assertTrue(live_vector_step('cmeq.'+str(lanes)+'s',['v0','v1','#0'],state,None,e))
                expected=sum((0xffffffff if value==0 else 0)<<(32*i) for i,value in enumerate(values))
                self.assertEqual(state.get('q0').expr,expected)


if __name__=='__main__':unittest.main()
