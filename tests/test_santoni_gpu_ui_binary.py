"""UI model boundaries reject missing handoff/cache/permission evidence."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import check_santoni_gpu_ui_kernel as ui
from santoni_gpu_binary_model import Memory
import check_santoni_gpu_kernel as decoder
from santoni_gpu_ui_native_cpu import UI_PURE


class UIModelBoundaries(unittest.TestCase):
    def model(self):
        model=object.__new__(ui.UIModel)
        model.e=decoder
        model.ui_on=True
        model.ui_case='normal'
        model.regs={(4,0x20c8):15,(5,0xc00):0x20000,(5,0x8000):0x1126,(5,0x87f4):0}
        model.ui_writes=[]
        model.tlbi=model.sync=False
        model.vm=SimpleNamespace(by_address={0x1000:'_sgpu_io_write32',0x1010:'_clean'})
        model.m=Memory(SimpleNamespace(segs=[]))
        model.m.map(ui.TABLES,7*4096)
        model.tables_dma=bytearray(7*4096)
        model.pure_calls=[]
        return model

    def before(self,*args):
        return decoder._State({'x'+str(i):decoder._Value(64,v) for i,v in enumerate(args)})

    def callback(self,model,target,*args):
        before=self.before(*args)
        return model.external_ui(target,before.copy(),before=before)

    def test_UI_PTE_publication_requires_stop_fault_route_and_disabled_CB(self):
        for key,wrong in (((4,0x20c8),14),((5,0xc00),0),((5,0x8000),0x1127)):
            model=self.model();model.regs[key]=wrong
            with self.assertRaises(ValueError):self.callback(model,0x1010,0,ui.TABLES+8192,4*4096)
        model=self.model()
        model.m.put(ui.TABLES+8192+8,0xa3000fc7,8)
        self.callback(model,0x1010,0,ui.TABLES+8192,4*4096)
        self.assertEqual(int.from_bytes(model.tables_dma[8200:8208],'little'),0xa3000fc7)

    def test_TLB_sync_cannot_precede_ASID_invalidation_or_use_another_write(self):
        model=self.model()
        model.ui_writes=list(ui.HANDOFF[:4])
        with self.assertRaises(ValueError):self.callback(model,0x1000,0,5,0x87f0,0)
        model=self.model()
        model.ui_writes=list(ui.HANDOFF[:3]);model.tlbi=False
        self.callback(model,0x1000,0,5,0x8610,1)
        self.assertTrue(model.tlbi)
        self.callback(model,0x1000,0,5,0x87f0,0)
        self.assertTrue(model.sync)
        model=self.model()
        with self.assertRaises(ValueError):self.callback(model,0x1000,0,4,0x3d000,0)

    def test_import_PTE_is_read_only_and_requires_translated_CB(self):
        model=self.model()
        model.regs[5,0xc00]=0;model.regs[5,0x8000]=0x1127
        model.ui_tlb=[0xa3000fc7]*960
        model.import_dma=[bytearray(ui.BYTES),bytearray(ui.BYTES)]
        model.gpu(ui.GVA+4096)
        with self.assertRaises(ValueError):model.gpu(ui.GVA+4096,True)
        model.ui_tlb[0]&=~128
        with self.assertRaises(ValueError):model.gpu(ui.GVA+4096)

    def test_native_UI_set_excludes_state_changes_and_submission(self):
        self.assertEqual(len(UI_PURE),5)
        for name in ('_sgpu_ui_remap','_sgpu_ui_submit','_sgpu_ui_start','_sgpu_ui_wait'):
            self.assertNotIn(name,UI_PURE)


if __name__=='__main__':unittest.main()
