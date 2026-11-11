"""New observer namespace, indirect dispatch and delivery refusal contracts."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import santoni_gpu_launcher_audit as audit
import santoni_gpu_launcher_gate as gate

class Image:
    def __init__(self,names):
        self.segs=[{'vmaddr':0x1000,'vmsize':0x10000,'initprot':3}]
        self.words={}
        table=next(iter(names[audit.DATA[2]]))
        for i,(descriptor,callback) in enumerate(zip(
                ('_vnop_open_desc','_vnop_close_desc','_vnop_ioctl_desc'),audit.CHANGED[-3:])):
            self.words[table+16*i]=next(iter(names[descriptor]))
            self.words[table+16*i+8]=next(iter(names[callback]))
    def read(self,address,size):
        if size!=8:raise ValueError('unreviewed fixture read')
        return self.words.get(address,0)

def names():
    all_names=(*audit.PUBLIC,*audit.DATA,*audit.CALLBACKS,*audit.CHANGED,*audit.TRACE_HELPERS,
        '_vnop_open_desc','_vnop_close_desc','_vnop_ioctl_desc')
    return {name:{0x1000+128*i} for i,name in enumerate(all_names)}

class TraceGates(unittest.TestCase):
    def test_new_callbacks_are_loaded_and_bound(self):
        n=names(); loaded=[]
        self.assertTrue(audit.load_launcher(lambda name:loaded.append(name),{},n))
        self.assertTrue(set(audit.CHANGED[-3:])<=set(loaded))
        self.assertTrue(audit.trace_bindings(Image(n),n)['success'])

    def test_each_substituted_vnode_callback_is_rejected(self):
        n=names()
        for index in range(3):
            with self.subTest(index=index):
                image=Image(n); table=next(iter(n[audit.DATA[2]]))
                image.words[table+16*index+8]=0xdead
                with self.assertRaises(ValueError):audit.trace_bindings(image,n)

    def test_duplicate_descriptors_and_readonly_counter_reject(self):
        n=names(); image=Image(n); table=next(iter(n[audit.DATA[2]]))
        image.words[table+16]=image.words[table]
        with self.assertRaises(ValueError):audit.trace_bindings(image,n)
        image=Image(n); image.segs[0]['initprot']=1
        with self.assertRaises(ValueError):audit.trace_bindings(image,n)

    def test_unreviewed_observer_namespace_rejects(self):
        n=names(); n['_mockfs_santoni_trace_extra']={0xfee0}
        with self.assertRaises(ValueError):audit.load_launcher(lambda _:None,{},n)

    def test_enabled_probe_requires_explicit_trace_certificate(self):
        report={gate.PRESENT:True,gate.ISA_GATE:True,gate.CONTROL_GATE:True,gate.LAUNCH_GATE:True,
            'EL0_launcher_mount_registry_checked':True,'EL0_launcher_trace_present':True,
            'EL0_launcher_trace_wiring_checked':True,'EL0_launcher_trace_dispatch_checked':True}
        gate.require_kernel_gates(report,3,enabled=True)
        for field in ('EL0_launcher_trace_present','EL0_launcher_trace_wiring_checked',
                      'EL0_launcher_trace_dispatch_checked'):
            for value in (None,False,1,'true'):
                with self.subTest(field=field,value=value):
                    invalid=copy.deepcopy(report);invalid[field]=value
                    with self.assertRaises(ValueError):gate.require_kernel_gates(invalid,3,enabled=True)

    def test_mode1_does_not_require_enabled_observation(self):
        report={gate.PRESENT:True,gate.ISA_GATE:True,gate.CONTROL_GATE:True,
            'EL0_launcher_trace_present':False,'EL0_launcher_trace_wiring_checked':False}
        gate.require_kernel_gates(report,1,enabled=False)

if __name__=='__main__':unittest.main()
