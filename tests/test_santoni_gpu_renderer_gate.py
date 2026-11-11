import unittest
import sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from tools import santoni_gpu_renderer_gate as gate
from tools import santoni_gpu_boot as boot
from tests.test_santoni_gpu_boot_gates import RECIPE,SHA

class RendererGate(unittest.TestCase):
    def test_exact_renderer_role_retains_baseline_and_separates_ui_copy(self):
        with patch.object(boot.subprocess,'check_output',return_value=RECIPE):
            line=boot.command_line(SHA,3,render_test=True,graphics_renderer=True)
        args=boot.command_args(line)
        expected={'cpus':'4','sweetfb_hz':'30','sweethidtest':'0','santonigpu':'3',
                  'santonigpu_render':'1','santonigpu_ui':'0','santonigpu_graphics':'1',
                  'santonigpu_raster':'1','santonigpu_gles':'1','santonigpu_renderer':'1'}
        for name,value in expected.items():self.assertEqual(args[name],value)
        self.assertLess(len(line),608)

    def test_disabled_and_invalid_roles(self):
        for mode in range(4):gate.validate(mode,False,False,False)
        for args in ((1,True,False,True),(2,True,False,True),(3,False,False,True),
                     (3,True,True,True),(3,True,False,1)):
            with self.assertRaises(ValueError):gate.validate(*args)

    def test_explicit_hardware_skip_keeps_exact_renderer_role(self):
        for skip in (False,True):gate.validate(3,True,False,True,skip)
        for skip in (0,1,None,'true'):
            with self.subTest(skip=skip),self.assertRaises(ValueError):
                gate.validate(3,True,False,True,skip)
        for mode,render,ui in ((0,True,False),(1,True,False),(2,True,False),
                               (3,False,False),(3,True,True)):
            with self.subTest(mode=mode,render=render,ui=ui),self.assertRaises(ValueError):
                gate.validate(mode,render,ui,True,True)

    def test_mixed_probe_and_renderer_is_refused(self):
        with self.assertRaises(ValueError):
            boot.command_line(SHA,3,render_test=True,user=True,graphics_renderer=True)

    def test_recipe_must_not_supply_renderer_flags(self):
        with patch.object(boot.subprocess,'check_output',return_value=RECIPE.replace('cpus=8','cpus=8 santonigpu_gles=1')):
            with self.assertRaises(ValueError):
                boot.command_line(SHA,3,render_test=True,graphics_renderer=True)
