"""Actual host-only capture writer, plus malformed capture intake negatives."""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from tests.test_santoni_graphics_msm import ROOT,MESA
from tests.reconstruct_santoni_touch import reconstruct
from tools.parse_santoni_graphics_capture import parse
from tools.build_santoni_graphics_capture import run_capture
class CaptureTests(unittest.TestCase):
    def test_actual_dimension_parser_and_compiling_mutants(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='capture-dimensions-c-',dir=preferred if preferred.is_dir() else None) as temporary:
            work=Path(temporary)
            original=(ROOT/'tools/santoni-graphics/capture/main.c').read_text().split('static GLuint compile(',1)[0]
            mutants={
                'unbounded-size':('value && value<=4096','value',7),
                'signed-or-spaced':("if(*text<'0' || *text>'9')return 0;",'',9),
            }
            for name,body,case in [('actual',original,None),*[(name,original.replace(old,new,1),case) for name,(old,new,case) in mutants.items()]]:
                if name!='actual':self.assertEqual(original.count(mutants[name][0]),1,name)
                (work/'capture_dimensions.h').write_text(body)
                for label,flags in [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:
                    binary=work/(name+'-'+label)
                    build=subprocess.run(['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-I'+str(work),
                        '-I'+str(ROOT/'tools/santoni-graphics'),'-I'+str(MESA/'include'),
                        str(ROOT/'tests/test_santoni_graphics_capture_dimensions.c'),'-o',str(binary)],capture_output=True,text=True,timeout=30)
                    self.assertEqual(build.returncode,0,build.stderr)
                    for test in (range(14) if case is None else [case]):
                        run=subprocess.run([str(binary),str(test)],capture_output=True,text=True,timeout=15)
                        if case is None:self.assertEqual(run.returncode,0,run.stdout+run.stderr)
                        else:self.assertNotEqual(run.returncode,0,name+' survived')
    def test_dimensions_refused_before_run_or_output(self):
        for width,height in ((0,64),(64,0),(-1,1280),(720,4097),(True,64),(64,1.5),('720',1280)):
            with self.subTest(width=width,height=height),tempfile.TemporaryDirectory(prefix='capture-dimensions-') as temporary:
                work=Path(temporary)
                with patch('tools.build_santoni_graphics_capture.subprocess.run') as execute:
                    with self.assertRaises(ValueError):run_capture(work/'missing',work,width,height)
                    execute.assert_not_called()
                self.assertEqual(list(work.iterdir()),[])
    def test_primary_and_diagnostic_runs_are_separate(self):
        for mode in ('success','crash','timeout','no-debugger'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory(prefix='capture-run-') as temporary:
                work=Path(temporary);calls=[]
                def execute(command,**arguments):
                    calls.append(command)
                    target=Path(arguments['env']['SANTONI_CAPTURE_DIR'])
                    self.assertEqual(arguments['env']['SANTONI_CAPTURE_WIDTH'],'720')
                    self.assertEqual(arguments['env']['SANTONI_CAPTURE_HEIGHT'],'1280')
                    self.assertEqual(arguments['env']['SANTONI_CAPTURE_UI'],'0')
                    arguments['stdout'].write('primary\n' if len(calls)==1 else 'diagnostic\n')
                    if len(calls)==1:
                        self.assertEqual(target,work/'packets');self.assertEqual(arguments['timeout'],120)
                        (target/'submit-0001.bin').write_bytes(b'primary')
                        if mode=='timeout':raise subprocess.TimeoutExpired(command,120)
                        return subprocess.CompletedProcess(command,0 if mode=='success' else -11)
                    self.assertEqual(target,work/'diagnostic-packets');self.assertEqual(arguments['timeout'],45)
                    self.assertEqual(command[0],'lldb')
                    (target/'submit-0001.bin').write_bytes(b'diagnostic')
                    if mode=='timeout':raise subprocess.TimeoutExpired(command,45)
                    if mode=='no-debugger':raise FileNotFoundError('lldb missing')
                    return subprocess.CompletedProcess(command,1)
                with patch('tools.build_santoni_graphics_capture.subprocess.run',side_effect=execute):
                    destination,record=run_capture(work/'capture-mesa',work,720,1280)
                self.assertEqual(record['width'],720);self.assertEqual(record['height'],1280)
                self.assertEqual(destination,work/'packets')
                self.assertEqual((destination/'submit-0001.bin').read_bytes(),b'primary')
                self.assertEqual(record['success'],mode=='success')
                self.assertEqual(record['run_timed_out'],mode=='timeout')
                self.assertEqual(record['debugger_timed_out'],mode=='timeout')
                self.assertEqual(len(calls),1 if mode=='success' else 2)
                if mode!='success':self.assertIn('diagnostic',(work/'backtrace.log').read_text())
    def test_UI_profile_is_explicit_and_overrides_inherited_environment(self):
        for enabled in (False,True):
            with self.subTest(enabled=enabled),tempfile.TemporaryDirectory(prefix='capture-UI-profile-') as temporary:
                work=Path(temporary)
                def execute(command,**arguments):
                    self.assertEqual(arguments['env']['SANTONI_CAPTURE_UI'],'1' if enabled else '0')
                    return subprocess.CompletedProcess(command,0)
                with patch.dict(os.environ,{'SANTONI_CAPTURE_UI':'1'}),patch('tools.build_santoni_graphics_capture.subprocess.run',side_effect=execute):
                    _,record=run_capture(work/'model',work,720,1280,enabled)
                self.assertEqual(record['ui_like_profile'],enabled)
        for invalid in (1,'1',None):
            with tempfile.TemporaryDirectory(prefix='capture-UI-invalid-') as temporary:
                work=Path(temporary)
                with patch('tools.build_santoni_graphics_capture.subprocess.run') as execute:
                    with self.assertRaises(ValueError):run_capture(work/'missing',work,720,1280,invalid)
                    execute.assert_not_called()
                self.assertEqual(list(work.iterdir()),[])
    def test_actual_capture_transport(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='mesa-capture-',dir=preferred if preferred.is_dir() else None) as temporary:
            work=Path(temporary);reconstruct(work/'source',targets=('bsd/dev/santoni_gpu_core.h','bsd/dev/santoni_gpu_graphics.h','bsd/dev/santoni_gpu_graphics_uapi.h'))
            for label,flags in [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:
                binary=work/label
                run=subprocess.run(['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-pthread',
                    '-I',str(work/'source/bsd/dev'),'-I',str(MESA/'include'),'-I',str(MESA/'include/drm-uapi'),
                    '-I',str(ROOT/'tools/santoni-graphics'),'-I',str(ROOT/'tools/santoni-graphics/include'),
                    str(ROOT/'tests/test_santoni_graphics_capture.c'),
                    *[str(ROOT/'tools/santoni-graphics'/name) for name in ('client.c','msm.c','drm.c','capture/transport.c','capture/submit.c')],
                    '-o',str(binary)],capture_output=True,text=True)
                self.assertEqual(run.returncode,0,run.stderr)
                for case in range(9):
                    directory=work/(label+'-'+str(case));directory.mkdir()
                    environment=os.environ.copy();environment['SANTONI_CAPTURE_DIR']=str(directory)
                    run=subprocess.run([str(binary),str(case)],env=environment,capture_output=True,text=True,timeout=15)
                    self.assertEqual(run.returncode,0,run.stdout+run.stderr)
                    captures=list(directory.glob('*.bin'));self.assertEqual(len(captures),int(case in (0,6)))
                    if case in (0,6):
                        data=captures[0].read_bytes();record=parse(data)
                        self.assertFalse(record['hardware_verified']);self.assertEqual(record['modeled_fence'],1)
                        self.assertEqual(len(record['roots']),1);self.assertEqual(next(iter(record['buffers'].values()))['payload'][:4],b'\x00\x80\x10\x70')
                        for corrupted in (data[:-1],data+b'\0',b'NOPE'+data[4:],data[:8]+struct.pack('<I',65)+data[12:]):
                            with self.assertRaises((ValueError,struct.error)):parse(corrupted)
if __name__=='__main__':unittest.main()
