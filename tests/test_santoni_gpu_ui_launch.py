"""Offline launch overlay preservation/refusal contracts with synthetic images."""
import copy
import hashlib
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest

from tests.test_santoni_graphics_library import fixture
from tests.test_santoni_ui_loader_binding import with_strings
from tools.build_santoni_graphics_gles import ui_artifact_path
from tools.santoni_gpu_ui_launch import stage,patch_plists,absolute_dependencies,AGGREGATE,INDIVIDUAL,EXECUTABLE

ROOT=Path(__file__).resolve().parents[1]

class LaunchOverlay(unittest.TestCase):
    def inputs(self,work):
        main=fixture()[0];main_sha=hashlib.sha256(main).hexdigest()
        main_path=ui_artifact_path(main_sha,'libsantoni-eagl.dylib')
        strings=(main_path+'\0sgfx_eagl_install\0/System/Library/Frameworks/OpenGLES.framework/OpenGLES\0').encode()
        loader=with_strings(fixture()[0],strings);loader_sha=hashlib.sha256(loader).hexdigest()
        loader_path=ui_artifact_path(loader_sha,'libsantoni-ui-loader.dylib')
        for name,data in [('main',main),('loader',loader)]:
            (work/name).write_bytes(data)
            (work/(name+'-cpu')).write_text(json.dumps({'success':True,'CPU_ISA_screened':True,
                'all_instruction_words_bound_to_image':True,'library_sha256':hashlib.sha256(data).hexdigest()}))
        manifest={'success':True,'eagl_library':{'sha256':main_sha,'bytes':len(main)},'ui_loader':{
            'sha256':loader_sha,'bytes':len(loader),'eagl_sha256':main_sha,'eagl_path':main_path,'loader_path':loader_path}}
        (work/'build').write_text(json.dumps(manifest))
        job={'Label':'com.apple.backboardd','ProgramArguments':[EXECUTABLE],'UserName':'mobile','GroupName':'mobile',
            'KeepAlive':True,'EnvironmentVariables':{'CA_TEST':'1'}}
        aggregate={'LaunchDaemons':{INDIVIDUAL:copy.deepcopy(job),'/unrelated.plist':{'Label':'unrelated','KeepAlive':False}},
            'UnrelatedSettings':[1,'unchanged']}
        for name,value in [('aggregate',aggregate),('individual',job)]:
            (work/name).write_bytes(plistlib.dumps(value,fmt=plistlib.FMT_BINARY,sort_keys=False))
        return [work/name for name in ('main','loader','main-cpu','loader-cpu','build','aggregate','individual')],main_path,loader_path

    def test_exact_offline_staging_restore_and_other_jobs_preserved(self):
        with tempfile.TemporaryDirectory(prefix='santoni-ui-launch-') as temporary:
            work=Path(temporary);args,main_path,loader_path=self.inputs(work)
            original=[p.read_bytes() for p in args];result=stage(*args,work/'overlay')
            self.assertTrue(result['success']);self.assertEqual(result['renderer_job_count'],1)
            for key in ('kernel_dyld_policy_verified','installed_root_verified','runtime_dyld_verified','boot_image_packaged','hardware_verified'):
                self.assertFalse(result[key])
            for index,path in ((5,AGGREGATE),(6,INDIVIDUAL)):
                self.assertEqual((work/'overlay/restore'/path.lstrip('/')).read_bytes(),original[index])
                expected=plistlib.loads(original[index])
                job=expected['LaunchDaemons'][INDIVIDUAL] if index==5 else expected
                job['EnvironmentVariables']['DYLD_INSERT_LIBRARIES']=loader_path
                actual=plistlib.loads((work/'overlay/root-overlay'/path.lstrip('/')).read_bytes())
                self.assertEqual(actual,expected)
            for index,path in ((0,main_path),(1,loader_path)):
                self.assertEqual((work/'overlay/root-overlay'/path.lstrip('/')).read_bytes(),original[index])
            self.assertEqual([p.read_bytes() for p in args],original)
            self.assertTrue(all(not row['installed_metadata_verified'] for row in result['files']))
            with self.assertRaises(FileExistsError):stage(*args,work/'overlay')

    def test_unknown_ambiguous_jobs_environment_and_paths_rejected(self):
        with tempfile.TemporaryDirectory(prefix='santoni-ui-launch-') as temporary:
            work=Path(temporary);args,_,loader_path=self.inputs(work)
            for mutation in ('duplicate','missing','moved','user','group','executable','arguments',
                'insert','search','env','jobs','path','non-job','non-aggregate'):
                with self.subTest(mutation=mutation):
                    combined=plistlib.loads(args[5].read_bytes());single=plistlib.loads(args[6].read_bytes());path=loader_path
                    job=combined['LaunchDaemons'][INDIVIDUAL]
                    if mutation=='duplicate':combined['LaunchDaemons']['/duplicate.plist']=copy.deepcopy(job)
                    elif mutation=='missing':del combined['LaunchDaemons'][INDIVIDUAL]
                    elif mutation=='moved':combined['LaunchDaemons']['/moved.plist']=combined['LaunchDaemons'].pop(INDIVIDUAL)
                    elif mutation=='user':job['UserName']='root'
                    elif mutation=='group':single['GroupName']='staff'
                    elif mutation=='executable':single['Program']='/tmp/backboardd'
                    elif mutation=='arguments':single['ProgramArguments'].append('--unknown')
                    elif mutation=='insert':job['EnvironmentVariables']={'DYLD_INSERT_LIBRARIES':'/tmp/unknown.dylib'}
                    elif mutation=='search':single['EnvironmentVariables']={'DYLD_LIBRARY_PATH':'/tmp'}
                    elif mutation=='env':single['EnvironmentVariables']={'CA_TEST':1}
                    elif mutation=='jobs':combined['LaunchDaemons']=[]
                    elif mutation=='path':path=path.replace('/usr/local/','/tmp/')
                    elif mutation=='non-job':single=[]
                    elif mutation=='non-aggregate':combined=[]
                    with self.assertRaises(ValueError):patch_plists(plistlib.dumps(combined),plistlib.dumps(single),path)

    def test_relative_dependency_refused(self):
        main=fixture()[0];old=b'/usr/lib/libSystem.B.dylib'
        self.assertIn(old,main)
        with self.assertRaises(ValueError):absolute_dependencies(main.replace(old,b'@rpath/libSystem.B.dylib'.ljust(len(old),b'\0')))

    def test_tools_run_by_absolute_filename_outside_repository(self):
        with tempfile.TemporaryDirectory(prefix='santoni-ui-cli-') as temporary:
            for script in ('tools/santoni_gpu_ui_launch.py','tools/check_santoni_ui_loader.py'):
                result=subprocess.run([sys.executable,str(ROOT/script),'--help'],cwd=temporary,capture_output=True,text=True,timeout=30)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn('--eagl',result.stdout)

if __name__=='__main__':unittest.main()
