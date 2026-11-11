"""Fresh scalar-client contracts; no previously completed native suites run here."""
from pathlib import Path
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from tests.native_santoni_gpu_core import reconstruct, core_link_dependencies
from tests.test_santoni_gpu_prepare import source_function

ROOT=Path(__file__).resolve().parents[1]
FILES=('bsd/dev/santoni_gpu.c','bsd/dev/santoni_gpu_core.c','bsd/dev/santoni_gpu_core.h','bsd/dev/santoni_gpu_uapi.h',
       'bsd/dev/santoni_gpu_launch.h','bsd/dev/santoni_gpu_launch_core.h')
VARIANTS=(('O0',['-O0']),('O2',['-O2']),('UBSan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all']))

class FailurePreservationTests(unittest.TestCase):
    def test_unexpected_failure_keeps_exact_binary_sources_and_result(self):
        with tempfile.TemporaryDirectory(prefix='user-failure-record-') as temporary:
            root=Path(temporary);source=root/'compile';source.mkdir()
            binary=source/'run';binary.write_bytes(b'controlled executable fixture')
            (source/'source.c').write_text('controlled source fixture\n')
            client=UserClientTests();client.root=source;client.compile_rows=[{'command':['compiler','source.c'],'exit':0}]
            result=subprocess.CompletedProcess([str(binary),'9'],1,'raw stdout','raw stderr')
            with patch.dict(os.environ,{'SANTONI_GPU_USER_FAILURE_DIR':str(root/'records')}),patch.object(subprocess,'run',return_value=result):
                with self.assertRaises(AssertionError):client.run_binary(binary,9)
            folders=list((root/'records').iterdir());self.assertEqual(len(folders),1)
            saved=folders[0];record=json.loads((saved/'failure.json').read_text())
            self.assertEqual((saved/'compiled-work/run').read_bytes(),binary.read_bytes())
            self.assertEqual((saved/'compiled-work/source.c').read_bytes(),(source/'source.c').read_bytes())
            self.assertEqual(record['binary_sha256'],hashlib.sha256(binary.read_bytes()).hexdigest())
            self.assertEqual((record['exit'],record['stdout'],record['stderr']),(1,'raw stdout','raw stderr'))
            self.assertEqual(record['compile_rows'],client.compile_rows)
            self.assertFalse(record['hardware_verified'])

class UserClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        cls.temp=tempfile.TemporaryDirectory(prefix='sgpu-user-',dir=preferred if preferred.is_dir() else None)
        cls.root=Path(cls.temp.name);reconstruct(cls.root/'current',targets=FILES)
        cls.dev=cls.root/'current/bsd/dev'
        cls.adapter=(cls.dev/'santoni_gpu.c').read_text()
        cls.core=(cls.dev/'santoni_gpu_core.c').read_text()
        cls.compile_rows=[]

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def compile(self,name,harness,flags,core=None,adapter=None):
        folder=self.root/name;folder.mkdir()
        if adapter is not None:
            if harness=='test_santoni_gpu_user_worker.c':
                model=(ROOT/'tests/test_santoni_gpu_session.c').read_text().split('int main(int argc,',1)[0]
                (folder/'santoni_gpu_session_model.h').write_text('#pragma once\n'+model)
                start=adapter.index('/* Session role:')
                end=adapter.index('static void sgpu_kernel_thread',start)
                header=adapter[start:end]
                header=header.split('/* Once-only full-buffer diagnostic,',1)[0]
                for option in ('sgpu_user_options','sgpu_user_test_options'):
                    header=header.replace(source_function(adapter,option),'')
                (folder/'santoni_gpu_session_adapter_actual.h').write_text(header)
            else:
                start=adapter.index('static LCK_GRP_DECLARE(sgpu_session_group,')
                end=adapter.index('/* A separate kernel-only producer',start)
                options=source_function(adapter,'sgpu_user_options')+'\n'
                if harness=='test_santoni_gpu_user_preflight.c':
                    options+=source_function(adapter,'sgpu_user_test_options')+'\n'
                header=(options+adapter[start:end]+'\n'+
                        source_function(adapter,'sgpu_session_producer')+'\n')
                (folder/'santoni_gpu_user_adapter_actual.h').write_text(header)
        source=self.dev/'santoni_gpu_core.c'
        if core is not None:
            source=folder/'santoni_gpu_core.c';source.write_text(core)
        binary=folder/'run'
        command=[*shlex.split(os.environ.get('HOST_CC','clang')),'-std=c11',*flags,'-pthread',
            '-Wall','-Wextra','-Werror','-DARM64_BOARD_CONFIG_SANTONI','-I',str(folder),
            '-I',str(self.dev),'-I',str(ROOT/'tests'),str(ROOT/'tests'/harness),str(source),
            *core_link_dependencies(self.dev),'-o',str(binary)]
        built=subprocess.run(command,capture_output=True,text=True,timeout=90)
        self.compile_rows.append({'name':name,'command':command,'exit':built.returncode,'stderr':built.stderr})
        self.assertEqual(built.returncode,0,built.stderr)
        return binary

    def run_binary(self,binary,case=None,passed=True):
        result=subprocess.run([str(binary),*(() if case is None else (str(case),))],
                              capture_output=True,text=True,timeout=30)
        records=os.environ.get('SANTONI_GPU_USER_FAILURE_DIR')
        if records and (result.returncode==0)!=passed:
            root=Path(records);root.mkdir(parents=True,exist_ok=True)
            destination=Path(tempfile.mkdtemp(prefix='unexpected-',dir=root))
            shutil.copytree(self.root,destination/'compiled-work')
            record={'command':[str(binary),*(() if case is None else (str(case),))],
                'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr,
                'pass_expected':passed,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
                'compile_rows':self.compile_rows,'hardware_verified':False}
            with (destination/'failure.json').open('x') as stream:json.dump(record,stream,indent=2)
        self.assertEqual(result.returncode==0,passed,result.stdout+result.stderr)

    def test_scalar_core_authority_packets_close_and_quota(self):
        for name,flags in VARIANTS:
            self.run_binary(self.compile(name+'core','test_santoni_gpu_user.c',flags))

    def test_actual_devfs_methods_registration_lifetime_and_threads(self):
        for name,flags in VARIANTS:
            binary=self.compile(name+'adapter','test_santoni_gpu_user_adapter.c',flags,adapter=self.adapter)
            for case in range(10):
                with self.subTest(variant=name,case=case): self.run_binary(binary,case)

    def mutations(self,selected_kind):
        mutations=(
            ('owner','core','owner!=client->owner','false',None),
            ('wire','core','!sgpu_client_packet_valid(command,packet)',
             '!sgpu_client_packet_valid(command,packet) && false',None),
            ('copy','core','next.value[i]=value[i];','next.value[i]=0;',None),
            ('root','adapter','!kauth_cred_issuser(kauth_cred_get())',
             '!kauth_cred_issuser(kauth_cred_get()) && false',1),
            ('reference','adapter','task_deallocate(owner);','if (opened) task_deallocate(owner);',1),
            ('transfer','adapter','task_t owner=current_task();\n    lck_mtx_lock',
             'task_t owner=(task_t)(uintptr_t)sgpu_user_client.owner;\n    lck_mtx_lock',2))
        for name,kind,old,new,case in mutations:
            if kind!=selected_kind:
                continue
            source=self.core if kind=='core' else self.adapter
            self.assertIn(old,source,name)
            changed=source.replace(old,new,1)
            harness='test_santoni_gpu_user'+('_adapter' if kind=='adapter' else '')+'.c'
            binary=self.compile('unsafe-'+name,harness,['-O2'],
                core=changed if kind=='core' else None,
                adapter=changed if kind=='adapter' else None)
            self.run_binary(binary,case,False)

    def test_compiling_unsafe_core_mutations_reject(self):
        self.mutations('core')

    def test_compiling_unsafe_adapter_mutations_reject(self):
        self.mutations('adapter')

    def test_automatic_kernel_preflight_contracts(self):
        for name,flags in VARIANTS:
            binary=self.compile(name+'preflight','test_santoni_gpu_user_preflight.c',flags,adapter=self.adapter)
            for case in range(12):
                with self.subTest(variant=name,case=case): self.run_binary(binary,case)

    def test_compiling_unsafe_preflight_mutations_reject(self):
        changes=(('opt-in','sg.user!=1 || sg.user_test!=1','sg.user!=1 || (sg.user_test!=1 && false)',0),
            ('attempt-cap','attempt<10000','attempt<10001',4),
            ('wave','state.idle<=wave_idle','(state.idle<=wave_idle && false)',1),
            ('publication','!result.publish_attempted','(!result.publish_attempted && false)',5),
            ('admission-idle','wave_idle=request.idle;','wave_idle=state.idle;',8),
            ('backward-clock','now<*last','(now<*last && false)',9),
            ('terminal-deadline','now-start>=100000000u','(now-start>=100000000u && false)',10),
            ('close','(void)sgpu_user_ioctl(makedev(sgpu_user_major,0),SGPU_USER_CLOSE',
             'if (passed) (void)sgpu_user_ioctl(makedev(sgpu_user_major,0),SGPU_USER_CLOSE',4))
        for name,old,new,case in changes:
            self.assertIn(old,self.adapter,name)
            changed=self.adapter.replace(old,new,1)
            binary=self.compile('unsafe-preflight-'+name,'test_santoni_gpu_user_preflight.c',['-O2'],adapter=changed)
            self.run_binary(binary,case,False)

    def test_preflight_through_actual_worker_core_and_threads(self):
        for name,flags in VARIANTS:
            binary=self.compile(name+'worker','test_santoni_gpu_user_worker.c',flags,adapter=self.adapter)
            for case in range(6):
                with self.subTest(variant=name,case=case): self.run_binary(binary,case)

if __name__=='__main__': unittest.main()
