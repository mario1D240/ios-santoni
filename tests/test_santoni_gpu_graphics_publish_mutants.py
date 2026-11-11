"""Compiling unsafe changes must fail the actual publication harness."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from tests import test_santoni_gpu_graphics_publish as contract
from tests.test_santoni_gpu_prepare import source_function
from tests.native_santoni_gpu_core import reconstruct, core_link_dependencies

ROOT=contract.ROOT
MUTANTS=(
    ('cache',0,'p->ops->clean(p->ops->ctx,ring,SGPU_PAGE);','if(false)p->ops->clean(p->ops->ctx,ring,SGPU_PAGE);'),
    ('late-tables',29,'!sgpu_graphics_hw_tables() || !sgpu_graphics_hw_state(previous,0,0x1127,0) ||\n        !sgpu_graphics_hw_tables()','false'),
    ('late-cp',30,'!sgpu_graphics_hw_state(previous,0,0x1127,0)','false'),
    ('write-readback',22,'!checked_write32(p,SG_GPU,SG_RB_WPTR,~0u,pos+n)','false'),
    ('rptr',23,'!poll(p,SG_GPU,SG_RB_RPTR,~0u,pos+n,POLL_US)','false'),
    ('busy',24,'!poll(p,SG_GPU,SG_STATUS,SG_BUSY_MASK,0,POLL_US)','false'),
    ('quarantine',22,'sgpu_graphics_hw_fail(SG_COMMAND_TIMEOUT);goto done;','if(false)sgpu_graphics_hw_fail(SG_COMMAND_TIMEOUT);goto done;'),
)
INPUTS=(*contract.INPUTS,'tests/test_santoni_gpu_graphics_publish_mutants.py','tests/test_santoni_gpu_prepare.py')


class PublicationMutants(unittest.TestCase):
    def test_compiling_mutants(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='graphics-publish-mutants-',dir=preferred if preferred.is_dir() else None) as t:
            work=Path(t);source=work/'source';receipt=reconstruct(source,targets=contract.FILES)
            actual=(source/'bsd/dev/santoni_gpu_core.c').read_text()
            function=source_function(actual,'sgpu_graphics_hw_publish')
            (work/'santoni_gpu_live_ui_model.h').write_text(contract.model_header())
            (work/'santoni_gpu_session_model.h').write_text((ROOT/'tests/test_santoni_gpu_session.c').read_text().split('static bool boot_session(',1)[0])
            rows=[];record={'success':False,'hardware_verified':False,'rows':rows,
                'source_sha256':{**receipt['sha256'],**receipt['dependencies'],**receipt['native_link_dependencies']},
                'inputs_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in INPUTS}}
            try:
                for label,case,old,new in MUTANTS:
                    self.assertEqual(function.count(old),1,label)
                    changed=actual.replace(function,function.replace(old,new),1)
                    mutant=work/(label+'.c');mutant.write_text(changed);binary=work/label
                    built=subprocess.run(['clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-DARM64_BOARD_CONFIG_SANTONI',
                        '-I',str(source/'bsd/dev'),'-I',str(work),'-I',str(ROOT/'tests'),
                        str(ROOT/'tests/test_santoni_gpu_graphics_publish.c'),str(mutant),*core_link_dependencies(source/'bsd/dev'),'-o',str(binary)],capture_output=True,text=True,timeout=90)
                    row={'label':label,'case':case,'compile_exit':built.returncode,'compile_stderr':built.stderr,
                        'mutant_sha256':hashlib.sha256(mutant.read_bytes()).hexdigest()};rows.append(row)
                    self.assertEqual(built.returncode,0,built.stderr)
                    ran=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=30)
                    row.update(exit_code=ran.returncode,stdout=ran.stdout,stderr=ran.stderr)
                    self.assertNotEqual(ran.returncode,0,label+' survived')
                record['success']=True
            finally:
                path=os.environ.get('SANTONI_GRAPHICS_PUBLISH_MUTANTS_RECORD')
                if path:Path(path).write_text(json.dumps(record,indent=2)+'\n')


if __name__=='__main__':unittest.main()
