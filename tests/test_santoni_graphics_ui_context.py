"""Exercise actual thread ownership, surface refresh/commit and failure retention."""
from pathlib import Path
from tests.test_santoni_gpu_prepare import source_function
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
DRAFT=ROOT/'tools/santoni-graphics'
class UIContextTests(unittest.TestCase):
    def test_actual_context(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='ui-context-',dir=preferred if preferred.is_dir() else None) as temporary:
            for label,flags in [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined','-fno-sanitize-recover=all'])]:
                binary=Path(temporary)/label
                command=['clang','-std=c11',*flags,'-Wall','-Wextra','-Werror','-pthread',
                    '-I',str(DRAFT),str(ROOT/'tests/test_santoni_graphics_ui_context.c'),
                    str(DRAFT/'ui_context.c'),str(DRAFT/'ui_surface.c'),'-o',str(binary)]
                run=subprocess.run(command,capture_output=True,text=True)
                self.assertEqual(run.returncode,0,run.stderr)
                for case in range(19):
                    run=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=15)
                    self.assertEqual(run.returncode,0,run.stdout+run.stderr)
    def test_compiling_unsafe_context_variants(self):
        mutations=(
            ('foreign-thread','(c->owned && !pthread_equal(c->owner,pthread_self()))','false',1),
            ('seed-refresh','seed!=t->seed','seed==t->seed',0),
            ('completed-dirty','t->dirty=false','t->dirty=true',0),
            ('quarantine','if(c->report.first_failure || c->group->first_failure)goto done;','if(false)goto done;',15),
            ('restore','ok=ok && restored','ok=ok || restored',10),
        )
        source=(DRAFT/'ui_context.c').read_text()
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='ui-context-mutants-',dir=preferred if preferred.is_dir() else None) as temporary:
            for name,old,new,case in mutations:
                scope=source_function(source,'sgfx_ui_context_bind') if name=='foreign-thread' else source
                self.assertEqual(scope.count(old),1,name)
                body=source.replace(scope,scope.replace(old,new,1),1)
                if name=='quarantine':
                    # Shared groups add an independent final-release guard.
                    # The unsafe variant must bypass both quarantine checks.
                    second='if(!group_known(g) || !g->references || g->first_failure)return false;'
                    self.assertEqual(body.count(second),1)
                    body=body.replace(second,'if(!group_known(g) || !g->references)return false;',1)
                changed=Path(temporary)/(name+'.c');changed.write_text(body)
                binary=Path(temporary)/name
                run=subprocess.run(['clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-pthread',
                    '-I',str(DRAFT),str(ROOT/'tests/test_santoni_graphics_ui_context.c'),
                    str(changed),str(DRAFT/'ui_surface.c'),'-o',str(binary)],capture_output=True,text=True)
                self.assertEqual(run.returncode,0,run.stderr)
                run=subprocess.run([str(binary),str(case)],capture_output=True,text=True,timeout=15)
                self.assertNotEqual(run.returncode,0,name)
if __name__=='__main__':unittest.main()
