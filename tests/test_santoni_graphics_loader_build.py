"""Actual build orchestration and signed-library loader binding; toolchain modeled."""
import hashlib,json,subprocess,tempfile,unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
from tools import build_santoni_graphics_gles as build
from tools.generate_santoni_gl_dispatch import prototypes
from tests.test_santoni_graphics_msm import MESA

class LoaderBuildTests(unittest.TestCase):
    def test_content_paths_and_thin_loader_inventory(self):
        digest='a'*64
        self.assertEqual(build.ui_artifact_path(digest,'libsantoni-eagl.dylib'),
            '/usr/local/lib/santoni-gpu-ui/'+digest+'/libsantoni-eagl.dylib')
        self.assertEqual(build.ui_loader_config(digest),'#define SANTONI_UI_LIBRARY_PATH '+json.dumps(build.ui_artifact_path(digest,'libsantoni-eagl.dylib'))+'\n')
        for bad in ('A'*64,'a'*63,'a'*65,'../'+'a'*61,None):
            with self.subTest(bad=bad),self.assertRaises(ValueError):build.ui_artifact_path(bad,'libsantoni-eagl.dylib')
        with self.assertRaises(ValueError):build.ui_artifact_path(digest,'other.dylib')
        symbols='00000010 T _sgfx_ui_loader_start\n'
        self.assertEqual(build.check_loader_inventory(symbols,'/usr/lib/libSystem.B.dylib'),{'_sgfx_ui_loader_start':'00000010'})
        for bad in ('','00000000 T _sgfx_ui_loader_start\n',symbols*2,symbols+' U _glClear\n',symbols+'00000020 T _sgfx_eagl_install\n'):
            with self.subTest(symbols=bad),self.assertRaises(ValueError):build.check_loader_inventory(bad,'/usr/lib/libSystem.B.dylib')
        with self.assertRaises(ValueError):build.check_loader_inventory(symbols,'OpenGLES.framework/OpenGLES')

    def test_loader_requires_eagl_before_output(self):
        with patch.object(build.platform,'system',return_value='Darwin'),patch.object(build,'prepare_source') as prepare:
            with self.assertRaisesRegex(ValueError,'requires'):build.build('unused','unused',False,True)
            prepare.assert_not_called()

    def test_build_compiles_readiness_and_binds_signed_eagl_bytes(self):
        self.exercise(False)

    def test_changed_eagl_bytes_during_loader_build_refused(self):
        with self.assertRaisesRegex(ValueError,'changed during loader'):self.exercise(True)

    def test_missing_configured_mesa_refused_before_build(self):
        with tempfile.TemporaryDirectory(prefix='loader-mesa-source-') as temporary:
            with patch(__name__+'.MESA',Path(temporary)/'missing-mesa'),patch.object(build,'prepare_source') as prepare:
                with self.assertRaises(FileNotFoundError):self.exercise(False)
                prepare.assert_not_called()

    def test_symlinked_host_temporary_path_preserves_exact_include_binding(self):
        with tempfile.TemporaryDirectory(prefix='loader-aliased-temp-') as temporary:
            root=Path(temporary);physical=root/'physical';physical.mkdir()
            alias=root/'alias';alias.symlink_to(physical,target_is_directory=True)
            @contextmanager
            def aliased_temp(*args,**kwargs):
                yield str(alias)
            with patch.object(tempfile,'TemporaryDirectory',side_effect=aliased_temp):self.exercise(False)

    def exercise(self,mutate):
        root=build.ROOT;mesa=MESA
        headers='\n'.join((mesa/'include'/name).read_text() for name in
            ('GL/gl.h','GL/glext.h','GLES/gl.h','GLES/glext.h','GLES2/gl2.h','GLES2/gl2ext.h','GLES3/gl3.h'))
        archive='\n'.join('00000010 T _'+name for name in prototypes(headers))
        eagl_symbols='\n'.join('00000010 T '+name for name in
            ('_glClear','_glDrawArrays','_glReadPixels','_fd5_emit_state','_ir3_compile_shader_nir','_sgfx_msm_command',
             '_sgfx_eagl_install','_sgfx_gles_ui_readback_proof','_sgfx_ios_renderer_wait','_sgfx_drm_open_renderer',
             '_sgfx_ui_context_attach','_sgfx_ui_context_flush'))+'\n'
        real_run=subprocess.run;real_output=subprocess.check_output;seen=[]
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='loader-build-',dir=preferred if preferred.is_dir() else None) as temporary:
            base=Path(temporary).resolve();output=base/'output';sdk=base/'sdk';sdk.mkdir()
            def prepare(unused,dest):
                dest.mkdir();return mesa,{'source_fixture':'pinned Mesa; toolchain mocked'}
            def query(command,**kwargs):
                if command[:3]==['xcrun','--sdk','iphoneos']:
                    if command[3:]==['--show-sdk-path']:return str(sdk)+'\n'
                    return 'test-'+command[-1]+'\n'
                return real_output(command,**kwargs)
            def run(command,**kwargs):
                if command[0]=='git':return real_run(command,**kwargs)
                seen.append(list(command))
                if command[0]=='meson':
                    work=output/'mesa-build';work.mkdir()
                    row={'file':str(mesa/'src/mesa/state_tracker/st_manager.c'),'arguments':
                        ['test-clang','--target=arm64-apple-ios16.0','-mcpu=cortex-a53',*build.IOS_CODEGEN_FLAGS,
                         '-c',str(mesa/'src/mesa/state_tracker/st_manager.c')]}
                    (work/'compile_commands.json').write_text(json.dumps([row]))
                elif command[0]=='ninja':
                    for name in build.LIBRARIES:
                        path=output/'mesa-build'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'modeled archive')
                elif command[0] in ('test-clang','test-clang++'):
                    path=Path(command[command.index('-o')+1])
                    path.write_bytes(('modeled '+path.name).encode())
                    if path.name=='ui_loader.o' and mutate:
                        with (output/'libsantoni-eagl.dylib').open('ab') as stream:stream.write(b'changed')
                elif command[0]=='codesign':
                    with Path(command[-1]).open('ab') as stream:stream.write(b'signed')
                elif command[:2]==['xcrun','nm']:
                    if 'mesa-archive-symbols.txt'==Path(kwargs['stdout'].name).name:kwargs['stdout'].write(archive)
                    elif Path(command[-1]).name=='libsantoni-ui-loader.dylib':kwargs['stdout'].write('00000010 T _sgfx_ui_loader_start\n')
                    else:kwargs['stdout'].write(eagl_symbols)
                    kwargs['stdout'].flush();kwargs['stdout'].close()
                elif command[:2]==['xcrun','otool']:
                    kwargs['stdout'].write('/usr/lib/libSystem.B.dylib\n');kwargs['stdout'].flush();kwargs['stdout'].close()
                else:raise AssertionError(command)
                return subprocess.CompletedProcess(command,0)
            with (patch.object(build.platform,'system',return_value='Darwin'),patch.object(build,'prepare_source',side_effect=prepare),
                  patch.object(build.subprocess,'check_output',side_effect=query),patch.object(build.subprocess,'run',side_effect=run)):
                record=build.build(mesa,output,True,True)
            self.assertFalse(record['hardware_verified']);self.assertFalse(record['ui_loader']['CPU_ISA_screened'])
            expected=hashlib.sha256((output/'libsantoni-eagl.dylib').read_bytes()).hexdigest()
            self.assertEqual(record['ui_loader']['eagl_sha256'],expected)
            self.assertEqual((output/'ui_loader_config.h').read_text(),build.ui_loader_config(expected))
            self.assertEqual(record['ui_loader']['loader_path'],build.ui_artifact_path(record['ui_loader']['sha256'],'libsantoni-ui-loader.dylib'))
            compiles=[c for c in seen if c[0]=='test-clang' and '-c' in c]
            self.assertTrue(any(c[c.index('-c')+1].endswith('/readiness.c') for c in compiles))
            self.assertEqual(record['compile_policy']['target_compiles'],1+len(compiles))
            loader_compile=next(c for c in compiles if c[c.index('-c')+1].endswith('/ui_loader.c'))
            self.assertIn('-I'+str(output),loader_compile)
            self.assertNotIn('OpenGLES',json.dumps([c for c in seen if '-dynamiclib' in c]))

if __name__=='__main__':unittest.main()
