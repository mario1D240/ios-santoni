#!/usr/bin/env python3
"""Link pinned Mesa/Gallium/IR3 GLES for iOS; no installation or GPU opt-in."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import shlex
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
LIBRARIES=tuple('src/'+name+'.a' for name in (
    'mesa/libmesa','gallium/auxiliary/libgallium','gallium/drivers/freedreno/libfreedreno',
    'gallium/winsys/freedreno/drm/libfreedrenowinsys',
    'freedreno/drm/libfreedreno_drm','freedreno/ir3/libfreedreno_ir3','freedreno/ir2/libfreedreno_ir2',
    'freedreno/fdl/libfreedreno_layout','freedreno/common/libfreedreno_common',
    'freedreno/isa/libir3encode','freedreno/isa/libir3decode','compiler/isaspec/libisaspec',
    'freedreno/perfcntrs/libfreedreno_perfcntrs','compiler/glsl/libglsl','compiler/glsl/glcpp/libglcpp',
    'compiler/nir/libnir','compiler/spirv/libvtn','compiler/libcompiler','mapi/glapi/libglapi_bridge',
    'mapi/shared-glapi/libglapi',
    'util/libxmlconfig','util/libmesa_util','util/libmesa_util_sse41','util/blake3/libblake3','c11/impl/libmesa_util_c11'))
# Keep switch dispatch direct and prevent unaligned compiler-outlined helpers.
# LLVM's align-all-functions value is log2(bytes): 4 requests 16-byte alignment.
# The full actual-library screen remains mandatory; these flags do not certify
# ISA/control flow/runtime behavior or remove function-pointer tail branches.
IOS_CODEGEN_FLAGS=('-fno-jump-tables',
    '-mllvm','-enable-machine-outliner=never',
    '-mllvm','-align-all-functions=4')
MESA_OPTIONS=(
    '-Db_ndebug=true','-Ddefault_library=static',
    '-Dplatforms=','-Degl=disabled','-Dglx=disabled','-Dgbm=disabled','-Dshared-glapi=enabled',
    '-Dgallium-drivers=freedreno','-Dvulkan-drivers=','-Dfreedreno-kmds=msm',
    '-Dllvm=disabled','-Dgles1=disabled','-Dgles2=enabled','-Dopengl=true',
    '-Dzstd=disabled','-Dzlib=disabled','-Dexpat=disabled','-Dxmlconfig=disabled',
    '-Dvalgrind=disabled','-Dlibunwind=disabled','-Dlmsensors=disabled',
    '-Dbuild-tests=false','-Dshader-cache=disabled','-Dperfetto=false',
    '-Dgallium-va=disabled','-Dgallium-vdpau=disabled','-Dgallium-rusticl=false','-Dtools=',
    '-Dhtml-docs=disabled','-Dteflon=false')


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def ui_artifact_path(digest,name):
    if not isinstance(digest,str) or re.fullmatch('[0-9a-f]{64}',digest) is None:
        raise ValueError('UI artifact SHA256 must be exact lowercase hex')
    if name not in ('libsantoni-eagl.dylib','libsantoni-ui-loader.dylib'):
        raise ValueError('unknown UI artifact role')
    return '/usr/local/lib/santoni-gpu-ui/'+digest+'/'+name


def ui_loader_config(eagl_sha256):
    return '#define SANTONI_UI_LIBRARY_PATH '+json.dumps(ui_artifact_path(eagl_sha256,'libsantoni-eagl.dylib'))+'\n'


def check_loader_inventory(symbols,libraries):
    rows=[line.split() for line in symbols.splitlines()]
    definitions=[row for row in rows if len(row)==3 and row[1] in ('T','t')]
    entry=[row for row in definitions if row[2]=='_sgfx_ui_loader_start']
    if len(entry)!=1 or re.fullmatch('[0-9a-fA-F]+',entry[0][0]) is None or int(entry[0][0],16)==0:
        raise ValueError('missing or ambiguous explicit loader entry')
    if any(len(row)>=2 and row[-2] in ('T','t','U') and
           row[-1].startswith(('_gl','_sgfx_gles_','_sgfx_eagl_')) for row in rows) or 'OpenGLES' in libraries:
        raise ValueError('loader must remain separate from Mesa/system GL linkage')
    return {'_sgfx_ui_loader_start':entry[0][0]}


def check_linked_inventory(symbols,libraries):
    if 'OpenGLES' in libraries:raise ValueError('system GL dependency is forbidden')
    # Verified in the real Darwin executable: hidden Mesa functions become
    # local text (t), while exported GL/frontend entry points remain text (T).
    rows=[line.split() for line in symbols.splitlines()]
    required=('_glClear','_glDrawArrays','_glReadPixels','_fd5_emit_state','_ir3_compile_shader_nir','_sgfx_msm_command')
    for name in required:
        defined=[row for row in rows if len(row)==3 and row[1] in ('T','t') and row[2]==name]
        if len(defined)!=1 or not re.fullmatch(r'[0-9a-fA-F]+',defined[0][0]) or int(defined[0][0],16)==0:
            raise ValueError('missing or ambiguous linked GLES/freedreno text: '+name)
    return {name:next(row[0] for row in rows if len(row)==3 and row[1] in ('T','t') and row[2]==name) for name in required}


def check_compile_policy(inventory):
    """Bind the actual target compile commands, not just cross-file intent."""
    if not isinstance(inventory,list) or not inventory or len(inventory)>100000:
        raise ValueError('compile-command inventory outside bound')
    checked=[]
    for row in inventory:
        if not isinstance(row,dict):raise ValueError('compile-command framing')
        arguments=row.get('arguments')
        if arguments is None:
            if not isinstance(row.get('command'),str):raise ValueError('missing compile command')
            arguments=shlex.split(row['command'])
        if not isinstance(arguments,list) or not arguments or any(not isinstance(a,str) for a in arguments):
            raise ValueError('compile-argument framing')
        if '--target=arm64-apple-ios16.0' not in arguments:continue # unshipped native build helpers
        if any(flag not in arguments for flag in IOS_CODEGEN_FLAGS) or '-fjump-tables' in arguments:
            raise ValueError('iOS compile omitted/overrode branch-only code generation')
        for index,argument in enumerate(arguments):
            if argument.startswith('-enable-machine-outliner') and argument!='-enable-machine-outliner=never':
                raise ValueError('iOS compile overrode machine-outliner exclusion')
            if argument.startswith('-align-all-functions') and argument!='-align-all-functions=4':
                raise ValueError('iOS compile overrode function alignment')
            if argument in ('-enable-machine-outliner=never','-align-all-functions=4') and (not index or arguments[index-1]!='-mllvm'):
                raise ValueError('LLVM code-generation option lacks driver forwarding')
        if '-mcpu=cortex-a53' not in arguments:
            raise ValueError('iOS compile omitted Cortex-A53 target')
        if not isinstance(row.get('file'),str) or not row['file']:raise ValueError('missing compile source')
        checked.append({'file':row['file'],'arguments':arguments})
    if not checked:raise ValueError('no iOS target compile commands')
    return {'target_compiles':len(checked),'codegen_flags':list(IOS_CODEGEN_FLAGS),
            'compile_commands_sha256':hashlib.sha256(json.dumps(checked,sort_keys=True).encode()).hexdigest(),
            'CPU_ISA_screened':False,'hardware_verified':False}


def prepare_source(mesa,output):
    mesa=Path(mesa).resolve();output=Path(output).resolve()
    if output.exists():raise ValueError('refusing to overwrite Mesa source/output')
    lock=json.loads((ROOT/'tools/santoni-graphics/mesa-reference.json').read_text())
    names=set(re.findall(r"option\(\s*'([^']+)'",(mesa/'meson_options.txt').read_text()))
    names.update(('b_ndebug','default_library'))
    for arg in MESA_OPTIONS:
        if arg[2:].split('=',1)[0] not in names:
            raise ValueError('option absent from pinned Mesa: '+arg)
    for name,want in lock['source_sha256'].items():
        if sha(mesa/name)!=want:raise ValueError('pinned Mesa input differs: '+name)
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=mesa,text=True).strip()
    if commit!=lock['commit']:raise ValueError('Mesa commit differs from dependency lock')
    output.mkdir(parents=True);source=output/'mesa-source'
    subprocess.run(['git','clone','--quiet','--shared','--no-checkout',str(mesa),str(source)],check=True)
    subprocess.run(['git','checkout','--quiet','--detach',lock['commit']],cwd=source,check=True)
    patch=ROOT/'tools/santoni-graphics/mesa-ios.patch'
    for args in (['git','apply','--check',str(patch)],['git','apply',str(patch)]):
        subprocess.run(args,cwd=source,check=True)
    names=subprocess.check_output(['git','diff','--name-only'],cwd=source,text=True).splitlines()
    record={'mesa':lock,'patch_sha256':sha(patch),'source_sha256':{name:sha(source/name) for name in names}}
    (output/'mesa-source.json').write_text(json.dumps(record,indent=2)+'\n')
    return source,record


def build(mesa,output,eagl=False,ui_loader=False):
    from tests.reconstruct_santoni_touch import reconstruct
    if platform.system()!='Darwin':raise ValueError('iOS GLES build requires macOS/Xcode')
    if ui_loader and not eagl:raise ValueError('UI loader requires the exact EAGL library build')
    output=Path(output).resolve();source,source_record=prepare_source(mesa,output)
    uapi=output/'uapi-source'
    receipt=reconstruct(uapi,targets=('bsd/dev/santoni_gpu_graphics_uapi.h',))
    own=ROOT/'tools/santoni-graphics'
    inputs={str(p.relative_to(ROOT)):sha(p) for p in sorted(own.rglob('*')) if p.is_file()}
    inputs[str(Path(__file__).resolve().relative_to(ROOT))]=sha(__file__)
    if eagl:inputs['tools/generate_santoni_gl_dispatch.py']=sha(ROOT/'tools/generate_santoni_gl_dispatch.py')
    sdk=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip()
    cc=subprocess.check_output(['xcrun','--sdk','iphoneos','--find','clang'],text=True).strip()
    cxx=subprocess.check_output(['xcrun','--sdk','iphoneos','--find','clang++'],text=True).strip()
    ar=subprocess.check_output(['xcrun','--sdk','iphoneos','--find','ar'],text=True).strip()
    target=['--target=arm64-apple-ios16.0','-isysroot',sdk,'-mcpu=cortex-a53',*IOS_CODEGEN_FLAGS]
    defines=['-DSANTONI_GFX_MESA=1','-I'+str(own),'-I'+str(own/'include'),'-I'+str(uapi/'bsd/dev')]
    cross=output/'ios-cross.txt'
    def array(items):return '['+', '.join(repr(item) for item in items)+']'
    cross.write_text('[binaries]\nc = '+array([cc,*target])+ '\ncpp = '+array([cxx,*target])+
        '\nobjc = '+array([cc,*target])+'\nar = '+repr(ar)+"\npkg-config = 'false'\n\n"+
        '[built-in options]\nc_args = '+array(defines)+'\ncpp_args = '+array(defines)+
        "\n\n[host_machine]\nsystem = 'darwin'\nsubsystem = 'ios'\ncpu_family = 'aarch64'\ncpu = 'arm64'\nendian = 'little'\n")
    build_dir=output/'mesa-build'
    configure=['meson','setup',str(build_dir),str(source),'--cross-file',str(cross),
        '--buildtype=release','--wrap-mode=nofallback',*MESA_OPTIONS]
    commands=[configure]
    with (output/'build.log').open('x') as log:
        subprocess.run(configure,stdout=log,stderr=subprocess.STDOUT,check=True)
        compile_mesa=['ninja','-C',str(build_dir),*LIBRARIES]
        subprocess.run(compile_mesa,stdout=log,stderr=subprocess.STDOUT,check=True);commands.append(compile_mesa)
        inventory=json.loads((build_dir/'compile_commands.json').read_text())
        compile_policy=check_compile_policy(inventory)
        tracker=next(row for row in inventory if row['file'].endswith('state_tracker/st_manager.c'))
        tracker_flags=tracker.get('arguments') or shlex.split(tracker['command'])
        tracker_defines=[arg for arg in tracker_flags if arg.startswith('-D')]
        includes=[source/'include',source/'include/drm-uapi',source/'src',source/'src/mesa',source/'src/mapi',source/'src/gallium/include',
            source/'src/gallium/auxiliary',source/'src/gallium/drivers',source/'src/gallium/winsys',source/'src/freedreno',
            build_dir/'src',build_dir/'src/mesa',build_dir/'src/mapi',build_dir/'src/util']
        objects=[]
        frontend_inventory=[]
        for name in ('client','commands','msm','drm','ios','gles','ui_surface','ui_gl','gles_probe'):
            obj=output/(name+'.o')
            command=[cc,*target,'-std=c11','-O2','-Wall','-Wextra','-Werror',*defines,*tracker_defines,
                *['-I'+str(path) for path in includes],'-c',str(own/(name+'.c')),'-o',str(obj)]
            subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True);commands.append(command);objects.append(obj)
            frontend_inventory.append({'file':str(own/(name+'.c')),'arguments':command})
        executable=output/'santoni-gles-probe'
        command=[cxx,*target,'-Wl,-dead_strip','-o',str(executable),*[str(obj) for obj in objects],
            *[str(build_dir/name) for name in LIBRARIES],'-framework','IOKit','-framework','CoreFoundation','-lz']
        # The GL entry points come from Mesa, not the system OpenGLES framework.
        subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True);commands.append(command)
        subprocess.run(['codesign','--force','--sign','-',str(executable)],stdout=log,stderr=subprocess.STDOUT,check=True)
        subprocess.run(['xcrun','nm',str(executable)],stdout=(output/'symbols.txt').open('x'),check=True)
        subprocess.run(['xcrun','otool','-L',str(executable)],stdout=(output/'libraries.txt').open('x'),check=True)
        if eagl:
            # The small proof executable strips unused GL functions. Resolve
            # GLI against the actual archives before linking the UI library.
            archive_symbols=output/'mesa-archive-symbols.txt'
            subprocess.run(['xcrun','nm',*[str(build_dir/name) for name in LIBRARIES]],stdout=archive_symbols.open('x'),check=True)
            from tools.generate_santoni_gl_dispatch import generate
            layout=own/'ios-dispatch-20H392.txt'
            headers='\n'.join((source/'include'/name).read_text() for name in
                ('GL/gl.h','GL/glext.h','GLES/gl.h','GLES/glext.h','GLES2/gl2.h','GLES2/gl2ext.h','GLES3/gl3.h'))
            dispatch,dispatch_record=generate(layout.read_text(),headers,archive_symbols.read_text())
            required={'glBlendFunc','glColorMask','glEnable','glDisable','glActiveTexture','glScissor',
                'glUniform1i','glUniformMatrix4fv','glGetUniformLocationARB','glCreateShaderObjectARB'}
            if required.intersection(dispatch_record['unavailable']):raise ValueError('Mesa archive lacks required UI GL entries')
            generated=output/'ui-generated.c'
            with generated.open('x') as stream:stream.write(dispatch)
            with (output/'ui-dispatch.json').open('x') as stream:json.dump(dispatch_record,stream,indent=2)
            ui_objects=[]
            for name in ('readiness','ui_context','ui_backend','ui_dispatch','ui_shader','ui_eagl','ui-generated'):
                obj=output/(name+'.o');input_source=generated if name=='ui-generated' else own/(name+'.c')
                command=[cc,*target,'-std=c11','-O2','-fPIC','-Wall','-Wextra','-Werror',*defines,*tracker_defines,
                    *['-I'+str(path) for path in includes],'-c',str(input_source),'-o',str(obj)]
                subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True);commands.append(command);ui_objects.append(obj)
                frontend_inventory.append({'file':str(input_source),'arguments':command})
            library=output/'libsantoni-eagl.dylib'
            command=[cxx,*target,'-dynamiclib','-Wl,-dead_strip','-Wl,-install_name,@rpath/libsantoni-eagl.dylib',
                '-o',str(library),*[str(obj) for obj in objects if obj.stem!='gles_probe'],*[str(obj) for obj in ui_objects],
                *[str(build_dir/name) for name in LIBRARIES],'-framework','IOKit','-framework','CoreFoundation',
                '-framework','IOSurface','-lobjc','-lz']
            subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True);commands.append(command)
            subprocess.run(['codesign','--force','--sign','-',str(library)],stdout=log,stderr=subprocess.STDOUT,check=True)
            subprocess.run(['xcrun','nm',str(library)],stdout=(output/'eagl-symbols.txt').open('x'),check=True)
            subprocess.run(['xcrun','otool','-L',str(library)],stdout=(output/'eagl-libraries.txt').open('x'),check=True)
            check_linked_inventory((output/'eagl-symbols.txt').read_text(),(output/'eagl-libraries.txt').read_text())
            rows=[line.split() for line in (output/'eagl-symbols.txt').read_text().splitlines()]
            for name in ('_sgfx_eagl_install','_sgfx_gles_ui_readback_proof','_sgfx_ios_renderer_wait',
                         '_sgfx_drm_open_renderer','_sgfx_ui_context_attach','_sgfx_ui_context_flush'):
                if sum(len(row)==3 and row[1] in ('T','t') and row[2]==name for row in rows)!=1:
                    raise ValueError('missing linked EAGL entry: '+name)
            if ui_loader:
                eagl_hash=sha(library);config=output/'ui_loader_config.h'
                with config.open('x') as stream:stream.write(ui_loader_config(eagl_hash))
                loader_object=output/'ui_loader.o';loader=output/'libsantoni-ui-loader.dylib'
                command=[cc,*target,'-std=c11','-O2','-fPIC','-Wall','-Wextra','-Werror','-I'+str(output),
                    '-c',str(own/'ui_loader.c'),'-o',str(loader_object)]
                subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True);commands.append(command)
                frontend_inventory.append({'file':str(own/'ui_loader.c'),'arguments':command})
                command=[cc,*target,'-dynamiclib','-Wl,-dead_strip','-Wl,-install_name,@rpath/libsantoni-ui-loader.dylib',
                    '-o',str(loader),str(loader_object)]
                subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True);commands.append(command)
                subprocess.run(['codesign','--force','--sign','-',str(loader)],stdout=log,stderr=subprocess.STDOUT,check=True)
                subprocess.run(['xcrun','nm',str(loader)],stdout=(output/'loader-symbols.txt').open('x'),check=True)
                subprocess.run(['xcrun','otool','-L',str(loader)],stdout=(output/'loader-libraries.txt').open('x'),check=True)
                loader_entries=check_loader_inventory((output/'loader-symbols.txt').read_text(),(output/'loader-libraries.txt').read_text())
                if sha(library)!=eagl_hash:raise ValueError('EAGL bytes changed during loader build')
                loader_record={'sha256':sha(loader),'bytes':loader.stat().st_size,'eagl_sha256':eagl_hash,
                    'eagl_path':ui_artifact_path(eagl_hash,'libsantoni-eagl.dylib'),
                    'loader_path':ui_artifact_path(sha(loader),'libsantoni-ui-loader.dylib'),
                    'config_sha256':sha(config),'linked_text':loader_entries,'CPU_ISA_screened':False,
                    'runtime_dyld_verified':False,'installed':False,'hardware_verified':False}
        compile_policy=check_compile_policy([*inventory,*frontend_inventory])
    symbols=(output/'symbols.txt').read_text()
    inventory=check_linked_inventory(symbols,(output/'libraries.txt').read_text())
    if any(sha(ROOT/name)!=want for name,want in inputs.items()):raise ValueError('frontend source changed during build')
    record={'success':True,'commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'mesa_source':source_record,'uapi_source':receipt,'inputs_sha256':inputs,'commands':commands,
        'executable_sha256':sha(executable),'bytes':executable.stat().st_size,'linked_text':inventory,
        'compile_policy':compile_policy,
        'mesa_libraries_sha256':{name:sha(build_dir/name) for name in LIBRARIES},
        'full_Gallium_linked':True,'hardware_verified':False,'EAGL_installed':False,'kernel_GLES_enabled':False}
    if eagl:record['eagl_library']={'sha256':sha(library),'bytes':library.stat().st_size,
        'dispatch':dispatch_record,'explicit_install_only':True,'installed':False,'hardware_verified':False,
        'private_framebuffer_semantics_implemented':False,'shader_compatibility_complete':False}
    if ui_loader:record['ui_loader']=loader_record
    (output/'build.json').write_text(json.dumps(record,indent=2)+'\n');return record


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--mesa',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--eagl',action='store_true',help='also link the explicit-install EAGL bridge; never installs it')
    p.add_argument('--ui-loader',action='store_true',help='also build the separate loader bound to the signed EAGL SHA; requires --eagl')
    args=p.parse_args();print(json.dumps(build(args.mesa,args.output,args.eagl,args.ui_loader),indent=2))
