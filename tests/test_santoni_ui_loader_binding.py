"""Exact image/report/readonly declaration checks; synthetic Mach-O fixtures."""
import hashlib,json,struct,subprocess,tempfile,unittest
from pathlib import Path
from tests.test_santoni_graphics_library import fixture
from tools.check_santoni_ui_loader import check,readonly_strings
from tools.build_santoni_graphics_gles import ui_artifact_path
from tests.test_santoni_graphics_build_policy import target_sdk_flags

ROOT=Path(__file__).resolve().parents[1]

def with_strings(data,text,writable=False):
    original=bytes(data);command_size=struct.unpack_from('<I',original,36)[0]
    section=struct.pack('<16s16sQQ8I',b'__cstring',b'__TEXT',0x4100,len(text),0x4100,0,0,0,2,0,0,0)
    commands=original[32:32+command_size]+section+original[32+command_size:32+struct.unpack_from('<I',original,20)[0]]
    result=bytearray(original);struct.pack_into('<I',result,20,len(commands));result[32:32+len(commands)]=commands
    struct.pack_into('<I',result,36,command_size+80);struct.pack_into('<I',result,32+64,3)
    if writable:struct.pack_into('<I',result,32+60,7)
    result.extend(b'\0'*(0x4100-len(result)));result.extend(text)
    struct.pack_into('<Q',result,32+48,len(result))
    return result

class LoaderBinding(unittest.TestCase):
    def test_compiled_loader_path_is_a_cstring_literal(self):
        # Compile the actual body with declared platform endpoints. This is an
        # object-section regression; platform layout/linking/runtime are modeled.
        source=(ROOT/'tools/santoni-graphics/ui_loader.c').read_text()
        body='\n'.join(line for line in source.splitlines() if not line.startswith('#include '))
        path=ui_artifact_path('a'*64,'libsantoni-eagl.dylib')
        declarations='''
typedef _Bool bool;
#define true 1
#define false 0
#define NULL ((void *)0)
typedef __SIZE_TYPE__ size_t;
typedef struct { unsigned long signature; char opaque[56]; } pthread_mutex_t;
#define PTHREAD_MUTEX_INITIALIZER {0,{0}}
#define RTLD_NOW 2
#define RTLD_LOCAL 4
#define RTLD_FIRST 256
int pthread_mutex_lock(pthread_mutex_t *);
int pthread_mutex_unlock(pthread_mutex_t *);
unsigned getuid(void);
void *dlopen(const char *,int);
void *dlsym(void *,const char *);
char *dlerror(void);
int memcmp(const void *,const void *,size_t);
int strcmp(const char *,const char *);
void *memcpy(void *,const void *,size_t);
extern void *stderr;
int fprintf(void *,const char *,...);
int fflush(void *);
int *__error(void);
#define errno (*__error())
#define STDERR_FILENO 2
long write(int,const void *,size_t);
'''
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='loader-cstring-',dir=preferred if preferred.is_dir() else None) as temporary:
            work=Path(temporary);src=work/'loader.c';obj=work/'loader.o'
            src.write_text('#define SANTONI_UI_LIBRARY_PATH '+json.dumps(path)+'\n'+declarations+body)
            built=subprocess.run(['clang','--target=arm64-apple-ios16.0','-mcpu=cortex-a53',*target_sdk_flags(),
                '-std=c11','-O2','-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror',
                '-c',str(src),'-o',str(obj)],capture_output=True,text=True,timeout=60)
            self.assertEqual(built.returncode,0,built.stderr)
            data=obj.read_bytes();ncmd=struct.unpack_from('<I',data,16)[0];position=32;blocks=[]
            for _ in range(ncmd):
                command,length=struct.unpack_from('<II',data,position)
                if command==0x19:
                    count=struct.unpack_from('<I',data,position+64)[0]
                    for i in range(count):
                        section=position+72+80*i
                        name,segment,address,span,offset=struct.unpack_from('<16s16sQQI',data,section)
                        flags=struct.unpack_from('<I',data,section+64)[0]
                        if name.rstrip(b'\0')==b'__cstring':
                            self.assertEqual(segment.rstrip(b'\0'),b'__TEXT');self.assertEqual(flags&255,2)
                            self.assertLessEqual(offset+span,len(data));blocks.append(data[offset:offset+span])
                position+=length
            self.assertEqual(sum(block.count(path.encode()+b'\0') for block in blocks),1)

    def test_exact_manifest_cpu_reports_and_readonly_strings(self):
        for mutation in (None,'missing-path','ambiguous-path','writable','manifest','report','pending-report','length'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory(prefix='loader-binding-') as temporary:
                work=Path(temporary);main,_=fixture();main_sha=hashlib.sha256(main).hexdigest()
                path=ui_artifact_path(main_sha,'libsantoni-eagl.dylib')
                strings=(path+'\0sgfx_eagl_install\0/System/Library/Frameworks/OpenGLES.framework/OpenGLES\0').encode()
                if mutation=='missing-path':strings=strings.replace(path.encode(),b'X'*len(path))
                if mutation=='ambiguous-path':strings+=path.encode()+b'\0'
                loader=with_strings(fixture()[0],strings,mutation=='writable');loader_sha=hashlib.sha256(loader).hexdigest()
                (work/'main').write_bytes(main);(work/'loader').write_bytes(loader)
                for name,digest in (('main-cpu',main_sha),('loader-cpu',loader_sha)):
                    report={'success':True,'CPU_ISA_screened':True,'all_instruction_words_bound_to_image':True,'library_sha256':digest}
                    if name=='loader-cpu' and mutation=='report':report['library_sha256']='0'*64
                    if name=='loader-cpu' and mutation=='pending-report':report['CPU_ISA_screened']=False
                    (work/name).write_text(json.dumps(report))
                manifest={'success':True,'eagl_library':{'sha256':main_sha,'bytes':len(main)},'ui_loader':{
                    'sha256':loader_sha,'bytes':len(loader),'eagl_sha256':main_sha,'eagl_path':path,
                    'loader_path':ui_artifact_path(loader_sha,'libsantoni-ui-loader.dylib')}}
                if mutation=='manifest':manifest['ui_loader']['eagl_sha256']='0'*64
                if mutation=='length':manifest['ui_loader']['bytes']-=1
                (work/'build').write_text(json.dumps(manifest))
                args=[work/p for p in ('main','loader','main-cpu','loader-cpu','build')]
                if mutation:
                    with self.assertRaises(ValueError):check(*args)
                else:
                    result=check(*args);self.assertTrue(result['success']);self.assertFalse(result['runtime_dyld_verified']);self.assertFalse(result['hardware_verified'])

if __name__=='__main__':unittest.main()
