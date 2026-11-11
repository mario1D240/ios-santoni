"""Check real reconstructed A53 scalar objects; external ABI endpoints modeled."""
import hashlib,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(os.environ.get('SANTONI_DYLD_PROJECT',str(Path(__file__).resolve().parents[1])))
sys.path.insert(0,str(ROOT/'tools'))
from tests.reconstruct_santoni_touch import reconstruct
from tests.test_santoni_gpu_prepare import source_function
from tests.santoni_gpu_macho_object import resolved_object
from tests.test_santoni_graphics_build_policy import target_sdk_flags
import check_santoni_gpu_kernel as e
import santoni_gpu_dyld_audit as audit
from santoni_gpu_renderer_audit import RENDERER,audit_renderer_task

# These are test endpoint declarations, not kernel headers. The full reference
# layout was separately compiled; actual linked policy data is checked by audit.
POLICY_ABI='''
typedef unsigned int mac_policy_handle_t;
struct mac_policy_ops {
    void (*before[117])(void);
    int (*mpo_policy_syscall)(proc_t,int,user_addr_t);
    void (*after[217])(void);
};
struct mac_policy_conf {
    const char *mpc_name,*mpc_fullname;
    char const * const *mpc_labelnames;
    unsigned int mpc_labelname_count;
    const struct mac_policy_ops *mpc_ops;
    int mpc_loadtime_flags;
    int *mpc_field_off;
    int mpc_runtime_flags;
    struct mac_policy_conf *mpc_list;
    void *mpc_data;
};
_Static_assert(sizeof(struct mac_policy_conf)==80,"policy conf ABI");
_Static_assert(sizeof(struct mac_policy_ops)==2680,"policy vector ABI");
_Static_assert(__builtin_offsetof(struct mac_policy_ops,mpo_policy_syscall)==936,"syscall hook ABI");
extern struct mac_policy_conf sweet_amfi_mac_conf,sweet_sandbox_mac_conf;
extern mac_policy_handle_t sweet_amfi_mac_handle,sweet_sandbox_mac_handle;
int mac_policy_register(struct mac_policy_conf *,mac_policy_handle_t *,void *);
int printf(const char *,...);
'''

class DyldBinaryAudit(unittest.TestCase):
    def test_actual_compiled_renderer_identity_with_current_context(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='renderer-context-',dir=preferred if preferred.is_dir() else None) as temporary:
            work=Path(temporary)
            reconstruction=reconstruct(work/'source',targets=('iokit/Kernel/arm/SantoniGraphics.cpp',))
            cpp=(work/'source/iokit/Kernel/arm/SantoniGraphics.cpp').read_text()
            header='''#include <stdint.h>
struct proc;struct task;struct vnode;
using proc_t=proc *;using task_t=task *;using vnode_t=vnode *;using vfs_context_t=void *;
struct vnode_attr {
 uint64_t va_supported,va_active;int va_vaflags;char unused[48];
 uint32_t va_uid,va_gid;uint16_t va_mode;char tail[362];
};
static_assert(sizeof(vnode_attr)==440,"XNU8796 attribute span");
static_assert(__builtin_offsetof(vnode_attr,va_uid)==68,"XNU8796 UID offset");
static_assert(__builtin_offsetof(vnode_attr,va_mode)==76,"XNU8796 mode offset");
enum {VREG=1,VNODE_LOOKUP_NOFOLLOW=1};
#define VATTR_INIT(v) do {(v)->va_supported=(v)->va_active=0; (v)->va_vaflags=0;} while(0)
#define ATTR_va_uid (1ull<<7)
#define ATTR_va_mode (1ull<<9)
#define VATTR_WANTED(v,k) ((v)->va_active|=ATTR_##k)
#define VATTR_IS_SUPPORTED(v,k) ((v)->va_supported&ATTR_##k)
extern "C" {
proc_t current_proc();task_t current_task();task_t proc_task(proc_t);
int proc_pid(proc_t);unsigned proc_getuid(proc_t);
vnode_t proc_getexecutablevnode(proc_t);vfs_context_t vfs_context_current();
int vnode_lookup(const char *,int,vnode_t *,vfs_context_t);
unsigned vnode_vtype(vnode_t);int vnode_getattr(vnode_t,vnode_attr *,vfs_context_t);
void vnode_put(vnode_t);
unsigned santoni_gpu_dyld_trace_begin(proc_t,unsigned);
void santoni_gpu_dyld_trace_event(proc_t,unsigned,unsigned,int);
}
'''
            body=source_function(cpp,'gfx_renderer_task')
            source=work/'renderer.cpp';source.write_text(header+'\n'+body+
                '\nextern "C" bool fixture_renderer(task_t owner){return gfx_renderer_task(owner);}\n')
            obj=work/'renderer.o'
            command=['clang++','-std=c++17','--target=arm64-apple-ios16.0','-mcpu=cortex-a53',
                *target_sdk_flags(),'-O2','-ffreestanding','-fno-jump-tables','-fno-exceptions',
                '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-mllvm','-enable-machine-outliner=never',
                '-mllvm','-align-all-functions=4','-Wall','-Wextra','-Werror','-c',str(source),'-o',str(obj)]
            built=subprocess.run(command,capture_output=True,text=True,timeout=60)
            self.assertEqual(built.returncode,0,built.stderr)
            original,data,names,image,relocations=resolved_object(obj)
            resolved=work/'resolved.o';resolved.write_bytes(data)
            run=subprocess.run(['llvm-objdump','-d','--mcpu=cortex-a53','--no-symbolic-operands',str(resolved)],
                capture_output=True,text=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr)
            address=next(iter(names[RENDERER]))
            code=e._Code(run.stdout,RENDERER,address,noreturn=names.get('___stack_chk_fail',()))
            report=audit_renderer_task({RENDERER:code},image,names,e)
            self.assertEqual(report['VFS_context_symbol'],'_vfs_context_current')
            self.assertEqual(len(report['cases']),23)
            record=os.environ.get('SANTONI_RENDERER_CONTEXT_RECORD')
            if record:
                with Path(record).open('x') as stream:json.dump({'success':True,'report':report,
                    'reconstruction':reconstruction,'object_sha256':hashlib.sha256(original).hexdigest(),
                    'resolved_object_sha256':hashlib.sha256(data).hexdigest(),'relocations':relocations,
                    'disassembly_sha256':hashlib.sha256(run.stdout.encode()).hexdigest(),
                    'VFS_and_process_responses_modeled':True,'hardware_verified':False},stream,indent=2)

    def test_actual_compiled_flags_callback_and_policy_data(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='dyld-binary-',dir=preferred if preferred.is_dir() else None) as temporary:
            work=Path(temporary)
            reconstruction=reconstruct(work/'source',targets=('bsd/kern/sweet_amfi.c','iokit/Kernel/arm/SantoniGraphics.cpp'))
            cpp=(work/'source/iokit/Kernel/arm/SantoniGraphics.cpp').read_text()
            c=(work/'source/bsd/kern/sweet_amfi.c').read_text()
            flags=source_function(cpp,'santoni_gpu_graphics_dyld_flags')
            first=c.index('extern uint64_t santoni_gpu_graphics_dyld_flags(struct proc *process);')
            block=c[first:c.index('#endif',first)]
            registration=source_function(c,'sweet_amfi_policy_register')
            header='#include "santoni_gpu_dyld_stubs.h"\n'
            flag_header='''#include <stdint.h>
struct proc;struct task;
using proc_t=struct proc *;using task_t=struct task *;
extern "C" proc_t current_proc(void);
extern "C" task_t current_task(void);
extern "C" int PE_parse_boot_argn(const char *,void *,unsigned);
extern "C" bool fixture_renderer(task_t);
static bool __attribute__((noinline)) gfx_renderer_task(task_t owner)
{return fixture_renderer(owner);}
'''
            (work/'flags.cpp').write_text(flag_header+'extern "C" {\n'+flags+'\n}\n')
            (work/'policy.c').write_text(header+POLICY_ABI+block+'\n'+registration+'\n')
            codegen=['--target=arm64-apple-ios16.0','-mcpu=cortex-a53',*target_sdk_flags(),'-O2','-ffreestanding','-fno-jump-tables',
                '-fno-asynchronous-unwind-tables','-fno-unwind-tables','-fno-exceptions',
                '-mllvm','-enable-machine-outliner=never','-mllvm','-align-all-functions=4','-Wall','-Wextra','-Werror',
                '-DARM64_BOARD_CONFIG_SANTONI','-I',str(ROOT/'tests')]
            commands=[];rows=[]
            for stem,compiler,language in [('flags','clang++','-std=c++17'),('policy','clang','-std=c11')]:
                source=work/(stem+('.cpp' if stem=='flags' else '.c'));obj=work/(stem+'.o')
                command=[compiler,language,*codegen,'-c',str(source),'-o',str(obj)]
                result=subprocess.run(command,capture_output=True,text=True,timeout=60)
                commands.append({'command':command,'exit':result.returncode,'stderr':result.stderr})
                self.assertEqual(result.returncode,0,result.stderr)
                original,data,names,image,relocations=resolved_object(obj)
                resolved=work/(stem+'-resolved.o');resolved.write_bytes(data)
                decoded=subprocess.run(['llvm-objdump','-d','--mcpu=cortex-a53','--no-symbolic-operands',str(resolved)],
                    capture_output=True,text=True,timeout=30)
                self.assertEqual(decoded.returncode,0,decoded.stderr)
                def code(symbol):
                    text=decoded.stdout;address=next(iter(names[symbol]))
                    if f'{address:016x} <{symbol}>:' not in text:
                        self.assertEqual(names[symbol],names['ltmp0'])
                        alias=f'{address:016x} <ltmp0>:';self.assertEqual(text.count(alias),1)
                        text=text.replace(alias,f'{address:016x} <{symbol}>:')
                    return e._Code(text,symbol,address,noreturn=names.get('___stack_chk_fail',()))
                if stem=='flags':
                    report=audit.audit_flags({audit.FLAGS:code(audit.FLAGS)},image,names,e)
                    self.assertEqual(len(report['cases']),62)
                else:
                    callback=audit.audit_callback({audit.CALLBACK:code(audit.CALLBACK)},image,names,e)
                    trace_codes={n:code(n) for n in (audit.TRACE_BEGIN,audit.TRACE_EVENT)}
                    trace=audit.audit_trace(trace_codes,image,names,e)
                    self.assertTrue(trace['success'])
                    counter=next(iter(names['_sweet_dyld_trace_counts']))
                    class CounterImage:
                        def __init__(self,kind):
                            self.kind=kind
                            self.segs=tuple({**seg,'initprot':5 if kind=='readonly' else seg['initprot'],
                                'filesize':0 if kind=='tail' else seg['vmsize']} for seg in image.segs)
                        def read(self,address,size):
                            if address==counter and size==12:
                                return 1 if self.kind=='dirty' else None if self.kind in ('tail','hole') else 0
                            return image.read(address,size)
                    self.assertTrue(audit.audit_trace(trace_codes,CounterImage('tail'),names,e)['success'])
                    for kind in ('readonly','dirty','hole'):
                        with self.subTest(counter_image=kind),self.assertRaises(ValueError):
                            audit.audit_trace(trace_codes,CounterImage(kind),names,e)
                    report=audit.audit_registration({audit.REGISTER:code(audit.REGISTER)},image,names,e)
                    self.assertEqual(len(callback['cases']),90);self.assertEqual(len(report['cases']),5)
                    ops=next(iter(names['_sweet_santoni_dyld_mac_ops']))
                    class ChangedImage:
                        def read(self,address,size):
                            value=image.read(address,size)
                            if value is None:return None
                            data_=bytearray(value.to_bytes(size,'little'))
                            # Inject an additional hook while preserving the syscall.
                            for i,byte in enumerate(next(iter(names[audit.CALLBACK])).to_bytes(8,'little')):
                                if address<=ops+i<address+size:data_[ops+i-address]=byte
                            return int.from_bytes(data_,'little')
                    with self.assertRaises(ValueError):audit.audit_registration({audit.REGISTER:code(audit.REGISTER)},ChangedImage(),names,e)
                rows.append({'role':stem,'object_sha256':hashlib.sha256(original).hexdigest(),
                    'resolved_image_sha256':hashlib.sha256(data).hexdigest(),'relocations':relocations,
                    'disassembly_sha256':hashlib.sha256(decoded.stdout.encode()).hexdigest(),'report':report,
                    'callback_report':callback if stem=='policy' else None,
                    'trace_report':trace if stem=='policy' else None})
            record=os.environ.get('SANTONI_DYLD_BINARY_RECORD')
            if record:
                with Path(record).open('x') as stream:json.dump({'success':True,'commands':commands,'rows':rows,
                    'reconstruction':reconstruction,'platform_and_policy_ABI_declarations_modeled':True,
                    'actual_linked_kernel_wiring_verified':False,'hardware_verified':False},stream,indent=2)

if __name__=='__main__':unittest.main()
