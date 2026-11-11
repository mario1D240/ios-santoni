"""Actual CPU compiler fixture and fail-closed iOS command policy checks."""
import copy
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from tools.build_santoni_graphics_gles import check_compile_policy,IOS_CODEGEN_FLAGS

def target_sdk_flags():
    if platform.system()!='Darwin':return []
    sdk=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip()
    if not sdk or not Path(sdk).is_dir():raise ValueError('iPhone SDK for object fixture is missing')
    return ['-isysroot',sdk]

class CompilePolicyTests(unittest.TestCase):
    def test_iPhone_object_sdk_is_explicit_on_Darwin(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(platform,'system',return_value='Darwin'),patch.object(subprocess,'check_output',return_value=temporary+'\n') as query:
                self.assertEqual(target_sdk_flags(),['-isysroot',temporary])
                query.assert_called_once_with(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True)
            with patch.object(platform,'system',return_value='Darwin'),patch.object(subprocess,'check_output',return_value=''):
                with self.assertRaises(ValueError):target_sdk_flags()
        with patch.object(platform,'system',return_value='Linux'),patch.object(subprocess,'check_output') as query:
            self.assertEqual(target_sdk_flags(),[]);query.assert_not_called()
    def commands(self):
        return [{'file':'vbo_exec.c','arguments':['clang','--target=arm64-apple-ios16.0','-mcpu=cortex-a53',*IOS_CODEGEN_FLAGS,'-c','vbo_exec.c']}]

    def test_arguments_and_shell_inventory(self):
        rows=self.commands();result=check_compile_policy(rows)
        self.assertEqual(result['target_compiles'],1)
        self.assertFalse(result['CPU_ISA_screened']);self.assertFalse(result['hardware_verified'])
        shell=[{'file':rows[0]['file'],'command':' '.join(rows[0]['arguments'])}]
        self.assertEqual(check_compile_policy(shell),result)
        rows.append({'file':'native-generator.c','arguments':['cc','-c','native-generator.c']})
        self.assertEqual(check_compile_policy(rows),result)

    def test_missing_flags_and_overrides_refused(self):
        for case in ('missing','override','earlier-override','cpu','file','args','empty','no-target','row','arguments',
                     'outliner','alignment','missing-forward'):
            with self.subTest(case=case),self.assertRaises(ValueError):
                rows=copy.deepcopy(self.commands());args=rows[0]['arguments']
                if case=='missing':args.remove('-fno-jump-tables')
                elif case=='override':args.append('-fjump-tables')
                elif case=='earlier-override':args.insert(1,'-fjump-tables')
                elif case=='cpu':args.remove('-mcpu=cortex-a53')
                elif case=='file':rows[0]['file']=''
                elif case=='args':rows[0].pop('arguments')
                elif case=='empty':rows=[]
                elif case=='no-target':args.remove('--target=arm64-apple-ios16.0')
                elif case=='row':rows=[None]
                elif case=='arguments':args.append(None)
                elif case=='outliner':args+=['-mllvm','-enable-machine-outliner=always']
                elif case=='alignment':args+=['-mllvm','-align-all-functions=2']
                elif case=='missing-forward':args.remove('-mllvm')
                check_compile_policy(rows)

    def test_actual_outliner_exclusion_and_function_alignment(self):
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='a53-outliner-policy-',dir=preferred if preferred.is_dir() else None) as temporary:
            work=Path(temporary);source=work/'outline.c'
            body='extern void effect(unsigned);\n'
            for i in range(12):
                body+=f'__attribute__((noinline,used)) unsigned action{i}(unsigned x) {{effect(x+1);effect(x+2);effect(x+3);return x+{i};}}\n'
            source.write_text(body);results={}
            variants=[('control',['-O2','-mllvm','-enable-machine-outliner=always'])]
            # UBSan's function-type checker adds an eight-byte type cookie
            # before each Darwin function entry. Production has no sanitizer
            # cookies; retain other UB checks without changing this layout
            # contract. No sanitizer exclusion is added to production flags.
            variants += [(label,[*flags,*IOS_CODEGEN_FLAGS]) for label,flags in
                [('O0',['-O0']),('O2',['-O2']),('ubsan',['-O2','-fsanitize=undefined',
                    '-fno-sanitize=function','-fno-sanitize-recover=all'])]]
            for label,flags in variants:
                obj=work/(label+'.o')
                build=subprocess.run(['clang','--target=arm64-apple-ios16.0','-mcpu=cortex-a53',*target_sdk_flags(),*flags,
                    '-Wall','-Wextra','-Werror','-c',str(source),'-o',str(obj)],capture_output=True,text=True,timeout=30)
                self.assertEqual(build.returncode,0,build.stderr)
                symbols=subprocess.run(['llvm-nm','--defined-only',str(obj)],capture_output=True,text=True,timeout=30)
                self.assertEqual(symbols.returncode,0,symbols.stderr);results[label]=symbols.stdout
            self.assertIn('OUTLINED_FUNCTION',results['control'])
            for label in ('O0','O2','ubsan'):
                with self.subTest(variant=label):
                    self.assertNotIn('OUTLINED_FUNCTION',results[label])
                    addresses=[int(line.split()[0],16) for line in results[label].splitlines() if re.search(r'\b_action\d+$',line)]
                    self.assertEqual(len(addresses),12);self.assertTrue(all(address%16==0 for address in addresses))

    def test_actual_a53_switch_object_has_no_indirect_dispatch(self):
        # This is a small standalone CPU object, NOT a local XNU kernel build.
        # The default control must really contain an indirect jump so this
        # fixture cannot pass merely because the compiler ignored the flag.
        self.assertIsNotNone(shutil.which('clang'));self.assertIsNotNone(shutil.which('llvm-objdump'))
        preferred=Path('/data/data/com.termux/files/usr/tmp/opencode')
        with tempfile.TemporaryDirectory(prefix='a53-switch-policy-',dir=preferred if preferred.is_dir() else None) as temporary:
            work=Path(temporary);source=work/'switch.c'
            body='\n'.join(f'extern unsigned action{i}(unsigned);' for i in range(15))
            body+='\nunsigned dispatch(unsigned mode,unsigned value) { switch(mode) {\n'
            body+='\n'.join(f'case {i}:return action{i}(value);' for i in range(15))
            body+='\ndefault:__builtin_unreachable(); } }\n'
            source.write_text(body)
            indirect=[]
            for label,flags in [('control',['-fjump-tables']),('branch-only',list(IOS_CODEGEN_FLAGS))]:
                obj=work/(label+'.o')
                build=subprocess.run(['clang','--target=arm64-apple-ios16.0','-mcpu=cortex-a53',*target_sdk_flags(),'-O2',*flags,
                    '-Wall','-Wextra','-Werror','-c',str(source),'-o',str(obj)],capture_output=True,text=True,timeout=30)
                self.assertEqual(build.returncode,0,build.stderr)
                decoded=subprocess.run(['llvm-objdump','-d','--disassemble-zeroes','--mcpu=cortex-a53',str(obj)],capture_output=True,text=True,timeout=30)
                self.assertEqual(decoded.returncode,0,decoded.stderr)
                self.assertNotIn('<unknown>',decoded.stdout)
                indirect.append(bool(re.search(r'\bbr\s+x\d+\b',decoded.stdout)))
            self.assertEqual(indirect,[True,False])

if __name__=='__main__':unittest.main()
