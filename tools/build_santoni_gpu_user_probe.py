#!/usr/bin/env python3
"""Build a freestanding A53 EL0 probe; never package/boot or change the iOS root.

Internal calls use ELF/AAPCS64 and the explicit Darwin SVC wrapper. No libc or
iOS SDK ABI is linked. Link VMAs exactly where mkinit's static Mach-O maps code;
the ELF is an intermediate for relocation/ISA inspection, not a device image.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

import mkinit

ROOT=Path(__file__).resolve().parents[1]
LINK='''ENTRY(_start)
SECTIONS {
 . = 0x100000400;
 .probe : {
   __probe_code_start = .;
   *(.text .text.*)
   __probe_code_end = .;
   *(.rodata .rodata.*)
 }
 .data : { *(.data .data.*) }
 .bss : { *(.bss .bss.* COMMON) }
 /DISCARD/ : { *(.comment .note* .eh_frame* .ARM.exidx* .ARM.extab*) }
}
ASSERT(SIZEOF(.data)==0, "probe must have no writable global data")
ASSERT(SIZEOF(.bss)==0, "probe must have no BSS")
ASSERT(SIZEOF(.probe)<=0x3c00, "probe exceeds static Mach-O text capacity")
'''


def wrap_object(code, start):
    """Minimal relocation-free Mach-O object consumed by unchanged mkinit."""
    command_size=152+24
    offset=32+command_size
    section=struct.pack('<16s16sQQIIIIIIII',b'__text',b'__TEXT',0,len(code),
                        offset,2,0,0,0x80000400,0,0,0)
    segment=mkinit.segment('__TEXT',0,len(code),offset,len(code),5,[section])
    symbols=offset+len(code); strings=symbols+16
    table=struct.pack('<6I',mkinit.LC_SYMTAB,24,symbols,1,strings,8)
    header=struct.pack('<8I',mkinit.MH_MAGIC_64,mkinit.CPU_TYPE_ARM64,0,1,2,command_size,0,0)
    symbol=struct.pack('<IBBHQ',1,0x0f,1,0,start)
    return header+segment+table+code+symbol+b'\0_start\0'


def build(output, uapi, trace_uapi=None):
    if output.exists(): raise ValueError('refusing to rebuild or overwrite an existing probe directory')
    output.mkdir(parents=True)
    uapi_data=uapi.read_bytes()
    trace_data=(trace_uapi or uapi.with_name('santoni_gpu_launch_trace.h')).read_bytes()
    (output/'santoni_gpu_uapi.h').write_bytes(uapi_data)
    (output/'santoni_gpu_launch_trace.h').write_bytes(trace_data)
    sources=['tools/santoni_gpu_user_probe.c','tools/santoni_gpu_user_probe_start.S']
    (output/'probe.ld').write_text(LINK)
    flags=['clang','--target=aarch64-none-elf','-mcpu=cortex-a53','-mgeneral-regs-only',
           '-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-unwind-tables',
           '-fno-asynchronous-unwind-tables','-O2','-Wall','-Wextra','-Werror','-I',str(output)]
    objects=[]
    for index,source in enumerate(sources):
        obj=output/('probe-'+str(index)+'.o')
        subprocess.run([*flags,'-c',str(ROOT/source),'-o',str(obj)],check=True,capture_output=True,text=True)
        objects.append(obj)
    elf=output/'probe.elf'
    subprocess.run(['ld.lld','--no-undefined','--build-id=none','-T',str(output/'probe.ld'),
                    *map(str,objects),'-o',str(elf)],check=True,capture_output=True,text=True)
    symbols=subprocess.check_output(['llvm-nm','--defined-only',str(elf)],text=True)
    undefined=subprocess.check_output(['llvm-nm','--undefined-only',str(elf)],text=True)
    if undefined.strip(): raise ValueError('probe unexpectedly imports external runtime symbols')
    (output/'symbols.txt').write_text(symbols)
    names={line.split()[2]:int(line.split()[0],16) for line in symbols.splitlines() if len(line.split())==3}
    raw=output/'probe.bin'
    subprocess.run(['llvm-objcopy','--only-section=.probe','-O','binary',str(elf),str(raw)],check=True)
    code=raw.read_bytes(); start=names['_start']-(mkinit.BASE+mkinit.CODE_OFF)
    if not 0<=start<len(code): raise ValueError('entry escapes the linked text')
    image=mkinit.build(wrap_object(code,start))
    (output/'probe.macho').write_bytes(image)
    record={'scope':'new freestanding EL0 probe build; no launch/boot/rootfs changes',
        'hardware_verified':False,'launcher_implemented':True,'requires_EL0_trace_kernel':True,
        'uapi_sha256':hashlib.sha256(uapi_data).hexdigest(),
        'trace_uapi_sha256':hashlib.sha256(trace_data).hexdigest(),
        'sources_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in sources},
        'elf_sha256':hashlib.sha256(elf.read_bytes()).hexdigest(),
        'macho_sha256':hashlib.sha256(image).hexdigest(),'macho_bytes':len(image),
        'code_bytes':names['__probe_code_end']-names['__probe_code_start'],
        'ro_blob_bytes':len(code),'entry_vma':names['_start'],
        'kernel_build_performed':False,'old_proven_init_changed':False}
    (output/'build.json').write_text(json.dumps(record,indent=2)+'\n')
    return record


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('--uapi',type=Path,required=True,help='recorded reconstructed production UAPI header')
    parser.add_argument('--trace-uapi',type=Path,help='production0211 trace header; defaults beside --uapi')
    args=parser.parse_args()
    try: print(json.dumps(build(args.output.resolve(),args.uapi.resolve(),
                               args.trace_uapi.resolve() if args.trace_uapi else None),indent=2))
    except (OSError,ValueError,subprocess.CalledProcessError) as error:
        print(str(error),file=sys.stderr)
        if isinstance(error,subprocess.CalledProcessError):print(error.stderr,file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
