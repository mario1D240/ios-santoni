#!/usr/bin/env python3
"""Run the shipped HID timer and 24-bit panel converter, with only I/O mocked."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

from reconstruct_santoni_touch import ROOT, HID, reconstruct

FRAMEBUFFER = 'iokit/Kernel/arm/SweetFramebuffer.cpp'


def function(text, marker):
    start = text.index(marker)
    pos = text.index('{', start)
    depth = 1
    end = pos + 1
    while depth:
        if text[end] == '{':
            depth += 1
        elif text[end] == '}':
            depth -= 1
        end += 1
    return text[start:end] + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out-dir', type=Path, required=True)
    parser.add_argument('--through', type=int)
    parser.add_argument('--sanitize', action='store_true')
    parser.add_argument('--cxx', default=os.environ.get('HOST_CXX', 'clang++'))
    args = parser.parse_args()
    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    generated = out / 'source'
    if generated.exists():
        shutil.rmtree(generated)
    manifest = reconstruct(generated, args.through, (HID, FRAMEBUFFER))
    hid = (generated / HID).read_text()
    fb = (generated / FRAMEBUFFER).read_text()
    functions = [function(hid, 'void\nSweetHIDButtons::testFired('),
                 function(hid, 'extern "C" void\nsweet_hid_key('),
                 function(hid, 'extern "C" void\nsweet_hid_touch(')]
    ready = 'extern "C" bool\nsweet_hid_buttons_ready('
    if ready in hid:
        functions.append('#define SANTONI_HOST_HAS_BUTTON_READY 1\n' + function(hid, ready))
    if 'static void\nsweet_bgra_to_bgr24(' in fb:
        functions.append(function(fb, 'static void\nsweet_bgra_to_bgr24('))
    functions.append(function(fb, 'void\nAppleCLCD::blitPanel('))
    header = '\n'.join(functions).replace(
        '__asm__ volatile("dsb sy" ::: "memory");', 'barriers++;')
    if '__asm__' in header:
        raise ValueError('Unknown assembly in extracted UI methods')
    (out / 'santoni_ui_actual.h').write_text(header)
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    binary = out / 'test_santoni_ui'
    flags = ['-std=c++14', '-O2', '-Wall', '-Wextra', '-Werror', '-I', str(out)]
    if args.sanitize:
        flags += ['-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run([args.cxx, *flags, str(ROOT / 'tests/test_santoni_ui.cpp'),
                    '-o', str(binary)], check=True, timeout=60)
    cases = subprocess.check_output([str(binary), '--list'], text=True).splitlines()
    results = []
    for case in cases:
        result = subprocess.run([str(binary), case], capture_output=True,
                                text=True, timeout=30)
        (out / f'{case}.log').write_text(result.stdout + result.stderr)
        results.append({'case': case, 'returncode': result.returncode})
        print(('FAIL ' + case + ': ' + result.stderr.strip()) if result.returncode
              else ('ok   ' + case))
    (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    failures = sum(bool(r['returncode']) for r in results)
    print(f'Santoni actual HID/display tests: {len(cases) - failures}/{len(cases)} passed')
    return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
