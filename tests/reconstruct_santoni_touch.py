#!/usr/bin/env python3
"""Reconstruct the *shipped* Santoni touch sources, not a stale local XNU tree.

Only the two relevant file sections are applied, in the same lexical patch order
as the kernel build. Every selected patch must pass git apply --check first.
Generated sources live in the caller's disposable output directory. No network,
device access, index changes, commits or external source checkout is involved.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
DRIVER = "bsd/dev/santoni_sdhci.c"
HID = "iokit/Kernel/arm/hid/SweetHID.cpp"
TARGETS = (DRIVER, HID)
START = "/*\n * SANTONI physical buttons and touchscreen handler."
END = "/*\n * Idempotent, non-fatal probe."
BARRIERS = re.compile(r'__asm__ volatile\("(dmb ish|dsb sy)" ::: "memory"\);')


def selected_sections(text, targets=None):
    """Keep complete unified headers/hunks (both plain and git-style patches)."""
    starts = list(re.finditer(rb"(?m)^--- ([^\n]+)\n\+\+\+ ([^\n]+)\n", text))
    targets = tuple(name.encode() for name in (TARGETS if targets is None else targets))
    result = []
    for i, match in enumerate(starts):
        old, new = (match.group(j).split(b"\t", 1)[0] for j in (1, 2))
        old = old[2:] if old.startswith(b"a/") else old
        new = new[2:] if new.startswith(b"b/") else new
        if old in targets or new in targets:
            if old != new and b"/dev/null" not in (old, new):
                raise ValueError("touch source rename needs explicit handling")
            end = starts[i + 1].start() if i + 1 < len(starts) else len(text)
            # git format-patch's signature is not part of the diff.
            section = text[match.start():end].split(b"\ndiff --git ", 1)[0]
            section = section.split(b"\n-- \n", 1)[0]
            result.append(section.rstrip(b"\n") + b"\n")
    return b"".join(result)


def reconstruct(output, through=None, targets=None):
    targets = TARGETS if targets is None else tuple(targets)
    output = Path(output).resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"refusing to overwrite nonempty source directory: {output}")
    output.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "--quiet", str(output)], check=True, timeout=15)
    applied = []
    for patch in sorted((ROOT / "xnu/patches").glob("*.patch")):
        number = re.match(r"^(\d+)-", patch.name)
        if through is not None and number and int(number.group(1)) > through:
            continue
        section = selected_sections(patch.read_bytes(), targets)
        if not section:
            continue
        for args in (["git", "apply", "--check", "-"], ["git", "apply", "-"]):
            try:
                subprocess.run(args, input=section, cwd=output,
                               check=True, capture_output=True, timeout=15)
            except subprocess.CalledProcessError as error:
                detail = error.stderr.decode(errors="replace").strip()
                raise RuntimeError(f"{patch.name}: {detail}") from error
        applied.append(patch.name)
    # 0207's pointer-free ABI is a local header dependency of the GPU core.
    # Preserve callers' requested hash set and historical through-N baselines,
    # while materializing the dependency when the reconstructed header uses it.
    dependency = 'bsd/dev/santoni_gpu_uapi.h'
    core_header = output / 'bsd/dev/santoni_gpu_core.h'
    dependencies = {}
    if (core_header.is_file() and b'#include "santoni_gpu_uapi.h"' in core_header.read_bytes()
            and dependency not in targets):
        for patch in sorted((ROOT / 'xnu/patches').glob('*.patch')):
            number = re.match(r'^(\d+)-', patch.name)
            if through is not None and number and int(number.group(1)) > through:
                continue
            section = selected_sections(patch.read_bytes(), (dependency,))
            if not section:
                continue
            for args in (['git', 'apply', '--check', '-'], ['git', 'apply', '-']):
                subprocess.run(args, input=section, cwd=output, check=True,
                               capture_output=True, timeout=15)
            if patch.name not in applied:
                applied.append(patch.name)
        dependencies[dependency] = hashlib.sha256((output / dependency).read_bytes()).hexdigest()
    hashes = {}
    for name in targets:
        hashes[name] = hashlib.sha256((output / name).read_bytes()).hexdigest()
    # The graphics controller is included by the original core/adapter. Resolve
    # only local Santoni GPU headers, recursively, through the SAME patch chain.
    # Callers' requested hashes stay separate from materialized dependencies.
    queue=list(targets)
    seen=set(queue)
    while queue:
        filename=queue.pop(0)
        path=output/filename
        if not path.is_file():continue
        for local in re.findall(rb'(?m)^#include "(santoni_gpu_[a-z_]+\.h)"',path.read_bytes()):
            dep='bsd/dev/'+local.decode()
            if dep in seen:continue
            seen.add(dep)
            if not (output/dep).is_file():
                for patch in sorted((ROOT/'xnu/patches').glob('*.patch')):
                    number=re.match(r'^(\d+)-',patch.name)
                    if through is not None and number and int(number.group(1))>through:continue
                    section=selected_sections(patch.read_bytes(),(dep,))
                    if not section:continue
                    for args in (['git','apply','--check','-'],['git','apply','-']):
                        subprocess.run(args,input=section,cwd=output,check=True,capture_output=True,timeout=15)
                    if patch.name not in applied:applied.append(patch.name)
            if not (output/dep).is_file():raise ValueError('GPU header dependency missing: '+dep)
            if dep not in targets:dependencies[dep]=hashlib.sha256((output/dep).read_bytes()).hexdigest()
            queue.append(dep)
    return {"patches": applied, "sha256": hashes, "dependencies": dependencies}


def extract_host_header(source, output):
    """Compile actual functions. The only transformation is ARM barriers.

    The harness implements kernel primitives/MMIO. It does NOT replace driver
    parsers, I2C routines, SMD lookup/packet code, voting, or the polling thread.
    #line keeps diagnostics tied to the reconstructed production source.
    """
    source = Path(source).resolve()
    text = source.read_text()
    if text.count(START) != 1 or text.count(END) != 1:
        raise ValueError("touch section boundaries missing or ambiguous")
    start = text.index(START)
    end = text.index(END, start)
    section = text[start:end]
    line = text[:start].count("\n") + 1
    helper = 'static void\nsantoni_udelay(uint32_t usecs)'
    if helper in text:
        helper_start = text.index(helper)
        helper_end = text.index('\n}\n', helper_start) + 3
        section = (text[helper_start:helper_end] + '\n' +
                   f'#line {line} {json.dumps(str(source))}\n' + section)
        line = text[:helper_start].count("\n") + 1
    transformed, count = BARRIERS.subn(
        lambda m: f'santoni_mock_barrier(__func__, "{m.group(1)}");', section)
    if not count or "__asm__" in transformed:
        raise ValueError("unrecognized assembly in touch section")
    header = (f"/* Source SHA256: {hashlib.sha256(source.read_bytes()).hexdigest()}\n"
              f" * Actual driver section; {count} ARM barriers mocked. */\n"
              + ("#define SANTONI_HOST_HAS_BUTTON_THREAD 1\n"
                 if "static void\nsantoni_buttons_thread(" in section else "") +
              f"#line {line} {json.dumps(str(source))}\n" + transformed)
    Path(output).write_text(header)
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--through", type=int)
    parser.add_argument("--header", type=Path)
    args = parser.parse_args()
    result = reconstruct(args.output, args.through)
    if args.header:
        result["mocked_barriers"] = extract_host_header(
            args.output / DRIVER, args.header)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
