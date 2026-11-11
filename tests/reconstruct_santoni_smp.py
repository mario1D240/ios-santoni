#!/usr/bin/env python3
"""Reconstruct shipped SMP sources from pinned public XNU + the full patch chain.

No kernel build, stale build-tree input, git index changes, or device access.
--upstream accepts an offline *pristine* xnu-8796.141.3 tree; every input is
SHA256 checked. Without it the small set of original files is fetched from
Apple's public source tag. All generated files stay in a disposable directory.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
TAG = "xnu-8796.141.3"
URL = f"https://raw.githubusercontent.com/apple-oss-distributions/xnu/{TAG}/"
CPU = "iokit/Kernel/arm/SweetCPU.cpp"
FIQ = "pexpert/arm/pe_fiq.c"
IRQ = "osfmk/arm64/sleh.c"
PROTOS = "pexpert/pexpert/arm/protos.h"
UPSTREAM = {
    FIQ: "c67135846514ce529291ae9566adc091cc3a8dd64ad6f643d4deb862f13bc194",
    IRQ: "046e6181a3a02d300d6f266a9b7ab8b29fefbe639a5eb9a1d6ab5df351f25dc4",
    PROTOS: "23ac6d9f9b7e5f34d911359007cef4394d3d58665c5339de52184cde7fb10b7f",
}
STARTUP = {
    "osfmk/kern/sched_prim.c": "6e3aa6911a36e416f169fa2a121a80b9c653220e273d641c6fbad9a335844a7f",
    "pexpert/pexpert/arm64/board_config.h": "1de4d28c9f2896dadbe0e1a430a9b2cea463817dd13523f03583a3a4c3edaab9",
    "osfmk/arm/caches_internal.h": "b74c450c23c6e4730eb7b0a1df886f6e3d4b9f1d51294d69be66f4495eee9d1c",
    "osfmk/arm64/cpu.c": "39e96d694f94262296d22f52d2e38614fd88a31b7ff77018da540d3cf3d70a1b",
    "osfmk/arm64/machine_routines.c": "663b25f0d52c811dc09a646ab8a5c904826f4312a1bfd23c2d3a9744cb3eb2a1",
    "osfmk/arm64/start.s": "bf92967ea96e638f5a9a002cd4e478272f08616531d212caa919944c85e8a023",
    "osfmk/arm/cpu_common.c": "668ab7f3ccbbb06576a5c23500807a4a782daaf4e8e81280762770287879f0f9",
    "osfmk/arm/rtclock.c": "fe73cdccc1b4e5b952ff28bbe6eb107811f33983a41f0e6528bcde927003154b",
    "osfmk/arm/caches.c": "1f60ebd42161f2e4d064100f008e84a7f2133272601602cd5c67fe1be2c2a41f",
}


def selected_sections(text, targets):
    """Select whole file diffs without decoding/normalizing whitespace."""
    starts = list(re.finditer(rb"(?m)^--- ([^\n]+)\n\+\+\+ ([^\n]+)\n", text))
    targets = {name.encode() for name in targets}
    result = []
    for i, match in enumerate(starts):
        old, new = (match.group(j).split(b"\t", 1)[0] for j in (1, 2))
        old = old[2:] if old.startswith(b"a/") else old
        new = new[2:] if new.startswith(b"b/") else new
        if old not in targets and new not in targets:
            continue
        if old != new and b"/dev/null" not in (old, new):
            raise ValueError("SMP source rename needs explicit handling")
        end = starts[i + 1].start() if i + 1 < len(starts) else len(text)
        section = text[match.start():end].split(b"\ndiff --git ", 1)[0]
        section = section.split(b"\n-- \n", 1)[0]
        result.append(section.rstrip(b"\n") + b"\n")
    return b"".join(result)


def originals(upstream=None, startup=False):
    expected = dict(UPSTREAM)
    if startup:
        expected.update(STARTUP)
    result = {}
    for name, digest in expected.items():
        if upstream:
            data = (Path(upstream) / name).read_bytes()
        else:
            with urlopen(URL + name, timeout=45) as response:
                data = response.read()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f"not pristine {TAG}: {name}")
        result[name] = data
    return result


def reconstruct(output, through=None, source=None):
    output = Path(output).resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"refusing to overwrite nonempty directory: {output}")
    output.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "--quiet", str(output)], check=True, timeout=15)
    source = originals() if source is None else source
    for name, data in source.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    targets = (CPU, *source.keys())
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
                subprocess.run(args, input=section, cwd=output, check=True,
                               capture_output=True, timeout=15)
            except subprocess.CalledProcessError as error:
                raise RuntimeError(f"{patch.name}: {error.stderr.decode()}") from error
        applied.append(patch.name)
    return {"upstream": TAG, "patches": applied,
            "sha256": {name: hashlib.sha256((output / name).read_bytes()).hexdigest()
                       for name in targets}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--through", type=int)
    parser.add_argument("--upstream", type=Path)
    parser.add_argument("--startup", action="store_true")
    args = parser.parse_args()
    result = reconstruct(args.output, args.through,
                         originals(args.upstream, args.startup))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
