#!/usr/bin/env python3
"""Host regressions executing actual patched GIC C and SGI C++/C routines.

Only includes, privileged instructions and MMIO accesses are substituted. The
entire pe_fiq.c and complete signalCPU/sleh_irq functions are otherwise intact.
No ARM kernel/cross compile. --through 166 demonstrates the original defects.
Use --upstream PATH for offline verified public XNU inputs; default fetches the
pinned originals. Temporary source trees/binaries are never repository inputs.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

from reconstruct_santoni_smp import CPU, FIQ, IRQ, ROOT, originals, reconstruct


def whole_function(text, signature):
    if text.count(signature) != 1:
        raise ValueError(f"missing/ambiguous function: {signature}")
    start = text.index(signature)
    end = text.index("\n}\n", start) + 3
    return text[start:end], text[:start].count("\n") + 1


def mock_mmio(text):
    """Replace only uint32 MMIO dereferences; balance nested address parens."""
    prefix = "*(volatile uint32_t *)("
    result = ""
    while prefix in text:
        begin = text.index(prefix)
        pos = begin + len(prefix)
        end, depth = pos, 1
        while depth:
            if text[end] == "(": depth += 1
            if text[end] == ")": depth -= 1
            end += 1
        result += text[:begin] + "mock_mmio32(" + text[pos:end - 1] + ")"
        text = text[end:]
    return result + text


def extract(tree, output):
    for name, filename, signature in (
        (FIQ, "santoni_fiq_actual.h", None),
        (CPU, "santoni_signal_actual.h", "void\nSweetCPU::signalCPU(IOCPU *target)"),
        (IRQ, "santoni_irq_actual.h", "void\nsleh_irq(arm_saved_state_t *state)"),
    ):
        data = (tree / name).read_bytes()
        text, line = data.decode(), 1
        if signature:
            text, line = whole_function(text, signature)
        # Keep line numbers for diagnostics while kernel headers are replaced
        # by the explicit fixture. No production expressions are rewritten.
        text = re.sub(r"(?m)^#include [^\n]*", "", text)
        text = mock_mmio(text)
        (output / filename).write_text(
            f"/* Source SHA256: {hashlib.sha256(data).hexdigest()} */\n"
            f"#line {line} {json.dumps(str(tree / name))}\n" + text)


def cases():
    result = [("unknown", i) for i in (0, 7, 8, 0xffffffff)]
    result += [("probe", bit, byte, word) for bit in range(8)
               for byte in range(4) for word in (0, 7)]
    result += [(kind, count, layout) for kind in ("spi", "private", "ipi")
               for count in (1, 4, 8) for layout in range(3)]
    result += [("badmask", mask) for mask in (0, 3, 0xff)]
    result += [("badtimer", timer) for timer in (0, 15, 32)]
    result += [("timerbound", timer) for timer in (16, 31)]
    result += [("invalidcpu",), ("sendbarrier",)]
    result += [("duplicate",), ("unprobed-target",), ("bank-isolation",), ("ns-groups",)]
    result += [("recv", source) for source in range(8)]
    result += [("receive-order",)]
    result += [("eoi-complete", kind) for kind in range(3)]
    result += [("spurious", irq) for irq in range(1020, 1024)]
    result += [("timer",), ("other",), ("repend",)]
    return result


def run_suite(tree, output, cxx, optimization="-O2"):
    output.mkdir(parents=True, exist_ok=True)
    extract(tree, output)
    binary = output / "santoni-smp-host"
    command = [*cxx, "-std=c++17", optimization, "-Wall", "-Wextra", "-Werror",
               # The unmodified pre-0167 function computes a GICv3-only sgi on
               # GICv2. Do not let that old warning mask behavioral red tests.
               "-Wno-unused-variable", "-I", str(output),
               str(ROOT / "tests/test_santoni_smp.cpp"), "-o", str(binary)]
    subprocess.run(command, check=True, timeout=60)
    failures = []
    for case in cases():
        result = subprocess.run([str(binary), *map(str, case)],
                                capture_output=True, text=True, timeout=5)
        if result.returncode:
            failures.append((case, result.stderr.strip()))
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path)
    parser.add_argument("--through", type=int)
    args = parser.parse_args()
    approved = Path("/data/data/com.termux/files/usr/tmp/opencode")
    with tempfile.TemporaryDirectory(prefix="santoni-smp-test-",
                                     dir=approved if approved.is_dir() else None) as tmp:
        work = Path(tmp)
        manifest = reconstruct(work / "src", args.through, originals(args.upstream))
        failures = run_suite(work / "src", work / "host",
                             shlex.split(os.environ.get("HOST_CXX", "c++")))
        print(json.dumps(manifest, indent=2))
        for case, detail in failures[:12]:
            print("FAIL", *case, detail)
        print(f"SMP actual-source contracts: {len(cases()) - len(failures)}/{len(cases())} passed")
        raise SystemExit(bool(failures))


if __name__ == "__main__":
    main()
