#!/usr/bin/env python3
"""Executable contract tests of the patch-chain's actual touch/RPM functions."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from reconstruct_santoni_touch import DRIVER, ROOT, extract_host_header, reconstruct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--cc", default=os.environ.get("HOST_CC", "clang"))
    parser.add_argument("--through", type=int)
    parser.add_argument("--source-tree", type=Path,
                        help="local scratch tree, for causal/mutation checks")
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--sanitize", action="store_true")
    args = parser.parse_args()
    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if args.source_tree:
        source = args.source_tree.resolve() / DRIVER
        manifest = {"source_tree": str(args.source_tree.resolve()),
                    "sha256": {DRIVER: hashlib.sha256(source.read_bytes()).hexdigest()}}
    else:
        generated = out / "source"
        # Only delete this runner's generated tree, never a supplied source tree.
        if generated.exists():
            shutil.rmtree(generated)
        manifest = reconstruct(generated, args.through)
        source = generated / DRIVER
    manifest["mocked_barriers"] = extract_host_header(
        source, out / "santoni_touch_driver.h")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    binary = out / "test_santoni_touch"
    flags = ["-std=c11", "-O1" if args.sanitize else "-O2",
             "-Wall", "-Wextra", "-Werror", "-I", str(out)]
    if args.sanitize:
        flags += ["-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    subprocess.run([args.cc, *flags, str(ROOT / "tests/test_santoni_touch.c"),
                    "-o", str(binary)], check=True, timeout=60)
    cases = subprocess.check_output([str(binary), "--list"], text=True,
                                    timeout=10).splitlines()
    if args.case:
        if any(name not in cases for name in args.case):
            parser.error("unknown test case")
        cases = args.case
    failures, results = [], []
    for name in cases:
        # Fresh process per case: also resets production function-local statics.
        result = subprocess.run([str(binary), name], text=True,
                                capture_output=True, timeout=15)
        (out / f"{name}.log").write_text(result.stdout + result.stderr)
        results.append({"case": name, "returncode": result.returncode,
                        "result": "fail" if result.returncode else "pass"})
        if result.returncode:
            failures.append(name)
            print(f"FAIL {name}: {result.stderr.strip()}")
        else:
            print(f"ok   {name}")
    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"Santoni actual-driver tests: {len(cases) - len(failures)}/{len(cases)} passed")
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(main())
