#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build"
PYTHON = sys.executable


def run_checked(command):
    command = [str(part) for part in command]
    print("    $ " + " ".join(command), flush=True)
    subprocess.run(command, check=True)


def step(name):
    print(f"\n==> {name}", flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Build and run the IPE capability tests against a kernel tree."
    )
    parser.add_argument("kernel_tree", type=Path)
    parser.add_argument("output", nargs="?", type=Path, default=ROOT / "out")
    args = parser.parse_args(argv)

    tree = args.kernel_tree.resolve()
    output = args.output.resolve()
    if not (tree / "Makefile").is_file() or not (
        tree / "scripts" / "kconfig" / "merge_config.sh"
    ).is_file():
        parser.error(f"not a Linux kernel tree: {tree}")

    BUILD.mkdir(exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    sudo = [] if os.geteuid() == 0 else ["sudo"]

    step("Prepare signing identities")
    run_checked([PYTHON, ROOT / "scripts" / "prepare-keys.py"])

    step("Prepare signed policies")
    run_checked([PYTHON, ROOT / "scripts" / "prepare-policies.py"])

    step("Build kernel")
    run_checked([PYTHON, ROOT / "scripts" / "build-kernel.py", tree])

    step("Verify kernel configuration")
    run_checked([PYTHON, ROOT / "scripts" / "assert-config.py"])

    step("Build guest image")
    run_checked(sudo + ["mkosi", "--directory", ROOT / "image", "-f", "build"])

    step("Run tests")
    run_checked(sudo + [PYTHON, ROOT / "scripts" / "run-vm.py", output])
    print(f"\nVerdict: {output / 'verdict.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
