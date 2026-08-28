#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import argparse
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE / "scripts"
PYTHON = sys.executable


def run_checked(command):
    command = [str(part) for part in command]
    print("    $ " + " ".join(command), flush=True)
    subprocess.run(command, check=True)


def step(name):
    print(f"\n==> {name}", flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Build and run the IPE tests against a kernel tree."
    )
    parser.add_argument("kernel_tree", type=Path)
    parser.add_argument("output", nargs="?", type=Path, default=HERE / "out")
    args = parser.parse_args(argv)

    tree = args.kernel_tree.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    sudo = [] if os.geteuid() == 0 else ["sudo"]

    step("Prepare signing identities")
    run_checked([PYTHON, SCRIPTS / "prepare-keys.py"])

    step("Build kernel")
    run_checked([PYTHON, SCRIPTS / "build-kernel.py", tree])

    step("Verify kernel configuration")
    run_checked([PYTHON, SCRIPTS / "assert-config.py"])

    step("Build the test kernel module")
    run_checked([PYTHON, SCRIPTS / "build-kernel-module.py"])

    step("Prepare the dm-verity image")
    run_checked([PYTHON, SCRIPTS / "build-dmverity-image.py"])

    step("Sign the fs-verity digest")
    run_checked([PYTHON, SCRIPTS / "build-fsverity-signature.py"])

    step("Prepare signed policies")
    run_checked([PYTHON, SCRIPTS / "prepare-policies.py"])

    step("Build guest image")
    run_checked(sudo + [PYTHON, SCRIPTS / "build-image.py"])

    step("Run tests")
    run_checked(sudo + [PYTHON, SCRIPTS / "run-vm.py", output])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
