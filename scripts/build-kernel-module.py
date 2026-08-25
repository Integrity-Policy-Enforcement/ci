#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the loadable module the KMODULE cases try to insert.

    build/kernel-module/
        ipe_test.ko           built against build/kernel, out of tree

The module does nothing; only whether the kernel accepts it matters.
"""

import os
import shutil
import subprocess
from pathlib import Path

import layout

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
SOURCE = ROOT / "kernel-module" / "ipe-test-module.c"
KERNEL = ROOT / "build" / "kernel"
OUTPUT = ROOT / "build" / "kernel-module"
NAME = layout.TEST_MODULE


def main():
    if not (KERNEL / "Module.symvers").is_file():
        raise SystemExit("the kernel is not built; run build-kernel.py")
    shutil.rmtree(OUTPUT, ignore_errors=True)
    OUTPUT.mkdir(parents=True)

    shutil.copy(SOURCE, OUTPUT / f"{NAME}.c")
    (OUTPUT / "Makefile").write_text(f"obj-m := {NAME}.o\n")
    subprocess.run(
        ["make", "-C", str(KERNEL), f"M={OUTPUT}", f"-j{os.cpu_count() or 1}", "modules"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    print(f"    Prepared {NAME}.ko")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
