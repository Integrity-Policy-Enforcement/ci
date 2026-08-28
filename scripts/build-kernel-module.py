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

import layout

NAME = layout.TEST_MODULE


def main():
    if not (layout.build.KERNEL / "Module.symvers").is_file():
        raise SystemExit("the kernel is not built; run build-kernel.py")
    shutil.rmtree(layout.build.KERNEL_MODULE, ignore_errors=True)
    layout.build.KERNEL_MODULE.mkdir(parents=True)

    shutil.copy(layout.source.KERNEL_MODULE, layout.build.KERNEL_MODULE / f"{NAME}.c")
    (layout.build.KERNEL_MODULE / "Makefile").write_text(f"obj-m := {NAME}.o\n")
    subprocess.run(
        ["make", "-C", str(layout.build.KERNEL), f"M={layout.build.KERNEL_MODULE}", f"-j{os.cpu_count() or 1}", "modules"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    print(f"    Prepared {NAME}.ko")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
