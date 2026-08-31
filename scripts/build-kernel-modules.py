#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the out-of-tree kernel modules used by the KMODULE cases.

    build/kernel-modules/
        ipe_test.ko           built against build/kernel

The ipe_test module does nothing; only whether the kernel accepts it matters.
"""

import os
import shutil
import subprocess

import layout


def main() -> int:
    if not (layout.build.KERNEL_DIR / "Module.symvers").is_file():
        raise SystemExit("the kernel is not built; run build-kernel.py")
    shutil.rmtree(layout.build.KERNEL_MODULES_DIR, ignore_errors=True)
    shutil.copytree(layout.source.KERNEL_MODULES_DIR, layout.build.KERNEL_MODULES_DIR)

    subprocess.run(
        [
            "make", "-C", str(layout.build.KERNEL_DIR),
            f"M={layout.build.KERNEL_MODULES_DIR}",
            f"-j{os.cpu_count() or 1}",
            "modules",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    if not layout.build.KMODULE_TEST_BINARY.is_file():
        raise SystemExit("the KMODULE test binary was not produced")
    print(f"    Prepared {layout.build.KMODULE_TEST_BINARY.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
