#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare the real kernel image and a valid CPIO for KEXEC load-only tests."""

import shutil
import subprocess

import layout


def main() -> int:
    images = tuple(
        (layout.build.KERNEL_STAGING_DIR / "usr/lib/modules").glob("*/vmlinuz")
    )
    if len(images) != 1:
        raise SystemExit("expected one installed kernel image; run build-kernel.py")
    layout.build.KEXEC_ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy(images[0], layout.build.KEXEC_IMAGE_TEST_BINARY)
    # An empty archive is sufficient: the tests stage it, but never boot it.
    subprocess.run(
        [
            layout.build.KERNEL_DIR / "usr/gen_init_cpio",
            "-t", "0", "-o", layout.build.KEXEC_INITRAMFS_TEST_BINARY,
            "/dev/null",
        ],
        check=True,
    )
    print("    Prepared the KEXEC kernel image and initramfs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
