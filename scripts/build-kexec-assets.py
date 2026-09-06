#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Copy the real built kernel image for KEXEC tests."""

import shutil

import layout


def main() -> int:
    images = tuple(
        (layout.build.KERNEL_STAGING_DIR / "usr/lib/modules").glob("*/vmlinuz")
    )
    if len(images) != 1:
        raise SystemExit("expected one installed kernel image; run build-kernel.py")
    layout.build.KEXEC_ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy(images[0], layout.build.KEXEC_IMAGE_TEST_BINARY)
    print("    Prepared the KEXEC kernel image")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
