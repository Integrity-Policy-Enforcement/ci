#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the guest image with mkosi.

Writes:

    image/output/ipe-tests.raw    the signed UKI and the dm-verity root
"""

import subprocess

import layout


def main():
    subprocess.run(
        ["mkosi", "--directory", str(layout.source.IMAGE), "-f", "build"], check=True
    )
    print(f"    Built {layout.build.GUEST_IMAGE.relative_to(layout.source.ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
