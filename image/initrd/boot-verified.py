#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the boot_verified cases before switch_root and save their outcomes.

IPE evaluates boot_verified for the file being authorized: a file from the
initramfs matches TRUE, while the same file copied to a separate tmpfs matches
FALSE. The later switch_root removes the initramfs files, so the payload suite
cannot repeat this comparison.

Run INITRAMFS_CASES with the shared runner and store their outcomes in
/run/ipe-boot-verified. The payload-side boot batch later reports those saved
outcomes as TAP results.
"""

import json
import shutil

import layout
import modules
import mounts
import runner
from cases.boot import INITRAMFS_CASES
from command import run


def main() -> int:
    """Run the initramfs-only cases and leave their outcomes under /run."""
    with (
        mounts.mounted_scope(directory=layout.initrd.BOOT_TMPFS_DIR),
        modules.loaded_scope(prefix=layout.initrd.POLICY_OP_TEST_MODULE.stem),
    ):
        run("insmod", layout.initrd.POLICY_OP_TEST_MODULE)
        mounts.tmpfs(layout.initrd.BOOT_TMPFS_DIR)
        shutil.copy(
            layout.initrd.KMODULE_TEST_BINARY,
            layout.initrd.BOOT_TMPFS_KMODULE_TEST_BINARY,
        )
        shutil.copy(
            layout.initrd.FIRMWARE_TEST_BINARY,
            layout.initrd.BOOT_TMPFS_FIRMWARE_TEST_BINARY,
        )
        shutil.copy(
            layout.initrd.KEXEC_IMAGE_TEST_BINARY,
            layout.initrd.BOOT_TMPFS_KEXEC_IMAGE_TEST_BINARY,
        )
        shutil.copy(
            layout.initrd.KEXEC_INITRAMFS_TEST_BINARY,
            layout.initrd.BOOT_TMPFS_KEXEC_INITRAMFS_TEST_BINARY,
        )
        shutil.copy(
            layout.initrd.POLICY_OP_TEST_BINARY,
            layout.initrd.BOOT_TMPFS_POLICY_OP_TEST_BINARY,
        )
        outcomes = {case.id: runner.test(case=case) for case in INITRAMFS_CASES}

    layout.initrd.BOOT_VERIFIED_RECORD.write_text(json.dumps(outcomes) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
