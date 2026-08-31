# SPDX-License-Identifier: GPL-2.0-only
"""Define the boot_verified cases and expose their saved outcomes to TAP.

IPE evaluates boot_verified for the file being authorized: a file from the
initramfs matches TRUE, while the same file copied to a separate tmpfs matches
FALSE. The initrd program image/initrd/boot-verified.py runs INITRAMFS_CASES
before switch_root and stores their outcomes in /run/ipe-boot-verified.

After switch_root, build() creates reporting-only cases. Each reads one saved
outcome instead of trying to access the removed initramfs files again.
"""

from functools import partial

import checks
import ipe
import layout
from model import Batch, Case

from . import kmodule

TRUE_ALLOW_POLICY = ipe.Policy(
    signed=layout.initrd.BOOT_VERIFIED_TRUE_POLICY,
    name="ipe_test_boot_verified",
)
FALSE_DENY_POLICY = ipe.Policy(
    signed=layout.initrd.BOOT_VERIFIED_FALSE_POLICY,
    name="ipe_test_boot_verified_false",
)
INITRAMFS_MODULE = layout.initrd.KMODULE_TEST_BINARY
TMPFS_MODULE = layout.initrd.BOOT_TMPFS_KMODULE_TEST_BINARY


INITRAMFS_CASES = (
    kmodule.case(
        "kmodule_boot_verified_true_initramfs_ok",
        TRUE_ALLOW_POLICY,
        INITRAMFS_MODULE,
        allowed=True,
    ),
    kmodule.case(
        "kmodule_boot_verified_true_tmpfs_denied",
        TRUE_ALLOW_POLICY,
        TMPFS_MODULE,
        allowed=False,
    ),
    kmodule.case(
        "kmodule_boot_verified_false_initramfs_ok",
        FALSE_DENY_POLICY,
        INITRAMFS_MODULE,
        allowed=True,
    ),
    kmodule.case(
        "kmodule_boot_verified_false_tmpfs_denied",
        FALSE_DENY_POLICY,
        TMPFS_MODULE,
        allowed=False,
    ),
)


def build() -> tuple[Batch, ...]:
    """The batches this group contributes."""
    return (
        Batch(
            "boot",
            tuple(
                Case(
                    id=case.id,
                    checks=(partial(checks.initramfs_case_passed, case.id),),
                )
                for case in INITRAMFS_CASES
            ),
        ),
    )
