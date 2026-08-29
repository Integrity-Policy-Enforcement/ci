# SPDX-License-Identifier: GPL-2.0-only
"""What IPE decides about the initramfs, which no case can ask after the switch.

boot_verified is true only while the initramfs is the running root.  The cases
below therefore run in the initramfs, driven by the same runner the payload
uses; image/initrd/boot-verified writes down how each one came out and the
batch here reports those outcomes.
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
INITRAMFS_MODULE = layout.initrd.TEST_MODULE
TMPFS_MODULE = layout.initrd.BOOT_TMPFS_MODULE


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
                Case(id=case.id, check=partial(checks.initramfs_case_passed, case.id))
                for case in INITRAMFS_CASES
            ),
        ),
    )
