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
import steps
from model import Batch, Case
from operations import KMODULE

TRUE_ALLOW_POLICY = ipe.Policy(
    layout.INITRD / "boot-verified-true.p7s", "ipe_test_boot_verified"
)
INITRAMFS_MODULE = layout.INITRD / layout.TEST_MODULE_FILE
TMPFS_MODULE = layout.BOOT_TMPFS_DIRECTORY / layout.TEST_MODULE_FILE


def initramfs_case(id, policy, module, allowed):
    return Case(
        id=id,
        setup=(
            partial(steps.activate_policy, policy),
            partial(ipe.set_enforcement, True),
        ),
        trigger=partial(KMODULE.attempt, module),
        expect=0 if allowed else KMODULE.refused,
    )


INITRAMFS_CASES = (
    initramfs_case(
        "kmodule_boot_verified_true_initramfs_ok",
        TRUE_ALLOW_POLICY,
        INITRAMFS_MODULE,
        allowed=True,
    ),
    initramfs_case(
        "kmodule_boot_verified_true_tmpfs_denied",
        TRUE_ALLOW_POLICY,
        TMPFS_MODULE,
        allowed=False,
    ),
)


def build():
    return (
        Batch(
            "boot",
            tuple(
                Case(id=case.id, check=partial(checks.initramfs_case_passed, case.id))
                for case in INITRAMFS_CASES
            ),
        ),
    )
