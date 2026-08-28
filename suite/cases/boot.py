# SPDX-License-Identifier: GPL-2.0-only
"""What IPE decides about the initramfs, which no case can ask after the switch.

boot_verified is true only while the initramfs is the running root.  The cases
below therefore run in the initramfs, driven by the same runner the payload
uses; image/initrd/boot-verified writes down how each one came out and the
batch here reports those outcomes.
"""

from functools import partial
from pathlib import Path

import checks
import ipe
import layout
import modules
import runtime
import steps
from model import Batch, Case
from operations import KMODULE
from scope import Collection

TRUE_ALLOW_POLICY = ipe.Policy(
    layout.initrd.ROOT / "boot-verified-true", "ipe_test_boot_verified"
)
FALSE_DENY_POLICY = ipe.Policy(
    layout.initrd.ROOT / "boot-verified-false", "ipe_test_boot_verified_false"
)
INITRAMFS_MODULE = layout.initrd.ROOT / layout.TEST_MODULE_FILE
TMPFS_MODULE = layout.initrd.BOOT_TMPFS_DIRECTORY / layout.TEST_MODULE_FILE


def initramfs_case(id: str, policy: ipe.Policy, module: Path, allowed: bool) -> Case:
    return Case(
        id=id,
        setup=(
            partial(steps.activate_policy, policy),
            partial(ipe.set_enforcement, True),
        ),
        trigger=partial(KMODULE.attempt, module),
        expect=0 if allowed else KMODULE.refused,
        scope=partial(
            runtime.case.scope,
            Collection(members=modules.loaded, discard=modules.remove),
        ),
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
    initramfs_case(
        "kmodule_boot_verified_false_initramfs_ok",
        FALSE_DENY_POLICY,
        INITRAMFS_MODULE,
        allowed=True,
    ),
    initramfs_case(
        "kmodule_boot_verified_false_tmpfs_denied",
        FALSE_DENY_POLICY,
        TMPFS_MODULE,
        allowed=False,
    ),
)


def build() -> tuple[Batch, ...]:
    return (
        Batch(
            "boot",
            tuple(
                Case(id=case.id, check=partial(checks.initramfs_case_passed, case.id))
                for case in INITRAMFS_CASES
            ),
        ),
    )
