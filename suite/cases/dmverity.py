# SPDX-License-Identifier: GPL-2.0-only

from functools import partial

import checks
import ipe
import layout
import mounts
import steps
from assets import (
    KMODULE_ROOTHASH_POLICY,
    KMODULE_SIGNATURE_FALSE_POLICY,
    KMODULE_SIGNATURE_TRUE_POLICY,
)
from model import Batch, Case
from operations import KMODULE

SIGNED = layout.DMVERITY_SIGNED_MOUNT
UNSIGNED = layout.DMVERITY_UNSIGNED_MOUNT
PLAIN = layout.PLAIN_MOUNT


def kmodule_case(id, policy, mount, allowed):
    return Case(
        id=id,
        setup=(
            partial(steps.activate_policy, policy),
            partial(ipe.set_enforcement, True),
        ),
        trigger=partial(KMODULE.attempt, mount / layout.TEST_MODULE_FILE),
        expect=0 if allowed else KMODULE.refused,
        check=partial(checks.operation_completed_is, KMODULE, allowed),
    )


def build():
    return (
        Batch(
            "dmverity",
            (
                kmodule_case(
                    "kmodule_signature_true_signed_ok",
                    KMODULE_SIGNATURE_TRUE_POLICY,
                    SIGNED,
                    allowed=True,
                ),
                kmodule_case(
                    "kmodule_signature_true_unsigned_denied",
                    KMODULE_SIGNATURE_TRUE_POLICY,
                    UNSIGNED,
                    allowed=False,
                ),
                kmodule_case(
                    "kmodule_signature_true_plain_denied",
                    KMODULE_SIGNATURE_TRUE_POLICY,
                    PLAIN,
                    allowed=False,
                ),
                kmodule_case(
                    "kmodule_signature_false_signed_ok",
                    KMODULE_SIGNATURE_FALSE_POLICY,
                    SIGNED,
                    allowed=True,
                ),
                kmodule_case(
                    "kmodule_signature_false_unsigned_denied",
                    KMODULE_SIGNATURE_FALSE_POLICY,
                    UNSIGNED,
                    allowed=False,
                ),
                kmodule_case(
                    "kmodule_signature_false_plain_denied",
                    KMODULE_SIGNATURE_FALSE_POLICY,
                    PLAIN,
                    allowed=False,
                ),
                kmodule_case(
                    "kmodule_roothash_signed_ok",
                    KMODULE_ROOTHASH_POLICY,
                    SIGNED,
                    allowed=True,
                ),
                kmodule_case(
                    "kmodule_roothash_unsigned_ok",
                    KMODULE_ROOTHASH_POLICY,
                    UNSIGNED,
                    allowed=True,
                ),
            ),
            (
                partial(ipe.set_enforcement, False),
                partial(mounts.dmverity, layout.DMVERITY_SIGNED_DEVICE, SIGNED, True),
                partial(
                    mounts.dmverity, layout.DMVERITY_UNSIGNED_DEVICE, UNSIGNED, False
                ),
                partial(mounts.tmpfs, PLAIN, layout.PAYLOAD / layout.TEST_MODULE_FILE),
            ),
        ),
    )
