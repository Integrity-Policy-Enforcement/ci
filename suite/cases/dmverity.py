# SPDX-License-Identifier: GPL-2.0-only

from functools import partial

import checks
import ipe
import layout
import mounts
import steps
from assets import KMODULE_SIGNATURE_TRUE_POLICY
from model import Batch, Case
from operations import KMODULE

SIGNED = layout.DMVERITY_SIGNED_MOUNT


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
            ),
            (
                partial(ipe.set_enforcement, False),
                partial(mounts.dmverity, layout.DMVERITY_SIGNED_DEVICE, SIGNED),
            ),
        ),
    )
