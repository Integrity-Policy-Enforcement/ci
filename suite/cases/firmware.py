# SPDX-License-Identifier: GPL-2.0-only

from functools import partial
from pathlib import Path

import checks
import firmware
import ipe
import steps
from model import Case
from operations import FIRMWARE_REQUEST_OPERATION


def case(id: str, policy: ipe.Policy, binary: Path, allowed: bool) -> Case:
    """Request a firmware binary and check whether IPE allowed it."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(FIRMWARE_REQUEST_OPERATION.attempt, binary=binary),
        checks=(
            partial(
                checks.errno_is,
                expected=0 if allowed else FIRMWARE_REQUEST_OPERATION.refused,
            ),
            partial(
                checks.operation_completed_is,
                operation=FIRMWARE_REQUEST_OPERATION,
                expected=allowed,
            ),
        ),
        extra_scopes=(firmware.request_scope,),
    )
