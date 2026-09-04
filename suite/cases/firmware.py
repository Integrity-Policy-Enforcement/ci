# SPDX-License-Identifier: GPL-2.0-only

from functools import partial
from pathlib import Path

import checks
import firmware
import ipe
import layout
import steps
from model import Case
from operations import (
    FIRMWARE_KERNEL_READ_REQUEST_FIRMWARE_OPERATION,
    FIRMWARE_REQUEST_REFUSED_ERRNO,
)


def request_firmware_case(id: str, policy: ipe.Policy, binary: Path, allowed: bool) -> Case:
    """Request a firmware binary and check whether IPE allowed it."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(FIRMWARE_KERNEL_READ_REQUEST_FIRMWARE_OPERATION.attempt, binary=binary),
        checks=(
            partial(
                checks.errno_is,
                expected=0 if allowed else FIRMWARE_REQUEST_REFUSED_ERRNO,
            ),
            partial(
                checks.operation_completed_is,
                operation=FIRMWARE_KERNEL_READ_REQUEST_FIRMWARE_OPERATION,
                completed=partial(
                    firmware.requested_firmware_matches,
                    expected=layout.guest.FIRMWARE_TEST_BINARY,
                ),
                expected=allowed,
            ),
        ),
        extra_scopes=(firmware.request_firmware_scope,),
    )
