# SPDX-License-Identifier: GPL-2.0-only

import errno
from functools import partial
from pathlib import Path

import checks
import firmware
import ipe
import layout
import steps
from model import Case, Operation

# Firmware search continues after IPE returns EACCES and ends with ENOENT.
FIRMWARE_REQUEST_REFUSED_ERRNO = errno.ENOENT

FIRMWARE_KERNEL_READ_REQUEST_FIRMWARE_OPERATION = Operation(
    id="firmware_kernel_read_request_firmware",
    attempt=firmware.request_firmware,
)


def request_firmware_case(
    id: str,
    policy: ipe.Policy,
    binary: Path,
    allowed: bool,
) -> Case:
    """Request a firmware binary and check whether IPE allowed it."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(
            FIRMWARE_KERNEL_READ_REQUEST_FIRMWARE_OPERATION.attempt,
            binary=binary,
        ),
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
