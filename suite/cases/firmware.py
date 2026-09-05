# SPDX-License-Identifier: GPL-2.0-only

from functools import partial
from pathlib import Path

import checks
import firmware
import ipe
import layout
import steps
from model import Case


def request_firmware_case(
    id: str,
    policy: ipe.Policy,
    binary: Path,
    expected_errno: int,
    expected_content_match: bool,
) -> Case:
    """Request firmware and check its errno and content."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(
            firmware.request_firmware,
            binary=binary,
        ),
        checks=(
            partial(
                checks.errno_is,
                expected=expected_errno,
            ),
            partial(
                firmware.check_requested_firmware,
                expected_binary=layout.guest.FIRMWARE_TEST_BINARY,
                expected_content_match=expected_content_match,
            ),
        ),
        extra_scopes=(firmware.request_firmware_scope,),
    )
