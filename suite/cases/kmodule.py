# SPDX-License-Identifier: GPL-2.0-only

from functools import partial
from pathlib import Path

import checks
import ipe
import modules
import steps
from model import Case
from operations import KMODULE_KERNEL_READ_INSMOD_OPERATION, KMODULE_TEST_BINARY_NAME


def insmod_case(id: str, policy: ipe.Policy, binary: Path, allowed: bool) -> Case:
    """Load a kernel module binary and check whether IPE allowed it."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(KMODULE_KERNEL_READ_INSMOD_OPERATION.attempt, binary=binary),
        checks=(
            partial(
                checks.returncode_is,
                expected=0 if allowed else KMODULE_KERNEL_READ_INSMOD_OPERATION.refused,
            ),
            partial(
                checks.operation_completed_is,
                operation=KMODULE_KERNEL_READ_INSMOD_OPERATION,
                expected=allowed,
            ),
        ),
        extra_scopes=(
            partial(modules.loaded_scope, prefix=KMODULE_TEST_BINARY_NAME),
        ),
    )
