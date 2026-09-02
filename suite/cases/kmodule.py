# SPDX-License-Identifier: GPL-2.0-only

from functools import partial
from pathlib import Path

import checks
import ipe
import modules
import runtime
import steps
from model import Case
from operations import KMODULE_INSERT_OPERATION, KMODULE_TEST_BINARY_NAME


def case(id: str, policy: ipe.Policy, binary: Path, allowed: bool) -> Case:
    """Load a kernel module binary and check whether IPE allowed it."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy),
            partial(steps.activate_policy, policy.name),
            partial(steps.set_enforcement, True),
        ),
        trigger=partial(KMODULE_INSERT_OPERATION.attempt, binary),
        checks=(
            partial(
                checks.returncode_is,
                0 if allowed else KMODULE_INSERT_OPERATION.refused,
            ),
            partial(
                checks.operation_completed_is,
                KMODULE_INSERT_OPERATION,
                allowed,
            ),
        ),
        scope=partial(
            runtime.case_scope,
            partial(modules.loaded_scope, prefix=KMODULE_TEST_BINARY_NAME),
        ),
    )
