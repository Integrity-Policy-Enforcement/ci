# SPDX-License-Identifier: GPL-2.0-only

from functools import partial
from pathlib import Path

import checks
import ipe
import modules
import runtime
import steps
from model import Case
from operations import KMODULE, TEST_MODULE_NAME


def case(id: str, policy: ipe.Policy, module: Path, allowed: bool) -> Case:
    """A case that loads a module under a policy and checks whether IPE allowed it."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy),
            partial(steps.activate_policy, policy.name),
            partial(steps.set_enforcement, True),
        ),
        trigger=partial(KMODULE.attempt, module),
        checks=(
            partial(
                checks.returncode_is,
                0 if allowed else KMODULE.refused,
            ),
            partial(checks.operation_completed_is, KMODULE, allowed),
        ),
        scope=partial(
            runtime.case_scope,
            partial(modules.loaded_scope, prefix=TEST_MODULE_NAME),
        ),
    )
