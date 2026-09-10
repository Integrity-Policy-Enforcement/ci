# SPDX-License-Identifier: GPL-2.0-only

from functools import partial
from pathlib import Path

import checks
import execute_mprotect
import ipe
import steps
from model import Case


def mprotect_case(
    id: str,
    policy: ipe.Policy,
    binary: Path,
    initial_protection: int,
    protection: int,
    expected_errno: int,
) -> Case:
    """Change a private file mapping and check success or the exact failure errno."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(
            execute_mprotect.protect_file,
            binary=binary,
            initial_protection=initial_protection,
            protection=protection,
        ),
        checks=(partial(checks.errno_is, expected=expected_errno),),
    )
