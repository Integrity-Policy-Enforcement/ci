# SPDX-License-Identifier: GPL-2.0-only

from functools import partial
from pathlib import Path

import checks
import execute
import ipe
import steps
from model import Case


def execve_case(
    id: str,
    policy: ipe.Policy,
    binary: Path,
    expected_errno: int,
    expected_returncode: int | None,
) -> Case:
    """Execute a static ELF and independently check exec errno and exit status."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(execute.execve, binary=binary),
        checks=(
            partial(checks.errno_is, expected=expected_errno),
            partial(execute.check_returncode, expected=expected_returncode),
        ),
    )
