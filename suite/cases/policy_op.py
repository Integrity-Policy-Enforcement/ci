# SPDX-License-Identifier: GPL-2.0-only

from functools import partial
from pathlib import Path

import checks
import ipe
import policy_op
import steps
from model import Case


def read_case(
    id: str,
    policy: ipe.Policy,
    binary: Path,
    expected_errno: int,
    expected_content: Path | bytes,
) -> Case:
    """Read a file as POLICY and check the errno and actual retained bytes."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(policy_op.read_file, binary=binary),
        checks=(
            partial(checks.errno_is, expected=expected_errno),
            partial(policy_op.check_contents, expected=expected_content),
        ),
    )
