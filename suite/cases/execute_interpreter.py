# SPDX-License-Identifier: GPL-2.0-only

from functools import partial
from pathlib import Path

import checks
import execute_interpreter
import ipe
import steps
from model import Case


def interpreter_case(
    id: str,
    policy: ipe.Policy,
    script: Path,
    from_stdin: bool,
    expected_errno: int,
    expected_returncode: int,
    expected_output: str,
) -> Case:
    """Check script authorization and whether the interpreter executed its command."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(execute_interpreter.interpret, script=script, from_stdin=from_stdin),
        checks=(
            partial(checks.errno_is, expected=expected_errno),
            partial(checks.returncode_is, expected=expected_returncode),
            partial(execute_interpreter.check_output, expected=expected_output),
        ),
    )
