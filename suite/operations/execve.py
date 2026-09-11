# SPDX-License-Identifier: GPL-2.0-only
"""execve operation: case construction, execution and result checks."""

import subprocess
from functools import partial
from pathlib import Path

import checks
import ipe
import steps
from model import Case, CaseState, Observation
from triggers import error_observation


def execve(binary: Path, state: CaseState) -> Observation:
    """Execute the original ELF, preserving exec errors separately from exit status."""
    try:
        result = subprocess.run(
            [str(binary)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True, check=False,
        )
    except OSError as failure:
        return error_observation(failure)
    return Observation(errno=0, returncode=result.returncode, message=result.stderr)


def check_returncode(expected: int | None, observation: Observation) -> str | None:
    """An exec refusal has no program exit status; a started program does."""
    if observation.returncode != expected:
        return f"program return code {observation.returncode}, expected {expected}"
    return None


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
        trigger=partial(execve, binary=binary),
        checks=(
            partial(checks.errno_is, expected=expected_errno),
            partial(check_returncode, expected=expected_returncode),
        ),
    )
