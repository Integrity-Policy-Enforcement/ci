# SPDX-License-Identifier: GPL-2.0-only
"""Script interpreter with AT_EXECVE_CHECK: trigger, output check and case factory."""

import re
import subprocess
from contextlib import nullcontext
from functools import partial
from pathlib import Path

import checks
import ipe
import layout
import steps
from model import Case, CaseState, Observation


def interpret(script: Path, from_stdin: bool, state: CaseState) -> Observation:
    """Run the interpreter and preserve its check errno, exit status and output.

    The interpreter reports the actual execveat-check errno before reading any
    script bytes. Failure to launch it, open its input or report that result is
    an error, not an accepted script denial. For stdin, pass the original file
    directly, not a pipe containing a userspace copy of its bytes.
    """
    argument = "--stdin" if from_stdin else str(script)
    with (script.open("rb") if from_stdin else nullcontext(subprocess.DEVNULL)) as source:
        result = subprocess.run(
            [str(layout.guest.FSVERITY_INTERPRETER_TEST_BINARY), argument],
            stdin=source, capture_output=True, text=True, env={}, check=False,
        )
    report = re.fullmatch(r"execveat errno=(\d+)\n", result.stderr)
    if report is None:
        raise RuntimeError(f"interpreter did not report its script check: {result.stderr!r}")
    state.observed.append(result.stdout)
    return Observation(errno=int(report[1]), returncode=result.returncode)


def check_output(expected: str, observation: Observation) -> str | None:
    """'1\n' proves the '+' script ran; a denied script must print nothing."""
    if observation.observed != (expected,):
        return f"interpreter output {observation.observed!r}, expected {(expected,)!r}"
    return None


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
        trigger=partial(interpret, script=script, from_stdin=from_stdin),
        checks=(
            partial(checks.errno_is, expected=expected_errno),
            partial(checks.returncode_is, expected=expected_returncode),
            partial(check_output, expected=expected_output),
        ),
    )
