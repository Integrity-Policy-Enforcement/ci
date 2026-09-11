# SPDX-License-Identifier: GPL-2.0-only
"""interpreter operation: case construction, execution and result checks."""

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
from triggers import error_observation

from . import execve


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


def exec_shebang(script: Path, state: CaseState) -> Observation:
    """Exec the script itself, preserving the kernel exec error before any interpreter.

    If exec succeeds, the interpreter checks its fd again and runs '+'. An
    interpreter-side denial has exec errno 0 and cannot masquerade as EACCES
    from the original script exec. Only a real exec refusal has no child status.
    """
    try:
        result = subprocess.run(
            [str(script)], stdin=subprocess.DEVNULL, capture_output=True,
            text=True, env={}, check=False,
        )
    except OSError as failure:
        return error_observation(failure)
    state.observed.append(result.stdout)
    return Observation(errno=0, returncode=result.returncode, message=result.stderr)


def check_shebang_output(expected: str, observation: Observation) -> str | None:
    """An executed script must report a successful check and produce its output."""
    if observation.message != "execveat errno=0\n":
        return f"interpreter did not report a successful script check: {observation.message!r}"
    return check_output(expected=expected, observation=observation)


def check_output(expected: str, observation: Observation) -> str | None:
    """'1\n' proves the '+' script ran; a denied script must print nothing."""
    if observation.observed != (expected,):
        return f"interpreter output {observation.observed!r}, expected {(expected,)!r}"
    return None


def shebang_case(
    id: str,
    policy: ipe.Policy,
    script: Path,
    expected_errno: int,
    expected_returncode: int | None,
    expected_output: str | None,
) -> Case:
    """Exec a shebang script, separating kernel refusal from interpreter failure."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(exec_shebang, script=script),
        checks=(
            partial(checks.errno_is, expected=expected_errno),
            partial(execve.check_returncode, expected=expected_returncode),
        ) + (
            (partial(check_shebang_output, expected=expected_output),)
            if expected_output is not None else ()
        ),
    )


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
