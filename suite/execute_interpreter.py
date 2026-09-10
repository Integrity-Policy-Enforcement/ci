# SPDX-License-Identifier: GPL-2.0-only

import re
import subprocess
from contextlib import nullcontext
from pathlib import Path

import layout
from model import CaseState, Observation
from triggers import error_observation


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
