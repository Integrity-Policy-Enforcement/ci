# SPDX-License-Identifier: GPL-2.0-only
"""preload operation: case construction, execution and result checks."""

import subprocess
from functools import partial
from pathlib import Path

import checks
import ipe
import layout
import steps
from model import Case, CaseState, Observation


def preload(library: Path, state: CaseState) -> Observation:
    """Start a normal dynamic ELF with exactly one requested preloaded library.

    The client, loader and libc are on the signed root. Only the target library
    varies. Exec/bootstrap errors are not accepted as preload denials. A rejected
    LD_PRELOAD object is normally ignored by glibc, so exit status alone cannot
    tell whether the requested library ran; retain stdout and stderr as evidence.
    """
    result = subprocess.run(
        [str(layout.guest.PRELOAD_CLIENT)], stdin=subprocess.DEVNULL,
        capture_output=True, text=True, check=False,
        env={"LC_ALL": "C", "LD_PRELOAD": str(library)},
    )
    state.observed.append(result.stdout)
    return Observation(returncode=result.returncode, message=result.stderr)


def check_preloaded(
    library: Path,
    expected_preloaded: bool,
    observation: Observation,
) -> str | None:
    """Check whether the constructor ran, and distinguish mapping denial from other errors.

    Allowed: stdout is exactly 'preload\\n' and stderr is empty.
    Denied: the constructor prints nothing, while the loader identifies this
    library and reports a segment-mapping failure. A missing file, wrong ELF
    architecture or merely nonempty stderr must not satisfy the denial case.
    """
    if len(observation.observed) != 1:
        return "missing preload program output"
    stdout, stderr = observation.observed[0], observation.message
    if expected_preloaded:
        if stdout != "preload\n" or stderr:
            return f"preload constructor did not run cleanly: stdout={stdout!r}, stderr={stderr!r}"
    else:
        if stdout:
            return f"denied preload unexpectedly ran code: {stdout!r}"
        if any(text not in stderr for text in (
            str(library), "cannot be preloaded", "failed to map segment", "ignored",
        )):
            return f"loader did not report a mapping refusal for {library}: {stderr!r}"
    return None


def preload_case(
    id: str,
    policy: ipe.Policy,
    library: Path,
    expected_returncode: int,
    expected_preloaded: bool,
) -> Case:
    """Check optional-library loading separately from the client's exit status."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(preload, library=library),
        checks=(
            partial(checks.returncode_is, expected=expected_returncode),
            partial(
                check_preloaded,
                library=library,
                expected_preloaded=expected_preloaded,
            ),
        ),
    )
