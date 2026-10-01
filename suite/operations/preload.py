# SPDX-License-Identifier: GPL-2.0-only
"""LD_PRELOAD: the trigger, its output check and the case factory."""

import subprocess
from functools import partial
from pathlib import Path

import checks
import ipe
import layout
import steps
from model import Case, CaseState, Observation

# The constructor's output when the loader mapped the library and ran it.
CONSTRUCTOR_OUTPUT = "preload\n"
# The loader's message when it could not map the library and skipped it.
LOADER_REFUSAL = (
    "ERROR: ld.so: object '{library}' from LD_PRELOAD cannot be preloaded "
    "(failed to map segment from shared object): ignored.\n"
)


def preload(library: Path, state: CaseState) -> Observation:
    """Run /usr/bin/true with LD_PRELOAD naming one library.

    Steps:
    1. Exec /usr/bin/true with only LD_PRELOAD=<library> in its environment.
    2. Its ELF loader maps the library executable before main(), and IPE
       checks that mapping. If IPE allows it, the library's constructor
       prints CONSTRUCTOR_OUTPUT. If IPE denies it, the loader prints
       LOADER_REFUSAL, skips the library and runs the program anyway.
    3. Record stdout and stderr, in that order. The program exits 0 in both
       cases.

    An exec failure of /usr/bin/true itself raises and is a preparation error,
    not a preload result.
    """
    result = subprocess.run(
        [str(layout.guest.PRELOAD_CLIENT)], stdin=subprocess.DEVNULL,
        capture_output=True, text=True, check=False,
        env={"LD_PRELOAD": str(library)},
    )
    state.observed.extend((result.stdout, result.stderr))
    return Observation(returncode=result.returncode)


def check_output(
    expected_stdout: str, expected_stderr: str, observation: Observation,
) -> str | None:
    """The program printed exactly this stdout and stderr."""
    if observation.observed != (expected_stdout, expected_stderr):
        return (
            f"expected stdout={expected_stdout!r} stderr={expected_stderr!r}, "
            f"got (stdout, stderr)={observation.observed!r}"
        )
    return None


def preload_case(id: str, policy: ipe.Policy, library: Path, expected_preloaded: bool) -> Case:
    """Run /usr/bin/true with LD_PRELOAD=<library> under one policy.

    The program exits 0 either way; its output shows what the loader did:
    - preloaded: stdout is the constructor's line and stderr is empty;
    - denied: stdout is empty and stderr is the loader's refusal for this
      library.
    Any other output, such as the loader's message for a missing file, fails.
    """
    if expected_preloaded:
        stdout, stderr = CONSTRUCTOR_OUTPUT, ""
    else:
        stdout, stderr = "", LOADER_REFUSAL.format(library=library)
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(preload, library=library),
        checks=(
            partial(checks.returncode_is, expected=0),
            partial(
                check_output,
                expected_stdout=stdout,
                expected_stderr=stderr,
            ),
        ),
    )
