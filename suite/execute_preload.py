# SPDX-License-Identifier: GPL-2.0-only

import subprocess
from pathlib import Path

import layout
from model import CaseState, Observation

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
