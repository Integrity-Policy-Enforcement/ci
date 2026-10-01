# SPDX-License-Identifier: GPL-2.0-only

from functools import partial
from pathlib import Path

import checks
import execute_preload
import ipe
import steps
from model import Case


def preload_case(id: str, policy: ipe.Policy, library: Path, expected_preloaded: bool) -> Case:
    """Run /usr/bin/true with LD_PRELOAD=<library> under one policy.

    The program exits 0 either way; its output shows what the loader did:
    - preloaded: stdout is the constructor's line and stderr is empty;
    - denied: stdout is empty and stderr is the loader's refusal for this
      library.
    Any other output, such as the loader's message for a missing file, fails.
    """
    if expected_preloaded:
        stdout, stderr = execute_preload.CONSTRUCTOR_OUTPUT, ""
    else:
        stdout, stderr = "", execute_preload.LOADER_REFUSAL.format(library=library)
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(execute_preload.preload, library=library),
        checks=(
            partial(checks.returncode_is, expected=0),
            partial(
                execute_preload.check_output,
                expected_stdout=stdout,
                expected_stderr=stderr,
            ),
        ),
    )
