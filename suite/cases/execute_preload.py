# SPDX-License-Identifier: GPL-2.0-only

from functools import partial
from pathlib import Path

import checks
import execute_preload
import ipe
import steps
from model import Case


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
        trigger=partial(execute_preload.preload, library=library),
        checks=(
            partial(checks.returncode_is, expected=expected_returncode),
            partial(
                execute_preload.check_preloaded,
                library=library,
                expected_preloaded=expected_preloaded,
            ),
        ),
    )
