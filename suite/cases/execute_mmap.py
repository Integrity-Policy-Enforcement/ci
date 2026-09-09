# SPDX-License-Identifier: GPL-2.0-only

from functools import partial
from pathlib import Path

import checks
import execute_mmap
import ipe
import steps
from model import Case


def mmap_case(
    id: str,
    policy: ipe.Policy,
    binary: Path | None,
    protection: int,
    shared: bool,
    expected_errno: int,
) -> Case:
    """Request a mapping and check success or the exact failure errno."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(
            execute_mmap.map_memory,
            binary=binary,
            protection=protection,
            shared=shared,
        ),
        checks=(partial(checks.errno_is, expected=expected_errno),),
    )
