# SPDX-License-Identifier: GPL-2.0-only

from functools import partial
from pathlib import Path

import checks
import ipe
import kexec
import steps
from model import Case


def file_load_case(
    id: str,
    policy: ipe.Policy,
    binary: Path,
    expected_errno: int,
    expected_loaded: bool,
) -> Case:
    """Load a kernel file, check the syscall and staged state, then unload it."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(kexec.load_file, binary=binary),
        checks=(
            partial(checks.errno_is, expected=expected_errno),
            partial(kexec.check_loaded, expected_loaded=expected_loaded),
        ),
        extra_scopes=(kexec.image_scope,),
    )


def buffer_load_case(
    id: str,
    policy: ipe.Policy,
    binary: Path,
    expected_errno: int,
    expected_loaded: bool,
) -> Case:
    """Try the userspace-segment syscall and check its errno and staged state."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(kexec.load_buffer, binary=binary),
        checks=(
            partial(checks.errno_is, expected=expected_errno),
            partial(kexec.check_loaded, expected_loaded=expected_loaded),
        ),
        extra_scopes=(kexec.image_scope,),
    )
