# SPDX-License-Identifier: GPL-2.0-only

from functools import partial
from pathlib import Path

import checks
import ipe
import layout
import modules
import steps
from model import Case, CaseState, Observation, Operation

# insmod reports a failed insertion with process return code 1, not an errno.
INSMOD_REFUSED_RETURN_CODE = 1
# This exact target name also reserves its prefix for case cleanup.
KMODULE_TEST_BINARY_NAME = layout.guest.KMODULE_TEST_BINARY.stem


def call_insmod(binary: Path, state: CaseState) -> Observation:
    """Try insmod and return what happened, without raising."""
    finished = modules.insmod(binary)
    return Observation(
        returncode=finished.returncode,
        message=finished.stderr.strip(),
    )


KMODULE_KERNEL_READ_INSMOD_OPERATION = Operation(
    id="kmodule_kernel_read_insmod",
    attempt=call_insmod,
)


def insmod_case(id: str, policy: ipe.Policy, binary: Path, allowed: bool) -> Case:
    """Load a kernel module binary and check whether IPE allowed it."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(KMODULE_KERNEL_READ_INSMOD_OPERATION.attempt, binary=binary),
        checks=(
            partial(
                checks.returncode_is,
                expected=0 if allowed else INSMOD_REFUSED_RETURN_CODE,
            ),
            partial(
                checks.operation_completed_is,
                operation=KMODULE_KERNEL_READ_INSMOD_OPERATION,
                completed=partial(
                    modules.is_loaded,
                    name=KMODULE_TEST_BINARY_NAME,
                ),
                expected=allowed,
            ),
        ),
        extra_scopes=(
            partial(modules.loaded_scope, prefix=KMODULE_TEST_BINARY_NAME),
        ),
    )
