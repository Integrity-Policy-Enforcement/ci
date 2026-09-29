# SPDX-License-Identifier: GPL-2.0-only

from functools import partial
from pathlib import Path

import checks
import execute
import execute_memfd
import ipe
import layout
import steps
from assets import BASELINE_POLICY
from model import Batch, Case


def memfd_case(
    id: str,
    policy: ipe.Policy,
    binary: Path,
    expected_errno: int,
    expected_returncode: int | None,
) -> Case:
    """Exec a memfd copy, checking exec refusal separately from program exit."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(execute_memfd.execute, binary=binary),
        checks=(
            partial(checks.errno_is, expected=expected_errno),
            partial(execute.check_returncode, expected=expected_returncode),
        ),
    )


def build() -> tuple[Batch, ...]:
    """Positive controls prove the memfd copies can actually execute."""
    return (
        Batch(
            id="memfd_controls",
            cases=(
                # Policy: the baseline policy allows EXECUTE unconditionally.
                # Input: the static ELF copied into a new unsealed MFD_EXEC memfd.
                # Match: baseline ALLOW -> exec succeeds -> exit 0, so a later EACCES
                #        comes from IPE policy rather than from executing a memfd.
                Case(
                    id="execute_bprm_check_execve_memfd_unsealed_control_ok",
                    setup=(
                        partial(steps.activate_policy, name=BASELINE_POLICY.name),
                        partial(steps.set_enforcement, enabled=True),
                    ),
                    trigger=partial(
                        execute_memfd.execute,
                        binary=layout.guest.EXECUTE_TEST_BINARY,
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(execute.check_returncode, expected=0),
                    ),
                ),
            ),
        ),
    )
