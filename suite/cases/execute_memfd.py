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
    huge: bool,
    sealed: bool,
    expected_errno: int,
    expected_returncode: int | None,
) -> Case:
    """Exec a memfd copy, checking syscall refusal separately from program exit."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(execute_memfd.execute, binary=binary, huge=huge, sealed=sealed),
        checks=(
            partial(checks.errno_is, expected=expected_errno),
            partial(execute.check_returncode, expected=expected_returncode),
        ),
    )


def build() -> tuple[Batch, ...]:
    """Positive controls prove the memfd fixtures can actually execute."""
    return (
        Batch(
            id="memfd_controls",
            cases=(
                # Policy: the existing baseline allows EXECUTE unconditionally.
                # Input: a complete ELF copied to an executable, unsealed memfd.
                # Match: default ALLOW -> exec succeeds -> exit(0).
                Case(
                    id="execute_bprm_check_execve_memfd_unsealed_control_ok",
                    setup=(
                        partial(steps.activate_policy, name=BASELINE_POLICY.name),
                        partial(steps.set_enforcement, enabled=True),
                    ),
                    trigger=partial(
                        execute_memfd.execute,
                        binary=layout.guest.MEMFD_TEST_BINARY,
                        huge=False,
                        sealed=False,
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(execute.check_returncode, expected=0),
                    ),
                ),
                # Policy: the existing baseline allows EXECUTE unconditionally.
                # Input: the valid ELF in a normal memfd, fully sealed.
                # Match: default ALLOW -> real exec succeeds -> exit(0), not a loader error.
                Case(
                    id="execute_bprm_check_execve_memfd_sealed_control_ok",
                    setup=(
                        partial(steps.activate_policy, name=BASELINE_POLICY.name),
                        partial(steps.set_enforcement, enabled=True),
                    ),
                    trigger=partial(
                        execute_memfd.execute,
                        binary=layout.guest.MEMFD_TEST_BINARY,
                        huge=False,
                        sealed=True,
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(execute.check_returncode, expected=0),
                    ),
                ),
            ),
        ),
    )
