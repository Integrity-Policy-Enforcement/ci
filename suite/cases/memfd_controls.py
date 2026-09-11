# SPDX-License-Identifier: GPL-2.0-only
"""Concrete positive controls for the four memfd execution variants."""

from functools import partial

import checks
import layout
import steps
from assets import BASELINE_POLICY
from model import Batch, Case
from operations import execve, memfd


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
                        memfd.execute,
                        binary=layout.guest.MEMFD_TEST_BINARY,
                        huge=False,
                        sealed=False,
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(execve.check_returncode, expected=0),
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
                        memfd.execute,
                        binary=layout.guest.MEMFD_TEST_BINARY,
                        huge=False,
                        sealed=True,
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(execve.check_returncode, expected=0),
                    ),
                ),
                # Policy: the existing baseline allows EXECUTE unconditionally.
                # Input: the valid ELF in a 2 MiB hugetlb memfd, unsealed.
                # Match: default ALLOW -> real exec succeeds -> exit(0), not a loader error.
                Case(
                    id="execute_bprm_check_execve_memfd_hugetlb_control_ok",
                    setup=(
                        partial(steps.activate_policy, name=BASELINE_POLICY.name),
                        partial(steps.set_enforcement, enabled=True),
                    ),
                    trigger=partial(
                        memfd.execute,
                        binary=layout.guest.MEMFD_TEST_BINARY,
                        huge=True,
                        sealed=False,
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(execve.check_returncode, expected=0),
                    ),
                    extra_scopes=(memfd.hugepages_scope,),
                ),
                # Policy: the existing baseline allows EXECUTE unconditionally.
                # Input: the valid ELF in a 2 MiB hugetlb memfd, fully sealed.
                # Match: default ALLOW -> real exec succeeds -> exit(0), not a loader error.
                Case(
                    id="execute_bprm_check_execve_memfd_hugetlb_sealed_control_ok",
                    setup=(
                        partial(steps.activate_policy, name=BASELINE_POLICY.name),
                        partial(steps.set_enforcement, enabled=True),
                    ),
                    trigger=partial(
                        memfd.execute,
                        binary=layout.guest.MEMFD_TEST_BINARY,
                        huge=True,
                        sealed=True,
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(execve.check_returncode, expected=0),
                    ),
                    extra_scopes=(memfd.hugepages_scope,),
                ),
            ),
        ),
    )
