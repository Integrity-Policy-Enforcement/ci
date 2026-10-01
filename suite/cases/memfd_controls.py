# SPDX-License-Identifier: GPL-2.0-only
"""Positive controls: each memfd variant executes under the baseline policy."""

from functools import partial

import checks
import layout
import steps
from assets import BASELINE_POLICY
from model import Batch, Case
from operations import execve, memfd


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
                        memfd.execute,
                        binary=layout.guest.EXECUTE_TEST_BINARY,
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(execve.check_returncode, expected=0),
                    ),
                ),
                # Policy: the baseline policy allows EXECUTE unconditionally.
                # Input: the same static ELF in a new MFD_EXEC memfd with all seals added.
                # Match: baseline ALLOW -> exec succeeds -> exit 0, so sealing itself does
                #        not stop exec and a later EACCES comes from IPE policy.
                Case(
                    id="execute_bprm_check_execve_memfd_sealed_control_ok",
                    setup=(
                        partial(steps.activate_policy, name=BASELINE_POLICY.name),
                        partial(steps.set_enforcement, enabled=True),
                    ),
                    trigger=partial(
                        memfd.execute,
                        binary=layout.guest.EXECUTE_TEST_BINARY,
                        sealed=True,
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(execve.check_returncode, expected=0),
                    ),
                ),
                # Policy: the baseline policy allows EXECUTE unconditionally.
                # Input: the 2 MiB-aligned ELF in a new unsealed MFD_EXEC hugetlb memfd.
                # Match: baseline ALLOW -> exec succeeds -> exit 0, so the hugetlb copy can
                #        run and a later EACCES comes from IPE policy.
                Case(
                    id="execute_bprm_check_execve_memfd_hugetlb_control_ok",
                    setup=(
                        partial(steps.activate_policy, name=BASELINE_POLICY.name),
                        partial(steps.set_enforcement, enabled=True),
                    ),
                    trigger=partial(
                        memfd.execute,
                        binary=layout.guest.HUGETLB_TEST_BINARY,
                        huge=True,
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(execve.check_returncode, expected=0),
                    ),
                    extra_scopes=(memfd.hugepages_scope,),
                ),
                # Policy: the baseline policy allows EXECUTE unconditionally.
                # Input: the 2 MiB-aligned ELF in a new hugetlb memfd with all seals added.
                # Match: baseline ALLOW -> exec succeeds -> exit 0, so sealing a hugetlb
                #        copy does not stop exec and a later EACCES comes from IPE policy.
                Case(
                    id="execute_bprm_check_execve_memfd_hugetlb_sealed_control_ok",
                    setup=(
                        partial(steps.activate_policy, name=BASELINE_POLICY.name),
                        partial(steps.set_enforcement, enabled=True),
                    ),
                    trigger=partial(
                        memfd.execute,
                        binary=layout.guest.HUGETLB_TEST_BINARY,
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
