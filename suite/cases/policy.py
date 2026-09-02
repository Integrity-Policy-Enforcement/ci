# SPDX-License-Identifier: GPL-2.0-only

import errno
from functools import partial

import checks
import ipe
import steps
import triggers
from assets import (
    BASELINE_POLICY,
    LIFECYCLE_POLICY_MALFORMED,
    LIFECYCLE_POLICY_OTHER_NAME,
    LIFECYCLE_POLICY_V0,
    LIFECYCLE_POLICY_V1,
    LIFECYCLE_POLICY_V1_VERSION,
    LIFECYCLE_POLICY_V2,
    LIFECYCLE_POLICY_V2_VERSION,
)
from model import Batch, Case


def build() -> tuple[Batch, ...]:
    """The batches this group contributes."""
    return (
        Batch(
            id="policy",
            cases=(
                Case(
                    id="policy_load_ok",
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.NEW_POLICY,
                        policy=None,
                        data=LIFECYCLE_POLICY_V1.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(
                            checks.policy_version_is,
                            policy=LIFECYCLE_POLICY_V1,
                            expected=LIFECYCLE_POLICY_V1_VERSION,
                        ),
                    ),
                ),
                Case(
                    id="policy_update_equal_estale",
                    setup=(partial(steps.deploy_policy, policy=LIFECYCLE_POLICY_V1),),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.UPDATE,
                        policy=LIFECYCLE_POLICY_V1,
                        data=LIFECYCLE_POLICY_V1.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.ESTALE),
                        partial(
                            checks.policy_version_is,
                            policy=LIFECYCLE_POLICY_V1,
                            expected=LIFECYCLE_POLICY_V1_VERSION,
                        ),
                    ),
                ),
                Case(
                    id="policy_update_older_estale",
                    setup=(partial(steps.deploy_policy, policy=LIFECYCLE_POLICY_V1),),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.UPDATE,
                        policy=LIFECYCLE_POLICY_V1,
                        data=LIFECYCLE_POLICY_V0.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.ESTALE),
                        partial(
                            checks.policy_version_is,
                            policy=LIFECYCLE_POLICY_V1,
                            expected=LIFECYCLE_POLICY_V1_VERSION,
                        ),
                    ),
                ),
                Case(
                    id="policy_update_newer_ok",
                    setup=(partial(steps.deploy_policy, policy=LIFECYCLE_POLICY_V1),),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.UPDATE,
                        policy=LIFECYCLE_POLICY_V1,
                        data=LIFECYCLE_POLICY_V2.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(
                            checks.policy_version_is,
                            policy=LIFECYCLE_POLICY_V1,
                            expected=LIFECYCLE_POLICY_V2_VERSION,
                        ),
                    ),
                ),
                Case(
                    id="policy_update_name_mismatch_einval",
                    setup=(partial(steps.deploy_policy, policy=LIFECYCLE_POLICY_V1),),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.UPDATE,
                        policy=LIFECYCLE_POLICY_V1,
                        data=LIFECYCLE_POLICY_OTHER_NAME.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EINVAL),
                        partial(
                            checks.policy_version_is,
                            policy=LIFECYCLE_POLICY_V1,
                            expected=LIFECYCLE_POLICY_V1_VERSION,
                        ),
                    ),
                ),
                Case(
                    id="policy_update_malformed_ebadmsg",
                    setup=(partial(steps.deploy_policy, policy=LIFECYCLE_POLICY_V1),),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.UPDATE,
                        policy=LIFECYCLE_POLICY_V1,
                        data=LIFECYCLE_POLICY_MALFORMED.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EBADMSG),
                        partial(
                            checks.policy_version_is,
                            policy=LIFECYCLE_POLICY_V1,
                            expected=LIFECYCLE_POLICY_V1_VERSION,
                        ),
                    ),
                ),
                Case(
                    id="policy_delete_inactive_ok",
                    setup=(partial(steps.deploy_policy, policy=LIFECYCLE_POLICY_V1),),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.DELETE,
                        policy=LIFECYCLE_POLICY_V1,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(
                            checks.policy_present_is,
                            policy=LIFECYCLE_POLICY_V1,
                            expected=False,
                        ),
                    ),
                ),
                Case(
                    id="policy_delete_active_eperm",
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.DELETE,
                        policy=BASELINE_POLICY,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        partial(
                            checks.policy_active_is,
                            policy=BASELINE_POLICY,
                            expected=True,
                        ),
                    ),
                ),
                Case(
                    id="policy_activate_older_einval",
                    setup=(partial(steps.deploy_policy, policy=LIFECYCLE_POLICY_V0),),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.ACTIVE,
                        policy=LIFECYCLE_POLICY_V1,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EINVAL),
                        partial(
                            checks.policy_active_is,
                            policy=BASELINE_POLICY,
                            expected=True,
                        ),
                    ),
                ),
            ),
        ),
    )
