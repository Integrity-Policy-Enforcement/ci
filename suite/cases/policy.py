# SPDX-License-Identifier: GPL-2.0-only

import errno
from functools import partial

import checks
import ipe
import steps
import triggers
from assets import (
    BASELINE_POLICY,
    POLICY_MALFORMED,
    POLICY_OTHER_NAME,
    POLICY_V0,
    POLICY_V1,
    POLICY_V1_VERSION,
    POLICY_V2,
    POLICY_V2_VERSION,
)
from model import Batch, Case


def build() -> tuple[Batch, ...]:
    return (Batch(
        "policy",
        (
        Case(
            id="policy_load_ok",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                POLICY_V1.signed.read_bytes(),
            ),
            expect=0,
            check=partial(checks.policy_version_is, POLICY_V1, POLICY_V1_VERSION),
        ),
        Case(
            id="policy_update_equal_estale",
            setup=(partial(steps.deploy_policy, POLICY_V1),),
            trigger=partial(
                triggers.write_node,
                ipe.node.UPDATE,
                POLICY_V1,
                POLICY_V1.signed.read_bytes(),
            ),
            expect=errno.ESTALE,
            check=partial(checks.policy_version_is, POLICY_V1, POLICY_V1_VERSION),
        ),
        Case(
            id="policy_update_older_estale",
            setup=(partial(steps.deploy_policy, POLICY_V1),),
            trigger=partial(
                triggers.write_node,
                ipe.node.UPDATE,
                POLICY_V1,
                POLICY_V0.signed.read_bytes(),
            ),
            expect=errno.ESTALE,
            check=partial(checks.policy_version_is, POLICY_V1, POLICY_V1_VERSION),
        ),
        Case(
            id="policy_update_newer_ok",
            setup=(partial(steps.deploy_policy, POLICY_V1),),
            trigger=partial(
                triggers.write_node,
                ipe.node.UPDATE,
                POLICY_V1,
                POLICY_V2.signed.read_bytes(),
            ),
            expect=0,
            check=partial(checks.policy_version_is, POLICY_V1, POLICY_V2_VERSION),
        ),
        Case(
            id="policy_update_name_mismatch_einval",
            setup=(partial(steps.deploy_policy, POLICY_V1),),
            trigger=partial(
                triggers.write_node,
                ipe.node.UPDATE,
                POLICY_V1,
                POLICY_OTHER_NAME.signed.read_bytes(),
            ),
            expect=errno.EINVAL,
            check=partial(checks.policy_version_is, POLICY_V1, POLICY_V1_VERSION),
        ),
        Case(
            id="policy_update_malformed_ebadmsg",
            setup=(partial(steps.deploy_policy, POLICY_V1),),
            trigger=partial(
                triggers.write_node,
                ipe.node.UPDATE,
                POLICY_V1,
                POLICY_MALFORMED.signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_version_is, POLICY_V1, POLICY_V1_VERSION),
        ),
        Case(
            id="policy_delete_inactive_ok",
            setup=(partial(steps.deploy_policy, POLICY_V1),),
            trigger=partial(triggers.write_node, ipe.node.DELETE, POLICY_V1, b"1"),
            expect=0,
            check=partial(checks.policy_present_is, POLICY_V1, False),
        ),
        Case(
            id="policy_delete_active_eperm",
            trigger=partial(triggers.write_node, ipe.node.DELETE, BASELINE_POLICY, b"1"),
            expect=errno.EPERM,
            check=partial(checks.policy_active_is, BASELINE_POLICY, True),
        ),
        Case(
            id="policy_activate_older_einval",
            setup=(partial(steps.deploy_policy, POLICY_V0),),
            trigger=partial(triggers.write_node, ipe.node.ACTIVE, POLICY_V1, b"1"),
            expect=errno.EINVAL,
            check=partial(checks.policy_active_is, BASELINE_POLICY, True),
        ),
        ),
    ),)
