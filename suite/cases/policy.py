# SPDX-License-Identifier: GPL-2.0-only

import errno
from functools import partial

import checks
import ipe
import steps
import triggers
from assets import (
    BASELINE_POLICY_NAME,
    POLICY_FIXTURE_MALFORMED_ASSET,
    POLICY_FIXTURE_OTHER_NAME_ASSET,
    POLICY_FIXTURE_V2_VERSION,
    POLICY_FIXTURE_V2_ASSET,
    POLICY_FIXTURE_NAME,
    POLICY_FIXTURE_V0_ASSET,
    POLICY_FIXTURE_V1_ASSET,
    POLICY_FIXTURE_V1_VERSION,
)
from model import Batch, Case


def build():
    return (Batch(
        "policy",
        (
        Case(
            id="policy_load_ok",
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy(POLICY_FIXTURE_V1_ASSET),
            ),
            expect=0,
            check=partial(checks.policy_version_is, POLICY_FIXTURE_NAME, POLICY_FIXTURE_V1_VERSION),
        ),
        Case(
            id="policy_update_equal_estale",
            setup=(partial(steps.deploy_policy, POLICY_FIXTURE_V1_ASSET),),
            trigger=partial(
                triggers.write_node,
                "update",
                POLICY_FIXTURE_NAME,
                ipe.signed_policy(POLICY_FIXTURE_V1_ASSET),
            ),
            expect=errno.ESTALE,
            check=partial(checks.policy_version_is, POLICY_FIXTURE_NAME, POLICY_FIXTURE_V1_VERSION),
        ),
        Case(
            id="policy_update_older_estale",
            setup=(partial(steps.deploy_policy, POLICY_FIXTURE_V1_ASSET),),
            trigger=partial(
                triggers.write_node,
                "update",
                POLICY_FIXTURE_NAME,
                ipe.signed_policy(POLICY_FIXTURE_V0_ASSET),
            ),
            expect=errno.ESTALE,
            check=partial(checks.policy_version_is, POLICY_FIXTURE_NAME, POLICY_FIXTURE_V1_VERSION),
        ),
        Case(
            id="policy_update_newer_ok",
            setup=(partial(steps.deploy_policy, POLICY_FIXTURE_V1_ASSET),),
            trigger=partial(
                triggers.write_node,
                "update",
                POLICY_FIXTURE_NAME,
                ipe.signed_policy(POLICY_FIXTURE_V2_ASSET),
            ),
            expect=0,
            check=partial(checks.policy_version_is, POLICY_FIXTURE_NAME, POLICY_FIXTURE_V2_VERSION),
        ),
        Case(
            id="policy_update_name_mismatch_einval",
            setup=(partial(steps.deploy_policy, POLICY_FIXTURE_V1_ASSET),),
            trigger=partial(
                triggers.write_node,
                "update",
                POLICY_FIXTURE_NAME,
                ipe.signed_policy(POLICY_FIXTURE_OTHER_NAME_ASSET),
            ),
            expect=errno.EINVAL,
            check=partial(checks.policy_version_is, POLICY_FIXTURE_NAME, POLICY_FIXTURE_V1_VERSION),
        ),
        Case(
            id="policy_update_malformed_ebadmsg",
            setup=(partial(steps.deploy_policy, POLICY_FIXTURE_V1_ASSET),),
            trigger=partial(
                triggers.write_node,
                "update",
                POLICY_FIXTURE_NAME,
                ipe.signed_policy(POLICY_FIXTURE_MALFORMED_ASSET),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_version_is, POLICY_FIXTURE_NAME, POLICY_FIXTURE_V1_VERSION),
        ),
        Case(
            id="policy_delete_inactive_ok",
            setup=(partial(steps.deploy_policy, POLICY_FIXTURE_V1_ASSET),),
            trigger=partial(triggers.write_node, "delete", POLICY_FIXTURE_NAME, b"1"),
            expect=0,
            check=partial(checks.policy_present_is, POLICY_FIXTURE_NAME, False),
        ),
        Case(
            id="policy_delete_active_eperm",
            trigger=partial(triggers.write_node, "delete", BASELINE_POLICY_NAME, b"1"),
            expect=errno.EPERM,
            check=partial(checks.policy_active_is, BASELINE_POLICY_NAME, True),
        ),
        Case(
            id="policy_activate_older_einval",
            setup=(partial(steps.deploy_policy, POLICY_FIXTURE_V0_ASSET),),
            trigger=partial(triggers.write_node, "active", POLICY_FIXTURE_NAME, b"1"),
            expect=errno.EINVAL,
            check=partial(checks.policy_active_is, BASELINE_POLICY_NAME, True),
        ),
        ),
    ),)
