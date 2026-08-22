# SPDX-License-Identifier: GPL-2.0-only

import errno
from functools import partial

import checks
import ipe
import steps
import triggers
from assets import (
    CAPABILITY_POLICY_NAME,
    CAPABILITY_POLICY_V1,
    CAPABILITY_POLICY_V1_VERSION,
    CAPABILITY_POLICY_V2,
    CAPABILITY_POLICY_V2_VERSION,
)
from model import Case


def build():
    opened_file = [None]

    return (
        Case(
            id="cap_update_nocap_eperm",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                steps.drop_mac_admin,
            ),
            trigger=partial(
                triggers.write_node,
                "update",
                CAPABILITY_POLICY_NAME,
                ipe.signed_policy(CAPABILITY_POLICY_V2),
            ),
            expect=errno.EPERM,
            check=partial(checks.policy_version_is, CAPABILITY_POLICY_NAME, CAPABILITY_POLICY_V1_VERSION),
        ),
        Case(
            id="cap_update_withcap_ok",
            setup=(partial(steps.deploy_policy, CAPABILITY_POLICY_V1),),
            trigger=partial(
                triggers.write_node,
                "update",
                CAPABILITY_POLICY_NAME,
                ipe.signed_policy(CAPABILITY_POLICY_V2),
            ),
            expect=0,
            check=partial(checks.policy_version_is, CAPABILITY_POLICY_NAME, CAPABILITY_POLICY_V2_VERSION),
        ),
        Case(
            id="cap_active_nocap_eperm",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                steps.drop_mac_admin,
            ),
            trigger=partial(
                triggers.write_node,
                "active",
                CAPABILITY_POLICY_NAME,
                b"1",
            ),
            expect=errno.EPERM,
            check=partial(checks.policy_active_is, CAPABILITY_POLICY_NAME, False),
        ),
        Case(
            id="cap_active_withcap_ok",
            setup=(partial(steps.deploy_policy, CAPABILITY_POLICY_V1),),
            trigger=partial(
                triggers.write_node,
                "active",
                CAPABILITY_POLICY_NAME,
                b"1",
            ),
            expect=0,
            check=partial(checks.policy_active_is, CAPABILITY_POLICY_NAME, True),
        ),
        Case(
            id="cap_audit_nocap_eperm",
            setup=(steps.drop_mac_admin,),
            trigger=partial(triggers.write_node, "success_audit", None, b"1"),
            expect=errno.EPERM,
            check=partial(checks.node_value_is, "success_audit", "0"),
        ),
        Case(
            id="cap_audit_withcap_ok",
            setup=(),
            trigger=partial(triggers.write_node, "success_audit", None, b"1"),
            expect=0,
            check=partial(checks.node_value_is, "success_audit", "1"),
        ),
        Case(
            id="cap_delete_nocap_eperm",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                steps.drop_mac_admin,
            ),
            trigger=partial(
                triggers.write_node,
                "delete",
                CAPABILITY_POLICY_NAME,
                b"1",
            ),
            expect=errno.EPERM,
            check=partial(checks.policy_present_is, CAPABILITY_POLICY_NAME, True),
        ),
        Case(
            id="cap_delete_withcap_ok",
            setup=(partial(steps.deploy_policy, CAPABILITY_POLICY_V1),),
            trigger=partial(
                triggers.write_node,
                "delete",
                CAPABILITY_POLICY_NAME,
                b"1",
            ),
            expect=0,
            check=partial(checks.policy_present_is, CAPABILITY_POLICY_NAME, False),
        ),
        Case(
            id="cap_enforce_nocap_eperm",
            setup=(steps.drop_mac_admin,),
            trigger=partial(triggers.write_node, "enforce", None, b"1"),
            expect=errno.EPERM,
            check=partial(checks.node_value_is, "enforce", "0"),
        ),
        Case(
            id="cap_enforce_withcap_ok",
            setup=(),
            trigger=partial(triggers.write_node, "enforce", None, b"1"),
            expect=0,
            check=partial(checks.node_value_is, "enforce", "1"),
        ),
        Case(
            id="cap_newpol_nocap_eperm",
            setup=(steps.drop_mac_admin,),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy(CAPABILITY_POLICY_V1),
            ),
            expect=errno.EPERM,
            check=partial(checks.policy_present_is, CAPABILITY_POLICY_NAME, False),
        ),
        Case(
            id="cap_newpol_withcap_ok",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy(CAPABILITY_POLICY_V1),
            ),
            expect=0,
            check=partial(checks.policy_present_is, CAPABILITY_POLICY_NAME, True),
        ),
        Case(
            id="cap_update_fcred_withcap_ok",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                partial(
                    steps.open_node,
                    "update",
                    CAPABILITY_POLICY_NAME,
                    opened_file,
                ),
                steps.drop_mac_admin,
            ),
            trigger=partial(
                triggers.write_opened_file,
                ipe.signed_policy(CAPABILITY_POLICY_V2),
                opened_file,
            ),
            expect=0,
            check=partial(
                checks.policy_version_is,
                CAPABILITY_POLICY_NAME,
                CAPABILITY_POLICY_V2_VERSION,
            ),
        ),
        Case(
            id="cap_update_fcred_nocap_eperm",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                steps.clear_mac_admin,
                partial(
                    steps.open_node,
                    "update",
                    CAPABILITY_POLICY_NAME,
                    opened_file,
                ),
                steps.raise_mac_admin,
            ),
            trigger=partial(
                triggers.write_opened_file,
                ipe.signed_policy(CAPABILITY_POLICY_V2),
                opened_file,
            ),
            expect=errno.EPERM,
            check=partial(
                checks.policy_version_is,
                CAPABILITY_POLICY_NAME,
                CAPABILITY_POLICY_V1_VERSION,
            ),
        ),
        Case(
            id="cap_active_fcred_withcap_ok",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                partial(
                    steps.open_node,
                    "active",
                    CAPABILITY_POLICY_NAME,
                    opened_file,
                ),
                steps.drop_mac_admin,
            ),
            trigger=partial(
                triggers.write_opened_file,
                b"1",
                opened_file,
            ),
            expect=0,
            check=partial(checks.policy_active_is, CAPABILITY_POLICY_NAME, True),
        ),
        Case(
            id="cap_active_fcred_nocap_eperm",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                steps.clear_mac_admin,
                partial(
                    steps.open_node,
                    "active",
                    CAPABILITY_POLICY_NAME,
                    opened_file,
                ),
                steps.raise_mac_admin,
            ),
            trigger=partial(
                triggers.write_opened_file,
                b"1",
                opened_file,
            ),
            expect=errno.EPERM,
            check=partial(checks.policy_active_is, CAPABILITY_POLICY_NAME, False),
        ),
    )
