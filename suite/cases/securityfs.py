# SPDX-License-Identifier: GPL-2.0-only

import errno
from functools import partial

import checks
import ipe
import steps
import triggers
from assets import (
    CAPABILITY_POLICY_V1,
    CAPABILITY_POLICY_V1_VERSION,
    CAPABILITY_POLICY_V2,
    CAPABILITY_POLICY_V2_VERSION,
)
from model import Batch, Case


def build():
    opened_file = [None]
    read_values = []
    truncated_policy = CAPABILITY_POLICY_V1.signed.read_bytes()
    truncated_policy = truncated_policy[: len(truncated_policy) // 2]
    trailing_fragment = CAPABILITY_POLICY_V1.signed.read_bytes()
    trailing_fragment = trailing_fragment[len(trailing_fragment) // 2 :]

    return (Batch(
        "securityfs",
        (
        Case(
            id="cap_update_nocap_eperm",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                steps.drop_mac_admin,
            ),
            trigger=partial(
                triggers.write_node,
                ipe.node.UPDATE,
                CAPABILITY_POLICY_V1,
                CAPABILITY_POLICY_V2.signed.read_bytes(),
            ),
            expect=errno.EPERM,
            check=partial(checks.policy_version_is, CAPABILITY_POLICY_V1, CAPABILITY_POLICY_V1_VERSION),
        ),
        Case(
            id="cap_update_withcap_ok",
            setup=(partial(steps.deploy_policy, CAPABILITY_POLICY_V1),),
            trigger=partial(
                triggers.write_node,
                ipe.node.UPDATE,
                CAPABILITY_POLICY_V1,
                CAPABILITY_POLICY_V2.signed.read_bytes(),
            ),
            expect=0,
            check=partial(checks.policy_version_is, CAPABILITY_POLICY_V1, CAPABILITY_POLICY_V2_VERSION),
        ),
        Case(
            id="cap_active_nocap_eperm",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                steps.drop_mac_admin,
            ),
            trigger=partial(
                triggers.write_node,
                ipe.node.ACTIVE,
                CAPABILITY_POLICY_V1,
                b"1",
            ),
            expect=errno.EPERM,
            check=partial(checks.policy_active_is, CAPABILITY_POLICY_V1, False),
        ),
        Case(
            id="cap_active_withcap_ok",
            setup=(partial(steps.deploy_policy, CAPABILITY_POLICY_V1),),
            trigger=partial(
                triggers.write_node,
                ipe.node.ACTIVE,
                CAPABILITY_POLICY_V1,
                b"1",
            ),
            expect=0,
            check=partial(checks.policy_active_is, CAPABILITY_POLICY_V1, True),
        ),
        Case(
            id="cap_audit_nocap_eperm",
            setup=(steps.drop_mac_admin,),
            trigger=partial(triggers.write_node, ipe.node.SUCCESS_AUDIT, None, b"1"),
            expect=errno.EPERM,
            check=partial(checks.node_value_is, ipe.node.SUCCESS_AUDIT, "0"),
        ),
        Case(
            id="cap_audit_withcap_ok",
            trigger=partial(triggers.write_node, ipe.node.SUCCESS_AUDIT, None, b"1"),
            expect=0,
            check=partial(checks.node_value_is, ipe.node.SUCCESS_AUDIT, "1"),
        ),
        Case(
            id="cap_delete_nocap_eperm",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                steps.drop_mac_admin,
            ),
            trigger=partial(
                triggers.write_node,
                ipe.node.DELETE,
                CAPABILITY_POLICY_V1,
                b"1",
            ),
            expect=errno.EPERM,
            check=partial(checks.policy_present_is, CAPABILITY_POLICY_V1, True),
        ),
        Case(
            id="cap_delete_withcap_ok",
            setup=(partial(steps.deploy_policy, CAPABILITY_POLICY_V1),),
            trigger=partial(
                triggers.write_node,
                ipe.node.DELETE,
                CAPABILITY_POLICY_V1,
                b"1",
            ),
            expect=0,
            check=partial(checks.policy_present_is, CAPABILITY_POLICY_V1, False),
        ),
        Case(
            id="cap_enforce_nocap_eperm",
            collect=(partial(steps.read_node, ipe.node.ENFORCE, None, read_values),),
            setup=(steps.drop_mac_admin,),
            trigger=partial(
                triggers.write_node_and_read, ipe.node.ENFORCE, None, b"1", read_values
            ),
            expect=errno.EPERM,
            check=checks.two_values_match,
        ),
        Case(
            id="cap_enforce_withcap_ok",
            trigger=partial(triggers.write_node, ipe.node.ENFORCE, None, b"1"),
            expect=0,
            check=partial(checks.node_value_is, ipe.node.ENFORCE, "1"),
        ),
        Case(
            id="cap_newpol_nocap_eperm",
            setup=(steps.drop_mac_admin,),
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                CAPABILITY_POLICY_V1.signed.read_bytes(),
            ),
            expect=errno.EPERM,
            check=partial(checks.policy_present_is, CAPABILITY_POLICY_V1, False),
        ),
        Case(
            id="cap_newpol_withcap_ok",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                CAPABILITY_POLICY_V1.signed.read_bytes(),
            ),
            expect=0,
            check=partial(checks.policy_present_is, CAPABILITY_POLICY_V1, True),
        ),
        Case(
            id="cap_update_fcred_withcap_ok",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                partial(
                    steps.open_node,
                    ipe.node.UPDATE,
                    CAPABILITY_POLICY_V1,
                    opened_file,
                ),
                steps.drop_mac_admin,
            ),
            trigger=partial(
                triggers.write_opened_file,
                CAPABILITY_POLICY_V2.signed.read_bytes(),
                opened_file,
            ),
            expect=0,
            check=partial(
                checks.policy_version_is,
                CAPABILITY_POLICY_V1,
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
                    ipe.node.UPDATE,
                    CAPABILITY_POLICY_V1,
                    opened_file,
                ),
                steps.raise_mac_admin,
            ),
            trigger=partial(
                triggers.write_opened_file,
                CAPABILITY_POLICY_V2.signed.read_bytes(),
                opened_file,
            ),
            expect=errno.EPERM,
            check=partial(
                checks.policy_version_is,
                CAPABILITY_POLICY_V1,
                CAPABILITY_POLICY_V1_VERSION,
            ),
        ),
        Case(
            id="cap_active_fcred_withcap_ok",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                partial(
                    steps.open_node,
                    ipe.node.ACTIVE,
                    CAPABILITY_POLICY_V1,
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
            check=partial(checks.policy_active_is, CAPABILITY_POLICY_V1, True),
        ),
        Case(
            id="cap_active_fcred_nocap_eperm",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                steps.clear_mac_admin,
                partial(
                    steps.open_node,
                    ipe.node.ACTIVE,
                    CAPABILITY_POLICY_V1,
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
            check=partial(checks.policy_active_is, CAPABILITY_POLICY_V1, False),
        ),
        Case(
            id="cap_audit_fcred_withcap_ok",
            setup=(
                partial(
                    steps.open_node,
                    ipe.node.SUCCESS_AUDIT,
                    None,
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
            check=partial(checks.node_value_is, ipe.node.SUCCESS_AUDIT, "1"),
        ),
        Case(
            id="cap_audit_fcred_nocap_eperm",
            setup=(
                steps.clear_mac_admin,
                partial(
                    steps.open_node,
                    ipe.node.SUCCESS_AUDIT,
                    None,
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
            check=partial(checks.node_value_is, ipe.node.SUCCESS_AUDIT, "0"),
        ),
        Case(
            id="cap_delete_fcred_withcap_ok",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                partial(
                    steps.open_node,
                    ipe.node.DELETE,
                    CAPABILITY_POLICY_V1,
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
            check=partial(checks.policy_present_is, CAPABILITY_POLICY_V1, False),
        ),
        Case(
            id="cap_delete_fcred_nocap_eperm",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                steps.clear_mac_admin,
                partial(
                    steps.open_node,
                    ipe.node.DELETE,
                    CAPABILITY_POLICY_V1,
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
            check=partial(checks.policy_present_is, CAPABILITY_POLICY_V1, True),
        ),
        Case(
            id="cap_enforce_fcred_withcap_ok",
            setup=(
                partial(
                    steps.open_node,
                    ipe.node.ENFORCE,
                    None,
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
            check=partial(checks.node_value_is, ipe.node.ENFORCE, "1"),
        ),
        Case(
            id="cap_enforce_fcred_nocap_eperm",
            collect=(partial(steps.read_node, ipe.node.ENFORCE, None, read_values),),
            setup=(
                steps.clear_mac_admin,
                partial(
                    steps.open_node,
                    ipe.node.ENFORCE,
                    None,
                    opened_file,
                ),
                steps.raise_mac_admin,
            ),
            trigger=partial(
                triggers.write_opened_file_and_read,
                ipe.node.ENFORCE,
                None,
                b"1",
                opened_file,
                read_values,
            ),
            expect=errno.EPERM,
            check=checks.two_values_match,
        ),
        Case(
            id="cap_newpol_fcred_withcap_ok",
            setup=(
                partial(
                    steps.open_node,
                    ipe.node.NEW_POLICY,
                    None,
                    opened_file,
                ),
                steps.drop_mac_admin,
            ),
            trigger=partial(
                triggers.write_opened_file,
                CAPABILITY_POLICY_V1.signed.read_bytes(),
                opened_file,
            ),
            expect=0,
            check=partial(checks.policy_present_is, CAPABILITY_POLICY_V1, True),
        ),
        Case(
            id="cap_newpol_fcred_nocap_eperm",
            setup=(
                steps.clear_mac_admin,
                partial(
                    steps.open_node,
                    ipe.node.NEW_POLICY,
                    None,
                    opened_file,
                ),
                steps.raise_mac_admin,
            ),
            trigger=partial(
                triggers.write_opened_file,
                CAPABILITY_POLICY_V1.signed.read_bytes(),
                opened_file,
            ),
            expect=errno.EPERM,
            check=partial(checks.policy_present_is, CAPABILITY_POLICY_V1, False),
        ),
        Case(
            id="userns_update_eperm",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                steps.unshare_user_namespace,
            ),
            trigger=partial(
                triggers.write_node,
                ipe.node.UPDATE,
                CAPABILITY_POLICY_V1,
                CAPABILITY_POLICY_V2.signed.read_bytes(),
            ),
            expect=errno.EPERM,
            check=partial(
                checks.policy_version_is,
                CAPABILITY_POLICY_V1,
                CAPABILITY_POLICY_V1_VERSION,
            ),
        ),
        Case(
            id="userns_active_eperm",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                steps.unshare_user_namespace,
            ),
            trigger=partial(
                triggers.write_node,
                ipe.node.ACTIVE,
                CAPABILITY_POLICY_V1,
                b"1",
            ),
            expect=errno.EPERM,
            check=partial(checks.policy_active_is, CAPABILITY_POLICY_V1, False),
        ),
        Case(
            id="userns_audit_eperm",
            setup=(
                steps.unshare_user_namespace,
            ),
            trigger=partial(
                triggers.write_node,
                ipe.node.SUCCESS_AUDIT,
                None,
                b"1",
            ),
            expect=errno.EPERM,
            check=partial(checks.node_value_is, ipe.node.SUCCESS_AUDIT, "0"),
        ),
        Case(
            id="userns_delete_eperm",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                steps.unshare_user_namespace,
            ),
            trigger=partial(
                triggers.write_node,
                ipe.node.DELETE,
                CAPABILITY_POLICY_V1,
                b"1",
            ),
            expect=errno.EPERM,
            check=partial(checks.policy_present_is, CAPABILITY_POLICY_V1, True),
        ),
        Case(
            id="userns_enforce_eperm",
            collect=(partial(steps.read_node, ipe.node.ENFORCE, None, read_values),),
            setup=(
                steps.unshare_user_namespace,
            ),
            trigger=partial(
                triggers.write_node_and_read,
                ipe.node.ENFORCE,
                None,
                b"1",
                read_values,
            ),
            expect=errno.EPERM,
            check=checks.two_values_match,
        ),
        Case(
            id="userns_newpol_eperm",
            setup=(
                steps.unshare_user_namespace,
            ),
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                CAPABILITY_POLICY_V1.signed.read_bytes(),
            ),
            expect=errno.EPERM,
            check=partial(checks.policy_present_is, CAPABILITY_POLICY_V1, False),
        ),
        Case(
            id="read_enforce_nocap_ok",
            setup=(
                partial(steps.read_node, ipe.node.ENFORCE, None, read_values),
                steps.drop_mac_admin,
            ),
            trigger=partial(triggers.read_node, ipe.node.ENFORCE, None, read_values),
            expect=0,
            check=checks.two_values_match,
        ),
        Case(
            id="read_audit_nocap_ok",
            setup=(
                partial(steps.read_node, ipe.node.SUCCESS_AUDIT, None, read_values),
                steps.drop_mac_admin,
            ),
            trigger=partial(triggers.read_node, ipe.node.SUCCESS_AUDIT, None, read_values),
            expect=0,
            check=checks.two_values_match,
        ),
        Case(
            id="read_active_nocap_ok",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                partial(steps.read_node, ipe.node.ACTIVE, CAPABILITY_POLICY_V1, read_values),
                steps.drop_mac_admin,
            ),
            trigger=partial(triggers.read_node, ipe.node.ACTIVE, CAPABILITY_POLICY_V1, read_values),
            expect=0,
            check=checks.two_values_match,
        ),
        Case(
            id="read_name_nocap_ok",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                partial(steps.read_node, "name", CAPABILITY_POLICY_V1, read_values),
                steps.drop_mac_admin,
            ),
            trigger=partial(triggers.read_node, "name", CAPABILITY_POLICY_V1, read_values),
            expect=0,
            check=checks.two_values_match,
        ),
        Case(
            id="read_policy_nocap_ok",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                partial(steps.read_node, ipe.node.POLICY, CAPABILITY_POLICY_V1, read_values),
                steps.drop_mac_admin,
            ),
            trigger=partial(triggers.read_node, ipe.node.POLICY, CAPABILITY_POLICY_V1, read_values),
            expect=0,
            check=checks.two_values_match,
        ),
        Case(
            id="read_version_nocap_ok",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                partial(steps.read_node, ipe.node.VERSION, CAPABILITY_POLICY_V1, read_values),
                steps.drop_mac_admin,
            ),
            trigger=partial(triggers.read_node, ipe.node.VERSION, CAPABILITY_POLICY_V1, read_values),
            expect=0,
            check=checks.two_values_match,
        ),
        Case(
            id="read_pkcs7_nocap_ok",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                partial(
                    steps.read_binary_node,
                    "pkcs7",
                    CAPABILITY_POLICY_V1,
                    read_values,
                ),
                steps.drop_mac_admin,
            ),
            trigger=partial(
                triggers.read_binary_node,
                "pkcs7",
                CAPABILITY_POLICY_V1,
                read_values,
            ),
            expect=0,
            check=checks.two_values_match,
        ),
        Case(
            id="badvalue_enforce_einval",
            setup=(partial(steps.read_node, ipe.node.ENFORCE, None, read_values),),
            trigger=partial(
                triggers.write_node_and_read,
                ipe.node.ENFORCE,
                None,
                b"maybe",
                read_values,
            ),
            expect=errno.EINVAL,
            check=checks.two_values_match,
        ),
        Case(
            id="badvalue_audit_einval",
            setup=(partial(steps.read_node, ipe.node.SUCCESS_AUDIT, None, read_values),),
            trigger=partial(
                triggers.write_node_and_read,
                ipe.node.SUCCESS_AUDIT,
                None,
                b"maybe",
                read_values,
            ),
            expect=errno.EINVAL,
            check=checks.two_values_match,
        ),
        Case(
            id="badvalue_active_einval",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                partial(steps.read_node, ipe.node.ACTIVE, CAPABILITY_POLICY_V1, read_values),
            ),
            trigger=partial(
                triggers.write_node_and_read,
                ipe.node.ACTIVE,
                CAPABILITY_POLICY_V1,
                b"maybe",
                read_values,
            ),
            expect=errno.EINVAL,
            check=checks.two_values_match,
        ),
        Case(
            id="badvalue_delete_einval",
            setup=(partial(steps.deploy_policy, CAPABILITY_POLICY_V1),),
            trigger=partial(
                triggers.write_node,
                ipe.node.DELETE,
                CAPABILITY_POLICY_V1,
                b"maybe",
            ),
            expect=errno.EINVAL,
            check=partial(checks.policy_present_is, CAPABILITY_POLICY_V1, True),
        ),
        Case(
            id="newpol_truncated_ebadmsg",
            trigger=partial(triggers.write_node, ipe.node.NEW_POLICY, None, truncated_policy),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, CAPABILITY_POLICY_V1, False),
        ),
        Case(
            id="newpol_trailing_fragment_ebadmsg",
            trigger=partial(triggers.write_node, ipe.node.NEW_POLICY, None, trailing_fragment),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, CAPABILITY_POLICY_V1, False),
        ),
        Case(
            id="newpol_duplicate_eexist",
            setup=(partial(steps.deploy_policy, CAPABILITY_POLICY_V1),),
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                CAPABILITY_POLICY_V1.signed.read_bytes(),
            ),
            expect=errno.EEXIST,
            check=partial(checks.policy_present_is, CAPABILITY_POLICY_V1, True),
        ),
        Case(
            id="toggle_audit_ok",
            setup=(partial(steps.read_node, ipe.node.SUCCESS_AUDIT, None, read_values),),
            trigger=partial(triggers.toggle_node, ipe.node.SUCCESS_AUDIT, None, read_values),
            expect=0,
            check=checks.two_values_differ,
        ),
        Case(
            id="toggle_enforce_ok",
            setup=(partial(steps.read_node, ipe.node.ENFORCE, None, read_values),),
            trigger=partial(triggers.toggle_node, ipe.node.ENFORCE, None, read_values),
            expect=0,
            check=checks.two_values_differ,
        ),
        ),
    ),)
