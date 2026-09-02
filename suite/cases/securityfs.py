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


def build() -> tuple[Batch, ...]:
    """The batches this group contributes."""
    truncated_policy = CAPABILITY_POLICY_V1.signed.read_bytes()
    truncated_policy = truncated_policy[: len(truncated_policy) // 2]
    trailing_fragment = CAPABILITY_POLICY_V1.signed.read_bytes()
    trailing_fragment = trailing_fragment[len(trailing_fragment) // 2 :]

    return (
        Batch(
            id="securityfs",
            cases=(
                Case(
                    id="cap_update_nocap_eperm",
                    setup=(
                        partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),
                        steps.drop_mac_admin,
                    ),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.UPDATE,
                        policy=CAPABILITY_POLICY_V1,
                        data=CAPABILITY_POLICY_V2.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        partial(
                            checks.policy_version_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=CAPABILITY_POLICY_V1_VERSION,
                        ),
                    ),
                ),
                Case(
                    id="cap_update_withcap_ok",
                    setup=(partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.UPDATE,
                        policy=CAPABILITY_POLICY_V1,
                        data=CAPABILITY_POLICY_V2.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(
                            checks.policy_version_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=CAPABILITY_POLICY_V2_VERSION,
                        ),
                    ),
                ),
                Case(
                    id="cap_active_nocap_eperm",
                    setup=(
                        partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),
                        steps.drop_mac_admin,
                    ),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.ACTIVE,
                        policy=CAPABILITY_POLICY_V1,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        partial(
                            checks.policy_active_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=False,
                        ),
                    ),
                ),
                Case(
                    id="cap_active_withcap_ok",
                    setup=(partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.ACTIVE,
                        policy=CAPABILITY_POLICY_V1,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(
                            checks.policy_active_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=True,
                        ),
                    ),
                ),
                Case(
                    id="cap_audit_nocap_eperm",
                    setup=(steps.drop_mac_admin,),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.SUCCESS_AUDIT,
                        policy=None,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        partial(
                            checks.node_value_is,
                            entry=ipe.node.SUCCESS_AUDIT,
                            expected="0",
                        ),
                    ),
                ),
                Case(
                    id="cap_audit_withcap_ok",
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.SUCCESS_AUDIT,
                        policy=None,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(
                            checks.node_value_is,
                            entry=ipe.node.SUCCESS_AUDIT,
                            expected="1",
                        ),
                    ),
                ),
                Case(
                    id="cap_delete_nocap_eperm",
                    setup=(
                        partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),
                        steps.drop_mac_admin,
                    ),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.DELETE,
                        policy=CAPABILITY_POLICY_V1,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        partial(
                            checks.policy_present_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=True,
                        ),
                    ),
                ),
                Case(
                    id="cap_delete_withcap_ok",
                    setup=(partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.DELETE,
                        policy=CAPABILITY_POLICY_V1,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(
                            checks.policy_present_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=False,
                        ),
                    ),
                ),
                Case(
                    id="cap_enforce_nocap_eperm",
                    collect=(
                        partial(steps.read_node, entry=ipe.node.ENFORCE, policy=None),
                    ),
                    setup=(steps.drop_mac_admin,),
                    trigger=partial(
                        triggers.write_node_and_read,
                        entry=ipe.node.ENFORCE,
                        policy=None,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        checks.two_values_match,
                    ),
                ),
                Case(
                    id="cap_enforce_withcap_ok",
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.ENFORCE,
                        policy=None,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(
                            checks.node_value_is, entry=ipe.node.ENFORCE, expected="1"
                        ),
                    ),
                ),
                Case(
                    id="cap_newpol_nocap_eperm",
                    setup=(steps.drop_mac_admin,),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.NEW_POLICY,
                        policy=None,
                        data=CAPABILITY_POLICY_V1.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        partial(
                            checks.policy_present_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=False,
                        ),
                    ),
                ),
                Case(
                    id="cap_newpol_withcap_ok",
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.NEW_POLICY,
                        policy=None,
                        data=CAPABILITY_POLICY_V1.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(
                            checks.policy_present_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=True,
                        ),
                    ),
                ),
                Case(
                    id="cap_update_fcred_withcap_ok",
                    setup=(
                        partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),
                        partial(
                            steps.open_node,
                            entry=ipe.node.UPDATE,
                            policy=CAPABILITY_POLICY_V1,
                        ),
                        steps.drop_mac_admin,
                    ),
                    trigger=partial(
                        triggers.write_opened_file,
                        data=CAPABILITY_POLICY_V2.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(
                            checks.policy_version_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=CAPABILITY_POLICY_V2_VERSION,
                        ),
                    ),
                ),
                Case(
                    id="cap_update_fcred_nocap_eperm",
                    setup=(
                        partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),
                        steps.clear_mac_admin,
                        partial(
                            steps.open_node,
                            entry=ipe.node.UPDATE,
                            policy=CAPABILITY_POLICY_V1,
                        ),
                        steps.raise_mac_admin,
                    ),
                    trigger=partial(
                        triggers.write_opened_file,
                        data=CAPABILITY_POLICY_V2.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        partial(
                            checks.policy_version_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=CAPABILITY_POLICY_V1_VERSION,
                        ),
                    ),
                ),
                Case(
                    id="cap_active_fcred_withcap_ok",
                    setup=(
                        partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),
                        partial(
                            steps.open_node,
                            entry=ipe.node.ACTIVE,
                            policy=CAPABILITY_POLICY_V1,
                        ),
                        steps.drop_mac_admin,
                    ),
                    trigger=partial(
                        triggers.write_opened_file,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(
                            checks.policy_active_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=True,
                        ),
                    ),
                ),
                Case(
                    id="cap_active_fcred_nocap_eperm",
                    setup=(
                        partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),
                        steps.clear_mac_admin,
                        partial(
                            steps.open_node,
                            entry=ipe.node.ACTIVE,
                            policy=CAPABILITY_POLICY_V1,
                        ),
                        steps.raise_mac_admin,
                    ),
                    trigger=partial(
                        triggers.write_opened_file,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        partial(
                            checks.policy_active_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=False,
                        ),
                    ),
                ),
                Case(
                    id="cap_audit_fcred_withcap_ok",
                    setup=(
                        partial(
                            steps.open_node,
                            entry=ipe.node.SUCCESS_AUDIT,
                            policy=None,
                        ),
                        steps.drop_mac_admin,
                    ),
                    trigger=partial(
                        triggers.write_opened_file,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(
                            checks.node_value_is,
                            entry=ipe.node.SUCCESS_AUDIT,
                            expected="1",
                        ),
                    ),
                ),
                Case(
                    id="cap_audit_fcred_nocap_eperm",
                    setup=(
                        steps.clear_mac_admin,
                        partial(
                            steps.open_node,
                            entry=ipe.node.SUCCESS_AUDIT,
                            policy=None,
                        ),
                        steps.raise_mac_admin,
                    ),
                    trigger=partial(
                        triggers.write_opened_file,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        partial(
                            checks.node_value_is,
                            entry=ipe.node.SUCCESS_AUDIT,
                            expected="0",
                        ),
                    ),
                ),
                Case(
                    id="cap_delete_fcred_withcap_ok",
                    setup=(
                        partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),
                        partial(
                            steps.open_node,
                            entry=ipe.node.DELETE,
                            policy=CAPABILITY_POLICY_V1,
                        ),
                        steps.drop_mac_admin,
                    ),
                    trigger=partial(
                        triggers.write_opened_file,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(
                            checks.policy_present_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=False,
                        ),
                    ),
                ),
                Case(
                    id="cap_delete_fcred_nocap_eperm",
                    setup=(
                        partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),
                        steps.clear_mac_admin,
                        partial(
                            steps.open_node,
                            entry=ipe.node.DELETE,
                            policy=CAPABILITY_POLICY_V1,
                        ),
                        steps.raise_mac_admin,
                    ),
                    trigger=partial(
                        triggers.write_opened_file,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        partial(
                            checks.policy_present_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=True,
                        ),
                    ),
                ),
                Case(
                    id="cap_enforce_fcred_withcap_ok",
                    setup=(
                        partial(
                            steps.open_node,
                            entry=ipe.node.ENFORCE,
                            policy=None,
                        ),
                        steps.drop_mac_admin,
                    ),
                    trigger=partial(
                        triggers.write_opened_file,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(
                            checks.node_value_is, entry=ipe.node.ENFORCE, expected="1"
                        ),
                    ),
                ),
                Case(
                    id="cap_enforce_fcred_nocap_eperm",
                    collect=(
                        partial(steps.read_node, entry=ipe.node.ENFORCE, policy=None),
                    ),
                    setup=(
                        steps.clear_mac_admin,
                        partial(
                            steps.open_node,
                            entry=ipe.node.ENFORCE,
                            policy=None,
                        ),
                        steps.raise_mac_admin,
                    ),
                    trigger=partial(
                        triggers.write_opened_file_and_read,
                        entry=ipe.node.ENFORCE,
                        policy=None,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        checks.two_values_match,
                    ),
                ),
                Case(
                    id="cap_newpol_fcred_withcap_ok",
                    setup=(
                        partial(
                            steps.open_node,
                            entry=ipe.node.NEW_POLICY,
                            policy=None,
                        ),
                        steps.drop_mac_admin,
                    ),
                    trigger=partial(
                        triggers.write_opened_file,
                        data=CAPABILITY_POLICY_V1.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(
                            checks.policy_present_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=True,
                        ),
                    ),
                ),
                Case(
                    id="cap_newpol_fcred_nocap_eperm",
                    setup=(
                        steps.clear_mac_admin,
                        partial(
                            steps.open_node,
                            entry=ipe.node.NEW_POLICY,
                            policy=None,
                        ),
                        steps.raise_mac_admin,
                    ),
                    trigger=partial(
                        triggers.write_opened_file,
                        data=CAPABILITY_POLICY_V1.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        partial(
                            checks.policy_present_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=False,
                        ),
                    ),
                ),
                Case(
                    id="userns_update_eperm",
                    setup=(
                        partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),
                        steps.unshare_user_namespace,
                    ),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.UPDATE,
                        policy=CAPABILITY_POLICY_V1,
                        data=CAPABILITY_POLICY_V2.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        partial(
                            checks.policy_version_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=CAPABILITY_POLICY_V1_VERSION,
                        ),
                    ),
                ),
                Case(
                    id="userns_active_eperm",
                    setup=(
                        partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),
                        steps.unshare_user_namespace,
                    ),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.ACTIVE,
                        policy=CAPABILITY_POLICY_V1,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        partial(
                            checks.policy_active_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=False,
                        ),
                    ),
                ),
                Case(
                    id="userns_audit_eperm",
                    setup=(steps.unshare_user_namespace,),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.SUCCESS_AUDIT,
                        policy=None,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        partial(
                            checks.node_value_is,
                            entry=ipe.node.SUCCESS_AUDIT,
                            expected="0",
                        ),
                    ),
                ),
                Case(
                    id="userns_delete_eperm",
                    setup=(
                        partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),
                        steps.unshare_user_namespace,
                    ),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.DELETE,
                        policy=CAPABILITY_POLICY_V1,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        partial(
                            checks.policy_present_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=True,
                        ),
                    ),
                ),
                Case(
                    id="userns_enforce_eperm",
                    collect=(
                        partial(steps.read_node, entry=ipe.node.ENFORCE, policy=None),
                    ),
                    setup=(steps.unshare_user_namespace,),
                    trigger=partial(
                        triggers.write_node_and_read,
                        entry=ipe.node.ENFORCE,
                        policy=None,
                        data=b"1",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        checks.two_values_match,
                    ),
                ),
                Case(
                    id="userns_newpol_eperm",
                    setup=(steps.unshare_user_namespace,),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.NEW_POLICY,
                        policy=None,
                        data=CAPABILITY_POLICY_V1.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EPERM),
                        partial(
                            checks.policy_present_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=False,
                        ),
                    ),
                ),
                Case(
                    id="read_enforce_nocap_ok",
                    setup=(
                        partial(steps.read_node, entry=ipe.node.ENFORCE, policy=None),
                        steps.drop_mac_admin,
                    ),
                    trigger=partial(
                        triggers.read_node, entry=ipe.node.ENFORCE, policy=None
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        checks.two_values_match,
                    ),
                ),
                Case(
                    id="read_audit_nocap_ok",
                    setup=(
                        partial(
                            steps.read_node, entry=ipe.node.SUCCESS_AUDIT, policy=None
                        ),
                        steps.drop_mac_admin,
                    ),
                    trigger=partial(
                        triggers.read_node, entry=ipe.node.SUCCESS_AUDIT, policy=None
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        checks.two_values_match,
                    ),
                ),
                Case(
                    id="read_active_nocap_ok",
                    setup=(
                        partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),
                        partial(
                            steps.read_node,
                            entry=ipe.node.ACTIVE,
                            policy=CAPABILITY_POLICY_V1,
                        ),
                        steps.drop_mac_admin,
                    ),
                    trigger=partial(
                        triggers.read_node,
                        entry=ipe.node.ACTIVE,
                        policy=CAPABILITY_POLICY_V1,
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        checks.two_values_match,
                    ),
                ),
                Case(
                    id="read_name_nocap_ok",
                    setup=(
                        partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),
                        partial(
                            steps.read_node, entry="name", policy=CAPABILITY_POLICY_V1
                        ),
                        steps.drop_mac_admin,
                    ),
                    trigger=partial(
                        triggers.read_node, entry="name", policy=CAPABILITY_POLICY_V1
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        checks.two_values_match,
                    ),
                ),
                Case(
                    id="read_policy_nocap_ok",
                    setup=(
                        partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),
                        partial(
                            steps.read_node,
                            entry=ipe.node.POLICY,
                            policy=CAPABILITY_POLICY_V1,
                        ),
                        steps.drop_mac_admin,
                    ),
                    trigger=partial(
                        triggers.read_node,
                        entry=ipe.node.POLICY,
                        policy=CAPABILITY_POLICY_V1,
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        checks.two_values_match,
                    ),
                ),
                Case(
                    id="read_version_nocap_ok",
                    setup=(
                        partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),
                        partial(
                            steps.read_node,
                            entry=ipe.node.VERSION,
                            policy=CAPABILITY_POLICY_V1,
                        ),
                        steps.drop_mac_admin,
                    ),
                    trigger=partial(
                        triggers.read_node,
                        entry=ipe.node.VERSION,
                        policy=CAPABILITY_POLICY_V1,
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        checks.two_values_match,
                    ),
                ),
                Case(
                    id="read_pkcs7_nocap_ok",
                    setup=(
                        partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),
                        partial(
                            steps.read_binary_node,
                            entry="pkcs7",
                            policy=CAPABILITY_POLICY_V1,
                        ),
                        steps.drop_mac_admin,
                    ),
                    trigger=partial(
                        triggers.read_binary_node,
                        entry="pkcs7",
                        policy=CAPABILITY_POLICY_V1,
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        checks.two_values_match,
                    ),
                ),
                Case(
                    id="badvalue_enforce_einval",
                    setup=(
                        partial(steps.read_node, entry=ipe.node.ENFORCE, policy=None),
                    ),
                    trigger=partial(
                        triggers.write_node_and_read,
                        entry=ipe.node.ENFORCE,
                        policy=None,
                        data=b"maybe",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EINVAL),
                        checks.two_values_match,
                    ),
                ),
                Case(
                    id="badvalue_audit_einval",
                    setup=(
                        partial(
                            steps.read_node, entry=ipe.node.SUCCESS_AUDIT, policy=None
                        ),
                    ),
                    trigger=partial(
                        triggers.write_node_and_read,
                        entry=ipe.node.SUCCESS_AUDIT,
                        policy=None,
                        data=b"maybe",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EINVAL),
                        checks.two_values_match,
                    ),
                ),
                Case(
                    id="badvalue_active_einval",
                    setup=(
                        partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),
                        partial(
                            steps.read_node,
                            entry=ipe.node.ACTIVE,
                            policy=CAPABILITY_POLICY_V1,
                        ),
                    ),
                    trigger=partial(
                        triggers.write_node_and_read,
                        entry=ipe.node.ACTIVE,
                        policy=CAPABILITY_POLICY_V1,
                        data=b"maybe",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EINVAL),
                        checks.two_values_match,
                    ),
                ),
                Case(
                    id="badvalue_delete_einval",
                    setup=(partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.DELETE,
                        policy=CAPABILITY_POLICY_V1,
                        data=b"maybe",
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EINVAL),
                        partial(
                            checks.policy_present_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=True,
                        ),
                    ),
                ),
                Case(
                    id="newpol_truncated_ebadmsg",
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.NEW_POLICY,
                        policy=None,
                        data=truncated_policy,
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EBADMSG),
                        partial(
                            checks.policy_present_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=False,
                        ),
                    ),
                ),
                Case(
                    id="newpol_trailing_fragment_ebadmsg",
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.NEW_POLICY,
                        policy=None,
                        data=trailing_fragment,
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EBADMSG),
                        partial(
                            checks.policy_present_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=False,
                        ),
                    ),
                ),
                Case(
                    id="newpol_duplicate_eexist",
                    setup=(partial(steps.deploy_policy, policy=CAPABILITY_POLICY_V1),),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.NEW_POLICY,
                        policy=None,
                        data=CAPABILITY_POLICY_V1.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EEXIST),
                        partial(
                            checks.policy_present_is,
                            policy=CAPABILITY_POLICY_V1,
                            expected=True,
                        ),
                    ),
                ),
                Case(
                    id="toggle_audit_ok",
                    setup=(
                        partial(
                            steps.read_node, entry=ipe.node.SUCCESS_AUDIT, policy=None
                        ),
                    ),
                    trigger=partial(
                        triggers.toggle_node, entry=ipe.node.SUCCESS_AUDIT, policy=None
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        checks.two_values_differ,
                    ),
                ),
                Case(
                    id="toggle_enforce_ok",
                    setup=(
                        partial(steps.read_node, entry=ipe.node.ENFORCE, policy=None),
                    ),
                    trigger=partial(
                        triggers.toggle_node, entry=ipe.node.ENFORCE, policy=None
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        checks.two_values_differ,
                    ),
                ),
            ),
        ),
    )
