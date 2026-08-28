# SPDX-License-Identifier: GPL-2.0-only

import errno
from functools import partial

import checks
import ipe
import triggers
from assets import TEXT_SPECIAL_NAME_POLICY, text_policy
from model import Batch, Case


def build():
    return (Batch(
        "policy_text",
        (
        Case(
            id="text_header_missing_version_ebadmsg",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("header_missing_version").signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, text_policy("header_missing_version"), False),
        ),
        Case(
            id="text_header_missing_name_ebadmsg",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("header_missing_name").signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=None,
        ),
        Case(
            id="text_header_swapped_ebadmsg",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("header_swapped").signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, text_policy("header_swapped"), False),
        ),
        Case(
            id="text_header_extra_field_ebadmsg",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("header_extra_field").signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, text_policy("header_extra_field"), False),
        ),
        Case(
            id="text_header_unknown_key_ebadmsg",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("header_unknown_key").signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=None,
        ),
        Case(
            id="text_header_absent_ebadmsg",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("header_absent").signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=None,
        ),
        Case(
            id="text_version_one_part_ebadmsg",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("version_one_part").signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, text_policy("version_one_part"), False),
        ),
        Case(
            id="text_version_two_parts_ebadmsg",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("version_two_parts").signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, text_policy("version_two_parts"), False),
        ),
        Case(
            id="text_version_four_parts_ebadmsg",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("version_four_parts").signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, text_policy("version_four_parts"), False),
        ),
        Case(
            id="text_version_empty_part_einval",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("version_empty_part").signed.read_bytes(),
            ),
            expect=errno.EINVAL,
            check=partial(checks.policy_present_is, text_policy("version_empty_part"), False),
        ),
        Case(
            id="text_version_non_numeric_einval",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("version_non_numeric").signed.read_bytes(),
            ),
            expect=errno.EINVAL,
            check=partial(checks.policy_present_is, text_policy("version_non_numeric"), False),
        ),
        Case(
            id="text_version_overflow_erange",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("version_overflow").signed.read_bytes(),
            ),
            expect=errno.ERANGE,
            check=partial(checks.policy_present_is, text_policy("version_overflow"), False),
        ),
        Case(
            id="text_rule_unknown_op_ebadmsg",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("rule_unknown_op").signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, text_policy("rule_unknown_op"), False),
        ),
        Case(
            id="text_rule_unknown_property_ebadmsg",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("rule_unknown_property").signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, text_policy("rule_unknown_property"), False),
        ),
        Case(
            id="text_rule_unknown_action_ebadmsg",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("rule_unknown_action").signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, text_policy("rule_unknown_action"), False),
        ),
        Case(
            id="text_rule_missing_action_ebadmsg",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("rule_missing_action").signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, text_policy("rule_missing_action"), False),
        ),
        Case(
            id="text_rule_default_with_property_ebadmsg",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("rule_default_with_property").signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, text_policy("rule_default_with_property"), False),
        ),
        Case(
            id="text_rule_duplicate_global_default_ebadmsg",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("rule_duplicate_global_default").signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, text_policy("rule_duplicate_global_default"), False),
        ),
        Case(
            id="text_rule_duplicate_op_default_ebadmsg",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("rule_duplicate_op_default").signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, text_policy("rule_duplicate_op_default"), False),
        ),
        Case(
            id="text_missing_op_default_ebadmsg",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("missing_op_default").signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, text_policy("missing_op_default"), False),
        ),
        Case(
            id="text_empty_ebadmsg",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("empty").signed.read_bytes(),
            ),
            expect=errno.EBADMSG,
            check=None,
        ),
        Case(
            id="text_comment_ok",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("comment_ok").signed.read_bytes(),
            ),
            expect=0,
            check=partial(checks.policy_present_is, text_policy("comment_ok"), True),
        ),
        Case(
            id="text_extra_spaces_ok",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("extra_spaces_ok").signed.read_bytes(),
            ),
            expect=0,
            check=partial(checks.policy_present_is, text_policy("extra_spaces_ok"), True),
        ),
        Case(
            id="text_blank_lines_ok",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("blank_lines_ok").signed.read_bytes(),
            ),
            expect=0,
            check=partial(checks.policy_present_is, text_policy("blank_lines_ok"), True),
        ),
        Case(
            id="text_op_default_ok",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("op_default_ok").signed.read_bytes(),
            ),
            expect=0,
            check=partial(checks.policy_present_is, text_policy("op_default_ok"), True),
        ),
        Case(
            id="text_multiple_rules_ok",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("multiple_rules_ok").signed.read_bytes(),
            ),
            expect=0,
            check=partial(checks.policy_present_is, text_policy("multiple_rules_ok"), True),
        ),
        Case(
            id="text_special_name_ok",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("special_name_ok").signed.read_bytes(),
            ),
            expect=0,
            check=partial(checks.policy_present_is, TEXT_SPECIAL_NAME_POLICY, True),
        ),
        Case(
            id="text_property_digest_ok",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("property_digest_ok").signed.read_bytes(),
            ),
            expect=0,
            check=partial(checks.policy_present_is, text_policy("property_digest_ok"), True),
        ),
        Case(
            id="text_property_boolean_ok",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                text_policy("property_boolean_ok").signed.read_bytes(),
            ),
            expect=0,
            check=partial(checks.policy_present_is, text_policy("property_boolean_ok"), True),
        ),
        ),
    ),)
