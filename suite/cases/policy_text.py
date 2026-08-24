# SPDX-License-Identifier: GPL-2.0-only

import errno
from functools import partial

import checks
import ipe
import triggers
from assets import TEXT_POLICY_NAME
from model import Case


def build():
    return (
        Case(
            id="text_header_missing_version_ebadmsg",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/header_missing_version"),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, TEXT_POLICY_NAME, False),
        ),
        Case(
            id="text_header_missing_name_ebadmsg",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/header_missing_name"),
            ),
            expect=errno.EBADMSG,
            check=None,
        ),
        Case(
            id="text_header_swapped_ebadmsg",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/header_swapped"),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, TEXT_POLICY_NAME, False),
        ),
        Case(
            id="text_header_extra_field_ebadmsg",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/header_extra_field"),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, TEXT_POLICY_NAME, False),
        ),
        Case(
            id="text_header_unknown_key_ebadmsg",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/header_unknown_key"),
            ),
            expect=errno.EBADMSG,
            check=None,
        ),
        Case(
            id="text_header_absent_ebadmsg",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/header_absent"),
            ),
            expect=errno.EBADMSG,
            check=None,
        ),
        Case(
            id="text_version_one_part_ebadmsg",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/version_one_part"),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, TEXT_POLICY_NAME, False),
        ),
        Case(
            id="text_version_two_parts_ebadmsg",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/version_two_parts"),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, TEXT_POLICY_NAME, False),
        ),
        Case(
            id="text_version_four_parts_ebadmsg",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/version_four_parts"),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, TEXT_POLICY_NAME, False),
        ),
        Case(
            id="text_version_empty_part_einval",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/version_empty_part"),
            ),
            expect=errno.EINVAL,
            check=partial(checks.policy_present_is, TEXT_POLICY_NAME, False),
        ),
        Case(
            id="text_version_non_numeric_einval",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/version_non_numeric"),
            ),
            expect=errno.EINVAL,
            check=partial(checks.policy_present_is, TEXT_POLICY_NAME, False),
        ),
        Case(
            id="text_version_overflow_erange",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/version_overflow"),
            ),
            expect=errno.ERANGE,
            check=partial(checks.policy_present_is, TEXT_POLICY_NAME, False),
        ),
        Case(
            id="text_rule_unknown_op_ebadmsg",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/rule_unknown_op"),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, TEXT_POLICY_NAME, False),
        ),
        Case(
            id="text_rule_unknown_property_ebadmsg",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/rule_unknown_property"),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, TEXT_POLICY_NAME, False),
        ),
        Case(
            id="text_rule_unknown_action_ebadmsg",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/rule_unknown_action"),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, TEXT_POLICY_NAME, False),
        ),
        Case(
            id="text_rule_missing_action_ebadmsg",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/rule_missing_action"),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, TEXT_POLICY_NAME, False),
        ),
        Case(
            id="text_rule_default_with_property_ebadmsg",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/rule_default_with_property"),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, TEXT_POLICY_NAME, False),
        ),
        Case(
            id="text_rule_duplicate_global_default_ebadmsg",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/rule_duplicate_global_default"),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, TEXT_POLICY_NAME, False),
        ),
        Case(
            id="text_rule_duplicate_op_default_ebadmsg",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy("policy_text/rule_duplicate_op_default"),
            ),
            expect=errno.EBADMSG,
            check=partial(checks.policy_present_is, TEXT_POLICY_NAME, False),
        ),
    )
