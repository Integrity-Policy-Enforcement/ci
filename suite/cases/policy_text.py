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
    )
