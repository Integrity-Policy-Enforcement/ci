# SPDX-License-Identifier: GPL-2.0-only

import errno
from functools import partial

import checks
import ipe
import triggers
from assets import UNTRUSTED_POLICY_ASSET, UNTRUSTED_POLICY_NAME
from model import Case


def build():
    return (
        Case(
            id="policy_signature_untrusted_enokey",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy(UNTRUSTED_POLICY_ASSET),
            ),
            expect=errno.ENOKEY,
            check=partial(checks.policy_present_is, UNTRUSTED_POLICY_NAME, False),
        ),
    )
