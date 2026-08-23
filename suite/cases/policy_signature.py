# SPDX-License-Identifier: GPL-2.0-only

import errno
from functools import partial

import checks
import ipe
import triggers
from assets import (
    REVOKED_POLICY_ASSET,
    REVOKED_POLICY_NAME,
    TAMPERED_POLICY_ASSET,
    TAMPERED_POLICY_NAME,
    UNTRUSTED_POLICY_ASSET,
    UNTRUSTED_POLICY_NAME,
)
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
        Case(
            id="policy_signature_revoked_ekeyrejected",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy(REVOKED_POLICY_ASSET),
            ),
            expect=errno.EKEYREJECTED,
            check=partial(checks.policy_present_is, REVOKED_POLICY_NAME, False),
        ),
        Case(
            id="policy_signature_tampered_ekeyrejected",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy(TAMPERED_POLICY_ASSET),
            ),
            expect=errno.EKEYREJECTED,
            check=partial(checks.policy_present_is, TAMPERED_POLICY_NAME, False),
        ),
    )
