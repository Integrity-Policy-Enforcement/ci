# SPDX-License-Identifier: GPL-2.0-only

import errno
from functools import partial

import checks
import ipe
import steps
import triggers
from assets import (
    PLATFORM_POLICY_ASSET,
    PLATFORM_POLICY_NAME,
    SECONDARY_KEYRING,
    SECONDARY_POLICY_ASSET,
    SECONDARY_POLICY_NAME,
    REVOKED_POLICY_ASSET,
    REVOKED_POLICY_NAME,
    TAMPERED_POLICY_ASSET,
    TAMPERED_POLICY_NAME,
    UNTRUSTED_POLICY_ASSET,
    UNTRUSTED_POLICY_NAME,
)
from model import Batch, Case


def build():
    return (Batch(
        "policy_signature",
        (
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
            id="policy_signature_secondary_linked_ok",
            setup=(
                partial(steps.link_certificate, SECONDARY_KEYRING, SECONDARY_POLICY_ASSET),
            ),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy(SECONDARY_POLICY_ASSET),
            ),
            expect=0,
            check=partial(checks.policy_present_is, SECONDARY_POLICY_NAME, True),
        ),
        Case(
            id="policy_signature_secondary_absent_enokey",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy(SECONDARY_POLICY_ASSET),
            ),
            expect=errno.ENOKEY,
            check=partial(checks.policy_present_is, SECONDARY_POLICY_NAME, False),
        ),
        Case(
            id="policy_signature_platform_ok",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy(PLATFORM_POLICY_ASSET),
            ),
            expect=0,
            check=partial(checks.policy_present_is, PLATFORM_POLICY_NAME, True),
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
        ),
    ),)
