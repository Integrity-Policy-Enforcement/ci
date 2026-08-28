# SPDX-License-Identifier: GPL-2.0-only

import errno
from functools import partial

import checks
import ipe
import keyring
import runtime
import steps
import triggers
from assets import (
    PLATFORM_POLICY,
    REVOKED_POLICY,
    SECONDARY_KEYRING,
    SECONDARY_POLICY,
    TAMPERED_POLICY,
    UNTRUSTED_POLICY,
)
from model import Batch, Case
from scope import Collection


def build() -> tuple[Batch, ...]:
    return (Batch(
        "policy_signature",
        (
        Case(
            id="policy_signature_untrusted_enokey",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                UNTRUSTED_POLICY.signed.read_bytes(),
            ),
            expect=errno.ENOKEY,
            check=partial(checks.policy_present_is, UNTRUSTED_POLICY, False),
        ),
        Case(
            id="policy_signature_secondary_linked_ok",
            setup=(
                partial(steps.link_certificate, SECONDARY_KEYRING, SECONDARY_POLICY),
            ),
            scope=partial(
                runtime.case.scope,
                Collection(
                    members=partial(keyring.linked_keys, SECONDARY_KEYRING),
                    discard=partial(keyring.unlink, keyring=SECONDARY_KEYRING),
                ),
            ),
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                SECONDARY_POLICY.signed.read_bytes(),
            ),
            expect=0,
            check=partial(checks.policy_present_is, SECONDARY_POLICY, True),
        ),
        Case(
            id="policy_signature_secondary_absent_enokey",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                SECONDARY_POLICY.signed.read_bytes(),
            ),
            expect=errno.ENOKEY,
            check=partial(checks.policy_present_is, SECONDARY_POLICY, False),
        ),
        Case(
            id="policy_signature_platform_ok",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                PLATFORM_POLICY.signed.read_bytes(),
            ),
            expect=0,
            check=partial(checks.policy_present_is, PLATFORM_POLICY, True),
        ),
        Case(
            id="policy_signature_revoked_ekeyrejected",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                REVOKED_POLICY.signed.read_bytes(),
            ),
            expect=errno.EKEYREJECTED,
            check=partial(checks.policy_present_is, REVOKED_POLICY, False),
        ),
        Case(
            id="policy_signature_tampered_ekeyrejected",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                TAMPERED_POLICY.signed.read_bytes(),
            ),
            expect=errno.EKEYREJECTED,
            check=partial(checks.policy_present_is, TAMPERED_POLICY, False),
        ),
        ),
    ),)
