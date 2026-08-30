# SPDX-License-Identifier: GPL-2.0-only

import errno
from functools import partial

import checks
import ipe
import keyring
import layout
import runtime
import triggers
from assets import (
    PLATFORM_POLICY,
    REVOKED_POLICY,
    SECONDARY_POLICY,
    TAMPERED_POLICY,
    UNTRUSTED_POLICY,
)
from model import Batch, Case, CaseState

SECONDARY_KEYRING = "%:.secondary_trusted_keys"


def link_intermediate(_state: CaseState) -> None:
    """Link the intermediate certificate for the secondary-keyring case."""
    keyring.add_certificate(
        SECONDARY_KEYRING,
        layout.guest.INTERMEDIATE_CERTIFICATE,
    )


def tampered_signature() -> bytes:
    """Replace the signed text without updating its signature."""
    original = layout.guest.TAMPERED_POLICY_TEXT.read_bytes()
    replacement = layout.guest.TAMPERED_POLICY_REPLACEMENT.read_bytes()
    if len(replacement) != len(original):
        raise RuntimeError("tampered policy texts differ in length")
    signed = TAMPERED_POLICY.signed.read_bytes()
    if signed.count(original) != 1:
        raise RuntimeError("signed policy does not contain its text exactly once")
    return signed.replace(original, replacement)


def build() -> tuple[Batch, ...]:
    """The batches this group contributes."""
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
            checks=(
                partial(checks.errno_is, errno.ENOKEY),
                partial(checks.policy_present_is, UNTRUSTED_POLICY, False),
            ),
        ),
        Case(
            id="policy_signature_secondary_linked_ok",
            setup=(link_intermediate,),
            scope=partial(
                runtime.case_scope,
                partial(keyring.linked_scope, SECONDARY_KEYRING),
            ),
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                SECONDARY_POLICY.signed.read_bytes(),
            ),
            checks=(
                partial(checks.errno_is, 0),
                partial(checks.policy_present_is, SECONDARY_POLICY, True),
            ),
        ),
        Case(
            id="policy_signature_secondary_absent_enokey",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                SECONDARY_POLICY.signed.read_bytes(),
            ),
            checks=(
                partial(checks.errno_is, errno.ENOKEY),
                partial(checks.policy_present_is, SECONDARY_POLICY, False),
            ),
        ),
        Case(
            id="policy_signature_platform_ok",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                PLATFORM_POLICY.signed.read_bytes(),
            ),
            checks=(
                partial(checks.errno_is, 0),
                partial(checks.policy_present_is, PLATFORM_POLICY, True),
            ),
        ),
        Case(
            id="policy_signature_revoked_ekeyrejected",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                REVOKED_POLICY.signed.read_bytes(),
            ),
            checks=(
                partial(checks.errno_is, errno.EKEYREJECTED),
                partial(checks.policy_present_is, REVOKED_POLICY, False),
            ),
        ),
        Case(
            id="policy_signature_tampered_ekeyrejected",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                tampered_signature(),
            ),
            checks=(
                partial(checks.errno_is, errno.EKEYREJECTED),
                partial(checks.policy_present_is, TAMPERED_POLICY, False),
            ),
        ),
        ),
    ),)
