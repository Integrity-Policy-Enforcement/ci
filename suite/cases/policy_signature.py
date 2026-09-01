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
    PLATFORM_KEYRING_SIGNATURE_POLICY,
    REVOKED_SIGNATURE_POLICY,
    SECONDARY_KEYRING_SIGNATURE_POLICY,
    TAMPERED_SIGNATURE_POLICY,
    UNTRUSTED_SIGNATURE_POLICY,
)
from model import Batch, Case

SECONDARY_KEYRING = "%:.secondary_trusted_keys"


def tampered_signature() -> bytes:
    """Replace the signed text without updating its signature."""
    original = layout.guest.TAMPERED_POLICY_TEXT.read_bytes()
    replacement = layout.guest.TAMPERED_POLICY_REPLACEMENT.read_bytes()
    if len(replacement) != len(original):
        raise RuntimeError("tampered policy texts differ in length")
    signed = TAMPERED_SIGNATURE_POLICY.signed.read_bytes()
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
                UNTRUSTED_SIGNATURE_POLICY.signed.read_bytes(),
            ),
            checks=(
                partial(checks.errno_is, errno.ENOKEY),
                partial(checks.policy_present_is, UNTRUSTED_SIGNATURE_POLICY, False),
            ),
        ),
        Case(
            id="policy_signature_secondary_linked_ok",
            scope=partial(
                runtime.case_scope,
                partial(
                    keyring.certificates_scope,
                    keyring=SECONDARY_KEYRING,
                    certificates=(layout.guest.INTERMEDIATE_CERTIFICATE,),
                ),
            ),
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                SECONDARY_KEYRING_SIGNATURE_POLICY.signed.read_bytes(),
            ),
            checks=(
                partial(checks.errno_is, 0),
                partial(checks.policy_present_is, SECONDARY_KEYRING_SIGNATURE_POLICY, True),
            ),
        ),
        Case(
            id="policy_signature_secondary_absent_enokey",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                SECONDARY_KEYRING_SIGNATURE_POLICY.signed.read_bytes(),
            ),
            checks=(
                partial(checks.errno_is, errno.ENOKEY),
                partial(checks.policy_present_is, SECONDARY_KEYRING_SIGNATURE_POLICY, False),
            ),
        ),
        Case(
            id="policy_signature_platform_ok",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                PLATFORM_KEYRING_SIGNATURE_POLICY.signed.read_bytes(),
            ),
            checks=(
                partial(checks.errno_is, 0),
                partial(checks.policy_present_is, PLATFORM_KEYRING_SIGNATURE_POLICY, True),
            ),
        ),
        Case(
            id="policy_signature_revoked_ekeyrejected",
            trigger=partial(
                triggers.write_node,
                ipe.node.NEW_POLICY,
                None,
                REVOKED_SIGNATURE_POLICY.signed.read_bytes(),
            ),
            checks=(
                partial(checks.errno_is, errno.EKEYREJECTED),
                partial(checks.policy_present_is, REVOKED_SIGNATURE_POLICY, False),
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
                partial(checks.policy_present_is, TAMPERED_SIGNATURE_POLICY, False),
            ),
        ),
        ),
    ),)
