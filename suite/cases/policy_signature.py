# SPDX-License-Identifier: GPL-2.0-only

import errno
import subprocess
from functools import partial

import checks
import ipe
import layout
import triggers
from assets import (
    IPE_KEYRING_SIGNATURE_POLICY,
    PLATFORM_KEYRING_SIGNATURE_POLICY,
    REVOKED_SIGNATURE_POLICY,
    SECONDARY_KEYRING_SIGNATURE_POLICY,
    TAMPERED_SIGNATURE_POLICY,
    UNTRUSTED_SIGNATURE_POLICY,
)
from model import Batch, Case, CaseState, Observation
from resources import keyring

SECONDARY_KEYRING = "%:.secondary_trusted_keys"
# Proposed KEY_SPEC_IPE_KEYRING value; its kernel UAPI review is ongoing.
IPE_KEYRING = "-12"
# Optional provisioning hardening, not required for .ipe activation; whether
# to retain this case in the initial CI contribution remains under review.
IPE_KEYRING_LOCKED_PERMISSIONS = "0x08030000"


def ipe_keyring_resolves(observation: Observation) -> str | None:
    """The special key ID names the dedicated .ipe keyring."""
    try:
        description = keyring.keyctl("describe", IPE_KEYRING).strip()
    except subprocess.CalledProcessError as failure:
        return f"KEY_SPEC_IPE_KEYRING did not resolve: {failure.stderr.decode().strip()}"
    if not description.endswith("keyring: .ipe"):
        return f"KEY_SPEC_IPE_KEYRING resolved to {description!r}"
    return None


def ipe_certificate_is_enrolled(observation: Observation) -> str | None:
    """The initrd linked exactly one certificate into .ipe."""
    try:
        linked = keyring.linked_keys(IPE_KEYRING)
    except subprocess.CalledProcessError as failure:
        return f"cannot list .ipe: {failure.stderr.decode().strip()}"
    if len(linked) != 1:
        return f".ipe contains {len(linked)} keys, expected one certificate"
    return None


def keyctl_observation(
    *arguments: str,
    state: CaseState,
    payload: bytes | None = None,
) -> Observation:
    """Run an expected-to-fail keyctl operation and retain its status."""
    try:
        keyring.keyctl(*arguments, payload=payload)
    except subprocess.CalledProcessError as failure:
        return Observation(
            returncode=failure.returncode,
            message=failure.stderr.decode().strip(),
        )
    return Observation(returncode=0)


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
    return (
        Batch(
            id="policy_signature",
            cases=(
                # Pending review: whether IPE receives a KEY_SPEC UAPI ID.
                Case(
                    id="policy_signature_ipe_keyring_resolves",
                    checks=(ipe_keyring_resolves,),
                ),
                # Pending review: how runtime provisioning is enabled.
                Case(
                    id="policy_signature_ipe_certificate_enrolled",
                    checks=(ipe_certificate_is_enrolled,),
                ),
                # Pending review: whether CI should require permission lockdown.
                Case(
                    id="policy_signature_ipe_keyring_locked",
                    trigger=partial(
                        keyctl_observation,
                        "setperm",
                        IPE_KEYRING,
                        IPE_KEYRING_LOCKED_PERMISSIONS,
                    ),
                    checks=(partial(checks.returncode_is, expected=1),),
                ),
                # Pending review: either restriction model rejects this unrelated key.
                Case(
                    id="policy_signature_ipe_add_rejected",
                    trigger=partial(
                        keyctl_observation,
                        "padd",
                        "user",
                        "ipe-test-probe",
                        IPE_KEYRING,
                        payload=b"probe",
                    ),
                    checks=(partial(checks.returncode_is, expected=1),),
                ),
                # Pending review: whether the proposed KEY_SPEC UAPI is retained.
                Case(
                    id="policy_signature_ipe_no_possession",
                    trigger=partial(keyctl_observation, "id", IPE_KEYRING),
                    checks=(partial(checks.returncode_is, expected=1),),
                ),
                Case(
                    id="policy_signature_untrusted_enokey",
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.NEW_POLICY,
                        policy=None,
                        data=UNTRUSTED_SIGNATURE_POLICY.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.ENOKEY),
                        partial(
                            checks.policy_present_is,
                            policy=UNTRUSTED_SIGNATURE_POLICY,
                            expected=False,
                        ),
                    ),
                ),
                Case(
                    id="policy_signature_secondary_linked_ok",
                    extra_scopes=(
                        partial(
                            keyring.certificates_scope,
                            keyring=SECONDARY_KEYRING,
                            certificates=(layout.guest.INTERMEDIATE_CERTIFICATE,),
                        ),
                    ),
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.NEW_POLICY,
                        policy=None,
                        data=SECONDARY_KEYRING_SIGNATURE_POLICY.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(
                            checks.policy_present_is,
                            policy=SECONDARY_KEYRING_SIGNATURE_POLICY,
                            expected=True,
                        ),
                    ),
                ),
                Case(
                    id="policy_signature_secondary_absent_enokey",
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.NEW_POLICY,
                        policy=None,
                        data=SECONDARY_KEYRING_SIGNATURE_POLICY.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.ENOKEY),
                        partial(
                            checks.policy_present_is,
                            policy=SECONDARY_KEYRING_SIGNATURE_POLICY,
                            expected=False,
                        ),
                    ),
                ),
                Case(
                    id="policy_signature_platform_ok",
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.NEW_POLICY,
                        policy=None,
                        data=PLATFORM_KEYRING_SIGNATURE_POLICY.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(
                            checks.policy_present_is,
                            policy=PLATFORM_KEYRING_SIGNATURE_POLICY,
                            expected=True,
                        ),
                    ),
                ),
                # The existing untrusted, revoked and tampered cases run with
                # .ipe provisioned and provide negative coverage for the .ipe fallback.
                # Pending review: which restriction makes .ipe an active trust source.
                Case(
                    id="policy_signature_ipe_ok",
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.NEW_POLICY,
                        policy=None,
                        data=IPE_KEYRING_SIGNATURE_POLICY.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=0),
                        partial(
                            checks.policy_present_is,
                            policy=IPE_KEYRING_SIGNATURE_POLICY,
                            expected=True,
                        ),
                    ),
                ),
                Case(
                    id="policy_signature_revoked_ekeyrejected",
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.NEW_POLICY,
                        policy=None,
                        data=REVOKED_SIGNATURE_POLICY.signed.read_bytes(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EKEYREJECTED),
                        partial(
                            checks.policy_present_is,
                            policy=REVOKED_SIGNATURE_POLICY,
                            expected=False,
                        ),
                    ),
                ),
                Case(
                    id="policy_signature_tampered_ekeyrejected",
                    trigger=partial(
                        triggers.write_node,
                        entry=ipe.node.NEW_POLICY,
                        policy=None,
                        data=tampered_signature(),
                    ),
                    checks=(
                        partial(checks.errno_is, expected=errno.EKEYREJECTED),
                        partial(
                            checks.policy_present_is,
                            policy=TAMPERED_SIGNATURE_POLICY,
                            expected=False,
                        ),
                    ),
                ),
            ),
        ),
    )
