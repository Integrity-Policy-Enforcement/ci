#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Sign the policy fixtures, and fill in what only the build knows.

    build/policies/
        ipe_test_baseline-0.0.1.pol   the permissive floor a run starts from
        <group>/<name>.pol            a fixture, placeholders replaced
        <group>/<name>.p7s            it signed, by the builtin key unless
                                      the group needs another identity

A fixture that names a root hash or a digest cannot carry one, so it
carries a placeholder that the values under build/ replace.
"""

import shutil
import subprocess
from pathlib import Path

import layout

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
KEYS = ROOT / "build" / "keys"
SOURCE_POLICIES = ROOT / "policies"
DMVERITY = ROOT / "build" / layout.DMVERITY_ASSETS.name
ROOT_HASH_PLACEHOLDER = "@DMVERITY_ROOTHASH@"
OTHER_ROOT_HASH_PLACEHOLDER = "@DMVERITY_OTHER_ROOTHASH@"
HEX_DIGITS = "0123456789abcdef"
DMVERITY_ALGORITHM = "sha256"  # what veritysetup format defaults to
POLICIES = ROOT / "build" / "policies"
BUILTIN_KEY = KEYS / "builtin-key.pem"
BUILTIN_CERTIFICATE = KEYS / "builtin-cert.pem"
UNTRUSTED_KEY = KEYS / "untrusted-key.pem"
UNTRUSTED_CERTIFICATE = KEYS / "untrusted-cert.pem"
INTERMEDIATE_CERTIFICATE = KEYS / "intermediate-cert.pem"
SECONDARY_KEY = KEYS / "secondary-key.pem"
SECONDARY_CERTIFICATE = KEYS / "secondary-cert.pem"
SECONDARY_POLICY = "policy_signature/secondary.pol"
PLATFORM_KEY = KEYS / "secureboot-key.pem"
PLATFORM_CERTIFICATE = KEYS / "secureboot-cert.pem"
PLATFORM_POLICY = "policy_signature/platform.pol"
REVOKED_KEY = KEYS / "revoked-key.pem"
REVOKED_CERTIFICATE = KEYS / "revoked-cert.pem"
REVOKED_POLICY = "policy_signature/revoked.pol"
UNTRUSTED_POLICY = "policy_signature/untrusted.pol"
TAMPERED_POLICY = "policy_signature/tampered.pol"


def openssl(*args, **kwargs):
    subprocess.run(
        ["openssl", *map(str, args)],
        check=True,
        stdout=subprocess.DEVNULL,
        **kwargs,
    )


def sign(policy, output, key=BUILTIN_KEY, certificate=BUILTIN_CERTIFICATE, anchor=BUILTIN_CERTIFICATE):
    openssl(
        "cms",
        "-sign",
        "-in",
        policy,
        "-signer",
        certificate,
        "-inkey",
        key,
        "-binary",
        "-nodetach",
        "-noattr",
        "-outform",
        "DER",
        "-out",
        output,
        stderr=subprocess.DEVNULL,
    )
    content = subprocess.run(
        [
            "openssl",
            "cms",
            "-verify",
            "-in",
            str(output),
            "-inform",
            "DER",
            "-CAfile",
            str(anchor),
            "-partial_chain",
            "-purpose",
            "any",
            "-out",
            "/dev/stdout",
        ],
        check=True,
        capture_output=True,
    ).stdout
    if content != policy.read_bytes():
        raise SystemExit(f"signed content differs from {policy}")


def substitute_signed_content(policy, replacement, signature):
    signed_text = policy.read_bytes()
    replacement_text = replacement.read_bytes()
    if len(replacement_text) != len(signed_text):
        raise SystemExit(f"{replacement} must be the same length as {policy}")
    signature.write_bytes(signature.read_bytes().replace(signed_text, replacement_text))


def shift(hexadecimal):
    """A well formed value of the same length that nothing here carries."""
    return "".join(
        HEX_DIGITS[(HEX_DIGITS.index(digit) + 1) % len(HEX_DIGITS)] for digit in hexadecimal
    )


def measurements():
    """Every placeholder and the <algorithm>:<hex> a policy should name."""
    root_hash = (DMVERITY / layout.ROOT_HASH).read_text().strip()
    return {
        ROOT_HASH_PLACEHOLDER: f"{DMVERITY_ALGORITHM}:{root_hash}",
        OTHER_ROOT_HASH_PLACEHOLDER: f"{DMVERITY_ALGORITHM}:{shift(root_hash)}",
    }


def fill_in_measurements():
    replacements = measurements()
    for policy in POLICIES.rglob("*.pol"):
        text = policy.read_text()
        for placeholder, value in replacements.items():
            text = text.replace(placeholder, value)
        policy.write_text(text)


def main():
    if not BUILTIN_KEY.is_file() or not BUILTIN_CERTIFICATE.is_file():
        raise SystemExit("signing keys are missing; run prepare-keys.py")
    shutil.rmtree(POLICIES, ignore_errors=True)
    shutil.copytree(SOURCE_POLICIES, POLICIES)
    fill_in_measurements()

    for policy in POLICIES.rglob("*.pol"):
        sign(policy, policy.with_suffix(".p7s"))

    untrusted = POLICIES / UNTRUSTED_POLICY
    sign(
        untrusted,
        untrusted.with_suffix(".p7s"),
        UNTRUSTED_KEY,
        UNTRUSTED_CERTIFICATE,
        UNTRUSTED_CERTIFICATE,
    )

    secondary = POLICIES / SECONDARY_POLICY
    sign(
        secondary,
        secondary.with_suffix(".p7s"),
        SECONDARY_KEY,
        SECONDARY_CERTIFICATE,
        INTERMEDIATE_CERTIFICATE,
    )
    openssl(
        "x509", "-in", INTERMEDIATE_CERTIFICATE, "-outform", "DER",
        "-out", secondary.with_suffix(".der"),
    )

    platform = POLICIES / PLATFORM_POLICY
    sign(
        platform,
        platform.with_suffix(".p7s"),
        PLATFORM_KEY,
        PLATFORM_CERTIFICATE,
        PLATFORM_CERTIFICATE,
    )

    revoked = POLICIES / REVOKED_POLICY
    sign(
        revoked,
        revoked.with_suffix(".p7s"),
        REVOKED_KEY,
        REVOKED_CERTIFICATE,
        REVOKED_CERTIFICATE,
    )

    tampered = POLICIES / TAMPERED_POLICY
    substitute_signed_content(
        tampered, tampered.with_suffix(".replacement"), tampered.with_suffix(".p7s")
    )
    print(f"    Prepared {len(tuple(POLICIES.rglob('*.pol')))} signed policies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
