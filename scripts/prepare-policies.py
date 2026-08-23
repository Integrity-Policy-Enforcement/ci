#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import shutil
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
KEYS = ROOT / "build" / "keys"
SOURCE_POLICIES = ROOT / "policies"
POLICIES = ROOT / "build" / "policies"
KEY = KEYS / "signing-key.pem"
CERTIFICATE = KEYS / "signing-cert.pem"
UNTRUSTED_KEY = KEYS / "untrusted-key.pem"
UNTRUSTED_CERTIFICATE = KEYS / "untrusted-cert.pem"
UNTRUSTED_POLICY = "policy_signature/untrusted.pol"
TAMPERED_POLICY = "policy_signature/tampered.pol"


def openssl(*args, **kwargs):
    subprocess.run(
        ["openssl", *map(str, args)],
        check=True,
        stdout=subprocess.DEVNULL,
        **kwargs,
    )


def sign(policy, output, key=KEY, certificate=CERTIFICATE):
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
            str(certificate),
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


def main():
    if not KEY.is_file() or not CERTIFICATE.is_file():
        raise SystemExit("signing keys are missing; run prepare-keys.py")
    shutil.rmtree(POLICIES, ignore_errors=True)
    shutil.copytree(SOURCE_POLICIES, POLICIES)

    for policy in POLICIES.rglob("*.pol"):
        sign(policy, policy.with_suffix(".p7s"))

    untrusted = POLICIES / UNTRUSTED_POLICY
    sign(untrusted, untrusted.with_suffix(".p7s"), UNTRUSTED_KEY, UNTRUSTED_CERTIFICATE)

    tampered = POLICIES / TAMPERED_POLICY
    substitute_signed_content(
        tampered, tampered.with_suffix(".replacement"), tampered.with_suffix(".p7s")
    )
    print(f"    Prepared {len(tuple(POLICIES.rglob('*.pol')))} signed policies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
