#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Sign the policies, and fill in what only the build knows.

    build/policies/    the source policy tree, with placeholders filled,
                       and each .pol signed beside it as .p7s

A policy that names a root hash or a digest cannot carry one, so it
carries a placeholder that the values under build/ replace.
"""

import shutil
import subprocess
from pathlib import Path

import hashes
import layout
import signing

HEX_DIGITS = "0123456789abcdef"


def openssl(*args: object, **kwargs: object) -> None:
    subprocess.run(
        ["openssl", *map(str, args)],
        check=True,
        stdout=subprocess.DEVNULL,
        **kwargs,
    )


def sign(
    policy: Path,
    output: Path,
    key: Path = signing.BUILTIN.key,
    certificate: Path = signing.BUILTIN.certificate,
    anchor: Path = signing.BUILTIN.certificate,
) -> None:
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


def substitute_signed_content(policy: Path, replacement: Path, signature: Path) -> None:
    signed_text = policy.read_bytes()
    replacement_text = replacement.read_bytes()
    if len(replacement_text) != len(signed_text):
        raise SystemExit(f"{replacement} must be the same length as {policy}")
    signature.write_bytes(signature.read_bytes().replace(signed_text, replacement_text))


def shift(hexadecimal: str) -> str:
    """A well formed value of the same length that nothing here carries."""
    return "".join(
        HEX_DIGITS[(HEX_DIGITS.index(digit) + 1) % len(HEX_DIGITS)] for digit in hexadecimal
    )


def measurements() -> dict[str, str]:
    """Every placeholder and the <algorithm>:<hex> a policy should name."""
    table = {}
    for algorithm in hashes.ALGORITHMS:
        root_hash = layout.build.root_hash(algorithm).read_text().strip()
        digest = layout.build.fsverity_digest(algorithm).read_text().strip()
        upper = algorithm.upper()
        table[f"@DMVERITY_ROOTHASH_{upper}@"] = f"{algorithm}:{root_hash}"
        table[f"@DMVERITY_OTHER_ROOTHASH_{upper}@"] = f"{algorithm}:{shift(root_hash)}"
        table[f"@FSVERITY_DIGEST_{upper}@"] = f"{algorithm}:{digest}"
        table[f"@FSVERITY_OTHER_DIGEST_{upper}@"] = f"{algorithm}:{shift(digest)}"
    return table


def fill_in_measurements() -> None:
    replacements = measurements()
    for policy in layout.build.POLICIES.rglob("*.pol"):
        text = policy.read_text()
        for placeholder, value in replacements.items():
            text = text.replace(placeholder, value)
        policy.write_text(text)


def main() -> int:
    if not signing.BUILTIN.key.is_file() or not signing.BUILTIN.certificate.is_file():
        raise SystemExit("signing keys are missing; run prepare-keys.py")
    shutil.rmtree(layout.build.POLICIES, ignore_errors=True)
    shutil.copytree(layout.source.POLICIES, layout.build.POLICIES)
    fill_in_measurements()

    for policy in layout.build.POLICIES.rglob("*.pol"):
        sign(policy, policy.with_suffix(".p7s"))

    untrusted = layout.build.UNTRUSTED_POLICY_TEXT
    sign(
        untrusted,
        untrusted.with_suffix(".p7s"),
        signing.UNTRUSTED.key,
        signing.UNTRUSTED.certificate,
        signing.UNTRUSTED.certificate,
    )

    secondary = layout.build.SECONDARY_POLICY_TEXT
    sign(
        secondary,
        secondary.with_suffix(".p7s"),
        signing.SECONDARY.key,
        signing.SECONDARY.certificate,
        signing.INTERMEDIATE.certificate,
    )
    layout.build.SIGNER_CERTIFICATES.mkdir(parents=True, exist_ok=True)
    openssl(
        "x509", "-in", signing.INTERMEDIATE.certificate, "-outform", "DER",
        "-out", layout.build.INTERMEDIATE_CERTIFICATE,
    )

    platform = layout.build.PLATFORM_POLICY_TEXT
    sign(
        platform,
        platform.with_suffix(".p7s"),
        signing.SECUREBOOT.key,
        signing.SECUREBOOT.certificate,
        signing.SECUREBOOT.certificate,
    )

    revoked = layout.build.REVOKED_POLICY_TEXT
    sign(
        revoked,
        revoked.with_suffix(".p7s"),
        signing.REVOKED.key,
        signing.REVOKED.certificate,
        signing.REVOKED.certificate,
    )

    tampered = layout.build.TAMPERED_POLICY_TEXT
    substitute_signed_content(
        tampered, tampered.with_suffix(".replacement"), tampered.with_suffix(".p7s")
    )
    count = len(tuple(layout.build.POLICIES.rglob("*.pol")))
    print(f"    Prepared {count} signed policies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
