#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Create the signing identities the tests need.

    build/keys/
        builtin-key.pem       signs IPE policies; its certificate is built
        builtin-cert.pem      into the kernel and signs the dm-verity root
        intermediate-key.pem  issued by builtin, in no keyring
        intermediate-cert.pem
        secondary-key.pem     issued by intermediate, linked at run time
        secondary-cert.pem
        revoked-key.pem       self-signed, built into the blacklist
        revoked-cert.pem
        untrusted-key.pem     self-signed, in no keyring
        untrusted-cert.pem
        secureboot-key.pem    enrolled in the UEFI db, so it reaches .platform
        secureboot-cert.pem
        fsverity-key.pem      signs fs-verity digests; the initramfs adds
        fsverity-cert.pem     its certificate to the .fs-verity keyring
        fsverity-cert.der     the form keyctl takes, and the only DER made here
        module-signing.pem    key and certificate joined, for the kernel build

Every run creates them afresh, so changing them means rebuilding the
kernel and the image that trust them.
"""

import shutil
import subprocess
import layout
import signing
from pathlib import Path

# The initramfs adds this to the .fs-verity keyring, and keyctl takes DER.
FSVERITY_CERTIFICATE_DER = layout.build.KEYS / "fsverity-cert.der"

CERTIFICATE_CONFIG = """[req]
default_bits = 3072
distinguished_name = subject
prompt = no
x509_extensions = extensions

[subject]
O = IPE tests
CN = {common_name}

[extensions]
{extensions}"""

AUTHORITY_EXTENSIONS = """basicConstraints = critical,CA:TRUE
keyUsage = digitalSignature, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""

LEAF_EXTENSIONS = """basicConstraints = critical,CA:FALSE
keyUsage = digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""


def openssl(*args: object, **kwargs: object) -> None:
    subprocess.run(
        ["openssl", *map(str, args)],
        check=True,
        stdout=subprocess.DEVNULL,
        **kwargs,
    )


def generate_certificate(
    key: Path,
    certificate: Path,
    common_name: str,
    extensions: str,
    issuer: Path | None = None,
    issuer_key: Path | None = None,
) -> None:
    signer = ["-CA", issuer, "-CAkey", issuer_key] if issuer else []
    openssl(
        "req", "-new", "-nodes", "-sha256", "-days", "3", "-batch", "-x509",
        "-config", "/dev/stdin", "-keyout", key, "-out", certificate, *signer,
        input=CERTIFICATE_CONFIG.format(common_name=common_name, extensions=extensions),
        text=True,
        stderr=subprocess.DEVNULL,
    )
    key.chmod(0o600)


def main() -> int:
    shutil.rmtree(layout.build.KEYS, ignore_errors=True)
    layout.build.KEYS.mkdir(parents=True)
    generate_certificate(
        signing.BUILTIN.key, signing.BUILTIN.certificate, "Builtin IPE policy signing key", AUTHORITY_EXTENSIONS
    )
    generate_certificate(
        signing.UNTRUSTED.key,
        signing.UNTRUSTED.certificate,
        "Untrusted IPE policy signing key",
        LEAF_EXTENSIONS,
    )
    generate_certificate(
        signing.INTERMEDIATE.key,
        signing.INTERMEDIATE.certificate,
        "Intermediate IPE policy authority",
        AUTHORITY_EXTENSIONS,
        signing.BUILTIN.certificate,
        signing.BUILTIN.key,
    )
    generate_certificate(
        signing.SECONDARY.key,
        signing.SECONDARY.certificate,
        "Secondary keyring IPE policy signing key",
        LEAF_EXTENSIONS,
        signing.INTERMEDIATE.certificate,
        signing.INTERMEDIATE.key,
    )
    generate_certificate(
        signing.REVOKED.key,
        signing.REVOKED.certificate,
        "Revoked IPE policy signing key",
        LEAF_EXTENSIONS,
    )
    generate_certificate(
        signing.FSVERITY.key,
        signing.FSVERITY.certificate,
        "fs-verity file signing key",
        LEAF_EXTENSIONS,
    )
    generate_certificate(
        signing.SECUREBOOT.key,
        signing.SECUREBOOT.certificate,
        "Ephemeral Secure Boot signing key",
        LEAF_EXTENSIONS,
    )
    openssl(
        "x509", "-in", signing.FSVERITY.certificate, "-outform", "DER",
        "-out", FSVERITY_CERTIFICATE_DER,
    )
    signing.MODULE_SIGNING.write_bytes(signing.BUILTIN.key.read_bytes() + signing.BUILTIN.certificate.read_bytes())
    signing.MODULE_SIGNING.chmod(0o600)
    print("    Prepared signing identities")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
