#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Create the signing identities the tests need.

    build/keys/
        builtin-key.pem       private key that signs policies and root hashes
        builtin-cert.pem      self-signed CA certificate built into the kernel
        intermediate-key.pem  private key for the intermediate CA
        intermediate-cert.pem certificate signed by builtin; issues secondary
        secondary-key.pem     private key for the secondary identity
        secondary-cert.pem    certificate signed by intermediate
        revoked-key.pem       private key for the revoked identity
        revoked-cert.pem      self-signed certificate built into the blacklist
        untrusted-key.pem     private key for the untrusted identity
        untrusted-cert.pem    self-signed certificate in no trusted keyring
        secureboot-key.pem    private key for the Secure Boot identity
        secureboot-cert.pem   certificate enrolled in the UEFI db
        fsverity-key.pem      private key that signs fs-verity digests
        fsverity-cert.pem     certificate added to .fs-verity by the initrd
        fsverity-cert.der     DER encoding of fsverity-cert.pem for keyctl
        module-signing.pem    builtin key and certificate joined for the kernel

Every run creates them afresh, so changing them means rebuilding the
kernel and the image that trust them.
"""

import shutil
import subprocess

import layout
import signing

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
    *,
    identity: signing.Identity,
    common_name: str,
    extensions: str,
    issuer: signing.Identity | None = None,
) -> None:
    signer = (
        ["-CA", issuer.certificate, "-CAkey", issuer.key]
        if issuer
        else []
    )
    openssl(
        "req", "-new", "-nodes", "-sha256", "-days", "3", "-batch", "-x509",
        "-config", "/dev/stdin",
        "-keyout", identity.key,
        "-out", identity.certificate,
        *signer,
        input=CERTIFICATE_CONFIG.format(common_name=common_name, extensions=extensions),
        text=True,
        stderr=subprocess.DEVNULL,
    )
    identity.key.chmod(0o600)


def main() -> int:
    shutil.rmtree(layout.build.KEYS, ignore_errors=True)
    layout.build.KEYS.mkdir(parents=True)
    generate_certificate(
        identity=signing.BUILTIN,
        common_name="Builtin IPE policy signing key",
        extensions=AUTHORITY_EXTENSIONS,
    )
    generate_certificate(
        identity=signing.UNTRUSTED,
        common_name="Untrusted IPE policy signing key",
        extensions=LEAF_EXTENSIONS,
    )
    generate_certificate(
        identity=signing.INTERMEDIATE,
        common_name="Intermediate IPE policy authority",
        extensions=AUTHORITY_EXTENSIONS,
        issuer=signing.BUILTIN,
    )
    generate_certificate(
        identity=signing.SECONDARY,
        common_name="Secondary keyring IPE policy signing key",
        extensions=LEAF_EXTENSIONS,
        issuer=signing.INTERMEDIATE,
    )
    generate_certificate(
        identity=signing.REVOKED,
        common_name="Revoked IPE policy signing key",
        extensions=LEAF_EXTENSIONS,
    )
    generate_certificate(
        identity=signing.FSVERITY,
        common_name="fs-verity file signing key",
        extensions=LEAF_EXTENSIONS,
    )
    generate_certificate(
        identity=signing.SECUREBOOT,
        common_name="Ephemeral Secure Boot signing key",
        extensions=LEAF_EXTENSIONS,
    )
    openssl(
        "x509", "-in", signing.FSVERITY.certificate, "-outform", "DER",
        "-out", layout.build.FSVERITY_CERTIFICATE,
    )
    signing.MODULE_SIGNING.write_bytes(
        signing.BUILTIN.key.read_bytes() + signing.BUILTIN.certificate.read_bytes()
    )
    signing.MODULE_SIGNING.chmod(0o600)
    print("    Prepared signing identities")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
