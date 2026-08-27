#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Create the signing identities the tests need.

    build/keys/
        builtin-key.pem       signs IPE policies; its certificate is built
        builtin-cert.pem      into the kernel and signs the dm-verity root
        builtin-cert.der
        intermediate-*.pem    issued by builtin, in no keyring
        secondary-*.pem       issued by intermediate, linked at run time
        revoked-*.pem         self-signed, built into the blacklist
        untrusted-*.pem       self-signed, in no keyring
        secureboot-*.pem      enrolled in the UEFI db, so it reaches .platform
        module-signing.pem    key and certificate joined, for the kernel build

Every run creates them afresh, so changing them means rebuilding the
kernel and the image that trust them.
"""

import shutil
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
KEYS = ROOT / "build" / "keys"
BUILTIN_KEY = KEYS / "builtin-key.pem"
BUILTIN_CERTIFICATE = KEYS / "builtin-cert.pem"
BUILTIN_CERTIFICATE_DER = KEYS / "builtin-cert.der"
MODULE_KEY = KEYS / "module-signing.pem"
INTERMEDIATE_KEY = KEYS / "intermediate-key.pem"
INTERMEDIATE_CERTIFICATE = KEYS / "intermediate-cert.pem"
SECONDARY_KEY = KEYS / "secondary-key.pem"
SECONDARY_CERTIFICATE = KEYS / "secondary-cert.pem"
REVOKED_KEY = KEYS / "revoked-key.pem"
REVOKED_CERTIFICATE = KEYS / "revoked-cert.pem"
UNTRUSTED_KEY = KEYS / "untrusted-key.pem"
UNTRUSTED_CERTIFICATE = KEYS / "untrusted-cert.pem"
SECURE_BOOT_KEY = KEYS / "secureboot-key.pem"
SECURE_BOOT_CERTIFICATE = KEYS / "secureboot-cert.pem"


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


def openssl(*args, **kwargs):
    subprocess.run(
        ["openssl", *map(str, args)],
        check=True,
        stdout=subprocess.DEVNULL,
        **kwargs,
    )


def generate_certificate(key, certificate, common_name, extensions, issuer=None, issuer_key=None):
    signer = ["-CA", issuer, "-CAkey", issuer_key] if issuer else []
    openssl(
        "req", "-new", "-nodes", "-sha256", "-days", "3", "-batch", "-x509",
        "-config", "/dev/stdin", "-keyout", key, "-out", certificate, *signer,
        input=CERTIFICATE_CONFIG.format(common_name=common_name, extensions=extensions),
        text=True,
        stderr=subprocess.DEVNULL,
    )
    key.chmod(0o600)


def main():
    shutil.rmtree(KEYS, ignore_errors=True)
    KEYS.mkdir(parents=True)
    generate_certificate(
        BUILTIN_KEY, BUILTIN_CERTIFICATE, "Builtin IPE policy signing key", AUTHORITY_EXTENSIONS
    )
    generate_certificate(
        UNTRUSTED_KEY,
        UNTRUSTED_CERTIFICATE,
        "Untrusted IPE policy signing key",
        LEAF_EXTENSIONS,
    )
    generate_certificate(
        INTERMEDIATE_KEY,
        INTERMEDIATE_CERTIFICATE,
        "Intermediate IPE policy authority",
        AUTHORITY_EXTENSIONS,
        BUILTIN_CERTIFICATE,
        BUILTIN_KEY,
    )
    generate_certificate(
        SECONDARY_KEY,
        SECONDARY_CERTIFICATE,
        "Secondary keyring IPE policy signing key",
        LEAF_EXTENSIONS,
        INTERMEDIATE_CERTIFICATE,
        INTERMEDIATE_KEY,
    )
    generate_certificate(
        REVOKED_KEY,
        REVOKED_CERTIFICATE,
        "Revoked IPE policy signing key",
        LEAF_EXTENSIONS,
    )
    generate_certificate(
        SECURE_BOOT_KEY,
        SECURE_BOOT_CERTIFICATE,
        "Ephemeral Secure Boot signing key",
        LEAF_EXTENSIONS,
    )
    openssl(
        "x509",
        "-in",
        BUILTIN_CERTIFICATE,
        "-outform",
        "DER",
        "-out",
        BUILTIN_CERTIFICATE_DER,
    )
    MODULE_KEY.write_bytes(BUILTIN_KEY.read_bytes() + BUILTIN_CERTIFICATE.read_bytes())
    MODULE_KEY.chmod(0o600)
    print("    Prepared signing identities")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
