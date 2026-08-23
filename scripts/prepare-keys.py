#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import shutil
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
KEYS = ROOT / "build" / "keys"
KEY = KEYS / "signing-key.pem"
CERTIFICATE = KEYS / "signing-cert.pem"
CERTIFICATE_DER = KEYS / "signing-cert.der"
MODULE_KEY = KEYS / "module-signing.pem"
REVOKED_KEY = KEYS / "revoked-key.pem"
REVOKED_CERTIFICATE = KEYS / "revoked-cert.pem"
UNTRUSTED_KEY = KEYS / "untrusted-key.pem"
UNTRUSTED_CERTIFICATE = KEYS / "untrusted-cert.pem"
SECURE_BOOT_KEY = KEYS / "secureboot-key.pem"
SECURE_BOOT_CERTIFICATE = KEYS / "secureboot-cert.pem"

OPENSSL_CONFIG = """[req]
default_bits = 3072
distinguished_name = subject
prompt = no
x509_extensions = extensions

[subject]
O = IPE tests
CN = {common_name}

[extensions]
basicConstraints = critical,CA:FALSE
keyUsage = digitalSignature
subjectKeyIdentifier = hash
"""


def openssl(*args, **kwargs):
    subprocess.run(
        ["openssl", *map(str, args)],
        check=True,
        stdout=subprocess.DEVNULL,
        **kwargs,
    )


def generate_certificate(key, certificate, common_name):
    config = OPENSSL_CONFIG.format(common_name=common_name)
    openssl(
        "req",
        "-new",
        "-nodes",
        "-sha256",
        "-days",
        "3",
        "-batch",
        "-x509",
        "-config",
        "/dev/stdin",
        "-keyout",
        key,
        "-out",
        certificate,
        input=config,
        text=True,
        stderr=subprocess.DEVNULL,
    )
    key.chmod(0o600)


def main():
    shutil.rmtree(KEYS, ignore_errors=True)
    KEYS.mkdir(parents=True)
    generate_certificate(KEY, CERTIFICATE, "Ephemeral IPE policy signing key")
    generate_certificate(
        UNTRUSTED_KEY,
        UNTRUSTED_CERTIFICATE,
        "Untrusted IPE policy signing key",
    )
    generate_certificate(
        REVOKED_KEY,
        REVOKED_CERTIFICATE,
        "Revoked IPE policy signing key",
    )
    generate_certificate(
        SECURE_BOOT_KEY,
        SECURE_BOOT_CERTIFICATE,
        "Ephemeral Secure Boot signing key",
    )
    openssl(
        "x509",
        "-in",
        CERTIFICATE,
        "-outform",
        "DER",
        "-out",
        CERTIFICATE_DER,
    )
    MODULE_KEY.write_bytes(KEY.read_bytes() + CERTIFICATE.read_bytes())
    MODULE_KEY.chmod(0o600)
    print("    Prepared signing identities")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
