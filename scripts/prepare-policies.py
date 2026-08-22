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


def openssl(*args, **kwargs):
    subprocess.run(
        ["openssl", *map(str, args)],
        check=True,
        stdout=subprocess.DEVNULL,
        **kwargs,
    )


def sign(policy, output):
    openssl(
        "cms",
        "-sign",
        "-in",
        policy,
        "-signer",
        CERTIFICATE,
        "-inkey",
        KEY,
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
            str(CERTIFICATE),
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


def main():
    if not KEY.is_file() or not CERTIFICATE.is_file():
        raise SystemExit("signing keys are missing; run prepare-keys.py")
    shutil.rmtree(POLICIES, ignore_errors=True)
    shutil.copytree(SOURCE_POLICIES, POLICIES)

    for policy in POLICIES.rglob("*.pol"):
        sign(policy, policy.with_suffix(".p7s"))
    print(f"    Prepared {len(tuple(POLICIES.rglob('*.pol')))} signed policies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
