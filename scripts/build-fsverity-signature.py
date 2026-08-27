#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Sign the fs-verity digest of the test module.

    build/fsverity/
        ipe_test.digest       the digest, as ASCII hex
        ipe_test.p7s          that digest signed by the fs-verity key

The digest depends on the file alone, so it can be computed here, where
the key is, and the guest only has to enable fs-verity with the result.
"""

import shutil
import subprocess
from pathlib import Path

import layout

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
KEYS = ROOT / "build" / "keys"
OUTPUT = ROOT / "build" / layout.FSVERITY_ASSETS.name
KERNEL_MODULE = ROOT / "build" / "kernel-module" / layout.TEST_MODULE_FILE
FSVERITY_KEY = KEYS / "fsverity-key.pem"
FSVERITY_CERTIFICATE = KEYS / "fsverity-cert.pem"


def main():
    if not FSVERITY_KEY.is_file():
        raise SystemExit("signing keys are missing; run prepare-keys.py")
    if not KERNEL_MODULE.is_file():
        raise SystemExit("the test module is missing; run build-kernel-module.py")
    shutil.rmtree(OUTPUT, ignore_errors=True)
    OUTPUT.mkdir(parents=True)

    subprocess.run(
        [
            "fsverity", "sign", str(KERNEL_MODULE), str(OUTPUT / layout.FSVERITY_SIGNATURE),
            f"--key={FSVERITY_KEY}", f"--cert={FSVERITY_CERTIFICATE}",
            f"--hash-alg={layout.HASH_ALGORITHM}",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    reported = subprocess.run(
        ["fsverity", "digest", str(KERNEL_MODULE), f"--hash-alg={layout.HASH_ALGORITHM}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()[0]
    _, _, digest = reported.partition(":")
    (OUTPUT / layout.FSVERITY_DIGEST).write_text(digest + "\n")

    print(f"    Prepared the fs-verity signature in {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
