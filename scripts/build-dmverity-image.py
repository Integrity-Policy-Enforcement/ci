#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the dm-verity image the tests open.

    build/dmverity/
        dmverity.squashfs     holds ipe_test.ko, nothing else
        dmverity.hash         the Merkle tree veritysetup formatted
        dmverity.roothash     its root hash, as ASCII hex
        dmverity.p7s          that root hash signed by the builtin key
"""

import shutil
import subprocess
from pathlib import Path

import layout

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
KEYS = ROOT / "build" / "keys"
OUTPUT = ROOT / "build" / layout.DMVERITY_ASSETS.name
KERNEL_MODULE = ROOT / "build" / "kernel-module" / layout.TEST_MODULE_FILE
BUILTIN_KEY = KEYS / "builtin-key.pem"
BUILTIN_CERTIFICATE = KEYS / "builtin-cert.pem"


def run(*command, **kwargs):
    return subprocess.run(
        [str(part) for part in command], check=True, stdout=subprocess.DEVNULL, **kwargs
    )


def capture(*command):
    return subprocess.run(
        [str(part) for part in command], check=True, capture_output=True, text=True
    ).stdout


def build_squashfs(image):
    staging = OUTPUT / "tree"
    staging.mkdir()
    shutil.copy(KERNEL_MODULE, staging / KERNEL_MODULE.name)
    run("mksquashfs", staging, image, "-noappend", "-all-root")
    shutil.rmtree(staging)


def format_hash_tree(image, hash_tree):
    for line in capture("veritysetup", "format", image, hash_tree).splitlines():
        if line.startswith("Root hash:"):
            return line.split()[-1]
    raise SystemExit("veritysetup printed no root hash")


def sign_root_hash(root_hash, signature):
    plain = signature.with_suffix(".txt")
    plain.write_text(root_hash)
    run(
        "openssl", "cms", "-sign", "-binary", "-in", plain,
        "-signer", BUILTIN_CERTIFICATE, "-inkey", BUILTIN_KEY,
        "-noattr", "-outform", "DER", "-out", signature,
    )
    plain.unlink()


def main():
    if not BUILTIN_KEY.is_file():
        raise SystemExit("signing keys are missing; run prepare-keys.py")
    if not KERNEL_MODULE.is_file():
        raise SystemExit("the test module is missing; run build-kernel-module.py")
    shutil.rmtree(OUTPUT, ignore_errors=True)
    OUTPUT.mkdir(parents=True)

    image = OUTPUT / layout.SQUASHFS
    build_squashfs(image)
    root_hash = format_hash_tree(image, OUTPUT / layout.HASH_TREE)
    (OUTPUT / layout.ROOT_HASH).write_text(root_hash + "\n")
    sign_root_hash(root_hash, OUTPUT / layout.SIGNATURE)

    print(f"    Prepared the dm-verity image in {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
